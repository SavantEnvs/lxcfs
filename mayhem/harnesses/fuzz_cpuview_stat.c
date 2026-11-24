/* Fuzz cpuview_proc_stat() (src/proc_cpuview.c): lxcfs's per-container /proc/stat renderer.
 * It parses the host /proc/stat "cpuN ..." lines, matches CPUs against cpuset.cpus, reads
 * the CFS quota (cpu.max, or cpu.cfs_quota_us + cpu.cfs_period_us), merges the cgroup's
 * cpuacct usage and formats the result. This follows proc_stat_read(): usage comes from
 * read_cpuacct_usage_all(), then cpuview_proc_stat() runs on the /proc/stat text.
 * Input: see fake_cgroup.h; the bytes after the last cgroup value are the /proc/stat text.
 * The cpuview history (a hash of per-cgroup nodes) is freed and rebuilt after every input so
 * each run depends on that input only; it is always left initialised, because liblxcfs's
 * destructor (bindings.c lxcfs_exit) frees it at process exit. */
#include <stdio.h>
#include "fake_cgroup.h"
#include "proc_cpuview.h"

/* Environment mock: there is no FUSE request in flight, so nothing can be interrupted.
 * liblxcfs polls fuse_interrupted() in its stat-node and lock paths; libfuse's version reads
 * a pthread key that fuse_main() never set up here and dereferences garbage. This replaces
 * the libfuse3 library function only, no lxcfs code. */
int fuse_interrupted(void)
{
	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	init_cpuview();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t rest_len;
	struct cpuacct_usage *usage = NULL;
	int n = 0;
	char cg[] = "/fuzz";
	static char out[16384];
	const uint8_t *rest = fake_setup(data, size, &rest_len);
	char *cpuset = fake_val[F_CPUSET] ? fake_val[F_CPUSET] : "";

	if (read_cpuacct_usage_all(cg, cpuset, &usage, &n) != 0) {
		cgroup_ops = NULL;
		return 0;
	}

	/* exact-size copy so reads past the end of the /proc/stat text are visible to ASan */
	char *stat = malloc(rest_len ? rest_len : 1);
	if (!stat) {
		free(usage);
		cgroup_ops = NULL;
		return 0;
	}
	memcpy(stat, rest, rest_len);
	FILE *f = fmemopen(stat, rest_len ? rest_len : 1, "r");
	if (f) {
		(void)cpuview_proc_stat(cg, cg, cpuset, usage, n, f, out, sizeof(out));
		free_cpuview();
		init_cpuview();
		fclose(f);
	}
	free(stat);
	free(usage);
	cgroup_ops = NULL; /* lxcfs_exit() hands cgroup_ops to cgroup_exit() */
	return 0;
}
