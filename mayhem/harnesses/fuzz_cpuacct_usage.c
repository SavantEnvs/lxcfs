/* Fuzz read_cpuacct_usage_all() (src/proc_cpuview.c): the parser for cgroup v1
 * cpuacct.usage_all ("cpu user system\n0 123 456\n...") and its cpuacct.usage_percpu
 * fallback, both read from cgroupfs by lxcfs when it renders a container's /proc/stat.
 * Input: see fake_cgroup.h (selector byte, then NUL-separated cgroup file values). */
#include "fake_cgroup.h"
#include "proc_cpuview.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t rest;
	struct cpuacct_usage *usage = NULL;
	int n = 0;
	char cg[] = "/fuzz";
	char *cpuset;

	fake_setup(data, size, &rest);
	cpuset = fake_val[F_CPUSET] ? fake_val[F_CPUSET] : "";
	if (read_cpuacct_usage_all(cg, cpuset, &usage, &n) == 0)
		free(usage);
	cgroup_ops = NULL; /* lxcfs_exit() hands cgroup_ops to cgroup_exit() */
	return 0;
}
