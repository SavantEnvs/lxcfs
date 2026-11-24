/* A stand-in cgroup backend for the cpuview harnesses. lxcfs reads every cgroup file through
 * the global `cgroup_ops` (cgroup.h); here its get()/get_cpuset_cpus() return the fuzz-supplied
 * text for the named file instead of reading cgroupfs. Values are strdup'd (callers free them). */
#ifndef FAKE_CGROUP_H
#define FAKE_CGROUP_H
#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cgroups/cgroup.h"

#define FAKE_NFILES 6
enum { F_CPUSET, F_CPU_MAX, F_CFS_QUOTA, F_CFS_PERIOD, F_USAGE_ALL, F_USAGE_PERCPU };
static const char *fake_names[FAKE_NFILES] = {
	"cpuset.cpus", "cpu.max", "cpu.cfs_quota_us", "cpu.cfs_period_us",
	"cpuacct.usage_all", "cpuacct.usage_percpu",
};
static char *fake_val[FAKE_NFILES];
static struct cgroup_ops fake_ops;

static bool fake_get(struct cgroup_ops *ops, const char *controller, const char *cgroup,
		     const char *file, char **value)
{
	(void)ops; (void)controller; (void)cgroup;
	for (int i = 0; i < FAKE_NFILES; i++) {
		if (strcmp(file, fake_names[i]) == 0) {
			if (!fake_val[i])
				return false;
			*value = strdup(fake_val[i]);
			return *value != NULL;
		}
	}
	return false;
}

static int fake_get_cpuset_cpus(struct cgroup_ops *ops, const char *cgroup, char **value)
{
	(void)ops; (void)cgroup;
	if (!fake_val[F_CPUSET])
		return -1;
	*value = strdup(fake_val[F_CPUSET]);
	return *value ? 0 : -1;
}

/* Split `data` on NUL bytes into the FAKE_NFILES values (a missing part = file absent) and
 * return a pointer/length to whatever follows the last separator. Byte 0 selects the layout
 * (bit 0: pure cgroup2 -> cpu.max, else cgroup1 cfs_quota/period) and which files exist. */
static const uint8_t *fake_setup(const uint8_t *data, size_t size, size_t *rest_len)
{
	for (int i = 0; i < FAKE_NFILES; i++) {
		free(fake_val[i]);
		fake_val[i] = NULL;
	}
	memset(&fake_ops, 0, sizeof(fake_ops));
	fake_ops.get = fake_get;
	fake_ops.get_cpuset_cpus = fake_get_cpuset_cpus;
	cgroup_ops = &fake_ops;
	*rest_len = 0;
	if (size < 1)
		return data;
	uint8_t sel = data[0];
	fake_ops.cgroup_layout = (sel & 1) ? CGROUP_LAYOUT_UNIFIED : CGROUP_LAYOUT_LEGACY;
	data++; size--;
	for (int i = 0; i < FAKE_NFILES; i++) {
		const uint8_t *z = memchr(data, '\0', size);
		size_t n = z ? (size_t)(z - data) : size;
		/* bit 6: no cpuset.cpus; bit 7: no cpuacct.usage_all (-> usage_percpu fallback) */
		bool absent = (i == F_CPUSET) ? (sel & 0x40) : (i == F_USAGE_ALL) ? (sel & 0x80) : 0;
		if (!absent) {
			fake_val[i] = malloc(n + 1);
			if (fake_val[i]) {
				memcpy(fake_val[i], data, n);
				fake_val[i][n] = '\0';
			}
		}
		if (!z) {
			data += n; size = 0;
			break;
		}
		data = z + 1; size -= n + 1;
	}
	*rest_len = size;
	return data;
}
#endif
