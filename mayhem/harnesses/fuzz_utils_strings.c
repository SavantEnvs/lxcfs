/* Fuzz the string/number helpers lxcfs applies to every value it reads from cgroupfs and to
 * cgroup paths from /proc/<pid>/cgroup: safe_uint64/safe_uint32 (base 10 and 16),
 * trim_whitespace_in_place (src/utils.c), prune_init_slice (src/utils.c) and
 * prune_init_scope (src/cgroups/cgroup.c). Each call gets its own exact-size NUL-terminated
 * heap copy of the input. */
#include "config.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "cgroups/cgroup.h"

static char *dup_input(const uint8_t *data, size_t size)
{
	char *s = malloc(size + 1);
	if (s) {
		memcpy(s, data, size);
		s[size] = '\0';
	}
	return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *s;
	uint64_t u64;
	uint32_t u32;

	if ((s = dup_input(data, size))) { (void)safe_uint64(s, &u64, 10); free(s); }
	if ((s = dup_input(data, size))) { (void)safe_uint64(s, &u64, 16); free(s); }
	if ((s = dup_input(data, size))) { (void)safe_uint32(s, &u32, 10); free(s); }
	if ((s = dup_input(data, size))) { (void)safe_uint32(s, &u32, 16); free(s); }
	if ((s = dup_input(data, size))) {
		char *t = trim_whitespace_in_place(s);
		if (t) (void)safe_uint64(t, &u64, 10);
		free(s);
	}
	if ((s = dup_input(data, size))) { prune_init_slice(s); free(s); }
	if ((s = dup_input(data, size))) { (void)prune_init_scope(s); free(s); }
	return 0;
}
