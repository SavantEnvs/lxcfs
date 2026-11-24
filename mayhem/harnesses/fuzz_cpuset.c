/* Fuzz the cpuset.cpus list parser (src/cpuset_parse.c): cpu_in_cpuset() and
 * cpu_number_in_cpuset(), the public entry points lxcfs uses on every cpuset.cpus value it
 * reads from cgroupfs ("0-3,5,7-9").
 * Input: byte 0 = cpu number to look up, the rest = the cpuset string, copied into an
 * exact-size heap buffer and NUL-terminated (cgroup values are C strings) so ASan sees any
 * read past the terminator. */
#include "config.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cpuset_parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return 0;
	int cpu = data[0];
	size_t n = size - 1;
	char *s = malloc(n + 1);
	if (!s)
		return 0;
	memcpy(s, data + 1, n);
	s[n] = '\0';
	(void)cpu_in_cpuset(cpu, s);
	(void)cpu_number_in_cpuset(s);
	free(s);
	return 0;
}
