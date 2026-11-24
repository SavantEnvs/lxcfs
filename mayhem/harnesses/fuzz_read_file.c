/* Fuzz the file slurpers every cgroup/proc file read in lxcfs goes through:
 * read_file_at() (src/utils.c) and read_file()/read_file_strip_newline()/readat_file()
 * (src/cgroups/cgroup_utils.c). The input is written to a fresh temp file under $TMPDIR. */
#include "config.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"
#include "cgroups/cgroup_utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *tmp = getenv("TMPDIR");
	char path[4096];
	char *dir, *base, *r;
	int fd, dfd;

	if (!tmp || !*tmp)
		tmp = "/tmp";
	snprintf(path, sizeof(path), "%s/lxcfs-fuzz-XXXXXX", tmp);
	fd = mkstemp(path);
	if (fd < 0)
		return 0;
	if (size && write(fd, data, size) != (ssize_t)size) {
		close(fd);
		unlink(path);
		return 0;
	}
	close(fd);

	r = read_file_at(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
	free(r);
	r = read_file(path);
	free(r);
	r = read_file_strip_newline(path);
	free(r);

	dir = strdup(path);
	if (dir) {
		base = strrchr(dir, '/');
		*base++ = '\0';
		dfd = open(*dir ? dir : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (dfd >= 0) {
			r = readat_file(dfd, base);
			free(r);
			close(dfd);
		}
		free(dir);
	}
	unlink(path);
	return 0;
}
