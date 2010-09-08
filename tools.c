#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "tools.h"

void *mmap_file(const char *path)
{
	int fd;
	struct stat st;
	void *ptr;

	fd = open(path, O_RDONLY);
	fstat(fd, &st);

	ptr = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	return ptr;
}

void memcpy_to_file(const char *fname, u8 *ptr, u64 size)
{
	FILE *fp;

	fp = fopen(fname, "w");
	fwrite(ptr, size, 1, fp);
	fclose(fp);
}
