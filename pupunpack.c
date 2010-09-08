#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "tools.h"

static u8 *pup = NULL;
static u64 n_sections;

static void get_fname(char *fname, u64 idx)
{
	memset(fname, 0, 256);
	if (idx == 0)
		strcpy(fname, "version.txt");
	else
		snprintf(fname, 255, "section-%lld", idx);
}

static void do_section(u64 i)
{
	u64 unk;
	u64 offset;
	u64 size;
	u64 idx;
	u8 *hash;
	u32 j;
	char fname[256];
	
	unk = be64(pup + 48 + 32*i);
	offset = be64(pup + 56 + 32*i);
	size = be64(pup + 64 + 32*i);
	idx = be64(pup + 48 + 32*n_sections + 32*i);
	hash = pup + 56 + 32*n_sections + 32*i;

	printf(" section #%lld: unk: %llx offset: %llx size: %llx\n", idx, unk, offset, size);
	printf("              hash:");
	for (j = 0; j < 20; j++)
		printf("%02x", hash[j]);
	printf("\n");

	get_fname(fname, idx);
	memcpy_to_file(fname, pup + offset, size);
}

static void do_pup(void)
{
	u64 hdr_size;
	u64 data_size;
	u64 i;
	
	n_sections = be64(pup + 24);
	hdr_size = be64(pup + 32);
	data_size = be64(pup + 40);

	printf("sections: %lld\n", n_sections);
	printf("hdr size: %lld\n", hdr_size);
	printf("data size: %llx\n", data_size);

	for (i = 0; i < n_sections; i++)
		do_section(i);
}

int main(int argc, char *argv[])
{
	(void)argc;

	if (argv[2] == 0)
		return 0;

	mkdir(argv[2], 0777);
	chdir(argv[2]);

	pup = mmap_file(argv[1]);

	do_pup();

	return 0;
}
