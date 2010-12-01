// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "tools.h"

static u8 *pup = NULL;
static u64 n_sections;
static u64 hdr_size;

static struct id2name_tbl t_names[] = {
	{0x100, "version.txt"},
	{0x101, "license.txt"},
	{0x102, "promo_flags.txt"},
	{0x103, "update_flags.txt"},
	{0x104, "patch_build.txt"},
	{0x200, "ps3swu.self"},
	{0x201, "vsh.tar"},
	{0x202, "dots.txt"},
	{0x203, "patch_data.pkg"},
	{0x300, "update_files.tar"},
	{0, NULL}
};

static void do_section(u64 i)
{
	u8 *ptr;
	u64 entry;
	u64 offset;
	u64 size;
	const char *fname;

	ptr = pup + 0x30 + 0x20 * i;
	entry  = be64(ptr);
	offset = be64(ptr + 0x08);
	size   = be64(ptr + 0x10);

	fname = id2name(entry, t_names, NULL);
	if (fname == NULL)
		fail("unknown entry id: %08x_%08x", (u32)(entry >> 32), (u32)entry);

	printf("unpacking %s (%08x_%08x bytes)...\n", fname, (u32)(size >> 32), (u32)size);
	memcpy_to_file(fname, pup + offset, size);
}

static void do_pup(void)
{
	u64 data_size;
	u64 i;
	
	n_sections = be64(pup + 0x18);
	hdr_size   = be64(pup + 0x20);
	data_size  = be64(pup + 0x28);

	printf("sections: %lld\n", n_sections);
	printf("hdr size: %llx\n", hdr_size);
	printf("data size: %llx\n", data_size);

	for (i = 0; i < n_sections; i++)
		do_section(i);
}

int main(int argc, char *argv[])
{
	(void)argc;

	if (argc < 3)
		fail("usage: pupunpack filename.pup directory");

	pup = mmap_file(argv[1]);

	if(pup != NULL)
	{
		mkdir(argv[2], 0777);
		chdir(argv[2]);
		do_pup();
	}

	return 0;
}
