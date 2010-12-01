// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

u8 *pkg = NULL;
static u64 dec_size;

static void parse_pkg(void);

static void unpack_file(u32 i)
{
	u8 *ptr;
	u8 name[33];
	u64 offset;
	u64 size;

	ptr = pkg + 0x10 + 0x30 * i;

	offset = be64(ptr + 0x00);
	size   = be64(ptr + 0x08);

	memset(name, 0, sizeof name);
	strncpy((char *)name, (char *)(ptr + 0x10), 0x20);

	printf("unpacking %s...\n", name);
	memcpy_to_file((char *)name, pkg + offset, size);
}

static void parse_pkg_1(void)
{
	u32 n_files;
	u64 size;
	u32 i;

	n_files = be32(pkg + 4);
	size = be64(pkg + 8);

	for (i = 0; i < n_files; i++)
		unpack_file(i);
}

static void decompress_pkg(void *ptr)
{
	u32 meta_offset;
	u32 n_sections;
	u32 i;
	u64 offset;
	u64 size;
	int compressed;
	u8 *tmp;

	meta_offset = be32(pkg + 0x0c);
	n_sections  = be32(pkg + meta_offset + 0x60 + 0xc);

	for (i = 0; i < n_sections; i++) {
		tmp = pkg + meta_offset + 0x80 + 0x30 * i;
		offset = be64(tmp);
		size = be64(tmp + 8);

		compressed = 0;
		if (be32(tmp + 0x2c) == 0x2)
			compressed = 1;

		if (compressed) {
			// XXX: is always only the last section compressed?
			if (i + 1 != n_sections)
				fail("weird pkg: not only last section is compressed");
			decompress(pkg + offset, size,
			           ptr, dec_size); 
		} else {
	
			memcpy(tmp, pkg + offset, size);
			tmp += size;
			dec_size -= size;
		}
	}
}

static void parse_pkg_sce(void)
{
	u16 flags;
	u16 type;
	u32 hdr_len;
	u8 *ptr;
	struct keylist *k;

	flags    = be16(pkg + 0x08);
	type     = be16(pkg + 0x0a);
	hdr_len  = be64(pkg + 0x10);
	dec_size = be64(pkg + 0x18);

	if (type != 3)
		fail("no update .pkg file");

	if (flags & 0x8000) {
		pkg += hdr_len;
		return parse_pkg_1();
	}

	k = keys_get(KEY_PKG);

	if (sce_decrypt_header(pkg, k) < 0)
		fail("header decryption failed");

	if (sce_decrypt_data(pkg) < 0)
		fail("data decryption failed");

	ptr = malloc(dec_size);
	memset(ptr, 0, dec_size);

	decompress_pkg(ptr);

	pkg = ptr;

	parse_pkg();
}

static void parse_pkg(void)
{
	if (memcmp(pkg, "SCE", 3) == 0)
		parse_pkg_sce();
	else if (be32(pkg) == 1)
		parse_pkg_1();
	else
		fail("unknown pkg type");
}

int main(int argc, char *argv[])
{
	if (argc != 3)
		fail("usage: unpkg filename.pkg target");

	pkg = mmap_file(argv[1]);

	if (chdir(argv[2]) != 0)
		fail("chdir");

	parse_pkg();

	return 0;
}
