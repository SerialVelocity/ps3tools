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
#include <sys/stat.h>

u8 *pkg = NULL;
static u64 dec_size;

static void decompress_pkg(void *ptr)
{
	u32 meta_offset;
	u32 n_sections;
	u64 offset;
	u64 size;
	int compressed;
	u8 *tmp;

	meta_offset = be32(pkg + 0x0c);
	n_sections  = be32(pkg + meta_offset + 0x60 + 0xc);

	if (n_sections != 3)
		fail("invalid package file.");

	tmp = pkg + meta_offset + 0x80 + 0x30 * 0;
	offset = be64(tmp);
	if (be32(pkg + offset + 0x4) != 3)
		fail("not a flash package");

	tmp = pkg + meta_offset + 0x80 + 0x30 * 2;
	offset = be64(tmp);
	size = be64(tmp + 8);

	compressed = 0;
	if (be32(tmp + 0x2c) == 0x2)
		compressed = 1;

	printf("compressed: %d; %08x\n", compressed, be32(tmp + 0x2c));
	if (compressed)
		decompress(pkg + offset, size, ptr, dec_size); 
	else
		memcpy(ptr, pkg + offset, size);
}

static void decrypt_pkg(void)
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
		fail("no flash .pkg file");

	if (flags & 0x8000)
		fail("not encrypted");

	k = keys_get(KEY_PKG);

	if (sce_decrypt_header(pkg, k) < 0)
		fail("header decryption failed");

	if (sce_decrypt_data(pkg) < 0)
		fail("data decryption failed");

	ptr = malloc(dec_size);
	memset(ptr, 0xaa, dec_size);

	decompress_pkg(ptr);

	pkg = ptr;
}

static void write_tar(const char *f)
{
	FILE *fp;

	fp = fopen(f, "wb");
	fwrite(pkg, dec_size, 1, fp);
	fclose(fp);
}

int main(int argc, char *argv[])
{
	if (argc != 3)
		fail("usage: unflashpkg filename.pkg target.tar");

	pkg = mmap_file(argv[1]);

	decrypt_pkg();
	write_tar(argv[2]);

	return 0;
}
