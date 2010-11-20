// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define	MAX_SECTIONS	255

static u8 *self = NULL;
static u8 *elf = NULL;
static FILE *out = NULL;

static u64 info_offset;
static u32 sdk_type;
static u64 phdr_offset;
static u64 shdr_offset;
static u64 sec_offset;
static u64 ver_offset;
static u64 version;
static u64 elf_offset;
static u64 meta_offset;
static u64 header_len;
static u64 filesize;
static u32 arch64;
static u32 n_sections;

static struct elf_hdr ehdr;

static struct {
	u32 offset;
	u32 size;
	u32 compressed;
	u32 size_uncompressed;
} self_sections[MAX_SECTIONS];

static void read_header(void)
{
	sdk_type =    be16(self + 0x08);
	meta_offset = be32(self + 0x0c);
	header_len =  be64(self + 0x10);
	filesize =    be64(self + 0x18);
	info_offset = be64(self + 0x28);
	elf_offset =  be64(self + 0x30);
	phdr_offset = be64(self + 0x38) - elf_offset;
	shdr_offset = be64(self + 0x40) - elf_offset;
	sec_offset =  be64(self + 0x48);
	ver_offset =  be64(self + 0x50);

	version =   be64(self + info_offset + 0x10);

	elf = self + elf_offset;
	arch64 = elf_read_hdr(elf, &ehdr);
}

struct self_sec {
	u32 idx;
	u64 offset;
	u64 size;
	u32 compressed;
	u32 encrypted;
	u64 next;
};

static void read_section(u32 i, struct self_sec *sec)
{
	u8 *ptr;

	ptr = self + sec_offset + i*0x20;

	sec->idx = i;
	sec->offset     = be64(ptr + 0x00);
	sec->size       = be64(ptr + 0x08);
	sec->compressed = be32(ptr + 0x10) == 2 ? 1 : 0;
	sec->encrypted  = be32(ptr + 0x20);
	sec->next       = be64(ptr + 0x20);
}

static int qsort_compare(const void *a, const void *b)
{
	const struct self_sec *sa, *sb;
	sa = a;
	sb = b;

	if (sa->offset > sb->offset)
		return 1;
	else if(sa->offset < sb->offset)
		return -1;
	else
		return 0;
}

static void read_sections(void)
{
	struct self_sec s[MAX_SECTIONS];
	struct elf_phdr p;
	u32 i;
	u32 j;
	u32 n_secs;
	u32 self_offset, elf_offset;

	memset(s, 0, sizeof s);
	for (i = 0, j = 0; i < ehdr.e_phnum; i++) {
		read_section(i, &s[j]);
		if (s[j].compressed)
			j++;
	}

	n_secs = j;
	qsort(s, n_secs, sizeof(*s), qsort_compare);

	elf_offset = 0;
	self_offset = header_len;
	j = 0;
	i = 0;
	while (elf_offset < filesize) {
		if (i == n_secs) {
			printf("final: %08x -> %08x\n", elf_offset, filesize);
			self_sections[j].offset = self_offset;
			self_sections[j].size = filesize - elf_offset;
			self_sections[j].compressed = 0;
			self_sections[j].size_uncompressed = filesize - elf_offset;
			elf_offset = filesize;
		} else if (self_offset == s[i].offset) {
			printf("compressed: %08x (size: %08x)\n", self_offset, s[i].size);
			self_sections[j].offset = self_offset;
			self_sections[j].size = s[i].size;
			self_sections[j].compressed = 1;
			elf_read_phdr(arch64, elf + phdr_offset +
					(ehdr.e_phentsize * s[i].idx), &p);
			self_sections[j].size_uncompressed = p.p_filesz;

			elf_offset += p.p_filesz;
			self_offset += s[i].size;
			i++;
		} else {
			printf("gap: %08x -> %08x\n", self_offset, s[i].offset);
			elf_read_phdr(arch64, elf + phdr_offset +
					(ehdr.e_phentsize * s[i].idx), &p);
			self_sections[j].offset = self_offset;
			self_sections[j].size = p.p_off - elf_offset;
			self_sections[j].compressed = 0;
			self_sections[j].size_uncompressed = self_sections[j].size;

			elf_offset += self_sections[j].size;
			self_offset += s[i].offset - self_offset;
		}
		j++;
	}

	n_sections = j;
}

static void write_elf(void)
{
	u32 i;
	u8 *bfr;
	u32 size;
	u32 offset = 0;

	for (i = 0; i < n_sections; i++) {
		if (self_sections[i].compressed) {
			size = self_sections[i].size_uncompressed;

			bfr = malloc(size);
			if (bfr == NULL)
				fail("failed to allocate %d bytes", size);

			printf("[%08x %08x]*\n", offset, size);
			offset += size;
	
			decompress(self + self_sections[i].offset,
			           self_sections[i].size,
				   bfr, size);
			fwrite(bfr, size, 1, out);
			free(bfr);
		} else {
			bfr = self + self_sections[i].offset;
			size = self_sections[i].size;
			printf("[%08x %08x]\n", offset, size);
			offset += size;
	
			fwrite(bfr, size, 1, out);
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc != 3)
		fail("usage: unself in.self out.elf");

	self = mmap_file(argv[1]);
	out = fopen(argv[2], "w");

	read_header();
	read_sections();

	if (sdk_type != 0x8000)
		fail("Only non-encrypted fselfs are supported. (type: %x)",
		     sdk_type);

	write_elf();
	fclose(out);

	return 0;
}
