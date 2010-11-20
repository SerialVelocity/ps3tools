// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef TOOLS_H__
#define TOOLS_H__ 1
#include <stdint.h>

#include "types.h"

void *mmap_file(const char *path);
void memcpy_to_file(const char *fname, u8 *ptr, u64 size);

int elf_read_hdr(u8 *hdr, struct elf_hdr *h);
void elf_read_phdr(int arch64, u8 *phdr, struct elf_phdr *p);
void elf_read_shdr(int arch64, u8 *shdr, struct elf_shdr *s);

void fail(const char *fmt, ...);

void decompress(u8 *in, u64 in_len, u8 *out, u64 out_len);

#define		round_up(x,n)	(-(-(x) & -(n)))

#define		array_size(x)	(sizeof(x) / sizeof(*(x)))
#endif
