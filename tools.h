// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef TOOLS_H__
#define TOOLS_H__ 1
#include <stdint.h>

#include "types.h"

enum sce_key {
	KEY_LV0 = 0,
	KEY_LV1,
	KEY_LV2,
	KEY_APP,
	KEY_ISO,
	KEY_LDR,
	KEY_PKG,
	KEY_SPP
};

void *mmap_file(const char *path);
void memcpy_to_file(const char *fname, u8 *ptr, u64 size);
const char *id2name(u32 id, struct id2name_tbl *t, const char *unk);
void fail(const char *fmt, ...);
void decompress(u8 *in, u64 in_len, u8 *out, u64 out_len);

int elf_read_hdr(u8 *hdr, struct elf_hdr *h);
void elf_read_phdr(int arch64, u8 *phdr, struct elf_phdr *p);
void elf_read_shdr(int arch64, u8 *shdr, struct elf_shdr *s);
void elf_write_shdr(int arch64, u8 *shdr, struct elf_shdr *s);

void aes256cbc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
void aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);

struct keylist *keys_get(enum sce_key type);

int sce_decrypt_header(u8 *ptr, struct keylist *klist);
int sce_decrypt_data(u8 *ptr);

#define		round_up(x,n)	(-(-(x) & -(n)))

#define		array_size(x)	(sizeof(x) / sizeof(*(x)))
#endif
