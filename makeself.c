// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#define	MAX_PHDR	255

static u8 *elf = NULL;
static u8 *self = NULL;

static enum sce_key type;

struct elf_hdr ehdr;
struct elf_phdr phdr[MAX_PHDR];
static int arch64;

static u8 sce_header[0x70];
static u8 info_header[0x20];
static u8 ctrl_header[0x70];

static u8 *sec_header;
static u32 sec_header_size;

static u8 *meta_header;
static u32 meta_header_size;

static u64 header_size;
static u32 meta_offset;
static u64 elf_size;
static u64 info_offset;
static u64 elf_offset;
static u64 phdr_offset;
static u64 shdr_offset;
static u64 sec_offset;
static u64 ctrl_offset;


struct key ks;

static u8 p[20];
static u8 a[20];
static u8 b[20];
static u8 N[21];
static u8 Gx[20];
static u8 Gy[20];
static u8 Q[40];
static u8 k[21];

static void get_rand(u8 *bfr, u32 size)
{
	while (size--)
		*bfr++ = 0xaa;
}

static void get_type(const char *p)
{
	if (strncmp(p, "lv2", 4) == 0)
		type = KEY_LV2;
	else if (strncmp(p, "iso", 4) == 0)
		type = KEY_ISO;
	else if (strncmp(p, "app", 4) == 0)
		type = KEY_APP;
	else
		fail("invalid type: %s", p);
}

static void get_keys(const char *suffix)
{
	if (key_get(type, suffix, &ks) < 0)
		fail("key_get failed");

	if (ks.pub_avail < 0)
		fail("no public key available");

	if (ks.priv_avail < 0)
		fail("no private key available");

	if (ecdsa_get_params(ks.ctype, p, a, b, N, Gx, Gy) < 0)
		fail("ecdsa_get_params() failed");

	memcpy(Q, ks.pub, 40);
	memcpy(k, ks.priv, 21);
}

static void parse_elf(void)
{
	u32 i;

	arch64 = elf_read_hdr(elf, &ehdr);

	for (i = 0; i < ehdr.e_phnum; i++)
		elf_read_phdr(arch64, elf + ehdr.e_phoff + i * ehdr.e_phentsize, &phdr[i]);
}

static void build_sce_hdr(void)
{
	memset(sce_header, 0, sizeof sce_header);

	wbe32(sce_header + 0x00, 0x53434500);	// magic
	wbe32(sce_header + 0x04, 2);		// version
	wbe16(sce_header + 0x08, 1);		// dunno, sdk type?
	wbe16(sce_header + 0x0a, 1);		// SCE header type; self
	wbe32(sce_header + 0x0c, meta_offset);
	wbe64(sce_header + 0x10, header_size);
	wbe64(sce_header + 0x18, elf_size);
	wbe64(sce_header + 0x20, 3);		// dunno, has to be 3
	wbe64(sce_header + 0x28, info_offset);
	wbe64(sce_header + 0x30, elf_offset);
	wbe64(sce_header + 0x38, phdr_offset);
	wbe64(sce_header + 0x40, shdr_offset);
	wbe64(sce_header + 0x48, sec_offset);
	wbe64(sce_header + 0x50, 0xf0f);
	wbe64(sce_header + 0x58, ctrl_offset);
	wbe64(sce_header + 0x60, 0x70);		// ctrl size
}

static void build_info_hdr(void)
{
	u32 app_type;
	u64 auth_id;

	memset(info_header, 0, sizeof info_header);

	switch (type) {
		case KEY_APP:
			app_type = 4;
			auth_id = 0x1010000001000003ULL;
			break;
		case KEY_LV2:
			app_type = 2;
			auth_id = 0x1050000003000001ULL;
			break;
		case KEY_ISO:
			app_type = 5;
			auth_id = 0x1070000020000001ULL;
			break;
		default:
			fail("something that should never fail failed.");	
	}

	wbe64(info_header + 0x00, auth_id);
	wbe32(info_header + 0x0c, app_type);
	wbe64(info_header + 0x10, 0x0001000000000000ULL); // version 1.0.0
}

static void build_ctrl_hdr(void)
{
	memset(ctrl_header, 0, sizeof ctrl_header);

	wbe32(ctrl_header + 0x00, 1);		// type: control flags
	wbe32(ctrl_header + 0x04, 0x30);	// length
	// flags are all zero here

	wbe32(ctrl_header + 0x30, 2);		// type: digest
	wbe32(ctrl_header + 0x34, 0x40);	// length
}

static void build_sec_hdr(void)
{
	u32 i;
	u8 *ptr;

	sec_header_size = ehdr.e_phnum * 0x20;
	sec_header = malloc(sec_header_size);

	memset(sec_header, 0, sec_header_size);

	for (i = 0; i < ehdr.e_phnum; i++) {
		ptr = sec_header + i * 0x20;

		wbe64(ptr + 0x00, phdr[i].p_off + header_size);
		wbe64(ptr + 0x08, phdr[i].p_filesz);
		wbe32(ptr + 0x10, 1);		// not compressed
		wbe32(ptr + 0x14, 0);		// unknown
		wbe32(ptr + 0x18, 0);		// unknown

		if (phdr[i].p_type == 1) 
			wbe32(ptr + 0x1c, 1);	// encrypted LOAD phdr
		else
			wbe32(ptr + 0x1c, 0);	// no loadable phdr
	}
}

static void build_meta_hdr(void)
{
	u32 i;
	u8 *ptr;

	meta_header_size = 0x80 + ehdr.e_phnum * (0x30 + 0x20 + 0x60) + 0x30;
	meta_header = malloc(meta_header_size);
	memset(meta_header, 0, sizeof meta_header);

	ptr = meta_header + 0x20;

	// aes keys for meta encryption
	get_rand(ptr, 0x10);
	get_rand(ptr + 0x20, 0x10);
	ptr += 0x40;

	// area covered by the signature
	wbe64(ptr + 0x00, meta_offset + meta_header_size - 0x30);
	wbe32(ptr + 0x0c, ehdr.e_phnum);	// number of encrypted headers
	wbe32(ptr + 0x10, ehdr.e_phnum * 8);	// number of keys/hashes required
	ptr += 0x20;

	// add encrypted phdr information
	for (i = 0; i < ehdr.e_phnum; i++) {
		wbe64(ptr + 0x00, phdr[i].p_off + header_size);
		wbe64(ptr + 0x08, phdr[i].p_filesz);

		// unknown
		wbe32(ptr + 0x10, 2);
		wbe32(ptr + 0x14, i);		// phdr index maybe?
		wbe32(ptr + 0x18, 2);

		wbe32(ptr + 0x1c, i*8);		// sha index
		wbe32(ptr + 0x20, 3);		// phdr is encrypted
		wbe32(ptr + 0x24, (i*8) + 6);	// key index
		wbe32(ptr + 0x28, (i*8) + 7);	// iv index
		wbe32(ptr + 0x2c, 1);		// not compressed

		ptr += 0x30;
	}

	// add keys/ivs and hmac keys
	get_rand(ptr, ehdr.e_phnum * 8 * 0x10);
}

static void calculate_hashes(void)
{
	u32 i;
	u8 *keys;

	keys = self + meta_offset + 0x80 + (0x30 * ehdr.e_phnum);

	for (i = 0; i < ehdr.e_phnum; i++) {
		memset(keys + (i * 8 * 0x10), 0, 0x20);
		sha1_hmac(keys + ((i * 8) + 2) * 0x10,
		          elf + phdr[i].p_off,
			  phdr[i].p_filesz,
			  keys + (i * 8) * 0x10
			 );
	}	
}

static void build_hdr(void)
{
	memcpy(self, sce_header, sizeof sce_header);
	memcpy(self + info_offset, info_header, sizeof info_header);
	memcpy(self + ctrl_offset, ctrl_header, sizeof ctrl_header);
	memcpy(self + sec_offset, sec_header, sec_header_size);
	memcpy(self + phdr_offset, elf + ehdr.e_phoff, ehdr.e_phnum * ehdr.e_phentsize);
	memcpy(self + shdr_offset, elf + ehdr.e_shoff, ehdr.e_shnum * ehdr.e_shentsize);
	memcpy(self + meta_offset, meta_header, meta_header_size);
	memcpy(self + elf_offset, elf, ehdr.e_ehsize);
	memcpy(self + header_size, elf, elf_size);
}

static void sign_hdr(void)
{
	u8 *r, *s;
	u8 hash[20];
	u64 sig_len;

	sig_len = be64(self + meta_offset + 0x60);
	r = self + sig_len;
	s = r + 21;

	sha1(self, sig_len, hash);

	// TODO :-)
}

static u64 get_filesize(const char *path)
{
	struct stat st;

	stat(path, &st);

	return st.st_size;
}

int main(int argc, char *argv[])
{
	FILE *fp;

	if (argc != 5)
		fail("usage: makeself [type] [version suffix] [elf] [self]");

	get_type(argv[1]);
	get_keys(argv[2]);

	elf_size = get_filesize(argv[3]);
	elf = mmap_file(argv[3]);

	parse_elf();

	info_offset = 0x70;
	ctrl_offset = round_up(info_offset + 0x20, 0x10);
	sec_offset = round_up(ctrl_offset + 0x70, 0x10);
	elf_offset = round_up(sec_offset + ehdr.e_phnum * 0x20, 0x10);
	phdr_offset = round_up(elf_offset + ehdr.e_ehsize, 0x10);	
	shdr_offset = round_up(phdr_offset + ehdr.e_phentsize * ehdr.e_phnum, 0x10);	
	meta_offset = round_up(shdr_offset + ehdr.e_shentsize * ehdr.e_shnum, 0x10);
	header_size = round_up(meta_offset + 0x80 + ehdr.e_phnum * (0x30 + 0x20 + 0x60) + 0x30, 0x10);

	build_sce_hdr();
	build_info_hdr();
	build_ctrl_hdr();
	build_sec_hdr();
	build_meta_hdr();

	self = malloc(header_size + elf_size);
	memset(self, 0, header_size + elf_size);

	build_hdr();
	calculate_hashes();
	sign_hdr();

	sce_encrypt_data(self);
	sce_encrypt_header(self, &ks);

	fp = fopen(argv[4], "wb");
	if (fp == NULL)
		fail("fopen(%s) failed", argv[4]);

	if (fwrite(self, header_size + elf_size, 1, fp) != 1)
		fail("unable to write self");

	fclose(fp);

	return 0;
}
