// Copyright 2010	Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <zlib.h>
#include <dirent.h>

#include "tools.h"
#include "aes.h"

//
// misc
//
void *mmap_file(const char *path)
{
	int fd;
	struct stat st;
	void *ptr;

	fd = open(path, O_RDONLY);
	if(fd == -1)
		fail("open %s", path);
	if(fstat(fd, &st) != 0)
		fail("fstat %s", path);

	ptr = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if(ptr==NULL)
		fail("mmap");
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

void fail(const char *a, ...)
{
	char msg[1024];
	va_list va;

	va_start(va, a);
	vsnprintf(msg, sizeof msg, a, va);
	fprintf(stderr, "%s\n", msg);
	perror("perror");

	exit(1);
}

void decompress(u8 *in, u64 in_len, u8 *out, u64 out_len)
{
	z_stream s;
	int ret;

	memset(&s, 0, sizeof(s));

	s.zalloc = Z_NULL;
	s.zfree = Z_NULL;
	s.opaque = Z_NULL;

	ret = inflateInit(&s);
	if (ret != Z_OK)
		fail("inflateInit returned %d", ret);

	s.avail_in = in_len;
	s.next_in = in;

	s.avail_out = out_len;
	s.next_out = out;

	ret = inflate(&s, Z_FINISH);
	if (ret != Z_OK && ret != Z_STREAM_END)
		fail("inflate returned %d", ret);

	inflateEnd(&s);
}

const char *id2name(u32 id, struct id2name_tbl *t, const char *unk)
{
	while (t->name != NULL) {
		if (id == t->id)
			return t->name;
		t++;
	}
	return unk;
}

//
// ELF helpers
//
int elf_read_hdr(u8 *hdr, struct elf_hdr *h)
{
	int arch64;
	memcpy(h->e_ident, hdr, 16);
	hdr += 16;

	arch64 = h->e_ident[4] == 2;

	h->e_type = be16(hdr);
	hdr += 2;
	h->e_machine = be16(hdr);
	hdr += 2;
	h->e_version = be32(hdr);
	hdr += 4;
	
	if (arch64) {
		h->e_entry = be64(hdr);
		h->e_phoff = be64(hdr + 8);
		h->e_shoff = be64(hdr + 16);
		hdr += 24;
	} else {
		h->e_entry = be32(hdr);
		h->e_phoff = be32(hdr + 4);
		h->e_shoff = be32(hdr + 8);
		hdr += 12;
	}

	h->e_flags = be32(hdr);
	hdr += 4;

	h->e_ehsize = be16(hdr);
	hdr += 2;
	h->e_phentsize = be16(hdr);
	hdr += 2;
	h->e_phnum = be16(hdr);
	hdr += 2;
	h->e_shentsize = be16(hdr);
	hdr += 2;
	h->e_shnum = be16(hdr);
	hdr += 2;
	h->e_shtrndx = be16(hdr);

	return arch64;
}

void elf_read_phdr(int arch64, u8 *phdr, struct elf_phdr *p)
{
	if (arch64) {
		p->p_type =   be32(phdr + 0);
		p->p_flags =  be32(phdr + 4);
		p->p_off =    be64(phdr + 1*8);
		p->p_vaddr =  be64(phdr + 2*8);
		p->p_paddr =  be64(phdr + 3*8);
		p->p_filesz = be64(phdr + 4*8);
		p->p_memsz =  be64(phdr + 5*8);
		p->p_align =  be64(phdr + 6*8);
	} else {	
		p->p_type =   be32(phdr + 0*4);
		p->p_off =    be32(phdr + 1*4);
		p->p_vaddr =  be32(phdr + 2*4);
		p->p_paddr =  be32(phdr + 3*4);
		p->p_filesz = be32(phdr + 4*4);
		p->p_memsz =  be32(phdr + 5*4);
		p->p_flags =  be32(phdr + 6*4);
		p->p_align =  be32(phdr + 7*4);
	}
}

void elf_read_shdr(int arch64, u8 *shdr, struct elf_shdr *s)
{
	if (arch64) {
		s->sh_name =	  be32(shdr + 0*4);
		s->sh_type =	  be32(shdr + 1*4);
		s->sh_flags =	  be64(shdr + 2*4);
		s->sh_addr =	  be64(shdr + 2*4 + 1*8);
		s->sh_offset =	  be64(shdr + 2*4 + 2*8);
		s->sh_size =	  be64(shdr + 2*4 + 3*8);
		s->sh_link =	  be32(shdr + 2*4 + 4*8);
		s->sh_info =	  be32(shdr + 3*4 + 4*8);
		s->sh_addralign = be64(shdr + 4*4 + 4*8);
		s->sh_entsize =   be64(shdr + 4*4 + 5*8);
	} else {
		s->sh_name =	  be32(shdr + 0*4);
		s->sh_type =	  be32(shdr + 1*4);
		s->sh_flags =	  be32(shdr + 2*4);
		s->sh_addr =	  be32(shdr + 3*4);
		s->sh_offset =	  be32(shdr + 4*4);
		s->sh_size =	  be32(shdr + 5*4);
		s->sh_link =	  be32(shdr + 6*4);
		s->sh_info =	  be32(shdr + 7*4);
		s->sh_addralign = be32(shdr + 8*4);
		s->sh_entsize =   be32(shdr + 9*4);
	}
}

//
// crypto
//
void aes256cbc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out)
{
	AES_KEY k;
	u32 i;
	u8 tmp[16];

	memset(&k, 0, sizeof k);
	AES_set_decrypt_key(key, 256, &k);

	while (len > 0) {
		memcpy(tmp, in, 16);
		AES_decrypt(in, out, &k);

		for (i = 0; i < 16; i++)
			out[i] ^= iv[i];

		memcpy(iv, tmp, 16);

		out += 16;
		in += 16;
		len -= 16;

	}
}

void aes128ctr(u8 *key, u8 *nonce, u8 *in, u64 len, u8 *out)
{
	AES_KEY k;
	u32 i;
	u8 ctr[16];
	u64 tmp;

	memset(ctr, 0, 16);
	memset(&k, 0, sizeof k);

	AES_set_encrypt_key(key, 128, &k);

	for (i = 0; i < len; i++) {
		if ((i & 0xf) == 0) {
			AES_encrypt(nonce, ctr, &k);
	
			// increase nonce
			tmp = be64(nonce + 8) + 1;
			wbe64(nonce + 8, tmp);
			if (tmp == 0)
				wbe64(nonce, be64(nonce) + 1);
		}
		*out++ = *in++ ^ ctr[i & 0x0f];
	}
}
	
static struct id2name_tbl t_key2file[] = {
	{KEY_LV0, "lv0"},
	{KEY_LV1, "lv1"},
	{KEY_LV2, "lv2"},
	{KEY_APP, "app"},
	{KEY_ISO, "iso"},
	{KEY_LDR, "ldr"},
	{KEY_PKG, "pkg"},
	{0, NULL}
};

static int key_build_path(char *ptr)
{
	char *home = NULL;

	memset(ptr, 0, 256);

	home = getenv("HOME");
	if (home == NULL)
		return -1;

	snprintf(ptr, 256, "%s/.ps3/", home);

	return 0;
}

static int key_read(const char *path, u32 len, u8 *dst)
{
	FILE *fp = NULL;
	u32 read;
	int ret = -1;

	fp = fopen(path, "r");
	if (fp == NULL)
		goto fail;

	read = fread(dst, len, 1, fp);

	if (read != 1)
		goto fail;

	ret = 0;

fail:
	if (fp != NULL)
		fclose(fp);

	return ret;
}

struct keylist *keys_get(enum sce_key type)
{
	const char *name = NULL;
	char base[256];
	struct keylist *klist;
	DIR *dp;
	struct dirent *dent;
	void *tmp = NULL;
	char path[256];
	char *id;

	klist = malloc(sizeof *klist);
	if (klist == NULL)
		goto fail;

	memset(klist, 0, sizeof *klist);

	name = id2name(type, t_key2file, NULL);
	if (name == NULL)
		goto fail;

	if (key_build_path(base) < 0)
		goto fail;

	dp = opendir(base);
	if (dp == NULL)
		goto fail;

	while ((dent = readdir(dp)) != NULL) {
		if (strncmp(dent->d_name, name, strlen(name)) == 0 &&
		    strstr(dent->d_name, "key") != NULL) {
			tmp = realloc(klist->keys, (klist->n + 1) * sizeof(struct key));
			if (tmp == NULL)
				goto fail;

			id = strrchr(dent->d_name, '-');
			if (id != NULL)
				id++;

			klist->keys = tmp;
			snprintf(path, sizeof path, "%s/%s-key-%s", base, name, id);
			key_read(path, 32, klist->keys[klist->n].key);
	
			snprintf(path, sizeof path, "%s/%s-iv-%s", base, name, id);
			key_read(path, 16, klist->keys[klist->n].iv);

			klist->n++;
		}
	}

	return klist;

fail:
	if (klist != NULL) {
		if (klist->keys != NULL)
			free(klist->keys);
		free(klist);
	}
	klist = NULL;

	return NULL;
}

int sce_decrypt_header(u8 *ptr, struct keylist *klist)
{
	u32 meta_offset;
	u32 meta_len;
	u64 header_len;
	u32 i, j;
	u8 tmp[0x40];
	int success = 0;


	meta_offset = be32(ptr + 0x0c);
	header_len  = be64(ptr + 0x10);

	for (i = 0; i < klist->n; i++) {
		aes256cbc(klist->keys[i].key,
			  klist->keys[i].iv,
			  ptr + meta_offset + 0x20,
			  0x40,
			  tmp); 

		success = 1;
		for (j = 0x10; j < (0x10 + 0x10); j++)
			if (tmp[j] != 0)
				success = 0;
	
		for (j = 0x30; j < (0x30 + 0x10); j++)
			if (tmp[j] != 0)
			       success = 0;

		if (success == 1) {
			memcpy(ptr + meta_offset + 0x20, tmp, 0x40);
			break;
		}
	}

	if (success != 1)
		return -1;

	aes128ctr(ptr + meta_offset + 0x20,
		  ptr + meta_offset + 0x40,
		  ptr + meta_offset + 0x60,
		  0x20,
		  ptr + meta_offset + 0x60);

	meta_len = header_len - meta_offset;

	aes128ctr(ptr + meta_offset + 0x20,
		  ptr + meta_offset + 0x40,
		  ptr + meta_offset + 0x80,
		  meta_len - 0x80,
		  ptr + meta_offset + 0x80);
	return 0;
}

static void print_hash(u8 *ptr, u32 len)
{
	while(len--)
		printf(" %02x", *ptr++);
}
int sce_decrypt_data(u8 *ptr)
{
	u64 meta_offset;
	u32 meta_len;
	u32 meta_n_hdr;
	u64 header_len;
	u32 i;

	u64 offset;
	u64 size;
	u32 keyid;
	u32 nonceid;
	u8 *tmp;

	meta_offset = be32(ptr + 0x0c);
	header_len  = be64(ptr + 0x10);
	meta_len = header_len - meta_offset;
	meta_n_hdr = be32(ptr + meta_offset + 0x60 + 0xc);

	for (i = 0; i < meta_n_hdr; i++) {
		tmp = ptr + meta_offset + 0x80 + 0x30*i;
		offset = be64(tmp);
		size = be64(tmp + 8);
		keyid = be32(tmp + 0x24);
		nonceid = be32(tmp + 0x28);

		if (keyid == 0xffffffff || nonceid == 0xffffffff)
			continue;

		aes128ctr(ptr + meta_offset + 0x80 + 0x30 * meta_n_hdr + keyid * 0x10,
		          ptr + meta_offset + 0x80 + 0x30 * meta_n_hdr + nonceid * 0x10,
 		          ptr + offset,
			  size,
			  ptr + offset);
	}

	return 0;
}
