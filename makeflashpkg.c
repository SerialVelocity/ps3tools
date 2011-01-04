// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <zlib.h>
#include <time.h>

#define	MAX_FILES	255

static struct key k;

static u8 *pkg = NULL;
static u64 pkg_size = 0;
static u8 info_hdr[0x80];

static u8 sce_hdr[0x20];
static u8 meta_hdr[0x2a0];

static u8 *pkg_files = NULL;
static u64 pkg_files_size = 0;
static u64 pkg_real_size = 0;

static void get_keys(const char *suffix)
{
	if (key_get(KEY_PKG, suffix, &k) < 0)
		fail("key_get() failed");

	if (k.pub_avail < 0)
		fail("no public key available");

	if (k.priv_avail < 0)
		fail("no private key available");

	if (ecdsa_set_curve(k.ctype) < 0)
		fail("ecdsa_set_curve failed");

	ecdsa_set_pub(k.pub);
	ecdsa_set_priv(k.priv);
}


static void get_file(const char *f)
{
	u8 *tmp;
	struct stat st;
	uLongf size_zlib;
	int res;

	tmp = mmap_file(f);
	if (stat(f, &st) < 0)
		fail("cannot stat %s", f);

	pkg_files_size = compressBound(st.st_size);
	pkg_files = malloc(pkg_files_size);
	if (pkg_files == NULL)
		fail("out of memory");

	size_zlib = pkg_files_size;
	res = compress(pkg_files, &size_zlib, tmp, st.st_size);
	if (res != Z_OK)	
		fail("compress returned %d", res);

	pkg_files_size = size_zlib;
	pkg_files = realloc(pkg_files, pkg_files_size);
	pkg_real_size = st.st_size;
}

static void build_sce_hdr(void)
{
	memset(sce_hdr, 0, sizeof sce_hdr);

	wbe32(sce_hdr + 0x00, 0x53434500);	// magic
	wbe32(sce_hdr + 0x04, 2);		// version
	wbe16(sce_hdr + 0x08, 0);		// dunno, sdk type?
	wbe16(sce_hdr + 0x0a, 3);		// SCE header type; pkg
	wbe32(sce_hdr + 0x0c, 0);		// meta offset
	wbe64(sce_hdr + 0x10, sizeof sce_hdr + sizeof meta_hdr);
	wbe64(sce_hdr + 0x18, 0x80 + pkg_real_size);
}

static void build_meta_hdr(void)
{
	u8 *ptr;

	memset(meta_hdr, 0, sizeof sce_hdr);
	ptr = meta_hdr;

	// keys for metadata encryptiomn
	get_rand(ptr, 0x10);
	get_rand(ptr + 0x20, 0x10);
	ptr += 0x40;

	// area covered by the signature
	wbe64(ptr + 0x00, sizeof sce_hdr + sizeof meta_hdr - 0x30);
	wbe32(ptr + 0x0c, 3);		// number of encrypted headers
	wbe32(ptr + 0x10, 3 * 8);	// number of keys/hashes required
	ptr += 0x20;

	// first info header
	wbe64(ptr + 0x00, 0x2c0);	// offset
	wbe64(ptr + 0x08, 0x40);	// size
	wbe32(ptr + 0x10, 1); 		// unknown
	wbe32(ptr + 0x14, 1);		// index
	wbe32(ptr + 0x18, 2);		// unknown again
	wbe32(ptr + 0x1c, 0);		// sha index
	wbe32(ptr + 0x20, 1);		// no encryption
	wbe32(ptr + 0x24, 0xffffffff);	// key index
	wbe32(ptr + 0x28, 0xffffffff);	// iv index
	wbe32(ptr + 0x2c, 0x1);		// no compression
	ptr += 0x30;

	// second info header
	wbe64(ptr + 0x00, 0x300);	// offset
	wbe64(ptr + 0x08, 0x40);	// size
	wbe32(ptr + 0x10, 2); 		// unknown
	wbe32(ptr + 0x14, 2);		// index
	wbe32(ptr + 0x18, 2);		// unknown again
	wbe32(ptr + 0x1c, 8);		// sha index
	wbe32(ptr + 0x20, 1);		// no encryption
	wbe32(ptr + 0x24, 0xffffffff);	// key index
	wbe32(ptr + 0x28, 0xffffffff);	// iv index
	wbe32(ptr + 0x2c, 0x1);		// no compression
	ptr += 0x30;

	// package files
	wbe64(ptr + 0x00, 0x340);	// offset
	wbe64(ptr + 0x08, pkg_files_size);
	wbe32(ptr + 0x10, 3); 		// unknown
	wbe32(ptr + 0x14, 3);		// index
	wbe32(ptr + 0x18, 2);		// unknown again
	wbe32(ptr + 0x1c, 16);		// sha index
	wbe32(ptr + 0x20, 3);		// encrypted
	wbe32(ptr + 0x24, 22);		// key index
	wbe32(ptr + 0x28, 23);		// iv index
	wbe32(ptr + 0x2c, 2);		// compressed
	ptr += 0x30;

	// add keys/ivs and hmac keys
	get_rand(ptr, 3 * 8 * 0x10);
}

static u64 get_timestamp(void)
{
	time_t tt;
	struct tm *t;
	u64 ts = 0;

	tt = time(NULL);
	t = gmtime(&tt);

	t->tm_year += 1900;

	ts |= t->tm_year / 1000;
	ts <<= 4;
	ts |= (t->tm_year % 1000) / 100;
	ts <<= 4;
	ts |= (t->tm_year % 100) / 10;
	ts <<= 4;
	ts |= (t->tm_year % 10);

	t->tm_mon++;
	ts <<= 4;
	ts |= (t->tm_mon % 100) / 10;
	ts <<= 4;
	ts |= (t->tm_mon % 10);

	ts <<= 4;
	ts |= (t->tm_mday % 100) / 10;
	ts <<= 4;
	ts |= (t->tm_mday % 10);

	ts <<= 4;
	ts |= (t->tm_hour % 100) / 10;
	ts <<= 4;
	ts |= (t->tm_hour % 10);

	ts <<= 4;
	ts |= (t->tm_min % 100) / 10;
	ts <<= 4;
	ts |= (t->tm_min % 10);

	ts <<= 4;
	ts |= (t->tm_sec % 100) / 10;
	ts <<= 4;
	ts |= (t->tm_sec % 10);

	ts <<= 8;

	return ts;
}

static void build_info_hdr(void)
{
	// TODO: figure all those values out :-)
	u8 *p;

	memset(info_hdr, 0, sizeof info_hdr);

	p = info_hdr;
	wbe32(p + 0x00, 3);
	wbe32(p + 0x04, 3);
	wbe64(p + 0x08, 0);
	wbe64(p + 0x10, get_timestamp());
	wbe64(p + 0x18, pkg_real_size - 0x80);
	wbe64(p + 0x20, pkg_files_size);
	wbe64(p + 0x28, 0);	// XXX: ???
	wbe64(p + 0x30, 0);
	wbe64(p + 0x38, 0);

	p += 0x40;
	wbe64(p + 0x00, 3);
	wbe64(p + 0x08, 0x40);
	wbe64(p + 0x10, 0);
	wbe64(p + 0x18, pkg_real_size - 0x80);
	wbe64(p + 0x20, 1);
	wbe64(p + 0x28, 1);
	wbe64(p + 0x30, 0);
	wbe64(p + 0x38, 0);
}

static void build_pkg(void)
{
	pkg_size = 0x340 + pkg_files_size;

	pkg = malloc(pkg_size);
	if (pkg == NULL)
		fail("out of memory");

	memset(pkg, 0, sizeof pkg);

	memcpy(pkg, sce_hdr, 0x20);
	memcpy(pkg + 0x20, meta_hdr, 0x2a0);
	memcpy(pkg + 0x2c0, info_hdr, 0x80);	
	memcpy(pkg + 0x340, pkg_files, pkg_files_size);
}

static void calculate_hash(u8 *data, u64 len, u8 *digest)
{
	memset(digest, 0, 0x20);
	sha1_hmac(digest + 0x20, data, len, digest);
}

static void calculate_hashes(void)
{
	calculate_hash(pkg + 0x2c0, 0x40, pkg + 0x80 + 3*0x30);
	calculate_hash(pkg + 0x300, 0x40, pkg + 0x80 + 3*0x30 + 8*0x10);
	calculate_hash(pkg + 0x340, pkg_files_size,
			pkg + 0x80 + 3*0x30 + 16*0x10);
}

static void sign_hdr(void)
{
	u8 *r, *s;
	u8 hash[20];
	u64 sig_len;

	sig_len = be64(pkg + 0x60);
	r = pkg + sig_len;
	s = r + 21;

	sha1(pkg, sig_len, hash);

	ecdsa_sign(hash, r, s);
}

int main(int argc, char *argv[])
{
	FILE *fp;

	if (argc != 4)
		fail("usage: makeflashpkg [key suffix] filename.pkg filename.tar");

	get_keys(argv[1]);
	get_file(argv[2]);

	build_info_hdr();
	build_meta_hdr();
	build_sce_hdr();
	build_pkg();

	calculate_hashes();
	sign_hdr();

	sce_encrypt_data(pkg);
	sce_encrypt_header(pkg, &k);

	fp = fopen(argv[3], "wb");
	if (fp == NULL)
		fail("fopen(%s) failed", argv[3]);

	if (fwrite(pkg, pkg_size, 1, fp) != 1)
		fail("fwrite failed");

	fclose(fp);

	return 0;
}
