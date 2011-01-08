// make_self by geohot
// part of geohot's awesome tools for the PS3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <time.h>

#include <openssl/sha.h>
#include <openssl/aes.h>
#include "zlib.h"

//#include "../include/ps3_common.h"
#include <elf.h>
#include "tools.h"
#include "types.h"
#include "ghelper.h"

// all big endian
typedef struct {
  u32 s_magic;      // set to 0x53434500(SCE)
  u32 s_hdrversion; // set to 2
  u16 s_flags;      // 1 is retail
  u16 s_hdrtype;    // 1=SELF, 3=PKG
  u32 s_esize;      // extended self header size(metadata - sizeof(Self_Shdr))
// at +0x10
  u64 s_shsize;     // self header size
  u64 s_exsize;     // extracted file size
} Self_Shdr;    // self header

typedef struct {
  u64 e_magic;      // set to 3
  u64 e_ihoff;      // info header offset in file
  u64 e_ehoff;      // elf header offset
  u64 e_phoff;      // elf phdr offset
  u64 e_shoff;      // elf shdr offset
  u64 e_pmoff;      // elf phdr map offset
  u64 e_svoff;      // SDK version offset
  u64 e_cfoff;      // control flags offset
  u64 e_cfsize;     // control flags size
  u64 e_padding;
} Self_Ehdr;    // extended self header

typedef struct {
  u64 i_authid;     // authid
  u32 i_magic;      // 0x01000002
  u32 i_apptype;    // 4 is application
  u64 i_version;    // 0x0001004000001000 was a good version
  u64 i_padding;
} Self_Ihdr;    // self info header

typedef struct {
  u8 version[0x10];
} Self_SDKversion;

typedef struct {
  u8 cflags1[0x10];
  u8 cflags2[0x20];
  u8 cflags3[0x10];
  u8 hashes[0x30];
} Self_Cflags;

typedef struct {
  u64 pm_offset;
  u64 pm_size;
  u32 pm_compressed; // 2 for compressed, 1 for pt
  u32 pm_unknown2;
  u32 pm_unknown3;
  u32 pm_encrypted;  // 1 for encrypted
} Self_PMhdr;   // phdr map

typedef struct {
  u64 signature_offset;
  u32 unknown1;
  u32 segment_count;
  u32 crypt_len;  // /0x10
  u32 unknown2;
  u64 padding;
} segment_certification_header;

typedef struct {
  u64 segment_offset;
  u64 segment_size;
  u32 segment_crypt_flag;
  u32 segment_number;
  u32 unknown2;
  u32 segment_sha1_index;
  u32 unknown3;
  u32 segment_erk_index;
  u32 segment_riv_index;
  u32 unknown4;
} segment_certification_segment;

typedef struct {
  u8 erk[0x10];
  u8 padding1[0x10];
  u8 riv[0x10];
  u8 padding2[0x10];
} metadata_crypt_header;

typedef struct {
  u8 sha1[0x20];
  u8 hmac[0x40];
} segment_certification_crypt;

typedef struct {
  u8 sha1[0x20];
  u8 hmac[0x40];
  u8 erk[0x10];
  u8 riv[0x10];
} segment_certification_crypt_encrypted;

typedef struct {
  u8 padding1[1];
  u8 R[0x14];
  u8 padding2[1];
  u8 S[0x14];
  u8 padding3[6];
} segment_certification_sign;

typedef struct {
  Self_PMhdr pmhdr;
  segment_certification_segment enc_segment;
  segment_certification_crypt_encrypted crypt_segment;
  u8* data;
  u32 len;
  u32 rlen;
  void* next_section;
} Self_Section;

u8 nubpadding_static[] = {
  0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1B,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00
};

u8 cflags_static[] = {
  0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x62,0x7C,0xB1,0x80,0x8A,0xB9,0x38,0xE3,0x2C,0x8C,0x09,0x17,0x08,0x72,0x6A,0x57,
  0x9E,0x25,0x86,0xE4,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

u8 sdkversion_static[] = {
  0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00
};

AES_KEY aes_key;
struct key ks;

u8* input_elf_data;

//#define NO_CRYPT

static enum sce_key get_type(const char *p)
{
	if (strncmp(p, "lv0", 4) == 0)
		return KEY_LV0;
	else if (strncmp(p, "lv1", 4) == 0)
		return KEY_LV1;
	else if (strncmp(p, "lv2", 4) == 0)
		return KEY_LV2;
	else if (strncmp(p, "iso", 4) == 0)
		return KEY_ISO;
	else if (strncmp(p, "app", 4) == 0)
		return KEY_APP;
	else if (strncmp(p, "ldr", 4) == 0)
		return KEY_LDR;
	else
		fail("invalid type: %s", p);
}

static void get_keys(const char *inType, const char *suffix)
{
	enum sce_key type;
	type = get_type(inType);
	if (key_get(type, suffix, &ks) < 0)
		fail("key_get failed");

	if (ks.pub_avail < 0)
		fail("no public key available");

	if (ks.priv_avail < 0)
		fail("no private key available");

	if (ecdsa_set_curve(ks.ctype) < 0)
		fail("ecdsa_set_curve failed");

	ecdsa_set_pub(ks.pub);
	ecdsa_set_priv(ks.priv);
}

int main(int argc, char* argv[]) {
  int i;
  u8 ecount_buf[0x10], iv[0x10];
  size_t countp;
  int num;

  if(argc < 4) {
    printf("usage: %s input.elf output.self keytype keysuffix\n", argv[0]);
    return -1;
  }

  Elf64_Ehdr input_elf_header;
  FILE *input_elf_file = fopen(argv[1], "rb");

  fseek(input_elf_file, 0, SEEK_END);
  int nlen = ftell(input_elf_file);
  fseek(input_elf_file, 0, SEEK_SET);
  input_elf_data = (u8*)malloc(nlen);
  fread(input_elf_data, 1, nlen, input_elf_file);
  fclose(input_elf_file);

  memcpy(&input_elf_header, input_elf_data, sizeof(input_elf_header));


  FILE *output_self_file = fopen(argv[2], "wb");


  printf("ELF header size @ %x\n", get_u16(&(input_elf_header.e_ehsize)) );
  printf("%d program headers @ %64llX\n", get_u16(&(input_elf_header.e_phnum)), get_u64(&(input_elf_header.e_phoff)));
  printf("%d section headers @ %64llX\n", get_u16(&(input_elf_header.e_shnum)), get_u64(&(input_elf_header.e_shoff)));

  Self_Shdr output_self_header; memset(&output_self_header, 0, sizeof(output_self_header));
  Self_Ehdr output_extended_self_header; memset(&output_extended_self_header, 0, sizeof(output_extended_self_header));
  Self_Ihdr output_self_info_header; memset(&output_self_info_header, 0, sizeof(output_self_info_header));

  set_u32(&(output_self_header.s_magic), 0x53434500);
  set_u32(&(output_self_header.s_hdrversion), 2);
  set_u16(&(output_self_header.s_flags), 1);
  set_u16(&(output_self_header.s_hdrtype), 1);
  // header size and file size aren't known yet

  set_u64(&(output_extended_self_header.e_magic), 3);
  set_u64(&(output_extended_self_header.e_ihoff), sizeof(Self_Shdr)+sizeof(Self_Ehdr));
  set_u64(&(output_extended_self_header.e_ehoff), sizeof(Self_Shdr)+sizeof(Self_Ehdr)+sizeof(Self_Ihdr));
  set_u64(&(output_extended_self_header.e_phoff), sizeof(Self_Shdr)+sizeof(Self_Ehdr)+sizeof(Self_Ihdr)+get_u64(&(input_elf_header.e_phoff)));
  // section header offset unknown

  set_u64(&(output_self_info_header.i_authid), 0x1070000500000001LL);
  set_u32(&(output_self_info_header.i_magic), 0x01000002);
  set_u32(&(output_self_info_header.i_apptype), 4);
  set_u64(&(output_self_info_header.i_version), 0x0003000000000000LL);

// set static data
  int phnum = get_u16(&(input_elf_header.e_phnum));
  u32 phsize = (sizeof(Elf64_Phdr)*get_u16(&(input_elf_header.e_phnum))); 

  Self_SDKversion sdkversion;
  Self_Cflags cflags;
  memcpy(&sdkversion, sdkversion_static, sizeof(Self_SDKversion));
  memcpy(&cflags, cflags_static, sizeof(Self_Cflags));

  int running_size = (sizeof(output_self_header)+sizeof(output_extended_self_header)+sizeof(output_self_info_header)+sizeof(input_elf_header)+phsize+0xF)&0xFFFFFFF0;

  set_u64(&(output_extended_self_header.e_pmoff), running_size); running_size += phnum*sizeof(Self_PMhdr);
  set_u64(&(output_extended_self_header.e_svoff), running_size); running_size += sizeof(Self_SDKversion);
  set_u64(&(output_extended_self_header.e_cfoff), running_size); running_size += sizeof(Self_Cflags);
  set_u64(&(output_extended_self_header.e_cfsize), sizeof(Self_Cflags));
  set_u32(&(output_self_header.s_esize), running_size - sizeof(output_self_header));

  printf("running size is %X\n", running_size);

  int maxsection = 6;

  running_size += sizeof(metadata_crypt_header)+sizeof(segment_certification_header)+maxsection*(sizeof(segment_certification_segment)+sizeof(segment_certification_crypt_encrypted))+sizeof(segment_certification_sign)+sizeof(nubpadding_static);

  printf("running size is %X\n", running_size);

  set_u64(&(output_self_header.s_shsize), running_size);

// init randomness
  gmp_randstate_t r_state;
  gmp_randinit_default(r_state);
  gmp_randseed_ui(r_state, time(NULL));

// loop through the sections

  segment_certification_header segment_header; memset(&segment_header, 0, sizeof(segment_header));
  Self_Section first_section;
  Self_Section* section_ptr = &first_section;

  set_u64(&(segment_header.signature_offset), running_size-sizeof(segment_certification_sign));
  set_u32(&(segment_header.unknown1), 1);
  set_u32(&(segment_header.segment_count), phnum);
  set_u32(&(segment_header.crypt_len), (phnum*sizeof(segment_certification_crypt_encrypted))/0x10);

  Elf64_Phdr* elf_segment = (Elf64_Phdr*)(&input_elf_data[get_u64(&(input_elf_header.e_phoff))]);

  for(i=0;i<phnum;i++) {
    memset(section_ptr, 0, sizeof(Self_Section));

    //set_u64(&(section_ptr->enc_segment.segment_offset), get_u64(&(elf_segment->p_vaddr)));
    set_u64(&(section_ptr->enc_segment.segment_offset), running_size);
    set_u64(&(section_ptr->enc_segment.segment_size), get_u64(&(elf_segment->p_filesz)));
    set_u32(&(section_ptr->enc_segment.segment_crypt_flag), 2);

    set_u32(&(section_ptr->enc_segment.segment_sha1_index), i*8);
    set_u32(&(section_ptr->enc_segment.segment_erk_index), i*8+6);
    set_u32(&(section_ptr->enc_segment.segment_riv_index), i*8+7);

    set_u32(&(section_ptr->enc_segment.segment_number), i);
    set_u32(&(section_ptr->enc_segment.unknown2), 2);
    set_u32(&(section_ptr->enc_segment.unknown3), 3);
    set_u32(&(section_ptr->enc_segment.unknown4), 2);

    set_u64(&(section_ptr->pmhdr.pm_offset), running_size);
    set_u64(&(section_ptr->pmhdr.pm_size), get_u64(&(elf_segment->p_filesz)));
    set_u32(&(section_ptr->pmhdr.pm_compressed), 1);
    set_u32(&(section_ptr->pmhdr.pm_encrypted), 1);

    mpz_t riv, erk, hmac;
    mpz_init(riv); mpz_init(erk); mpz_init(hmac);
    mpz_urandomb(erk, r_state, 128);
    mpz_urandomb(riv, r_state, 128);
    mpz_urandomb(hmac, r_state, 512);

    mpz_export(section_ptr->crypt_segment.erk, &countp, 1, 0x10, 1, 0, erk);
    mpz_export(section_ptr->crypt_segment.riv, &countp, 1, 0x10, 1, 0, riv);
    mpz_export(section_ptr->crypt_segment.hmac, &countp, 1, 0x40, 1, 0, hmac);

    section_ptr->rlen = get_u64(&(elf_segment->p_filesz));
    section_ptr->len = ((section_ptr->rlen)+0xF)&0xFFFFFFF0;
    section_ptr->data = (u8*)malloc(section_ptr->len);

    u32 in_data_offset = get_u64(&(elf_segment->p_offset)); // + get_u16(&(input_elf_header.e_ehsize)) + (sizeof(Elf64_Phdr)*get_u16(&(input_elf_header.e_phnum)));
    u8* in_data = &input_elf_data[in_data_offset];

    printf("processing segment %d with len %x offset %x\n", i, section_ptr->len, in_data_offset);
    //hexdump((u8*)elf_segment, sizeof(Elf64_Phdr));


    /*SHA_CTX c;
    SHA1_ghetto_init(&c, section_ptr->crypt_segment.hmac);
    SHA1_Update(&c, in_data, section_ptr->rlen);
    SHA1_ghetto_final(section_ptr->crypt_segment.sha1, &c, section_ptr->crypt_segment.hmac);*/
    sha1_hmac(section_ptr->crypt_segment.hmac, in_data, section_ptr->rlen, section_ptr->crypt_segment.sha1);

    memset(ecount_buf, 0, 16); num=0;
    AES_set_encrypt_key(section_ptr->crypt_segment.erk, 128, &aes_key);
    memcpy(iv, section_ptr->crypt_segment.riv, 16);

    #ifdef NO_CRYPT
      memcpy(section_ptr->data, in_data, section_ptr->len);   
    #else
      //AES_ctr128_encrypt(in_data, section_ptr->data, section_ptr->len, &aes_key, iv, ecount_buf, &num);
      aes128ctr((u8*)&aes_key, iv, in_data, section_ptr->len, section_ptr->data);
    #endif

    running_size += section_ptr->len;

// next
    if(i != phnum-1) {
      section_ptr->next_section = malloc(sizeof(Self_Section));
    }
    elf_segment += 1;  // 1 is sizeof(Elf64_Phdr)
    section_ptr = section_ptr->next_section;
  }

  printf("segment processing done\n");


// section table offset
  set_u64(&(output_extended_self_header.e_shoff), running_size);

// lay out the metadata
  u8 metadata[0x2000]; memset(metadata, 0, 0x2000);
  u32 metadata_len = 0;

  memcpy(&metadata[metadata_len], &output_self_header, sizeof(output_self_header)); metadata_len += sizeof(output_self_header);
  memcpy(&metadata[metadata_len], &output_extended_self_header, sizeof(output_extended_self_header)); metadata_len += sizeof(output_extended_self_header);
  memcpy(&metadata[metadata_len], &output_self_info_header, sizeof(output_self_info_header)); metadata_len += sizeof(output_self_info_header);
  memcpy(&metadata[metadata_len], &input_elf_header, sizeof(input_elf_header)); metadata_len += sizeof(input_elf_header);
  memcpy(&metadata[metadata_len], &input_elf_data[get_u64(&(input_elf_header.e_phoff))], phsize); metadata_len += phsize;
  metadata_len = (metadata_len+0xF)&0xFFFFFFF0;

  section_ptr = &first_section;
  while(section_ptr != NULL) {
    memcpy(&metadata[metadata_len], &(section_ptr->pmhdr), sizeof(section_ptr->pmhdr)); metadata_len += sizeof(section_ptr->pmhdr);
    section_ptr = section_ptr->next_section;
  }

  memcpy(&metadata[metadata_len], &sdkversion, sizeof(sdkversion)); metadata_len += sizeof(sdkversion);
  memcpy(&metadata[metadata_len], &cflags, sizeof(cflags)); metadata_len += sizeof(cflags);

  printf("top half of metadata ready\n");

// generate metadata encryption keys
  mpz_t bigriv, bigerk;
  mpz_init(bigriv); mpz_init(bigerk);
  mpz_urandomb(bigerk, r_state, 128);
  mpz_urandomb(bigriv, r_state, 128);

  metadata_crypt_header md_header;

  mpz_export(md_header.erk, &countp, 1, 0x10, 1, 0, bigerk);
  mpz_export(md_header.riv, &countp, 1, 0x10, 1, 0, bigriv);

  memcpy(&metadata[metadata_len], &md_header, sizeof(md_header)); metadata_len += sizeof(md_header);
  memcpy(&metadata[metadata_len], &segment_header, sizeof(segment_header)); metadata_len += sizeof(segment_header);

// copy section data
  int csection;

  csection = 0;
  section_ptr = &first_section;
  while(section_ptr != NULL) {
    memcpy(&metadata[metadata_len], &(section_ptr->enc_segment), sizeof(section_ptr->enc_segment)); metadata_len += sizeof(section_ptr->enc_segment);
    section_ptr = section_ptr->next_section;
    if((++csection) == maxsection) break;
  }

  csection = 0;
  section_ptr = &first_section;
  while(section_ptr != NULL) {
    memcpy(&metadata[metadata_len], &(section_ptr->crypt_segment), sizeof(section_ptr->crypt_segment)); metadata_len += sizeof(section_ptr->crypt_segment);
    section_ptr = section_ptr->next_section;
    if((++csection) == maxsection) break;
  }

// nubpadding time
  memcpy(&metadata[metadata_len], nubpadding_static, sizeof(nubpadding_static)); metadata_len += sizeof(nubpadding_static);

// sign shit
  u8 digest[0x14];
  sha1(metadata, metadata_len, digest);
  printf("metadata len is %X\n", metadata_len);
  //hexdump(metadata, metadata_len);
  //hexdump_nl(digest, 0x14);
  segment_certification_sign all_signed;
  memset(&all_signed, 0, sizeof(all_signed));

#ifdef GEOHOT_SIGN
  mpz_t n,k,da,kinv,r,cs,z;
  mpz_init(n); mpz_init(k); mpz_init(da); mpz_init(r); mpz_init(cs); mpz_init(z); mpz_init(kinv);
  mpz_import(r, 0x14, 1, 1, 0, 0, appold_R);
  mpz_import(n, 0x14, 1, 1, 0, 0, appold_n);
  mpz_import(k, 0x14, 1, 1, 0, 0, appold_K);
  mpz_import(da, 0x14, 1, 1, 0, 0, appold_Da);
  mpz_invert(kinv, k, n);

  mpz_import(z, 0x14, 1, 1, 0, 0, digest);

  mpz_mul(cs, r, da); mpz_mod(cs, cs, n);
  mpz_add(cs, cs, z); mpz_mod(cs, cs, n);
  mpz_mul(cs, cs, kinv); mpz_mod(cs, cs, n);

  mpz_export(all_signed.R, &countp, 1, 0x14, 1, 0, r);
  mpz_export(all_signed.S, &countp, 1, 0x14, 1, 0, cs);
#else
  get_keys(argv[3], argv[4]);
  //ecdsa_set_curve(appnew_ctype);
  //ecdsa_set_pub(appnew_pub);
  //ecdsa_set_priv(appnew_priv);
  //ecdsa_sign(digest, all_signed.R, all_signed.S);
#endif

  memcpy(&metadata[metadata_len], &all_signed, sizeof(all_signed)); metadata_len += sizeof(all_signed);

// encrypt metadata
  int metadata_offset = get_u32(&(output_self_header.s_esize)) + sizeof(Self_Shdr);

#ifndef NO_CRYPT
  /*memset(ecount_buf, 0, 16); num=0;
  AES_set_encrypt_key(&metadata[metadata_offset], 128, &aes_key);
  memcpy(iv, &metadata[metadata_offset+0x20], 16);
  //AES_ctr128_encrypt(&metadata[0x40+metadata_offset], &metadata[0x40+metadata_offset], metadata_len-metadata_offset-0x40, &aes_key, iv, ecount_buf, &num);
  aes128ctr(&metadata[0x20+metadata_offset], &metadata[0x40+metadata_offset], &metadata[0x60+metadata_offset], metadata_len-metadata_offset-0x60, &metadata[0x60+metadata_offset]);
  printf("encrypted metadata\n");

  //AES_set_encrypt_key(appold_erk, 256, &aes_key);
  //memcpy(iv, appold_riv, 16);
  AES_set_encrypt_key(appnew_erk, 256, &aes_key);
  memcpy(iv, appnew_riv, 16);
  //AES_cbc_encrypt(&metadata[metadata_offset], &metadata[metadata_offset], 0x40, &aes_key, iv, AES_ENCRYPT);
  aes256cbc_enc(appnew_erk, appnew_riv, &metadata[metadata_offset], 0x40, &metadata[metadata_offset]);

  printf("encrypted keys\n");*/
  //k.key = appnew_erk;
  //k.iv = appnew_riv;
  sce_encrypt_header(metadata, &ks);
#endif

// write the output self
  fwrite(metadata, 1, metadata_len, output_self_file);

  csection = 0;
  section_ptr = &first_section;
  while(section_ptr != 0) {
    printf("writing section with size %X\n", section_ptr->len);
    fwrite(section_ptr->data, 1, section_ptr->len, output_self_file);
    section_ptr = section_ptr->next_section;
    if((++csection) == maxsection) break;
  }

  fwrite(&input_elf_data[get_u64(&(input_elf_header.e_shoff))], sizeof(Elf64_Shdr), get_u16(&(input_elf_header.e_shnum)), output_self_file);

  fclose(output_self_file);
}
