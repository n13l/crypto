/*
 * Based on BSD code Jouni Malinen <j@w1.fi>
 *
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <sys/compiler.h>
#include <mem/unaligned.h>
#include <crypto/cipher.h>
#include <string.h>

/*
#define AES128_KEY_LENGTH 16
#define AES256_KEY_LENGTH 32

#define AES_BLOCK_SIZE 16

struct aes_gcm {
	u8 key[32];
	unsigned int key_size;
	u8 iv[16];
	unsigned int iv_size;
};

static void
rfc5246_gcm256_set_mac(struct cipher *cipher, const u8 *mac, unsigned int size)
{
}

static void
rfc5246_gcm256_set_key(struct cipher* cipher, const u8* key, unsigned int size)
{
}

static void
rfc5246_gcm256_set_iv(struct cipher* cipher, const u8* iv, unsigned int size)
{
}

static void
rfc5246_gcm256_decrypt(struct cipher *c, const u8* msg, unsigned int len,
                       u8 *out, unsigned int *out_len)
{
}

static void
rfc5246_gcm256_encrypt(struct cipher *c, const u8* msg, unsigned int len,
                       u8 *out, unsigned int *out_len)
{
}

static void
rfc5246_gcm256_encrypt_inplace(struct cipher *c, u8* msg, unsigned int len)
{
}

static void
rfc5246_gcm256_decrypt_inplace(struct cipher *c, u8* msg, unsigned int len)
{
}

struct cipher_algorithm rfc5246_aes128_gcm = {
	.name = "aes128-gcm",
	.id = CIPHER_AES128,
	.mode = CIPHER_MODE_GCM,
	.type = CIPHER_TYPE_BLOCK,
	.dialect = CIPHER_RFC5246,
	.ctx_size = sizeof(struct aes_gcm),
	.key_size = AES128_KEY_LENGTH,
	.block_size = 16,
	.iv_size = 0,
	.set_key = rfc5246_gcm256_set_key,
	.set_iv = rfc5246_gcm256_set_iv,
	.decrypt = rfc5246_gcm256_decrypt,
	.encrypt = rfc5246_gcm256_encrypt,
	.decrypt_inplace = rfc5246_gcm256_decrypt_inplace,
	.encrypt_inplace = rfc5246_gcm256_encrypt_inplace,
};

struct cipher_algorithm rfc5246_aes256_gcm = {
	.name = "aes256-gcm",
	.id = CIPHER_AES256,
	.mode = CIPHER_MODE_GCM,
	.type = CIPHER_TYPE_BLOCK,
	.dialect = CIPHER_RFC5246,
	.ctx_size = sizeof(struct aes_gcm),
	.key_size = AES256_KEY_LENGTH,
	.block_size = 32,
	.iv_size = 0,
	.set_key = rfc5246_gcm256_set_key,
	.set_mac = rfc5246_gcm256_set_mac,
	.set_iv = rfc5246_gcm256_set_iv,
	.decrypt = rfc5246_gcm256_decrypt,
	.encrypt = rfc5246_gcm256_encrypt,
	.decrypt_inplace = rfc5246_gcm256_decrypt_inplace,
	.encrypt_inplace = rfc5246_gcm256_encrypt_inplace,
};

void
crypto_init_rfc5246_aes256_gcm(void)
{
	crypto_cipher_register(&rfc5246_aes128_gcm);
	crypto_cipher_register(&rfc5246_aes256_gcm);
}

*/
#ifdef TEST_VECTORS

/* aes-gcm test data from NIST public test vectors */
static const u8 gcm_key[] = {
	0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
	0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
	0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const u8 gcm_iv[] = {
	0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const u8 gcm_pt[] = {
	0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
	0xcc, 0x2b, 0xf2, 0xa5
};

static const u8 gcm_aad[] = {
	0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
	0x7f, 0xec, 0x78, 0xde
};

static const u8 gcm_ct[] = {
	0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
	0xb9, 0xf2, 0x17, 0x36
};

static const u8 gcm_tag[] = {
	0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
	0x98, 0xf7, 0x7e, 0x0c
};

int main()
{
	return 0;
}

#endif
