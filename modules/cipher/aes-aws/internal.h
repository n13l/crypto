/*
 * Shared prototypes for the aws-lc AES-NI / ARMv8 assembly primitives used by
 * the accelerated AES cipher glue. These match the entry points exported by
 * vendor/aws-lc/.../aesni-x86_64.S + ghash-x86_64.S (x86_64) and
 * aesv8-armx.S + ghashv8-armx.S (ARMv8).
 */
#ifndef __OSS_CRYPTO_CIPHER_AES_AWS_INTERNAL_H__
#define __OSS_CRYPTO_CIPHER_AES_AWS_INTERNAL_H__

#include <hpc/compiler.h>
#include <stddef.h>
#include <stdint.h>

/* aws-lc AES_KEY: rd_key[4 * (AES_MAXNR + 1)] + rounds, AES_MAXNR == 14. */
#define AES_AWS_MAXNR 14
struct aes_key_st {
	uint32_t rd_key[4 * (AES_AWS_MAXNR + 1)];
	unsigned int rounds;
};
typedef struct aes_key_st AES_KEY;

/* 128-bit GHASH table element (see aws-lc modes/internal.h). */
typedef struct {
	uint64_t hi, lo;
} u128;

/* AES-NI / ARMv8 block-cipher primitives. Both architectures export the same
 * aes_hw_* names. set_*_key return 0 on success. */
int aes_hw_set_encrypt_key(const uint8_t *user_key, int bits, AES_KEY *key);
int aes_hw_set_decrypt_key(const uint8_t *user_key, int bits, AES_KEY *key);
void aes_hw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_hw_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
			const AES_KEY *key, uint8_t *ivec, int enc);
void aes_hw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
				 const AES_KEY *key, const uint8_t ivec[16]);

/*
 * GHASH primitives. The concrete flavour (CLMUL for x86_64, PMULL/v8 for
 * ARMv8) is selected by the per-architecture Kbuild via -D. |H| is passed as a
 * pair of big-endian-loaded 64-bit words (see CRYPTO_ghash_init in aws-lc).
 */
#ifndef AES_AWS_GHASH_INIT
#define AES_AWS_GHASH_INIT  gcm_init_clmul
#define AES_AWS_GHASH_GMULT gcm_gmult_clmul
#define AES_AWS_GHASH_GHASH gcm_ghash_clmul
#endif

void AES_AWS_GHASH_INIT(u128 Htable[16], const uint64_t H[2]);
void AES_AWS_GHASH_GMULT(uint8_t Xi[16], const u128 Htable[16]);
void AES_AWS_GHASH_GHASH(uint8_t Xi[16], const u128 Htable[16],
			 const uint8_t *inp, size_t len);

#endif
