#ifndef __CRYPTO_CIPHER_CAMELLIA_H__
#define __CRYPTO_CIPHER_CAMELLIA_H__

#include <hpc/compiler.h>
#include <stddef.h>

/*
 * Camellia (RFC 3713, ISO/IEC 18033-3), the block cipher of the TLS suites
 * RFC 5932 (CBC) and RFC 6367 (CBC with SHA-2, and GCM) register. A 128-bit
 * block under a 128-, 192- or 256-bit key: an 18-round Feistel network for
 * the short key and 24 rounds for the long ones, with the FL/FL^-1 layers
 * every six rounds. TLS names the 128- and 256-bit keys.
 *
 * The context carries its chaining block the way struct aesN_ctx does. One
 * backend, portable C, no assembly.
 */

#define CAMELLIA_BLOCKLEN   16
#define CAMELLIA128_KEYLEN  16
#define CAMELLIA192_KEYLEN  24
#define CAMELLIA256_KEYLEN  32

struct camellia_ctx {
	u64 kw[4];		/* the whitening keys, encryption order */
	u64 k[24];		/* the round keys                       */
	u64 ke[6];		/* the FL/FL^-1 keys                    */
	unsigned int rounds;	/* 18 or 24                             */
	u8 Iv[CAMELLIA_BLOCKLEN];
};

/* the key schedule alone; -1 for a key that is not 16, 24 or 32 bytes */
int
camellia_setkey(struct camellia_ctx *ctx, const u8 *key, size_t key_len);

void
camellia_encrypt_block(const struct camellia_ctx *ctx, const u8 *in, u8 *out);

void
camellia_decrypt_block(const struct camellia_ctx *ctx, const u8 *in, u8 *out);

int
camellia_cbc_init_ctx_iv(struct camellia_ctx *ctx, const u8 *key,
                         size_t key_len, const u8 *iv);

void
camellia_cbc_encrypt(struct camellia_ctx *ctx, u8 *buf, u32 length);

void
camellia_cbc_decrypt(struct camellia_ctx *ctx, u8 *buf, u32 length);

/* Camellia-GCM (RFC 6367), in the contract of <crypto/cipher/aes/gcm.h>. */
#define CAMELLIA_GCM_AUTH_FAILURE 0x55555555

int
camellia_gcm_encrypt_aad(u8 *output, const u8 *input, int input_length,
                         const u8 *aad, size_t aad_len,
                         const u8 *key, size_t key_len,
                         const u8 *iv, size_t iv_len);

int
camellia_gcm_decrypt_aad(u8 *output, const u8 *input, int input_length,
                         const u8 *aad, size_t aad_len,
                         const u8 *key, size_t key_len,
                         const u8 *iv, size_t iv_len);

int
camellia_gcm_encrypt(u8 *output, const u8 *input, int input_length,
                     const u8 *key, size_t key_len,
                     const u8 *iv, size_t iv_len);

int
camellia_gcm_decrypt(u8 *output, const u8 *input, int input_length,
                     const u8 *key, size_t key_len,
                     const u8 *iv, size_t iv_len);

#endif
