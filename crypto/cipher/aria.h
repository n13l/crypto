#ifndef __CRYPTO_CIPHER_ARIA_H__
#define __CRYPTO_CIPHER_ARIA_H__

#include <hpc/compiler.h>
#include <stddef.h>

/*
 * ARIA (RFC 5794, KS X 1213), the Korean block cipher of the TLS 1.2 suites
 * RFC 6209 registers: *_WITH_ARIA_128_GCM_SHA256, *_WITH_ARIA_256_GCM_SHA384
 * and their CBC twins. A 128-bit block under a 128-, 192- or 256-bit key, 12,
 * 14 or 16 rounds of an involutional SPN; TLS names the 128- and 256-bit
 * keys.
 *
 * The context carries its chaining block the way struct aesN_ctx does. One
 * backend, portable C, no assembly.
 */

#define ARIA_BLOCKLEN   16
#define ARIA128_KEYLEN  16
#define ARIA192_KEYLEN  24
#define ARIA256_KEYLEN  32
#define ARIA_ROUNDS_MAX 16

struct aria_ctx {
	u8 ek[ARIA_ROUNDS_MAX + 1][ARIA_BLOCKLEN];	/* encryption round keys */
	u8 dk[ARIA_ROUNDS_MAX + 1][ARIA_BLOCKLEN];	/* decryption round keys */
	unsigned int rounds;
	u8 Iv[ARIA_BLOCKLEN];
};

/* the key schedule alone; -1 for a key that is not 16, 24 or 32 bytes */
int
aria_setkey(struct aria_ctx *ctx, const u8 *key, size_t key_len);

void
aria_encrypt_block(const struct aria_ctx *ctx, const u8 *in, u8 *out);

void
aria_decrypt_block(const struct aria_ctx *ctx, const u8 *in, u8 *out);

int
aria_cbc_init_ctx_iv(struct aria_ctx *ctx, const u8 *key, size_t key_len,
                     const u8 *iv);

void
aria_cbc_encrypt(struct aria_ctx *ctx, u8 *buf, u32 length);

void
aria_cbc_decrypt(struct aria_ctx *ctx, u8 *buf, u32 length);

/* ARIA-GCM, in the contract of <crypto/cipher/aes/gcm.h>: a 12-byte nonce
 * and a 16-byte tag appended to the ciphertext. See <crypto/cipher/sm4.h>. */
#define ARIA_GCM_AUTH_FAILURE 0x55555555

int
aria_gcm_encrypt_aad(u8 *output, const u8 *input, int input_length,
                     const u8 *aad, size_t aad_len,
                     const u8 *key, size_t key_len,
                     const u8 *iv, size_t iv_len);

int
aria_gcm_decrypt_aad(u8 *output, const u8 *input, int input_length,
                     const u8 *aad, size_t aad_len,
                     const u8 *key, size_t key_len,
                     const u8 *iv, size_t iv_len);

int
aria_gcm_encrypt(u8 *output, const u8 *input, int input_length,
                 const u8 *key, size_t key_len, const u8 *iv, size_t iv_len);

int
aria_gcm_decrypt(u8 *output, const u8 *input, int input_length,
                 const u8 *key, size_t key_len, const u8 *iv, size_t iv_len);

#endif
