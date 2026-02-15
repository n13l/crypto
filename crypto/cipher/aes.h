#ifndef __CRYPTO_CIPHER_AES_H__
#define __CRYPTO_CIPHER_AES_H__

#include <hpc/compiler.h>

#define AES_BLOCKLEN 16
#define AES128_KEYLEN 16
#define AES128_keyExpSize 176

/*
 * Accelerated backends (e.g. aws-lc AES-NI / ARMv8) reinterpret the ctx
 * storage below as their own, smaller state (raw key + IV; the key schedule
 * is (re)built by the hardware per operation). The generic table-based
 * implementation only ever touches the named fields. The accelerated glue
 * carries a _Static_assert that its state fits within sizeof(struct aesN_ctx).
 */
struct aes128_ctx {
	u8 RoundKey[AES128_keyExpSize];
	u8 Iv[AES_BLOCKLEN];
	const u8 *key;
	const u8 *iv;
};

#define AES256_KEYLEN 32
#define AES256_keyExpSize 240

struct aes256_ctx {
	u8 RoundKey[AES256_keyExpSize];
	u8 Iv[AES_BLOCKLEN];
	const u8 *key;
	const u8 *iv;
};

void
aes128_cbc_init(struct aes128_ctx *aes, const u8 *key);

void
aes128_cbc_init_ctx_iv(struct aes128_ctx *ctx, const u8 *key, const u8 *iv);

void
aes128_cbc_encrypt(struct aes128_ctx *ctx, u8 *buf, u32 length);

void
aes128_cbc_decrypt(struct aes128_ctx *ctx, u8 *buf, u32 length);

void
aes256_cbc_init(struct aes256_ctx *aes, const u8 *key);

void
aes256_cbc_init_ctx_iv(struct aes256_ctx *ctx, const u8 *key, const u8 *iv);

void
aes256_cbc_encrypt(struct aes256_ctx *ctx, u8 *buf, u32 length);

void
aes256_cbc_decrypt(struct aes256_ctx *ctx, u8 *buf, u32 length);

/*
 * AES-GCM AEAD (no associated data, 12-byte IV, 16-byte tag).
 *
 * encrypt: |input_length| plaintext bytes -> |input_length| ciphertext bytes
 *          followed by a 16-byte tag written to |output|. |output| must have
 *          room for input_length + 16 bytes. Returns 0 on success.
 * decrypt: |input_length| = ciphertext + 16-byte trailing tag. On success the
 *          leading input_length - 16 plaintext bytes are written to |output|
 *          and 0 is returned; a non-zero return means tag verification failed.
 */
int
aes_gcm_decrypt(u8 *output, const u8 *input, int input_length,
         const u8* key, const size_t key_len, const u8 *iv, const size_t iv_len);

#endif
