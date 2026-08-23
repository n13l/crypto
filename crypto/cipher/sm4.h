#ifndef __CRYPTO_CIPHER_SM4_H__
#define __CRYPTO_CIPHER_SM4_H__

#include <hpc/compiler.h>
#include <stddef.h>

/*
 * SM4 (GB/T 32907-2016, ISO/IEC 18033-3:2010/Amd 1), the block cipher of the
 * ShangMi TLS 1.3 suites: TLS_SM4_GCM_SM3 and TLS_SM4_CCM_SM3 (RFC 8998), and
 * of the GB/T 38636 suites a decoder for that protocol would need in CBC.
 *
 * A 128-bit block under a 128-bit key, 32 rounds of one unbalanced Feistel
 * step. The context carries its chaining block the way struct aesN_ctx does,
 * so a caller decrypting a record at a time hands over successive buffers
 * and the IV follows by itself.
 *
 * One backend, portable C, and no assembly: the ShangMi traffic this exists
 * to read is a handful of records in a corpus rather than a throughput path.
 */

#define SM4_BLOCKLEN 16
#define SM4_KEYLEN   16
#define SM4_ROUNDS   32

struct sm4_ctx {
	u32 rk[SM4_ROUNDS];		/* the round keys, encryption order */
	u8 Iv[SM4_BLOCKLEN];
};

/* the key schedule alone, for a caller that runs its own mode over it */
void
sm4_setkey(struct sm4_ctx *ctx, const u8 *key);

/* One block, no chaining: what the modes are built from, and what a test
 * vector is stated in. |in| and |out| may be the same buffer. */
void
sm4_encrypt_block(const struct sm4_ctx *ctx, const u8 *in, u8 *out);

void
sm4_decrypt_block(const struct sm4_ctx *ctx, const u8 *in, u8 *out);

void
sm4_cbc_init_ctx_iv(struct sm4_ctx *ctx, const u8 *key, const u8 *iv);

void
sm4_cbc_encrypt(struct sm4_ctx *ctx, u8 *buf, u32 length);

void
sm4_cbc_decrypt(struct sm4_ctx *ctx, u8 *buf, u32 length);

/*
 * SM4-GCM AEAD (NIST SP 800-38D over SM4), in the contract of
 * <crypto/cipher/aes/gcm.h>: a 12-byte nonce, a 16-byte tag appended to the
 * ciphertext, and associated data authenticated but not encrypted.
 *
 * encrypt: |input_length| plaintext bytes -> |input_length| ciphertext bytes
 *          followed by the tag, so |output| needs input_length + 16 bytes.
 *          Returns 0 on success.
 * decrypt: |input_length| counts the trailing tag. On success the leading
 *          input_length - 16 plaintext bytes are written to |output| and 0 is
 *          returned; SM4_GCM_AUTH_FAILURE means the tag did not verify or a
 *          parameter was refused (a key that is not 16 bytes).
 *
 * The plain pair is the aad pair with no associated data.
 */
#define SM4_GCM_AUTH_FAILURE 0x55555555

int
sm4_gcm_encrypt_aad(u8 *output, const u8 *input, int input_length,
                    const u8 *aad, size_t aad_len,
                    const u8 *key, size_t key_len,
                    const u8 *iv, size_t iv_len);

int
sm4_gcm_decrypt_aad(u8 *output, const u8 *input, int input_length,
                    const u8 *aad, size_t aad_len,
                    const u8 *key, size_t key_len,
                    const u8 *iv, size_t iv_len);

int
sm4_gcm_encrypt(u8 *output, const u8 *input, int input_length,
                const u8 *key, size_t key_len, const u8 *iv, size_t iv_len);

int
sm4_gcm_decrypt(u8 *output, const u8 *input, int input_length,
                const u8 *key, size_t key_len, const u8 *iv, size_t iv_len);

/*
 * SM4-CCM (SP 800-38C over SM4), the mode ../aes/ccm.h describes, compiled
 * from the same ../../modules/cipher/aes-ccm/ccm.c over this block cipher: a
 * 12-byte nonce, a tag of 16 (TLS_SM4_CCM_SM3) appended to the ciphertext,
 * SM4_CCM_AUTH_FAILURE on a tag that does not verify. What a failed decrypt
 * leaves in |output| is unauthenticated bytes — see that header.
 */
#define SM4_CCM_AUTH_FAILURE 0x55555556

int
sm4_ccm_encrypt_aad(u8 *output, const u8 *input, int input_length,
                    const u8 *aad, size_t aad_len,
                    const u8 *key, size_t key_len,
                    const u8 *iv, size_t iv_len, size_t tag_len);

int
sm4_ccm_decrypt_aad(u8 *output, const u8 *input, int input_length,
                    const u8 *aad, size_t aad_len,
                    const u8 *key, size_t key_len,
                    const u8 *iv, size_t iv_len, size_t tag_len);

#endif
