/*
 * AES-GCM in TLS has 3 parts:
 *
 * salt, 4 bytes, generated in handshake, not changed in whole session
 * nonce_explicit, 8 bytes, chosen by the sender and carried in each 
 * SSL record inner_counter, 4 bytes, used in AES-GCM internal
 *
 * Implementations not using a counter/sequence-based AES-GCM nonce 
 * were found to be indeed vulnerable by the "Nonce-Disrespecting 
 * Adversaries" paper.
 *
 * GCM/CCM mode only part of IV comes from PRF
 * https://github.com/nonce-disrespect/nonce-disrespect
 */

#include <string.h>
#include <sys/compiler.h>
#include <sys/log.h>
#include <crypto/cipher.h>
#include <crypto/abi/ssl/aes.h>

#define AES128_KEY_LENGTH                         16
#define AES256_KEY_LENGTH                         32
#define AES_BLOCK_SIZE                            16
#define AES128_BLOCK_SIZE                         16
#define AES256_BLOCK_SIZE                         32

#define TLS_GCM_TLS_FIXED_IV_LEN                  4
#define TLS_GCM_TLS_EXPLICIT_IV_LEN               8
#define TLS_GCM_TLS_TAG_LEN                       16
#define TLS_GCM_FIXED_IV_LEN                      4
#define TLS_GCM_EXPLICIT_IV_LEN                   8
#define TLS_GCM_TAG_LEN                           16

#define TLS_GCM_IV_LEN (TLS_GCM_FIXED_IV_LEN + TLS_GCM_EXPLICIT_IV_LEN)

struct rfc5246_aes_gcm {
	const u8 *key, *iv;
	unsigned int key_len, iv_len;
	u64 seqno;
};

struct rfc5246_gcm_nonce {
	u8 salt[TLS_GCM_FIXED_IV_LEN];
	u8 nonce_explicit[TLS_GCM_EXPLICIT_IV_LEN];
};

static void
rfc5246_gcm_init(struct cipher *cipher, const u8 *key, unsigned int klen,
              const u8* iv, unsigned int ilen, const u8* mac, unsigned int mlen)
{
	struct rfc5246_aes_gcm *c = (__typeof__(c))cipher;
	c->seqno = 0;
	c->key_len = c->iv_len = 0;
}

static void
rfc5246_gcm_set_mac(struct cipher *cipher, const u8 *mac, unsigned int len)
{
}

static void
rfc5246_gcm_set_key(struct cipher *cipher, const u8 *key, unsigned int len)
{
	struct rfc5246_aes_gcm *c = (__typeof__(c))cipher;
	c->key = key;
	c->key_len = len;
}

static void
rfc5246_gcm_set_iv(struct cipher *cipher, const u8 *iv, unsigned int len)
{
	struct rfc5246_aes_gcm *c = (__typeof__(c))cipher;
	c->iv = iv;
	c->iv_len = len;
}

#define aes_seed_concate2(s1, l1, s2, l2) \
({ \
	u8 *__seed = alloca(32); \
	memcpy(&__seed[0], (s1), (l1)); \
	memcpy(&__seed[(l1)],(s2), (l2)); \
	__seed; \
})

static void
rfc5246_gcm_decrypt(struct cipher *cipher, const u8* msg, unsigned int mlen,
                    u8 *out, unsigned int *len)
{
	struct rfc5246_aes_gcm *c = (__typeof__(c))cipher;
	int size = mlen - TLS_GCM_EXPLICIT_IV_LEN;
	u8 *nonce = aes_seed_concate2(c->iv, c->iv_len,
	                              msg, TLS_GCM_EXPLICIT_IV_LEN);

	int rv = openssl_aes_gcm_decrypt(msg + TLS_GCM_EXPLICIT_IV_LEN, size,
	                        c->key, c->key_len, nonce, TLS_GCM_IV_LEN, out);

	*len = rv < 1 ? 0 : rv;
}

static void
rfc5246_gcm_encrypt(struct cipher *c, const u8* msg, unsigned int mlen,
                    u8 *out, unsigned int *olen)
{
}

struct cipher_algorithm rfc5246_aes128_gcm = {
	.name = "aes128-gcm",
	.id = CIPHER_AES128,
	.mode = CIPHER_MODE_GCM,
	.type = CIPHER_TYPE_BLOCK,
	.dialect = CIPHER_RFC5246,
	.ctx_size = sizeof(struct rfc5246_aes_gcm),
	.key_size = AES128_KEY_LENGTH,
	.block_size = AES128_BLOCK_SIZE,
	.iv_size = TLS_GCM_IV_LEN,
	.init = rfc5246_gcm_init,
	.set_key = rfc5246_gcm_set_key,
	.set_mac = rfc5246_gcm_set_mac,
	.set_iv = rfc5246_gcm_set_iv,
	.decrypt = rfc5246_gcm_decrypt,
	.encrypt = rfc5246_gcm_encrypt,
};

struct cipher_algorithm rfc5246_aes256_gcm = {
	.name = "aes256-gcm",
	.id = CIPHER_AES256,
	.mode = CIPHER_MODE_GCM,
	.type = CIPHER_TYPE_BLOCK,
	.dialect = CIPHER_RFC5246,
	.ctx_size = sizeof(struct rfc5246_aes_gcm),
	.key_size = AES256_KEY_LENGTH,
	.block_size = AES256_BLOCK_SIZE,
	.iv_size = TLS_GCM_IV_LEN,
	.init = rfc5246_gcm_init,
	.set_key = rfc5246_gcm_set_key,
	.set_mac = rfc5246_gcm_set_mac,
	.set_iv = rfc5246_gcm_set_iv,
	.decrypt = rfc5246_gcm_decrypt,
	.encrypt = rfc5246_gcm_encrypt,
};

void
crypto_init_rfc5246_aes256_gcm(void)
{
	crypto_cipher_register(&rfc5246_aes128_gcm);
	crypto_cipher_register(&rfc5246_aes256_gcm);
}
