#define __CRYPTO_CIPHER_MODULE__
#include <string.h>
#include <crypto/cipher.h>
#include <crypto/cipher/sm4.h>

/* SM4-CBC */

struct cipher_sm4_cbc {
	struct sm4_ctx ctx;
	u8 key[SM4_KEYLEN];
	unsigned int key_len;
};

_Static_assert(sizeof(struct cipher_sm4_cbc) <= CIPHER_CTXT_SIZE_MAX,
	       "SM4-CBC context is too large");

static void
sm4_cbc_algorithm_init(struct cipher *cipher,
		       const u8 *key, unsigned int key_len,
		       const u8 *iv, unsigned int iv_len,
		       const u8 *mac, unsigned int mac_len)
{
	struct cipher_sm4_cbc *c = (struct cipher_sm4_cbc *)cipher;

	(void)mac; (void)mac_len; (void)iv_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len == SM4_KEYLEN) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv)
		sm4_cbc_init_ctx_iv(&c->ctx, c->key, iv);
}

static void
sm4_cbc_algorithm_set_key(struct cipher *cipher, const u8 *key,
			  unsigned int len)
{
	struct cipher_sm4_cbc *c = (struct cipher_sm4_cbc *)cipher;

	if (len != SM4_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
sm4_cbc_algorithm_set_iv(struct cipher *cipher, const u8 *iv, unsigned int len)
{
	struct cipher_sm4_cbc *c = (struct cipher_sm4_cbc *)cipher;

	(void)len;
	sm4_cbc_init_ctx_iv(&c->ctx, c->key, iv);
}

static void
sm4_cbc_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			  unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_sm4_cbc *c = (struct cipher_sm4_cbc *)cipher;

	memcpy(out, msg, len);
	sm4_cbc_decrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
sm4_cbc_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			  unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_sm4_cbc *c = (struct cipher_sm4_cbc *)cipher;

	memcpy(out, msg, len);
	sm4_cbc_encrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
sm4_cbc_algorithm_decrypt_inplace(struct cipher *cipher, u8 *msg,
				  unsigned int len)
{
	struct cipher_sm4_cbc *c = (struct cipher_sm4_cbc *)cipher;

	sm4_cbc_decrypt(&c->ctx, msg, len);
}

static void
sm4_cbc_algorithm_encrypt_inplace(struct cipher *cipher, u8 *msg,
				  unsigned int len)
{
	struct cipher_sm4_cbc *c = (struct cipher_sm4_cbc *)cipher;

	sm4_cbc_encrypt(&c->ctx, msg, len);
}

static struct cipher_algorithm sm4_cbc_algorithm = {
	.name = "sm4-cbc",
	.desc = "SM4-CBC",
	.id = C_SM4,
	.mode = M_CBC,
	.type = C_TYPE_BLOCK,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_sm4_cbc),
	.key_size = SM4_KEYLEN,
	.block_size = SM4_BLOCKLEN,
	.iv_size = SM4_BLOCKLEN,
	.init = sm4_cbc_algorithm_init,
	.set_key = sm4_cbc_algorithm_set_key,
	.set_iv = sm4_cbc_algorithm_set_iv,
	.decrypt = sm4_cbc_algorithm_decrypt,
	.encrypt = sm4_cbc_algorithm_encrypt,
	.decrypt_inplace = sm4_cbc_algorithm_decrypt_inplace,
	.encrypt_inplace = sm4_cbc_algorithm_encrypt_inplace,
};

/* SM4-GCM and SM4-CCM AEAD (RFC 8998): encrypt appends the 16-byte tag,
 * decrypt expects it trailing the ciphertext and verifies it. No associated
 * data through this interface, as with the AES entries beside it. */

#define SM4_AEAD_NONCE_MAX 16
#define SM4_AEAD_TAG_LEN   16

struct cipher_sm4_aead {
	u8 key[SM4_KEYLEN];
	u8 iv[SM4_AEAD_NONCE_MAX];
	unsigned int key_len;
	unsigned int iv_len;
};

_Static_assert(sizeof(struct cipher_sm4_aead) <= CIPHER_CTXT_SIZE_MAX,
	       "SM4 AEAD context is too large");

static void
sm4_aead_algorithm_init(struct cipher *cipher,
			const u8 *key, unsigned int key_len,
			const u8 *iv, unsigned int iv_len,
			const u8 *mac, unsigned int mac_len)
{
	struct cipher_sm4_aead *c = (struct cipher_sm4_aead *)cipher;

	(void)mac; (void)mac_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len == SM4_KEYLEN) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv && iv_len <= SM4_AEAD_NONCE_MAX) {
		memcpy(c->iv, iv, iv_len);
		c->iv_len = iv_len;
	}
}

static void
sm4_aead_algorithm_set_key(struct cipher *cipher, const u8 *key,
			   unsigned int len)
{
	struct cipher_sm4_aead *c = (struct cipher_sm4_aead *)cipher;

	if (len != SM4_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
sm4_aead_algorithm_set_iv(struct cipher *cipher, const u8 *iv, unsigned int len)
{
	struct cipher_sm4_aead *c = (struct cipher_sm4_aead *)cipher;

	if (len > SM4_AEAD_NONCE_MAX)
		return;
	memcpy(c->iv, iv, len);
	c->iv_len = len;
}

static void
sm4_gcm_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			  unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_sm4_aead *c = (struct cipher_sm4_aead *)cipher;
	int rv;

	if (len < SM4_AEAD_TAG_LEN) {
		*out_len = 0;
		return;
	}
	rv = sm4_gcm_decrypt(out, msg, (int)len, c->key, c->key_len,
			     c->iv, c->iv_len);
	*out_len = rv ? 0 : len - SM4_AEAD_TAG_LEN;
}

static void
sm4_gcm_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			  unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_sm4_aead *c = (struct cipher_sm4_aead *)cipher;
	int rv;

	rv = sm4_gcm_encrypt(out, msg, (int)len, c->key, c->key_len,
			     c->iv, c->iv_len);
	*out_len = rv ? 0 : len + SM4_AEAD_TAG_LEN;
}

static void
sm4_ccm_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			  unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_sm4_aead *c = (struct cipher_sm4_aead *)cipher;
	int rv;

	if (len < SM4_AEAD_TAG_LEN) {
		*out_len = 0;
		return;
	}
	rv = sm4_ccm_decrypt_aad(out, msg, (int)len, NULL, 0, c->key,
				 c->key_len, c->iv, c->iv_len,
				 SM4_AEAD_TAG_LEN);
	*out_len = rv ? 0 : len - SM4_AEAD_TAG_LEN;
}

static void
sm4_ccm_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			  unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_sm4_aead *c = (struct cipher_sm4_aead *)cipher;
	int rv;

	rv = sm4_ccm_encrypt_aad(out, msg, (int)len, NULL, 0, c->key,
				 c->key_len, c->iv, c->iv_len,
				 SM4_AEAD_TAG_LEN);
	*out_len = rv ? 0 : len + SM4_AEAD_TAG_LEN;
}

static struct cipher_algorithm sm4_gcm_algorithm = {
	.name = "sm4-gcm",
	.desc = "SM4-GCM",
	.id = C_SM4,
	.mode = M_GCM,
	.type = C_TYPE_AEAD,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_sm4_aead),
	.key_size = SM4_KEYLEN,
	.block_size = SM4_BLOCKLEN,
	.iv_size = 12,
	.mac_size = 16,
	.init = sm4_aead_algorithm_init,
	.set_key = sm4_aead_algorithm_set_key,
	.set_iv = sm4_aead_algorithm_set_iv,
	.decrypt = sm4_gcm_algorithm_decrypt,
	.encrypt = sm4_gcm_algorithm_encrypt,
};

static struct cipher_algorithm sm4_ccm_algorithm = {
	.name = "sm4-ccm",
	.desc = "SM4-CCM",
	.id = C_SM4,
	.mode = M_CCM,
	.type = C_TYPE_AEAD,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_sm4_aead),
	.key_size = SM4_KEYLEN,
	.block_size = SM4_BLOCKLEN,
	.iv_size = 12,
	.mac_size = 16,
	.init = sm4_aead_algorithm_init,
	.set_key = sm4_aead_algorithm_set_key,
	.set_iv = sm4_aead_algorithm_set_iv,
	.decrypt = sm4_ccm_algorithm_decrypt,
	.encrypt = sm4_ccm_algorithm_encrypt,
};

static void __init__ cipher_sm4_init(void)
{
	crypto_cipher_register(&sm4_cbc_algorithm);
	crypto_cipher_register(&sm4_gcm_algorithm);
	crypto_cipher_register(&sm4_ccm_algorithm);
}
