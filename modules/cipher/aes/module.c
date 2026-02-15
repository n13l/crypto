#define __CRYPTO_CIPHER_MODULE__
#include <string.h>
#include <crypto/cipher.h>
#include <crypto/cipher/aes.h>
#include <crypto/cipher/aes/gcm.h>

/* AES-128/256-CBC */

struct cipher_aes128_cbc {
	struct aes128_ctx ctx;
	u8 key[AES128_KEYLEN];
	unsigned int key_len;
};

_Static_assert(sizeof(struct cipher_aes128_cbc) <= CIPHER_CTXT_SIZE_MAX,
	       "AES-128-CBC context is too large");

static void
aes128_cbc_algorithm_init(struct cipher *cipher,
			  const u8 *key, unsigned int key_len,
			  const u8 *iv, unsigned int iv_len,
			  const u8 *mac, unsigned int mac_len)
{
	struct cipher_aes128_cbc *c = (struct cipher_aes128_cbc *)cipher;

	(void)mac; (void)mac_len; (void)iv_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len == AES128_KEYLEN) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv)
		aes128_cbc_init_ctx_iv(&c->ctx, c->key, iv);
}

static void
aes128_cbc_algorithm_set_key(struct cipher *cipher, const u8 *key,
			     unsigned int len)
{
	struct cipher_aes128_cbc *c = (struct cipher_aes128_cbc *)cipher;

	if (len != AES128_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
aes128_cbc_algorithm_set_iv(struct cipher *cipher, const u8 *iv,
			    unsigned int len)
{
	struct cipher_aes128_cbc *c = (struct cipher_aes128_cbc *)cipher;

	(void)len;
	aes128_cbc_init_ctx_iv(&c->ctx, c->key, iv);
}

static void
aes128_cbc_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			     unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aes128_cbc *c = (struct cipher_aes128_cbc *)cipher;

	memcpy(out, msg, len);
	aes128_cbc_decrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
aes128_cbc_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			     unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aes128_cbc *c = (struct cipher_aes128_cbc *)cipher;

	memcpy(out, msg, len);
	aes128_cbc_encrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
aes128_cbc_algorithm_decrypt_inplace(struct cipher *cipher, u8 *msg,
				     unsigned int len)
{
	struct cipher_aes128_cbc *c = (struct cipher_aes128_cbc *)cipher;

	aes128_cbc_decrypt(&c->ctx, msg, len);
}

static void
aes128_cbc_algorithm_encrypt_inplace(struct cipher *cipher, u8 *msg,
				     unsigned int len)
{
	struct cipher_aes128_cbc *c = (struct cipher_aes128_cbc *)cipher;

	aes128_cbc_encrypt(&c->ctx, msg, len);
}

static struct cipher_algorithm aes128_cbc_algorithm = {
	.name = "aes-128-cbc",
	.desc = "AES-128-CBC",
	.id = C_AES128,
	.mode = M_CBC,
	.type = C_TYPE_BLOCK,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_aes128_cbc),
	.key_size = AES128_KEYLEN,
	.block_size = AES_BLOCKLEN,
	.iv_size = AES_BLOCKLEN,
	.init = aes128_cbc_algorithm_init,
	.set_key = aes128_cbc_algorithm_set_key,
	.set_iv = aes128_cbc_algorithm_set_iv,
	.decrypt = aes128_cbc_algorithm_decrypt,
	.encrypt = aes128_cbc_algorithm_encrypt,
	.decrypt_inplace = aes128_cbc_algorithm_decrypt_inplace,
	.encrypt_inplace = aes128_cbc_algorithm_encrypt_inplace,
};

struct cipher_aes256_cbc {
	struct aes256_ctx ctx;
	u8 key[AES256_KEYLEN];
	unsigned int key_len;
};

_Static_assert(sizeof(struct cipher_aes256_cbc) <= CIPHER_CTXT_SIZE_MAX,
	       "AES-256-CBC context is too large");

static void
aes256_cbc_algorithm_init(struct cipher *cipher,
			  const u8 *key, unsigned int key_len,
			  const u8 *iv, unsigned int iv_len,
			  const u8 *mac, unsigned int mac_len)
{
	struct cipher_aes256_cbc *c = (struct cipher_aes256_cbc *)cipher;

	(void)mac; (void)mac_len; (void)iv_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len == AES256_KEYLEN) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv)
		aes256_cbc_init_ctx_iv(&c->ctx, c->key, iv);
}

static void
aes256_cbc_algorithm_set_key(struct cipher *cipher, const u8 *key,
			     unsigned int len)
{
	struct cipher_aes256_cbc *c = (struct cipher_aes256_cbc *)cipher;

	if (len != AES256_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
aes256_cbc_algorithm_set_iv(struct cipher *cipher, const u8 *iv,
			    unsigned int len)
{
	struct cipher_aes256_cbc *c = (struct cipher_aes256_cbc *)cipher;

	(void)len;
	aes256_cbc_init_ctx_iv(&c->ctx, c->key, iv);
}

static void
aes256_cbc_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			     unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aes256_cbc *c = (struct cipher_aes256_cbc *)cipher;

	memcpy(out, msg, len);
	aes256_cbc_decrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
aes256_cbc_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			     unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aes256_cbc *c = (struct cipher_aes256_cbc *)cipher;

	memcpy(out, msg, len);
	aes256_cbc_encrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
aes256_cbc_algorithm_decrypt_inplace(struct cipher *cipher, u8 *msg,
				     unsigned int len)
{
	struct cipher_aes256_cbc *c = (struct cipher_aes256_cbc *)cipher;

	aes256_cbc_decrypt(&c->ctx, msg, len);
}

static void
aes256_cbc_algorithm_encrypt_inplace(struct cipher *cipher, u8 *msg,
				     unsigned int len)
{
	struct cipher_aes256_cbc *c = (struct cipher_aes256_cbc *)cipher;

	aes256_cbc_encrypt(&c->ctx, msg, len);
}

static struct cipher_algorithm aes256_cbc_algorithm = {
	.name = "aes-256-cbc",
	.desc = "AES-256-CBC",
	.id = C_AES256,
	.mode = M_CBC,
	.type = C_TYPE_BLOCK,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_aes256_cbc),
	.key_size = AES256_KEYLEN,
	.block_size = AES_BLOCKLEN,
	.iv_size = AES_BLOCKLEN,
	.init = aes256_cbc_algorithm_init,
	.set_key = aes256_cbc_algorithm_set_key,
	.set_iv = aes256_cbc_algorithm_set_iv,
	.decrypt = aes256_cbc_algorithm_decrypt,
	.encrypt = aes256_cbc_algorithm_encrypt,
	.decrypt_inplace = aes256_cbc_algorithm_decrypt_inplace,
	.encrypt_inplace = aes256_cbc_algorithm_encrypt_inplace,
};

/* AES-128/256-GCM AEAD (RFC 5116): encrypt appends the 16-byte tag to the
 * ciphertext, decrypt expects the tag trailing the ciphertext and verifies
 * it. No associated data is authenticated. Mirrors the ChaCha20-Poly1305
 * convention used elsewhere in this subsystem. */

#define AES_GCM_NONCE_MAX 16
#define AES_GCM_TAG_LEN   16

struct cipher_aes_gcm {
	u8 key[AES256_KEYLEN];
	u8 iv[AES_GCM_NONCE_MAX];
	unsigned int key_len;
	unsigned int iv_len;
};

_Static_assert(sizeof(struct cipher_aes_gcm) <= CIPHER_CTXT_SIZE_MAX,
	       "AES-GCM context is too large");

static void
aes_gcm_algorithm_init(struct cipher *cipher,
		       const u8 *key, unsigned int key_len,
		       const u8 *iv, unsigned int iv_len,
		       const u8 *mac, unsigned int mac_len)
{
	struct cipher_aes_gcm *c = (struct cipher_aes_gcm *)cipher;

	(void)mac; (void)mac_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len <= AES256_KEYLEN) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv && iv_len <= AES_GCM_NONCE_MAX) {
		memcpy(c->iv, iv, iv_len);
		c->iv_len = iv_len;
	}
}

static void
aes_gcm_algorithm_set_key(struct cipher *cipher, const u8 *key,
			  unsigned int len)
{
	struct cipher_aes_gcm *c = (struct cipher_aes_gcm *)cipher;

	if (len > AES256_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
aes_gcm_algorithm_set_iv(struct cipher *cipher, const u8 *iv, unsigned int len)
{
	struct cipher_aes_gcm *c = (struct cipher_aes_gcm *)cipher;

	if (len > AES_GCM_NONCE_MAX)
		return;
	memcpy(c->iv, iv, len);
	c->iv_len = len;
}

static void
aes_gcm_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			  unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aes_gcm *c = (struct cipher_aes_gcm *)cipher;
	int rv;

	if (len < AES_GCM_TAG_LEN) {
		*out_len = 0;
		return;
	}

	rv = aes_gcm_decrypt(out, msg, len, c->key, c->key_len,
			     c->iv, c->iv_len);
	*out_len = rv ? 0 : len - AES_GCM_TAG_LEN;
}

static void
aes_gcm_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			  unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aes_gcm *c = (struct cipher_aes_gcm *)cipher;
	int rv;

	rv = aes_gcm_encrypt(out, msg, len, c->key, c->key_len,
			     c->iv, c->iv_len);
	*out_len = rv ? 0 : len + AES_GCM_TAG_LEN;
}

static struct cipher_algorithm aes128_gcm_algorithm = {
	.name = "aes-128-gcm",
	.desc = "AES-128-GCM",
	.id = C_AES128,
	.mode = M_GCM,
	.type = C_TYPE_AEAD,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_aes_gcm),
	.key_size = AES128_KEYLEN,
	.block_size = AES_BLOCKLEN,
	.iv_size = 12,
	.mac_size = 16,
	.init = aes_gcm_algorithm_init,
	.set_key = aes_gcm_algorithm_set_key,
	.set_iv = aes_gcm_algorithm_set_iv,
	.decrypt = aes_gcm_algorithm_decrypt,
	.encrypt = aes_gcm_algorithm_encrypt,
};

static struct cipher_algorithm aes256_gcm_algorithm = {
	.name = "aes-256-gcm",
	.desc = "AES-256-GCM",
	.id = C_AES256,
	.mode = M_GCM,
	.type = C_TYPE_AEAD,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_aes_gcm),
	.key_size = AES256_KEYLEN,
	.block_size = AES_BLOCKLEN,
	.iv_size = 12,
	.mac_size = 16,
	.init = aes_gcm_algorithm_init,
	.set_key = aes_gcm_algorithm_set_key,
	.set_iv = aes_gcm_algorithm_set_iv,
	.decrypt = aes_gcm_algorithm_decrypt,
	.encrypt = aes_gcm_algorithm_encrypt,
};

static void __init__ cipher_aes_init(void)
{
	aes_init_keygen_tables();
	crypto_cipher_register(&aes128_cbc_algorithm);
	crypto_cipher_register(&aes256_cbc_algorithm);
	crypto_cipher_register(&aes128_gcm_algorithm);
	crypto_cipher_register(&aes256_gcm_algorithm);
}
