#define __CRYPTO_CIPHER_MODULE__
#include <string.h>
#include <crypto/cipher.h>
#include <crypto/cipher/aria.h>

/*
 * The registry entries for the loadable-module build: ARIA in CBC and GCM
 * at the two key widths TLS names. The block-cipher context carries its own
 * key schedule, so the CBC entries keep the raw key only to re-run it when the
 * IV is set, the way the AES entries beside them do.
 */

struct cipher_aria_cbc {
	struct aria_ctx ctx;
	u8 key[ARIA256_KEYLEN];
	unsigned int key_len;
};

struct cipher_aria_aead {
	u8 key[ARIA256_KEYLEN];
	u8 iv[16];
	unsigned int key_len;
	unsigned int iv_len;
};

_Static_assert(sizeof(struct cipher_aria_cbc) <= CIPHER_CTXT_SIZE_MAX,
	       "ARIA-CBC context is too large");

static void
aria_cbc_algorithm_init(struct cipher *cipher,
			const u8 *key, unsigned int key_len,
			const u8 *iv, unsigned int iv_len,
			const u8 *mac, unsigned int mac_len)
{
	struct cipher_aria_cbc *c = (struct cipher_aria_cbc *)cipher;

	(void)mac; (void)mac_len; (void)iv_len;
	memset(c, 0, sizeof(*c));
	if (key && (key_len == ARIA128_KEYLEN || key_len == ARIA256_KEYLEN)) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv && c->key_len)
		aria_cbc_init_ctx_iv(&c->ctx, c->key, c->key_len, iv);
}

static void
aria_cbc_algorithm_set_key(struct cipher *cipher, const u8 *key,
			   unsigned int len)
{
	struct cipher_aria_cbc *c = (struct cipher_aria_cbc *)cipher;

	if (len != ARIA128_KEYLEN && len != ARIA256_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
aria_cbc_algorithm_set_iv(struct cipher *cipher, const u8 *iv, unsigned int len)
{
	struct cipher_aria_cbc *c = (struct cipher_aria_cbc *)cipher;

	(void)len;
	if (c->key_len)
		aria_cbc_init_ctx_iv(&c->ctx, c->key, c->key_len, iv);
}

static void
aria_cbc_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aria_cbc *c = (struct cipher_aria_cbc *)cipher;

	memcpy(out, msg, len);
	aria_cbc_decrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
aria_cbc_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aria_cbc *c = (struct cipher_aria_cbc *)cipher;

	memcpy(out, msg, len);
	aria_cbc_encrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
aria_cbc_algorithm_decrypt_inplace(struct cipher *cipher, u8 *msg,
				   unsigned int len)
{
	aria_cbc_decrypt(&((struct cipher_aria_cbc *)cipher)->ctx, msg, len);
}

static void
aria_cbc_algorithm_encrypt_inplace(struct cipher *cipher, u8 *msg,
				   unsigned int len)
{
	aria_cbc_encrypt(&((struct cipher_aria_cbc *)cipher)->ctx, msg, len);
}

static void
aria_aead_algorithm_init(struct cipher *cipher,
			 const u8 *key, unsigned int key_len,
			 const u8 *iv, unsigned int iv_len,
			 const u8 *mac, unsigned int mac_len)
{
	struct cipher_aria_aead *c = (struct cipher_aria_aead *)cipher;

	(void)mac; (void)mac_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len <= ARIA256_KEYLEN) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv && iv_len <= sizeof(c->iv)) {
		memcpy(c->iv, iv, iv_len);
		c->iv_len = iv_len;
	}
}

static void
aria_aead_algorithm_set_key(struct cipher *cipher, const u8 *key,
			    unsigned int len)
{
	struct cipher_aria_aead *c = (struct cipher_aria_aead *)cipher;

	if (len > ARIA256_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
aria_aead_algorithm_set_iv(struct cipher *cipher, const u8 *iv,
			   unsigned int len)
{
	struct cipher_aria_aead *c = (struct cipher_aria_aead *)cipher;

	if (len > sizeof(c->iv))
		return;
	memcpy(c->iv, iv, len);
	c->iv_len = len;
}

static void
aria_gcm_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aria_aead *c = (struct cipher_aria_aead *)cipher;
	int rv;

	if (len < 16) {
		*out_len = 0;
		return;
	}
	rv = aria_gcm_decrypt(out, msg, (int)len, c->key, c->key_len,
			      c->iv, c->iv_len);
	*out_len = rv ? 0 : len - 16;
}

static void
aria_gcm_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_aria_aead *c = (struct cipher_aria_aead *)cipher;
	int rv;

	rv = aria_gcm_encrypt(out, msg, (int)len, c->key, c->key_len,
			      c->iv, c->iv_len);
	*out_len = rv ? 0 : len + 16;
}

#define ARIA_CBC(_var, _name, _desc, _id, _klen) \
static struct cipher_algorithm _var = { \
	.name = _name, .desc = _desc, .id = _id, .mode = M_CBC, \
	.type = C_TYPE_BLOCK, .dialect = C_DIALECT_NONE, \
	.ctx_size = sizeof(struct cipher_aria_cbc), .key_size = _klen, \
	.block_size = ARIA_BLOCKLEN, .iv_size = ARIA_BLOCKLEN, \
	.init = aria_cbc_algorithm_init, .set_key = aria_cbc_algorithm_set_key, \
	.set_iv = aria_cbc_algorithm_set_iv, \
	.decrypt = aria_cbc_algorithm_decrypt, \
	.encrypt = aria_cbc_algorithm_encrypt, \
	.decrypt_inplace = aria_cbc_algorithm_decrypt_inplace, \
	.encrypt_inplace = aria_cbc_algorithm_encrypt_inplace, \
}

#define ARIA_GCM(_var, _name, _desc, _id, _klen) \
static struct cipher_algorithm _var = { \
	.name = _name, .desc = _desc, .id = _id, .mode = M_GCM, \
	.type = C_TYPE_AEAD, .dialect = C_DIALECT_NONE, \
	.ctx_size = sizeof(struct cipher_aria_aead), .key_size = _klen, \
	.block_size = ARIA_BLOCKLEN, .iv_size = 12, .mac_size = 16, \
	.init = aria_aead_algorithm_init, \
	.set_key = aria_aead_algorithm_set_key, \
	.set_iv = aria_aead_algorithm_set_iv, \
	.decrypt = aria_gcm_algorithm_decrypt, \
	.encrypt = aria_gcm_algorithm_encrypt, \
}

ARIA_CBC(aria128_cbc_algorithm, "aria-128-cbc", "ARIA-128-CBC",
	 C_ARIA128, ARIA128_KEYLEN);
ARIA_CBC(aria256_cbc_algorithm, "aria-256-cbc", "ARIA-256-CBC",
	 C_ARIA256, ARIA256_KEYLEN);
ARIA_GCM(aria128_gcm_algorithm, "aria-128-gcm", "ARIA-128-GCM",
	 C_ARIA128, ARIA128_KEYLEN);
ARIA_GCM(aria256_gcm_algorithm, "aria-256-gcm", "ARIA-256-GCM",
	 C_ARIA256, ARIA256_KEYLEN);

static void __init__ cipher_aria_init(void)
{
	crypto_cipher_register(&aria128_cbc_algorithm);
	crypto_cipher_register(&aria256_cbc_algorithm);
	crypto_cipher_register(&aria128_gcm_algorithm);
	crypto_cipher_register(&aria256_gcm_algorithm);
}
