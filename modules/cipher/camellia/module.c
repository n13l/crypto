#define __CRYPTO_CIPHER_MODULE__
#include <string.h>
#include <crypto/cipher.h>
#include <crypto/cipher/camellia.h>

/*
 * The registry entries for the loadable-module build: Camellia in CBC and GCM
 * at the two key widths TLS names. The block-cipher context carries its own
 * key schedule, so the CBC entries keep the raw key only to re-run it when the
 * IV is set, the way the AES entries beside them do.
 */

struct cipher_camellia_cbc {
	struct camellia_ctx ctx;
	u8 key[CAMELLIA256_KEYLEN];
	unsigned int key_len;
};

struct cipher_camellia_aead {
	u8 key[CAMELLIA256_KEYLEN];
	u8 iv[16];
	unsigned int key_len;
	unsigned int iv_len;
};

_Static_assert(sizeof(struct cipher_camellia_cbc) <= CIPHER_CTXT_SIZE_MAX,
	       "Camellia-CBC context is too large");

static void
camellia_cbc_algorithm_init(struct cipher *cipher,
			const u8 *key, unsigned int key_len,
			const u8 *iv, unsigned int iv_len,
			const u8 *mac, unsigned int mac_len)
{
	struct cipher_camellia_cbc *c = (struct cipher_camellia_cbc *)cipher;

	(void)mac; (void)mac_len; (void)iv_len;
	memset(c, 0, sizeof(*c));
	if (key && (key_len == CAMELLIA128_KEYLEN || key_len == CAMELLIA256_KEYLEN)) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv && c->key_len)
		camellia_cbc_init_ctx_iv(&c->ctx, c->key, c->key_len, iv);
}

static void
camellia_cbc_algorithm_set_key(struct cipher *cipher, const u8 *key,
			   unsigned int len)
{
	struct cipher_camellia_cbc *c = (struct cipher_camellia_cbc *)cipher;

	if (len != CAMELLIA128_KEYLEN && len != CAMELLIA256_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
camellia_cbc_algorithm_set_iv(struct cipher *cipher, const u8 *iv, unsigned int len)
{
	struct cipher_camellia_cbc *c = (struct cipher_camellia_cbc *)cipher;

	(void)len;
	if (c->key_len)
		camellia_cbc_init_ctx_iv(&c->ctx, c->key, c->key_len, iv);
}

static void
camellia_cbc_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_camellia_cbc *c = (struct cipher_camellia_cbc *)cipher;

	memcpy(out, msg, len);
	camellia_cbc_decrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
camellia_cbc_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_camellia_cbc *c = (struct cipher_camellia_cbc *)cipher;

	memcpy(out, msg, len);
	camellia_cbc_encrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
camellia_cbc_algorithm_decrypt_inplace(struct cipher *cipher, u8 *msg,
				   unsigned int len)
{
	camellia_cbc_decrypt(&((struct cipher_camellia_cbc *)cipher)->ctx, msg, len);
}

static void
camellia_cbc_algorithm_encrypt_inplace(struct cipher *cipher, u8 *msg,
				   unsigned int len)
{
	camellia_cbc_encrypt(&((struct cipher_camellia_cbc *)cipher)->ctx, msg, len);
}

static void
camellia_aead_algorithm_init(struct cipher *cipher,
			 const u8 *key, unsigned int key_len,
			 const u8 *iv, unsigned int iv_len,
			 const u8 *mac, unsigned int mac_len)
{
	struct cipher_camellia_aead *c = (struct cipher_camellia_aead *)cipher;

	(void)mac; (void)mac_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len <= CAMELLIA256_KEYLEN) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv && iv_len <= sizeof(c->iv)) {
		memcpy(c->iv, iv, iv_len);
		c->iv_len = iv_len;
	}
}

static void
camellia_aead_algorithm_set_key(struct cipher *cipher, const u8 *key,
			    unsigned int len)
{
	struct cipher_camellia_aead *c = (struct cipher_camellia_aead *)cipher;

	if (len > CAMELLIA256_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
camellia_aead_algorithm_set_iv(struct cipher *cipher, const u8 *iv,
			   unsigned int len)
{
	struct cipher_camellia_aead *c = (struct cipher_camellia_aead *)cipher;

	if (len > sizeof(c->iv))
		return;
	memcpy(c->iv, iv, len);
	c->iv_len = len;
}

static void
camellia_gcm_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_camellia_aead *c = (struct cipher_camellia_aead *)cipher;
	int rv;

	if (len < 16) {
		*out_len = 0;
		return;
	}
	rv = camellia_gcm_decrypt(out, msg, (int)len, c->key, c->key_len,
			      c->iv, c->iv_len);
	*out_len = rv ? 0 : len - 16;
}

static void
camellia_gcm_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_camellia_aead *c = (struct cipher_camellia_aead *)cipher;
	int rv;

	rv = camellia_gcm_encrypt(out, msg, (int)len, c->key, c->key_len,
			      c->iv, c->iv_len);
	*out_len = rv ? 0 : len + 16;
}

#define CAMELLIA_CBC(_var, _name, _desc, _id, _klen) \
static struct cipher_algorithm _var = { \
	.name = _name, .desc = _desc, .id = _id, .mode = M_CBC, \
	.type = C_TYPE_BLOCK, .dialect = C_DIALECT_NONE, \
	.ctx_size = sizeof(struct cipher_camellia_cbc), .key_size = _klen, \
	.block_size = CAMELLIA_BLOCKLEN, .iv_size = CAMELLIA_BLOCKLEN, \
	.init = camellia_cbc_algorithm_init, .set_key = camellia_cbc_algorithm_set_key, \
	.set_iv = camellia_cbc_algorithm_set_iv, \
	.decrypt = camellia_cbc_algorithm_decrypt, \
	.encrypt = camellia_cbc_algorithm_encrypt, \
	.decrypt_inplace = camellia_cbc_algorithm_decrypt_inplace, \
	.encrypt_inplace = camellia_cbc_algorithm_encrypt_inplace, \
}

#define CAMELLIA_GCM(_var, _name, _desc, _id, _klen) \
static struct cipher_algorithm _var = { \
	.name = _name, .desc = _desc, .id = _id, .mode = M_GCM, \
	.type = C_TYPE_AEAD, .dialect = C_DIALECT_NONE, \
	.ctx_size = sizeof(struct cipher_camellia_aead), .key_size = _klen, \
	.block_size = CAMELLIA_BLOCKLEN, .iv_size = 12, .mac_size = 16, \
	.init = camellia_aead_algorithm_init, \
	.set_key = camellia_aead_algorithm_set_key, \
	.set_iv = camellia_aead_algorithm_set_iv, \
	.decrypt = camellia_gcm_algorithm_decrypt, \
	.encrypt = camellia_gcm_algorithm_encrypt, \
}

CAMELLIA_CBC(camellia128_cbc_algorithm, "camellia-128-cbc", "Camellia-128-CBC",
	 C_CAMELLIA128, CAMELLIA128_KEYLEN);
CAMELLIA_CBC(camellia256_cbc_algorithm, "camellia-256-cbc", "Camellia-256-CBC",
	 C_CAMELLIA256, CAMELLIA256_KEYLEN);
CAMELLIA_GCM(camellia128_gcm_algorithm, "camellia-128-gcm", "Camellia-128-GCM",
	 C_CAMELLIA128, CAMELLIA128_KEYLEN);
CAMELLIA_GCM(camellia256_gcm_algorithm, "camellia-256-gcm", "Camellia-256-GCM",
	 C_CAMELLIA256, CAMELLIA256_KEYLEN);

static void __init__ cipher_camellia_init(void)
{
	crypto_cipher_register(&camellia128_cbc_algorithm);
	crypto_cipher_register(&camellia256_cbc_algorithm);
	crypto_cipher_register(&camellia128_gcm_algorithm);
	crypto_cipher_register(&camellia256_gcm_algorithm);
}
