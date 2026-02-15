#define __CRYPTO_CIPHER_MODULE__
#include <string.h>
#include <crypto/cipher.h>
#include <crypto/cipher/rc4.h>

/*
 * RC4-128. The registered algorithm keeps the keystream state of one
 * direction, so init() is the only place a key may be set: RC4 has no IV to
 * re-seed from and re-keying mid-stream would silently rewind the keystream.
 * set_iv is therefore absent rather than a no-op.
 */

struct cipher_rc4 {
	struct rc4_ctx ctx;
};

_Static_assert(sizeof(struct cipher_rc4) <= CIPHER_CTXT_SIZE_MAX,
	       "RC4 context is too large");

static void
rc4_algorithm_init(struct cipher *cipher, const u8 *key, unsigned int key_len,
		   const u8 *iv, unsigned int iv_len,
		   const u8 *mac, unsigned int mac_len)
{
	struct cipher_rc4 *c = (struct cipher_rc4 *)cipher;

	(void)iv; (void)iv_len; (void)mac; (void)mac_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len && key_len <= RC4_KEYLEN_MAX)
		rc4_init(&c->ctx, key, key_len);
}

static void
rc4_algorithm_set_key(struct cipher *cipher, const u8 *key, unsigned int len)
{
	struct cipher_rc4 *c = (struct cipher_rc4 *)cipher;

	if (!len || len > RC4_KEYLEN_MAX)
		return;
	rc4_init(&c->ctx, key, len);
}

static void
rc4_algorithm_crypt(struct cipher *cipher, const u8 *msg, unsigned int len,
		    u8 *out, unsigned int *out_len)
{
	struct cipher_rc4 *c = (struct cipher_rc4 *)cipher;

	memcpy(out, msg, len);
	rc4_crypt(&c->ctx, out, len);
	*out_len = len;
}

static void
rc4_algorithm_crypt_inplace(struct cipher *cipher, u8 *msg, unsigned int len)
{
	struct cipher_rc4 *c = (struct cipher_rc4 *)cipher;

	rc4_crypt(&c->ctx, msg, len);
}

static struct cipher_algorithm rc4_128_algorithm = {
	.name = "rc4-128",
	.desc = "RC4-128",
	.id = C_RC4128,
	.mode = M_NA,
	.type = C_TYPE_STREAM,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_rc4),
	.key_size = 16,
	.block_size = 1,
	.iv_size = 0,
	.init = rc4_algorithm_init,
	.set_key = rc4_algorithm_set_key,
	/* one function each way, because RC4 is its own inverse */
	.decrypt = rc4_algorithm_crypt,
	.encrypt = rc4_algorithm_crypt,
	.decrypt_inplace = rc4_algorithm_crypt_inplace,
	.encrypt_inplace = rc4_algorithm_crypt_inplace,
};

static void __init__ cipher_rc4_init(void)
{
	crypto_cipher_register(&rc4_128_algorithm);
}
