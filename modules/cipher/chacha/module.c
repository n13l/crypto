#define __CRYPTO_CIPHER_MODULE__
#include <string.h>
#include <crypto/cipher.h>
#include <crypto/cipher/chachapoly.h>

/* ChaCha20-Poly1305 AEAD (RFC 7539): decrypt expects the 16-byte tag
 * appended to the ciphertext, encrypt appends it to the output. */

#define CHACHAPOLY_NONCE_LEN 12

struct cipher_chachapoly {
	struct chachapoly_ctx ctx;
	u8 iv[CHACHAPOLY_NONCE_LEN];
	unsigned int iv_len;
};

_Static_assert(sizeof(struct cipher_chachapoly) <= CIPHER_CTXT_SIZE_MAX,
	       "ChaCha20-Poly1305 context is too large");

static void
chachapoly_algorithm_init(struct cipher *cipher,
			  const u8 *key, unsigned int key_len,
			  const u8 *iv, unsigned int iv_len,
			  const u8 *mac, unsigned int mac_len)
{
	struct cipher_chachapoly *c = (struct cipher_chachapoly *)cipher;

	(void)mac; (void)mac_len;
	memset(c, 0, sizeof(*c));
	if (key)
		chachapoly_init(&c->ctx, key, key_len * 8);
	if (iv && iv_len <= CHACHAPOLY_NONCE_LEN) {
		memcpy(c->iv, iv, iv_len);
		c->iv_len = iv_len;
	}
}

static void
chachapoly_algorithm_set_key(struct cipher *cipher, const u8 *key,
			     unsigned int len)
{
	struct cipher_chachapoly *c = (struct cipher_chachapoly *)cipher;

	chachapoly_init(&c->ctx, key, len * 8);
}

static void
chachapoly_algorithm_set_iv(struct cipher *cipher, const u8 *iv,
			    unsigned int len)
{
	struct cipher_chachapoly *c = (struct cipher_chachapoly *)cipher;

	if (len > CHACHAPOLY_NONCE_LEN)
		return;
	memcpy(c->iv, iv, len);
	c->iv_len = len;
}

static void
chachapoly_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			     unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_chachapoly *c = (struct cipher_chachapoly *)cipher;
	int rv;

	if (len < POLY1305_TAGLEN) {
		*out_len = 0;
		return;
	}

	rv = chachapoly_crypt(&c->ctx, c->iv, NULL, 0,
			      (void *)msg, len - POLY1305_TAGLEN, out,
			      (void *)(msg + len - POLY1305_TAGLEN),
			      POLY1305_TAGLEN, 0);
	*out_len = rv ? 0 : len - POLY1305_TAGLEN;
}

static void
chachapoly_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			     unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_chachapoly *c = (struct cipher_chachapoly *)cipher;
	int rv;

	rv = chachapoly_crypt(&c->ctx, c->iv, NULL, 0,
			      (void *)msg, len, out,
			      out + len, POLY1305_TAGLEN, 1);
	*out_len = rv ? 0 : len + POLY1305_TAGLEN;
}

static struct cipher_algorithm chachapoly_algorithm = {
	.name = "chacha20-poly1305",
	.desc = "ChaCha20-Poly1305",
	.id = C_CHACHA20,
	.mode = M_POLY1305,
	.type = C_TYPE_AEAD,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_chachapoly),
	.key_size = 32,
	.block_size = CHACHA_BLOCKLEN,
	.iv_size = CHACHAPOLY_NONCE_LEN,
	.mac_size = POLY1305_TAGLEN,
	.init = chachapoly_algorithm_init,
	.set_key = chachapoly_algorithm_set_key,
	.set_iv = chachapoly_algorithm_set_iv,
	.decrypt = chachapoly_algorithm_decrypt,
	.encrypt = chachapoly_algorithm_encrypt,
};

static void __init__ cipher_chacha_init(void)
{
	crypto_cipher_register(&chachapoly_algorithm);
}
