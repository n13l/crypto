#define __CRYPTO_CIPHER_MODULE__
#include <string.h>
#include <crypto/cipher.h>
#include <crypto/cipher/des3.h>

/* 3DES-EDE-CBC */

struct cipher_des3_cbc {
	struct des3_ctx ctx;
	u8 key[DES3_KEYLEN];
	unsigned int key_len;
};

_Static_assert(sizeof(struct cipher_des3_cbc) <= CIPHER_CTXT_SIZE_MAX,
	       "3DES-EDE-CBC context is too large");

static void
des3_cbc_algorithm_init(struct cipher *cipher,
			const u8 *key, unsigned int key_len,
			const u8 *iv, unsigned int iv_len,
			const u8 *mac, unsigned int mac_len)
{
	struct cipher_des3_cbc *c = (struct cipher_des3_cbc *)cipher;

	(void)mac; (void)mac_len; (void)iv_len;
	memset(c, 0, sizeof(*c));
	if (key && key_len == DES3_KEYLEN) {
		memcpy(c->key, key, key_len);
		c->key_len = key_len;
	}
	if (iv)
		des3_cbc_init_ctx_iv(&c->ctx, c->key, iv);
}

static void
des3_cbc_algorithm_set_key(struct cipher *cipher, const u8 *key,
			   unsigned int len)
{
	struct cipher_des3_cbc *c = (struct cipher_des3_cbc *)cipher;

	if (len != DES3_KEYLEN)
		return;
	memcpy(c->key, key, len);
	c->key_len = len;
}

static void
des3_cbc_algorithm_set_iv(struct cipher *cipher, const u8 *iv, unsigned int len)
{
	struct cipher_des3_cbc *c = (struct cipher_des3_cbc *)cipher;

	(void)len;
	des3_cbc_init_ctx_iv(&c->ctx, c->key, iv);
}

static void
des3_cbc_algorithm_decrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_des3_cbc *c = (struct cipher_des3_cbc *)cipher;

	memcpy(out, msg, len);
	des3_cbc_decrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
des3_cbc_algorithm_encrypt(struct cipher *cipher, const u8 *msg,
			   unsigned int len, u8 *out, unsigned int *out_len)
{
	struct cipher_des3_cbc *c = (struct cipher_des3_cbc *)cipher;

	memcpy(out, msg, len);
	des3_cbc_encrypt(&c->ctx, out, len);
	*out_len = len;
}

static void
des3_cbc_algorithm_decrypt_inplace(struct cipher *cipher, u8 *msg,
				   unsigned int len)
{
	struct cipher_des3_cbc *c = (struct cipher_des3_cbc *)cipher;

	des3_cbc_decrypt(&c->ctx, msg, len);
}

static void
des3_cbc_algorithm_encrypt_inplace(struct cipher *cipher, u8 *msg,
				   unsigned int len)
{
	struct cipher_des3_cbc *c = (struct cipher_des3_cbc *)cipher;

	des3_cbc_encrypt(&c->ctx, msg, len);
}

static struct cipher_algorithm des3_cbc_algorithm = {
	.name = "3des-ede-cbc",
	.desc = "3DES-EDE-CBC",
	.id = C_3DESEDE,
	.mode = M_CBC,
	.type = C_TYPE_BLOCK,
	.dialect = C_DIALECT_NONE,
	.ctx_size = sizeof(struct cipher_des3_cbc),
	.key_size = DES3_KEYLEN,
	.block_size = DES3_BLOCKLEN,
	.iv_size = DES3_BLOCKLEN,
	.init = des3_cbc_algorithm_init,
	.set_key = des3_cbc_algorithm_set_key,
	.set_iv = des3_cbc_algorithm_set_iv,
	.decrypt = des3_cbc_algorithm_decrypt,
	.encrypt = des3_cbc_algorithm_encrypt,
	.decrypt_inplace = des3_cbc_algorithm_decrypt_inplace,
	.encrypt_inplace = des3_cbc_algorithm_encrypt_inplace,
};

static void __init__ cipher_des3_init(void)
{
	crypto_cipher_register(&des3_cbc_algorithm);
}
