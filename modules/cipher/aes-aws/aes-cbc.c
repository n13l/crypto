/*
 * AES-128/256-CBC glue over the aws-lc AES-NI / ARMv8 assembly. Provides the
 * same free-function API as the generic table-based implementation
 * (<crypto/cipher/aes.h>); the backend is chosen at build time by Kconfig.
 *
 * The cipher context storage (struct aes128_ctx / aes256_ctx) is reinterpreted
 * as a small key+IV record; the hardware key schedule is (re)built per call,
 * which is negligible next to a full record's worth of CBC blocks and keeps
 * the state comfortably within the shared context footprint.
 */
#include <string.h>
#include <crypto/cipher/aes.h>
#include "internal.h"

struct aws_aes_cbc {
	uint8_t iv[AES_BLOCKLEN];
	uint8_t key[AES256_KEYLEN];
	unsigned int key_bits;
};

_Static_assert(sizeof(struct aws_aes_cbc) <= sizeof(struct aes128_ctx),
	       "aws AES-CBC state does not fit in struct aes128_ctx");
_Static_assert(sizeof(struct aws_aes_cbc) <= sizeof(struct aes256_ctx),
	       "aws AES-CBC state does not fit in struct aes256_ctx");

/* AES-NI / ARMv8 need no precomputed tables. */
void aes_init_keygen_tables(void) {}

static void
cbc_setup(struct aws_aes_cbc *c, const u8 *key, unsigned int key_bits,
	  const u8 *iv)
{
	memset(c, 0, sizeof(*c));
	c->key_bits = key_bits;
	if (key)
		memcpy(c->key, key, key_bits / 8);
	if (iv)
		memcpy(c->iv, iv, AES_BLOCKLEN);
}

static void
cbc_crypt(struct aws_aes_cbc *c, u8 *buf, u32 length, int enc)
{
	AES_KEY ks;

	if (enc)
		aes_hw_set_encrypt_key(c->key, (int)c->key_bits, &ks);
	else
		aes_hw_set_decrypt_key(c->key, (int)c->key_bits, &ks);

	/* aes_hw_cbc_encrypt advances |iv| in place, so streaming calls chain. */
	aes_hw_cbc_encrypt(buf, buf, length, &ks, c->iv, enc);
}

void
aes128_cbc_init(struct aes128_ctx *aes, const u8 *key)
{
	cbc_setup((struct aws_aes_cbc *)aes, key, 128, NULL);
}

void
aes128_cbc_init_ctx_iv(struct aes128_ctx *ctx, const u8 *key, const u8 *iv)
{
	cbc_setup((struct aws_aes_cbc *)ctx, key, 128, iv);
}

void
aes128_cbc_encrypt(struct aes128_ctx *ctx, u8 *buf, u32 length)
{
	cbc_crypt((struct aws_aes_cbc *)ctx, buf, length, 1);
}

void
aes128_cbc_decrypt(struct aes128_ctx *ctx, u8 *buf, u32 length)
{
	cbc_crypt((struct aws_aes_cbc *)ctx, buf, length, 0);
}

void
aes256_cbc_init(struct aes256_ctx *aes, const u8 *key)
{
	cbc_setup((struct aws_aes_cbc *)aes, key, 256, NULL);
}

void
aes256_cbc_init_ctx_iv(struct aes256_ctx *ctx, const u8 *key, const u8 *iv)
{
	cbc_setup((struct aws_aes_cbc *)ctx, key, 256, iv);
}

void
aes256_cbc_encrypt(struct aes256_ctx *ctx, u8 *buf, u32 length)
{
	cbc_crypt((struct aws_aes_cbc *)ctx, buf, length, 1);
}

void
aes256_cbc_decrypt(struct aes256_ctx *ctx, u8 *buf, u32 length)
{
	cbc_crypt((struct aws_aes_cbc *)ctx, buf, length, 0);
}
