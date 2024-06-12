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

#define TLS_CBC_FIXED_IV_LEN                      0
#define TLS_CBC_EXPLICIT_IV_LEN                   16
#define TLS_CBC_TAG_LEN                           16
#define TLS_CBC_IV_LEN (TLS_CBC_FIXED_IV_LEN + TLS_CBC_EXPLICIT_IV_LEN)

#ifndef TLS_RECORD_LENGTH_MAX
#define TLS_RECORD_LENGTH_MAX                     0x5000 /* 20480 */
#endif

struct rfc5246_aes_cbc {
	const u8 *key, *iv, *mac;
	unsigned int key_len, iv_len, mac_len;
	u64 seqno;
};

static void
rfc5246_cbc_init(struct cipher *cipher, const u8 *key, unsigned int klen,
              const u8* iv, unsigned int ilen, const u8* mac, unsigned int mlen)
{
	struct rfc5246_aes_cbc *c = (__typeof__(c))cipher;
	c->seqno = 0;
	c->key_len = c->iv_len = c->mac_len = 0;
}

static void
rfc5246_cbc_set_mac(struct cipher *cipher, const u8 *mac, unsigned int len)
{
	struct rfc5246_aes_cbc *c = (__typeof__(c))cipher;
	c->mac = mac;
	c->mac_len = len;
}

static void
rfc5246_cbc_set_key(struct cipher *cipher, const u8 *key, unsigned int len)
{
	struct rfc5246_aes_cbc *c = (__typeof__(c))cipher;
	c->key = key;
	c->key_len = len;
}

static void
rfc5246_cbc_set_iv(struct cipher *cipher, const u8 *iv, unsigned int len)
{
	struct rfc5246_aes_cbc *c = (__typeof__(c))cipher;
	c->iv = iv;
	c->iv_len = len;
}

static void
rfc5246_cbc_decrypt(struct cipher *cipher, const u8* msg, unsigned int mlen,
                    u8 *out, unsigned int *len)
{
	struct rfc5246_aes_cbc *c = (__typeof__(c))cipher;
	u8 *ptr, buf[TLS_RECORD_LENGTH_MAX];
	int size = mlen;
	*len = 0;
	int rv = openssl_aes_cbc_decrypt(msg, size, c->key, c->key_len, c->iv,
                                         16, buf);
	c->seqno++;
	if (rv < 32)
		return;

	rv -= 16;

	u8 *pad = buf + (rv - 1);
	u8 padding_len = *pad ? *pad + 1:0;
	rv -= padding_len;
	int length = rv - c->iv_len;
	if (length < 0 || length > TLS_RECORD_LENGTH_MAX)
		return;

	*len = length;
	memcpy((void *)c->iv, out, 16);
	memcpy(out, buf + 16, length);
}

static void
rfc5246_cbc_encrypt(struct cipher *c, const u8* msg, unsigned int mlen,
                    u8 *out, unsigned int *olen)
{
}

struct cipher_algorithm rfc5246_aes128_cbc = {
	.name = "aes128-cbc",
	.id = CIPHER_AES128,
	.mode = CIPHER_MODE_CBC,
	.type = CIPHER_TYPE_BLOCK,
	.dialect = CIPHER_RFC5246,
	.ctx_size = sizeof(struct rfc5246_aes_cbc),
	.key_size = AES128_KEY_LENGTH,
	.block_size = AES128_BLOCK_SIZE,
	.iv_size = TLS_CBC_EXPLICIT_IV_LEN,
	.init = rfc5246_cbc_init,
	.set_key = rfc5246_cbc_set_key,
	.set_mac = rfc5246_cbc_set_mac,
	.set_iv = rfc5246_cbc_set_iv,
	.decrypt = rfc5246_cbc_decrypt,
	.encrypt = rfc5246_cbc_encrypt,
};

struct cipher_algorithm rfc5246_aes256_cbc = {
	.name = "aes256-cbc",
	.id = CIPHER_AES256,
	.mode = CIPHER_MODE_CBC,
	.type = CIPHER_TYPE_BLOCK,
	.dialect = CIPHER_RFC5246,
	.ctx_size = sizeof(struct rfc5246_aes_cbc),
	.key_size = AES256_KEY_LENGTH,
	.block_size = AES256_BLOCK_SIZE,
	.iv_size = TLS_CBC_EXPLICIT_IV_LEN,
	.init = rfc5246_cbc_init,
	.set_key = rfc5246_cbc_set_key,
	.set_mac = rfc5246_cbc_set_mac,
	.set_iv = rfc5246_cbc_set_iv,
	.decrypt = rfc5246_cbc_decrypt,
	.encrypt = rfc5246_cbc_encrypt,
};

void
crypto_init_rfc5246_aes256_cbc(void)
{
	crypto_cipher_register(&rfc5246_aes128_cbc);
	crypto_cipher_register(&rfc5246_aes256_cbc);
}
