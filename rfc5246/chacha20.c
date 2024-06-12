#include <string.h>
#include <sys/compiler.h>
#include <mem/unaligned.h>
#include <crypto/cipher.h>
#include <crypto/abi/ssl/chacha20.h>

/* 
 * AEAD_CHACHA20_POLY1305 requires a 96-bit nonce, which is formed as
 * follows:
 *
 * 1.  The 64-bit record sequence number is serialized as an 8-byte,
 * big-endian value and padded on the left with four 0x00 bytes.
 *
 * 2.  The padded sequence number is XORed with the client_write_IV
 * (when the client is sending) or server_write_IV (when the server is 
 * sending).
 *
 * In DTLS, the 64-bit seq_num is the 16-bit epoch concatenated with 
 * the48-bit seq_num.
 *
 * This nonce construction is different from the one used with AES-GCM
 * in TLS 1.2 but matches the scheme expected to be used in TLS 1.3.
 */

struct chacha20 {
	u8 key[32];
	unsigned key_len;
	u8 iv[12];
	unsigned iv_len;
	u64 seqno;
};
	
static void
chacha20_init(struct cipher *cipher, const u8 *key, unsigned int klen,
              const u8 *iv, unsigned int ilen, const u8 *mac, unsigned int mlen)
{
	struct chacha20 *c = (__typeof__(c))cipher;
	c->seqno = 0;
	c->key_len = c->iv_len = 0;
}

static void
chacha20_set_mac(struct cipher* cipher, const u8* mac, unsigned int size)
{
}

static void
chacha20_set_key(struct cipher *cipher, const u8 *key, unsigned int size)
{
	struct chacha20 *c = (__typeof__(c))cipher;
	memcpy(c->key, key, size);
	c->seqno = 0;
}

static void
chacha20_set_iv(struct cipher *cipher, const u8 *iv, unsigned int size)
{
	struct chacha20 *c = (__typeof__(c))cipher;
	memcpy(c->iv, iv, size);
}

static inline void buf_xor_12(u8 b1[12], const u8 b2[12])
{
	for(unsigned i = 0; i < 12; i++)
		b1[i] ^= b2[i];
}

static void
chacha20_decrypt(struct cipher *cipher, const u8 *msg, unsigned int msg_len,
                 u8 *out, unsigned int *len)
{
	struct chacha20 *c = (__typeof__(c))cipher;
	u8 iv[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	put_u64_be(iv + 4, c->seqno++);
	buf_xor_12(iv, c->iv);
	int rv = openssl_chacha20_poly1305_decrypt(msg, msg_len, c->key,
	                                           c->key_len, iv, 12, out);
	*len = rv < 1 ? 0: rv;
}

static void
chacha20_encrypt(struct cipher *cipher, const u8 *msg, unsigned int len,
             u8 *out, unsigned int *out_len)
{
}

struct cipher_algorithm chacha20_poly1305_rfc5246_cipher = {
	.name = "chacha20-poly1305",
	.id = CIPHER_CHACHA20,
	.mode = CIPHER_MODE_POLY1305,
	.type = CIPHER_TYPE_BLOCK, 
	.dialect = CIPHER_RFC5246,
	.ctx_size = sizeof(struct chacha20),
	.mac_size = 0,
	.key_size = 32,
	.block_size = 64,
	.init = chacha20_init,
	.set_mac = chacha20_set_mac,
	.set_key = chacha20_set_key,
	.set_iv = chacha20_set_iv,
	.decrypt = chacha20_decrypt,
	.encrypt = chacha20_encrypt,
};

void
crypto_init_rfc5246_chacha20_poly1305(void)
{
	crypto_cipher_register(&chacha20_poly1305_rfc5246_cipher);
}
