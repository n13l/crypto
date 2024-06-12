/*
 * The MIT License (MIT)         Copyright (c) 2016 Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"),to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include <sys/compiler.h>
#include <sys/log.h>
#include <bsd/array.h>
#include <crypto/cipher.h>

static void
none_init(struct cipher *cipher, const u8 *key, unsigned int klen,
              const u8* iv, unsigned int ilen, const u8* mac, unsigned int mlen)
{
}

static void
none_set_mac(struct cipher* cipher, const u8* mac, unsigned int size)
{
}

static void
none_set_key(struct cipher* cipher, const u8* key, unsigned int size)
{
}

static void
none_set_iv(struct cipher* cipher, const u8* iv, unsigned int size)
{
}

static void
none_decrypt(struct cipher *cipher, const u8* msg, unsigned int len,
             u8 *out, unsigned int *out_len)
{
}

static void
none_encrypt(struct cipher *cipher, const u8* msg, unsigned int len,
             u8 *out, unsigned int *out_len)
{
}

static void
none_encrypt_inplace(struct cipher *cipher, u8* msg, unsigned int len)
{
}

static void
none_decrypt_inplace(struct cipher *cipher, u8* msg, unsigned int len)
{
}

static struct cipher_algorithm none_cipher = {
	.name = "none",
	.id = CIPHER_NONE,
	.mode = CIPHER_MODE_NONE,
	.type = CIPHER_TYPE_NONE, 
	.dialect = CIPHER_DIALECT_NONE,
	.ctx_size = 0,
	.init = none_init,
	.set_mac = none_set_mac,
	.set_key = none_set_key,
	.set_iv = none_set_iv,
	.decrypt = none_decrypt,
	.encrypt = none_encrypt,
	.decrypt_inplace = none_decrypt_inplace,
	.encrypt_inplace = none_encrypt_inplace,
};

STATIC_1_BASED_ARRAY(struct cipher_algorithm*, ciphers, &none_cipher, 8);

void
crypto_cipher_register(struct cipher_algorithm *c)
{
	unsigned int index = crypto_cipher_mkid(c->id, c->mode, c->dialect);
	if (ciphers_verify(index) == 0)
		return;
	ciphers[ciphers_verify(index)] = c;
	c->index = index;
}

struct cipher_algorithm *
crypto_cipher_by_id(unsigned int id)
{
	return ciphers_at(id);
}

void
crypto_cipher_enum(fn_cipher_enum fn)
{
	for (unsigned i = 0; i < 255; i++)
		if (crypto_cipher_by_id(i) == &none_cipher)
			continue;
		else
			fn(crypto_cipher_by_id(i));
}

void crypto_init_null_cipher(void);
void crypto_init_rfc5246_aes256_gcm(void);
void crypto_init_rfc5246_aes256_cbc(void);
void crypto_init_rfc5246_chacha20_poly1305(void);

void __init__ crypto_cipher_init(void)
{
	crypto_init_null_cipher();
	crypto_init_rfc5246_aes256_cbc();
	crypto_init_rfc5246_aes256_gcm();
	crypto_init_rfc5246_chacha20_poly1305();
}

void crypto_cipher_opt(unsigned int opt)
{
}

