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
#include <crypto/cipher.h>
#include <string.h>

static void
null_init(struct cipher *cipher, const u8 *key, unsigned int klen,
              const u8* iv, unsigned int ilen, const u8* mac, unsigned int mlen)
{
}

static void
null_set_mac(struct cipher* cipher, const u8* mac, unsigned int size)
{
}

static void
null_set_key(struct cipher* cipher, const u8* key, unsigned int size)
{
}

static void
null_set_iv(struct cipher* cipher, const u8* iv, unsigned int size)
{
}

static void
null_decrypt(struct cipher *cipher, const u8* msg, unsigned int len,
             u8 *out, unsigned int *msg_len)
{
	memcpy(out, msg, len);
}

static void
null_encrypt(struct cipher *cipher, const u8* msg, unsigned int len,
             u8 *out, unsigned int *out_len)
{
	memcpy(out, msg, len);
}

static void
null_encrypt_inplace(struct cipher *cipher, u8* msg, unsigned int len)
{
}

static void
null_decrypt_inplace(struct cipher *cipher, u8* msg, unsigned int len)
{
}

static struct cipher_algorithm null_cipher = {
	.name = "null",
	.id = CIPHER_NULL,
	.mode = CIPHER_MODE_NULL,
	.type = CIPHER_TYPE_NULL, 
	.dialect = CIPHER_DIALECT_NONE,
	.ctx_size = 0,
	.mac_size = 0,
	.key_size = 0,
	.init = null_init,
	.set_mac = null_set_mac,
	.set_key = null_set_key,
	.set_iv = null_set_iv,
	.decrypt = null_decrypt,
	.encrypt = null_encrypt,
	.decrypt_inplace = null_decrypt_inplace,
	.encrypt_inplace = null_encrypt_inplace,
};

void crypto_init_null_cipher(void)
{
	crypto_cipher_register(&null_cipher);
}
