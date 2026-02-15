/*
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz>
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
 */

#ifndef __CRYPTO_CIPHER_H__
#define __CRYPTO_CIPHER_H__

/* Intrusive, lockless and hardware accelerated cryptography operations. */
#include <hpc/compiler.h>

#define CIPHER_CTXT_SIZE_MAX 512

enum {
	C_TYPE_NONE = 0,
	C_TYPE_NULL,
	C_TYPE_STREAM,
	C_TYPE_BLOCK,
	C_TYPE_AEAD,
	C_TYPE_LAST
};

enum {
	M_NA = 0,
	M_NONE,
	M_NULL,
	M_ECB,
	M_CBC,
	M_OFB,
	M_CTR,
	M_GCM,
	M_CCM,
	M_CCM_8,
	M_CCM8,
	M_XTS,
	M_STREAM,
	M_POLY1305,
	M_LAST = 15,
};

enum {
	C_DIALECT_NONE = 0,
	C_RFC5246,
	C_RFC8446,
	C_DIALECT_LAST = 4
};

enum {
	C_NONE = 0,
	C_NULL,
	C_RC2,
	C_RC4,
	C_IDEA,
	C_DES,
	C_3DES,
	C_SEED,
	C_ARIA128,
	C_ARIA256,
	C_CAMELLIA128,
	C_CAMELLIA256,
	C_AES128,
	C_AES192,
	C_AES256,
	C_CHACHA20,
	C_SM4,
	C_3DESEDE,
	C_DESCBC40,
	C_RC2CBC40,
	C_RC4128,
	C_RC440,
	C_DES40,
	C_KUZNYECHIKMGML,
	C_MAGMAMGML,
	C_KUZNYECHIKMGMS,
	C_MAGMAMGMS,
	C_KUZNYECHIKCTR,
	C_MAGMACTR,
	C_28147CNT,
	C_LAST
};

struct cipher {
	u8 data[CIPHER_CTXT_SIZE_MAX] _align_max;
};

struct cipher_algorithm;

typedef int (*fn_cipher_enum)(struct cipher_algorithm *);

typedef void (*fn_cipher_init)(struct cipher *,
                               const u8 *key, unsigned int key_len,
                               const u8 *iv, unsigned int iv_len,
                               const u8 *mac, unsigned int mac_len);

typedef void
(*fn_cipher_set_encrypt_then_mac)(struct cipher *, unsigned int val);

typedef void
(*fn_cipher_set_mac)(struct cipher *, const u8 *mac, unsigned int len);

typedef void
(*fn_cipher_set_key)(struct cipher *, const u8 *key, unsigned int len);

typedef void
(*fn_cipher_set_iv)(struct cipher *, const u8 *iv, unsigned int len);

typedef void
(*fn_cipher_crypt_inplace)(struct cipher *, u8 *msg, unsigned int len);

typedef void
(*fn_cipher_crypt)(struct cipher *, const u8 *msg, unsigned int len, u8 *out,
                   unsigned int *out_len);

struct cipher_algorithm {
	fn_cipher_init init;
	fn_cipher_crypt decrypt;
	fn_cipher_crypt encrypt;
	fn_cipher_crypt_inplace decrypt_inplace;
	fn_cipher_crypt_inplace encrypt_inplace;
	fn_cipher_set_mac set_mac;
	fn_cipher_set_key set_key;
	fn_cipher_set_iv set_iv;
	fn_cipher_set_encrypt_then_mac set_encrypt_then_mac;
	unsigned int ctx_size;
	unsigned int mac_size;
	unsigned int key_size;
	unsigned int block_size;
	unsigned int iv_size;
	unsigned int id;
	unsigned int index;
	unsigned int type;
	unsigned int mode;
	unsigned int dialect;
	const char *name;
	const char *desc;
};

/* C_LAST needs 5 bits, M_LAST 4: index = mode:4 | cipher:5 */
#define crypto_cipher_mkid(cipher, mode, dialect) (((mode) << 5) | (cipher))

void crypto_cipher_register(struct cipher_algorithm *alg);
struct cipher_algorithm *crypto_cipher_by_id(unsigned int id);
void crypto_cipher_enum(fn_cipher_enum fn);

#if !defined(CONFIG_MODULES) && !defined(__CRYPTO_CIPHER_MODULE__)
#define __CRYPTO_CIPHER_BUILT_IN_READY__
#ifdef CONFIG_CRYPTO_CIPHER_AES
#include <modules/cipher/aes/built-in.h>
#endif
#ifdef CONFIG_CRYPTO_CIPHER_CHACHA20
#include <modules/cipher/chacha/built-in.h>
#endif
#undef __CRYPTO_CIPHER_BUILT_IN_READY__
#endif

#endif
