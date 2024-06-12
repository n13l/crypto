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
 *
 */

#ifndef __CRYPTO_CIPHER_H__
#define __CRYPTO_CIPHER_H__

/* Intrusive, lockless and hardware accelerated cryptography operations. */
#include <sys/compiler.h>
/* Multi-buffer Crypto and hardware acceleration. */
#include <crypto/support.h>
/* Intrusive cryptography interface is designed to minimize overhead by avoiding
 * buffer copies, dynamic allocations and aiming for a desired asymptotic 
 * complexity. This ensures high speed and resource efficiency. Dynamic 
 * allocation allows handling integers of any size but comes at the expense of 
 * performance and may introduce side-channel vulnerabilities. */

/*
 * ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
 * https://tools.ietf.org/html/rfc7539
 *
 * 3. Implementation Advice
 *
 * It is not recommended to use a generic big number library such as the
 * one in OpenSSL for the arithmetic operations in Poly1305.  Such
 * libraries use dynamic allocation to be able to handle an integer of
 * any size, but that flexibility comes at the expense of performance as
 * well as side-channel security.  More efficient implementations that
 * run in constant time are available, one of them in D. J. Bernstein's
 * own library, NaCl ([NaCl]).  A constant-time but not optimal approach
 * would be to naively implement the arithmetic operations for 288-bit
 * integers, because even a naive implementation will not exceed 2^288
 * in the multiplication of (acc+block) and r.  An efficient constant-
 * time implementation can be found in the public domain library
 * poly1305-donna ([Poly1305_Donna]).
 *
 * Each block of ChaCha20 involves 16 move operations and one increment
 * operation for loading the state, 80 each of XOR, addition and Roll
 * operations for the rounds, 16 more add operations and 16 XOR
 * operations for protecting the plaintext.  Section 2.3 describes the
 * ChaCha block function as "adding the original input words".  This
 * implies that before starting the rounds on the ChaCha state, we copy
 * it aside, only to add it in later.  This is correct, but we can save
 * a few operations if we instead copy the state and do the work on the
 * copy.  This way, for the next block you don't need to recreate the
 * state, but only to increment the block counter.  This saves
 * approximately 5.5% of the cycles.
 */

/*
 * TODO: 
 * 
 * The current implementation uses multiple buffers for output parameters.
 * This requires additional buffer copies, increasing the risk of errors and 
 * impacting performance.
 * 
 */

__BEGIN_DECLS

#define CIPHER_CTX_MAX 512

enum {
	CIPHER_TYPE_NONE = 0,
	CIPHER_TYPE_NULL,
	CIPHER_TYPE_STREAM,
	CIPHER_TYPE_BLOCK,
	CIPHER_TYPE_AEAD,
	CIPHER_TYPE_LAST
};

enum {
	CIPHER_MODE_NONE = 0,
	CIPHER_MODE_NULL,
	CIPHER_MODE_ECB,
	CIPHER_MODE_CBC,
	CIPHER_MODE_OFB,
	CIPHER_MODE_CTR,
	CIPHER_MODE_GCM,
	CIPHER_MODE_CCM,
	CIPHER_MODE_CCM_8,
	CIPHER_MODE_XTS,
	CIPHER_MODE_STREAM,
	CIPHER_MODE_POLY1305,
	CIPHER_MODE_LAST = 15,
};

enum {
	CIPHER_DIALECT_NONE = 0,
	CIPHER_RFC5246,
	CIPHER_RFC8446,
	CIPHER_DIALECT_LAST = 4
};

enum {
	CIPHER_NONE = 0,
	CIPHER_NULL,
	CIPHER_RC2,
	CIPHER_RC4,
	CIPHER_IDEA,
	CIPHER_DES,
	CIPHER_3DES,
	CIPHER_SEED,
	CIPHER_CHACHA20,
	CIPHER_CAMELLIA128,
	CIPHER_CAMELLIA256,
	CIPHER_AES128,
	CIPHER_AES192,
	CIPHER_AES256,
	CIPHER_NAME_LAST = 31
};

struct cipher;
struct cipher_algorithm;
struct cipher_inplace;
struct cipher_multibufer;

typedef int (*fn_cipher_enum)(struct cipher_algorithm*);

typedef void (*fn_cipher_init)(struct cipher *,
                               const u8 *key, unsigned int key_len,
                               const u8 *mac, unsigned int mac_len,
                               const u8 *iv, unsigned int iv_len);

typedef void
(*fn_cipher_set_mac)(struct cipher *, const u8 *mac, unsigned int len);

typedef void
(*fn_cipher_set_key)(struct cipher *, const u8 *key, unsigned int len);

typedef void
(*fn_cipher_set_iv)(struct cipher *, const u8 *iv, unsigned int len);

typedef void
(*fn_cipher_crypt_inplace)(struct cipher *, u8 *msg , unsigned int len);

typedef void
(*fn_cipher_crypt)(struct cipher *, const u8 *msg, unsigned int len, u8 *out,
	           unsigned int *out_len);

typedef void
(*fn_cipher_cryptv)(struct cipher *, const struct crypto_vec *v, unsigned int );

struct cipher_algorithm {
	fn_cipher_init init;
	fn_cipher_crypt decrypt;
	fn_cipher_crypt encrypt;
	fn_cipher_crypt_inplace decrypt_inplace;
	fn_cipher_crypt_inplace encrypt_inplace;
	fn_cipher_set_mac set_mac;
	fn_cipher_set_key set_key;
	fn_cipher_set_iv set_iv;
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
	unsigned int features;
	const char *name;
	const char *desc;
};

struct cipher {
	u8 ctx[CIPHER_CTX_MAX];
};

void crypto_cipher_init(void);
void crypto_cipher_opt(unsigned int opt);
void crypto_cipher_register(struct cipher_algorithm *);
struct cipher_algorithm* crypto_cipher_by_id(unsigned int id);
void crypto_cipher_enum(fn_cipher_enum fn);

#define crypto_cipher_mkid(type, mode, dialect) ((mode << 4) | (type))

__END_DECLS

#endif
