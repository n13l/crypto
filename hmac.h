/*
 * The MIT License (MIT)         Copyright (c) 2016 Daniel Kubec <niel@rtfm.cz>
 *
 * HMAC-based Extract-and-Expand Key Derivation Function (HKDF) 
 * https://tools.ietf.org/html/rfc5869
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

#ifndef __CRYPTO_HMAC_H__
#define __CRYPTO_HMAC_H__

#include <sys/compiler.h>
#include <crypto/digest.h>

__BEGIN_DECLS

#define HMAC_CTX_MAX 328

enum hmac_algorithm_type {
	HMAC_NONE = 0,
	HMAC_MD5,
	HMAC_SHA1,
	HMAC_SHA224,
	HMAC_SHA256 = DIGEST_SHA256,
	HMAC_SHA384 = DIGEST_SHA384,
	HMAC_SHA512,
	HMAC_LAST
};

struct hmac_context;
typedef void
(*hmac_fn)(struct hmac_context *, const u8 *, unsigned int, const u8 *,
                  unsigned int ,u8 *, unsigned int);

typedef void
(*hmac_vector_fn)(struct hmac_context *, const u8 *, unsigned int,
              unsigned int, const u8 **, unsigned int *, u8 *, unsigned int);

struct hmac_context {
	u8 data[HMAC_CTX_MAX];
};

struct hmac_algorithm {
	hmac_fn hmac;
	hmac_vector_fn vector;
	const char *name;
	unsigned int ctx_size;
	unsigned int id;
};

void
crypto_hmac_register(struct hmac_algorithm *alg);
	
struct hmac_algorithm *
crypto_hmac_by_id(unsigned int id);

__END_DECLS

#endif
