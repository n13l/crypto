/*
 * The MIT License (MIT)         Copyright (c) 2013 Daniel Kubec <niel@rtfm.cz>
 *
 * Pseudorandom Function Family (PRF)
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

#ifndef __CRYPTO_PRF_H__
#define __CRYPTO_PRF_H__

#include <sys/compiler.h>
#include <crypto/digest.h>
#include <crypto/hmac.h>

__BEGIN_DECLS

enum {
	PRF_NONE = 0,
	PRF_NULL,
	PRF_SHA2_256 = DIGEST_SHA256,
	PRF_SHA2_384 = DIGEST_SHA384,
	PRF_SHA2_512 = DIGEST_SHA512,
	PRF_LAST
};

struct prf_context;

typedef void
(*fn_crypto_prf)(struct prf_context *,
                 const u8 *seed0, unsigned int seed0_len,
                 const u8 *seed1, unsigned int seed1_len,
                 const u8 *seed2, unsigned int seed2_len,
                 u8 *output, unsigned int output_len);

struct prf_algorithm {
	fn_crypto_prf derive;
	const char *name;
	unsigned int ctx_size;
	u8 id;
};

struct prf_context {
	u8 data[HMAC_CTX_MAX];
};

void
crypto_prf_register(struct prf_algorithm *);

struct prf_algorithm *
crypto_prf_by_id(unsigned int id);

__END_DECLS

#endif
