/*
 * The MIT License (MIT)         Copyright (c) 2013 Daniel Kubec <niel@rtfm.cz>
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

#ifndef __CRYPTO_HKDF_H__
#define __CRYPTO_HKDF_H__

#include <sys/compiler.h>
#include <crypto/digest.h>
#include <crypto/hmac.h>

enum {
	HKDF_NONE = 0,
	HKDF_SHA256,
	HKDF_SHA384,
	HKDF_SHA512,
	HKDF_LAST
};

struct hkdf_context;

typedef void
(*fn_hkdf_extract)(struct hkdf_context *hkdf,
                   const u8 *secret, unsigned int secret_len,
                   const char *label, unsigned int label_len,
                   const u8 *data, unsigned int data_len,
                   u8 *out, unsigned int len);

typedef void
(*fn_hkdf_expand)(struct hkdf_context *hkdf,
                  const u8 *secret, size_t secret_len,
                  const char *label, size_t label_len,
                  const u8 *data, size_t data_len,
                  u8 *output, size_t len);


struct hkdf_algorithm {
	fn_hkdf_extract extract;
	fn_hkdf_expand expand;
	const char *name;
	u8 id;
};

struct hkdf_context {
	u8 data[HMAC_CTX_MAX];
	fn_hkdf_extract extract;
	fn_hkdf_expand expand;
	struct hkdf_algorithm *algo;
};

void
crypto_hkdf_register(struct hkdf_algorithm *);

struct hkdf_algorithm *
crypto_hkdf_by_id(unsigned int id);

#endif
