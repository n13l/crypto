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

#ifndef __CRYPTO_DIGEST_H__
#define __CRYPTO_DIGEST_H__

#include <sys/compiler.h>

#define CRYPTO_DIGEST_TABLE_BITS 5

__BEGIN_DECLS

enum {
	DIGEST_NONE = 0,
	DIGEST_CRC16,
	DIGEST_CRC32,
	DIGEST_CRC32C,
	DIGEST_FNV,
	DIGEST_MD4,
	DIGEST_MD5,
	DIGEST_MD5_SHA1,
	DIGEST_SHA1,
	DIGEST_SHA224,
	DIGEST_SHA256,
	DIGEST_SHA384,
	DIGEST_SHA512,
	DIGEST_SIPHASH_24,
	DIGEST_LAST
};

struct digest;

typedef void (*fn_digest_init)(struct digest *);
typedef void (*fn_digest_copy)(struct digest *, struct digest *);
typedef void (*fn_digest_reset)(struct digest *);
typedef void (*fn_digest_update)(struct digest *, const u8 *, unsigned int);
typedef void (*fn_digest_digest)(struct digest *, u8 *);
typedef void (*fn_digest_hash)(const u8 *, unsigned int, u8 *);
typedef const u8 *(*fn_digest_zero)(void);

struct digest_algorithm {
	fn_digest_init init;
	fn_digest_copy copy;
	fn_digest_reset reset;
	fn_digest_update update;
	fn_digest_digest digest;
	fn_digest_hash hash;
	fn_digest_zero zero;
	unsigned int msg_size;
	unsigned int blk_size;
	unsigned int mac_size;
	unsigned int ctx_size;
	const char *name;
	const char *desc;
	unsigned int id;
};

#define DIGEST_CTX_MAX 328
struct digest {
	u8 data[DIGEST_CTX_MAX];
};

void
crypto_digest_register(struct digest_algorithm *);

struct digest_algorithm *
crypto_digest_by_id(unsigned int id);

__END_DECLS

#endif
