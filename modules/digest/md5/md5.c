/*
 * MD5 Message-Digest Algorithm (RFC 1321)
 *
 * The MIT License (MIT)                     Copyright (c) 2026
 *                                                  Daniel Kubec <niel@rtfm.cz>
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
 * Why a build has this at all: MD5 is half of the TLS 1.0/1.1 key schedule.
 * The PRF of RFC 2246 sec 5 is P_MD5 exclusive-ored with P_SHA-1, the Finished
 * of both versions hashes its transcript under MD5 as well as SHA-1, and the
 * *_WITH_*_MD5 suites of the same era authenticate a record with HMAC-MD5.
 * Nothing at TLS 1.2 or above reaches it, so the backend is off unless a
 * configuration asks for it (CONFIG_CRYPTO_MD5, configs/insecure.config).
 * It is a digest for reading that traffic, and is not a hash to choose.
 */

#include <hpc/compiler.h>
#include <hpc/cpu.h>
#include <hpc/mem/unaligned.h>
#include <string.h>

#ifndef MD5_SCOPE
#define MD5_SCOPE
#endif

/* struct md5 and the two sizes: one owner, read by this file and by
 * built-in.h alike, because a size build compiles the two separately */
#include "decl.h"

MD5_SCOPE void
md5_init(struct md5 *ctx)
{
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->len = 0;
	ctx->count = 0;
}

/*
 * The four round functions and the step of RFC 1321 sec 3.4, in Colin Plumb's
 * arrangement: the round constant is folded into the caller's argument, so a
 * step is one add, one rotate and one add.
 */
#define MD5_F1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_F2(x, y, z) MD5_F1(z, x, y)
#define MD5_F3(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_F4(x, y, z) ((y) ^ ((x) | ~(z)))

#define MD5_STEP(f, w, x, y, z, data, s) do { \
	(w) += f(x, y, z) + (data); \
	(w) = ((w) << (s)) | ((w) >> (32 - (s))); \
	(w) += (x); \
} while (0)

static void
md5_transform(struct md5 *ctx, const u8 *data)
{
	u32 a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
	u32 x[16];
	unsigned int i;

	/* MD5 reads its block as little-endian words, which is the one place
	 * it differs from every SHA in this directory */
	for (i = 0; i < 16; i++)
		x[i] = get_u32_le(data + 4 * i);

	MD5_STEP(MD5_F1, a, b, c, d, x[ 0] + 0xd76aa478,  7);
	MD5_STEP(MD5_F1, d, a, b, c, x[ 1] + 0xe8c7b756, 12);
	MD5_STEP(MD5_F1, c, d, a, b, x[ 2] + 0x242070db, 17);
	MD5_STEP(MD5_F1, b, c, d, a, x[ 3] + 0xc1bdceee, 22);
	MD5_STEP(MD5_F1, a, b, c, d, x[ 4] + 0xf57c0faf,  7);
	MD5_STEP(MD5_F1, d, a, b, c, x[ 5] + 0x4787c62a, 12);
	MD5_STEP(MD5_F1, c, d, a, b, x[ 6] + 0xa8304613, 17);
	MD5_STEP(MD5_F1, b, c, d, a, x[ 7] + 0xfd469501, 22);
	MD5_STEP(MD5_F1, a, b, c, d, x[ 8] + 0x698098d8,  7);
	MD5_STEP(MD5_F1, d, a, b, c, x[ 9] + 0x8b44f7af, 12);
	MD5_STEP(MD5_F1, c, d, a, b, x[10] + 0xffff5bb1, 17);
	MD5_STEP(MD5_F1, b, c, d, a, x[11] + 0x895cd7be, 22);
	MD5_STEP(MD5_F1, a, b, c, d, x[12] + 0x6b901122,  7);
	MD5_STEP(MD5_F1, d, a, b, c, x[13] + 0xfd987193, 12);
	MD5_STEP(MD5_F1, c, d, a, b, x[14] + 0xa679438e, 17);
	MD5_STEP(MD5_F1, b, c, d, a, x[15] + 0x49b40821, 22);

	MD5_STEP(MD5_F2, a, b, c, d, x[ 1] + 0xf61e2562,  5);
	MD5_STEP(MD5_F2, d, a, b, c, x[ 6] + 0xc040b340,  9);
	MD5_STEP(MD5_F2, c, d, a, b, x[11] + 0x265e5a51, 14);
	MD5_STEP(MD5_F2, b, c, d, a, x[ 0] + 0xe9b6c7aa, 20);
	MD5_STEP(MD5_F2, a, b, c, d, x[ 5] + 0xd62f105d,  5);
	MD5_STEP(MD5_F2, d, a, b, c, x[10] + 0x02441453,  9);
	MD5_STEP(MD5_F2, c, d, a, b, x[15] + 0xd8a1e681, 14);
	MD5_STEP(MD5_F2, b, c, d, a, x[ 4] + 0xe7d3fbc8, 20);
	MD5_STEP(MD5_F2, a, b, c, d, x[ 9] + 0x21e1cde6,  5);
	MD5_STEP(MD5_F2, d, a, b, c, x[14] + 0xc33707d6,  9);
	MD5_STEP(MD5_F2, c, d, a, b, x[ 3] + 0xf4d50d87, 14);
	MD5_STEP(MD5_F2, b, c, d, a, x[ 8] + 0x455a14ed, 20);
	MD5_STEP(MD5_F2, a, b, c, d, x[13] + 0xa9e3e905,  5);
	MD5_STEP(MD5_F2, d, a, b, c, x[ 2] + 0xfcefa3f8,  9);
	MD5_STEP(MD5_F2, c, d, a, b, x[ 7] + 0x676f02d9, 14);
	MD5_STEP(MD5_F2, b, c, d, a, x[12] + 0x8d2a4c8a, 20);

	MD5_STEP(MD5_F3, a, b, c, d, x[ 5] + 0xfffa3942,  4);
	MD5_STEP(MD5_F3, d, a, b, c, x[ 8] + 0x8771f681, 11);
	MD5_STEP(MD5_F3, c, d, a, b, x[11] + 0x6d9d6122, 16);
	MD5_STEP(MD5_F3, b, c, d, a, x[14] + 0xfde5380c, 23);
	MD5_STEP(MD5_F3, a, b, c, d, x[ 1] + 0xa4beea44,  4);
	MD5_STEP(MD5_F3, d, a, b, c, x[ 4] + 0x4bdecfa9, 11);
	MD5_STEP(MD5_F3, c, d, a, b, x[ 7] + 0xf6bb4b60, 16);
	MD5_STEP(MD5_F3, b, c, d, a, x[10] + 0xbebfbc70, 23);
	MD5_STEP(MD5_F3, a, b, c, d, x[13] + 0x289b7ec6,  4);
	MD5_STEP(MD5_F3, d, a, b, c, x[ 0] + 0xeaa127fa, 11);
	MD5_STEP(MD5_F3, c, d, a, b, x[ 3] + 0xd4ef3085, 16);
	MD5_STEP(MD5_F3, b, c, d, a, x[ 6] + 0x04881d05, 23);
	MD5_STEP(MD5_F3, a, b, c, d, x[ 9] + 0xd9d4d039,  4);
	MD5_STEP(MD5_F3, d, a, b, c, x[12] + 0xe6db99e5, 11);
	MD5_STEP(MD5_F3, c, d, a, b, x[15] + 0x1fa27cf8, 16);
	MD5_STEP(MD5_F3, b, c, d, a, x[ 2] + 0xc4ac5665, 23);

	MD5_STEP(MD5_F4, a, b, c, d, x[ 0] + 0xf4292244,  6);
	MD5_STEP(MD5_F4, d, a, b, c, x[ 7] + 0x432aff97, 10);
	MD5_STEP(MD5_F4, c, d, a, b, x[14] + 0xab9423a7, 15);
	MD5_STEP(MD5_F4, b, c, d, a, x[ 5] + 0xfc93a039, 21);
	MD5_STEP(MD5_F4, a, b, c, d, x[12] + 0x655b59c3,  6);
	MD5_STEP(MD5_F4, d, a, b, c, x[ 3] + 0x8f0ccc92, 10);
	MD5_STEP(MD5_F4, c, d, a, b, x[10] + 0xffeff47d, 15);
	MD5_STEP(MD5_F4, b, c, d, a, x[ 1] + 0x85845dd1, 21);
	MD5_STEP(MD5_F4, a, b, c, d, x[ 8] + 0x6fa87e4f,  6);
	MD5_STEP(MD5_F4, d, a, b, c, x[15] + 0xfe2ce6e0, 10);
	MD5_STEP(MD5_F4, c, d, a, b, x[ 6] + 0xa3014314, 15);
	MD5_STEP(MD5_F4, b, c, d, a, x[13] + 0x4e0811a1, 21);
	MD5_STEP(MD5_F4, a, b, c, d, x[ 4] + 0xf7537e82,  6);
	MD5_STEP(MD5_F4, d, a, b, c, x[11] + 0xbd3af235, 10);
	MD5_STEP(MD5_F4, c, d, a, b, x[ 2] + 0x2ad7d2bb, 15);
	MD5_STEP(MD5_F4, b, c, d, a, x[ 9] + 0xeb86d391, 21);

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
}

MD5_SCOPE void
md5_update(struct md5 *ctx, const u8 *buf, unsigned int len)
{
	ctx->len += len;

	if (ctx->count) {
		unsigned int fill = MD5_BLK_SIZE - ctx->count;

		if (len < fill) {
			memcpy(ctx->buf + ctx->count, buf, len);
			ctx->count += len;
			return;
		}
		memcpy(ctx->buf + ctx->count, buf, fill);
		md5_transform(ctx, ctx->buf);
		ctx->count = 0;
		buf += fill;
		len -= fill;
	}

	while (len >= MD5_BLK_SIZE) {
		md5_transform(ctx, buf);
		buf += MD5_BLK_SIZE;
		len -= MD5_BLK_SIZE;
	}

	if (len) {
		memcpy(ctx->buf, buf, len);
		ctx->count = len;
	}
}

MD5_SCOPE void
md5_final(struct md5 *ctx, u8 *digest)
{
	u64 bits = ctx->len << 3;
	unsigned int i;

	/* the 0x80 terminator, then zeroes to eight short of a block, then the
	 * length in bits as a little-endian 64 (RFC 1321 sec 3.2) */
	ctx->buf[ctx->count++] = 0x80;
	if (ctx->count > MD5_BLK_SIZE - 8) {
		memset(ctx->buf + ctx->count, 0, MD5_BLK_SIZE - ctx->count);
		md5_transform(ctx, ctx->buf);
		ctx->count = 0;
	}
	memset(ctx->buf + ctx->count, 0, MD5_BLK_SIZE - 8 - ctx->count);
	put_u64_le(ctx->buf + MD5_BLK_SIZE - 8, bits);
	md5_transform(ctx, ctx->buf);

	for (i = 0; i < 4; i++)
		put_u32_le(digest + 4 * i, ctx->h[i]);
}

MD5_SCOPE void
md5_hash(const u8 *buf, unsigned int len, u8 *out)
{
	struct md5 ctx;

	md5_init(&ctx);
	md5_update(&ctx, buf, len);
	md5_final(&ctx, out);
}
