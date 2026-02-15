/*
 * HMAC-MD5 implementation (RFC 2104)
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
 * HMAC is not broken by MD5's collisions, which is why this one composition
 * outlived the digest under it: what a TLS 1.0/1.1 record needs is a MAC, and
 * the *_WITH_*_MD5 suites name this one. Nothing else in the tree calls it.
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>

#ifndef HMAC_MD5_SCOPE
#define HMAC_MD5_SCOPE
#endif

#include "ctx.h"

HMAC_MD5_SCOPE void
hmac_md5_init(hmac_md5_ctx *ctx, const u8 *key, unsigned int key_size)
{
	u8 key_temp[MD5_DIGEST_SIZE];
	const u8 *key_used;
	unsigned int num, i;

	if (key_size > MD5_BLOCK_SIZE) {
		struct md5 tmp;

		arch_md5_init(&tmp);
		arch_md5_update(&tmp, key, key_size);
		arch_md5_final(&tmp, key_temp);
		key_used = key_temp;
		num = MD5_DIGEST_SIZE;
	} else {
		key_used = key;
		num = key_size;
	}

	memset(ctx->block_ipad + num, 0x36, MD5_BLOCK_SIZE - num);
	memset(ctx->block_opad + num, 0x5c, MD5_BLOCK_SIZE - num);
	for (i = 0; i < num; i++) {
		ctx->block_ipad[i] = (u8)(key_used[i] ^ 0x36);
		ctx->block_opad[i] = (u8)(key_used[i] ^ 0x5c);
	}

	arch_md5_init(&ctx->ctx_inside);
	arch_md5_update(&ctx->ctx_inside, ctx->block_ipad, MD5_BLOCK_SIZE);

	arch_md5_init(&ctx->ctx_outside);
	arch_md5_update(&ctx->ctx_outside, ctx->block_opad, MD5_BLOCK_SIZE);

	/* for hmac_md5_reinit */
	memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside, sizeof(struct md5));
	memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside, sizeof(struct md5));
}

HMAC_MD5_SCOPE void
hmac_md5_reinit(hmac_md5_ctx *ctx)
{
	memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit, sizeof(struct md5));
	memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit, sizeof(struct md5));
}

HMAC_MD5_SCOPE void
hmac_md5_update(hmac_md5_ctx *ctx, const u8 *msg, unsigned int len)
{
	arch_md5_update(&ctx->ctx_inside, msg, len);
}

HMAC_MD5_SCOPE void
hmac_md5_final(hmac_md5_ctx *ctx, u8 *mac, unsigned int mac_size)
{
	u8 digest_inside[MD5_DIGEST_SIZE];
	u8 mac_temp[MD5_DIGEST_SIZE];

	arch_md5_final(&ctx->ctx_inside, digest_inside);
	arch_md5_update(&ctx->ctx_outside, digest_inside, MD5_DIGEST_SIZE);
	arch_md5_final(&ctx->ctx_outside, mac_temp);
	memcpy(mac, mac_temp, mac_size);
}

HMAC_MD5_SCOPE void
hmac_md5(const u8 *key, unsigned int key_size, const u8 *msg,
         unsigned int msg_len, u8 *mac, unsigned int mac_size)
{
	hmac_md5_ctx ctx;

	hmac_md5_init(&ctx, key, key_size);
	hmac_md5_update(&ctx, msg, msg_len);
	hmac_md5_final(&ctx, mac, mac_size);
}
