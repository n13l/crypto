/*
 * HMAC-SM3 implementation (RFC 2104 over GB/T 32905)
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
 * What a TLS 1.3 ShangMi channel proves itself with: HKDF-Expand is HMAC over
 * the running hash (modules/net/tls/hs/tls13.h builds it from these calls),
 * and the Finished is HMAC-SM3 over the transcript hash. The composition is
 * RFC 2104's with SM3's 64-byte block, so it is the HMAC-SHA-256 file with the
 * digest renamed.
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>

#ifndef HMAC_SM3_SCOPE
#define HMAC_SM3_SCOPE
#endif

#include "ctx.h"

HMAC_SM3_SCOPE void
hmac_sm3_init(hmac_sm3_ctx *ctx, const u8 *key, unsigned int key_size)
{
	u8 key_temp[SM3_DIGEST_SIZE];
	const u8 *key_used;
	unsigned int num, i;

	if (key_size > SM3_BLOCK_SIZE) {
		struct sm3 tmp;

		arch_sm3_init(&tmp);
		arch_sm3_update(&tmp, key, key_size);
		arch_sm3_final(&tmp, key_temp);
		key_used = key_temp;
		num = SM3_DIGEST_SIZE;
	} else {
		key_used = key;
		num = key_size;
	}

	memset(ctx->block_ipad + num, 0x36, SM3_BLOCK_SIZE - num);
	memset(ctx->block_opad + num, 0x5c, SM3_BLOCK_SIZE - num);
	for (i = 0; i < num; i++) {
		ctx->block_ipad[i] = (u8)(key_used[i] ^ 0x36);
		ctx->block_opad[i] = (u8)(key_used[i] ^ 0x5c);
	}

	arch_sm3_init(&ctx->ctx_inside);
	arch_sm3_update(&ctx->ctx_inside, ctx->block_ipad, SM3_BLOCK_SIZE);

	arch_sm3_init(&ctx->ctx_outside);
	arch_sm3_update(&ctx->ctx_outside, ctx->block_opad, SM3_BLOCK_SIZE);

	/* for hmac_sm3_reinit */
	memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside, sizeof(struct sm3));
	memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside, sizeof(struct sm3));
}

HMAC_SM3_SCOPE void
hmac_sm3_reinit(hmac_sm3_ctx *ctx)
{
	memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit, sizeof(struct sm3));
	memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit, sizeof(struct sm3));
}

HMAC_SM3_SCOPE void
hmac_sm3_update(hmac_sm3_ctx *ctx, const u8 *msg, unsigned int len)
{
	arch_sm3_update(&ctx->ctx_inside, msg, len);
}

HMAC_SM3_SCOPE void
hmac_sm3_final(hmac_sm3_ctx *ctx, u8 *mac, unsigned int mac_size)
{
	u8 digest_inside[SM3_DIGEST_SIZE];
	u8 mac_temp[SM3_DIGEST_SIZE];

	arch_sm3_final(&ctx->ctx_inside, digest_inside);
	arch_sm3_update(&ctx->ctx_outside, digest_inside, SM3_DIGEST_SIZE);
	arch_sm3_final(&ctx->ctx_outside, mac_temp);
	memcpy(mac, mac_temp, mac_size);
}

HMAC_SM3_SCOPE void
hmac_sm3(const u8 *key, unsigned int key_size, const u8 *msg,
         unsigned int msg_len, u8 *mac, unsigned int mac_size)
{
	hmac_sm3_ctx ctx;

	hmac_sm3_init(&ctx, key, key_size);
	hmac_sm3_update(&ctx, msg, msg_len);
	hmac_sm3_final(&ctx, mac, mac_size);
}
