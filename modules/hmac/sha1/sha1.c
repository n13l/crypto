/*
 * HMAC-SHA-1-160 implementation
 *
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
 * https://tools.ietf.org/html/rfc2104
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>

typedef struct {
    struct sha1 ctx_inside;
    struct sha1 ctx_outside;
    struct sha1 ctx_inside_reinit;
    struct sha1 ctx_outside_reinit;
    u8 block_ipad[SHA1_BLOCK_SIZE];
    u8 block_opad[SHA1_BLOCK_SIZE];
} hmac_sha1_ctx;

/* HMAC-SHA-1-160 functions */

static void
hmac_sha1_160_init(hmac_sha1_ctx *ctx, const u8 *key, unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const u8 *key_used;
    u8 key_temp[SHA1_DIGEST_SIZE];
    int i;

    if (key_size == SHA1_BLOCK_SIZE) {
        key_used = key;
        num = SHA1_BLOCK_SIZE;
    } else {
        if (key_size > SHA1_BLOCK_SIZE){
            struct sha1 tmp;
            num = SHA1_DIGEST_SIZE;
            arch_sha1_160_init(&tmp);
            arch_sha1_160_update(&tmp, key, key_size);
            arch_sha1_160_final(&tmp, key_temp);
            key_used = key_temp;
        } else {
            key_used = key;
            num = key_size;
        }
        fill = SHA1_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    arch_sha1_160_init(&ctx->ctx_inside);
    arch_sha1_160_update(&ctx->ctx_inside, ctx->block_ipad, SHA1_BLOCK_SIZE);

    arch_sha1_160_init(&ctx->ctx_outside);
    arch_sha1_160_update(&ctx->ctx_outside, ctx->block_opad, SHA1_BLOCK_SIZE);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(struct sha1));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(struct sha1));
}

static void
hmac_sha1_160_reinit(hmac_sha1_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(struct sha1));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(struct sha1));
}

static void
hmac_sha1_160_update(hmac_sha1_ctx *ctx, const u8 *msg, unsigned int len)
{
    arch_sha1_160_update(&ctx->ctx_inside, msg, len);
}

static void
hmac_sha1_160_final(hmac_sha1_ctx *ctx, u8 *mac, unsigned int mac_size)
{
    u8 digest_inside[SHA1_DIGEST_SIZE];
    u8 mac_temp[SHA1_DIGEST_SIZE];

    arch_sha1_160_final(&ctx->ctx_inside, digest_inside);
    arch_sha1_160_update(&ctx->ctx_outside, digest_inside, SHA1_DIGEST_SIZE);
    arch_sha1_160_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

static void
hmac_sha1_160(const u8 *key, unsigned int key_size,
              const u8 *msg, unsigned int msg_len,
              u8 *mac, unsigned mac_size)
{
    hmac_sha1_ctx ctx;

    hmac_sha1_160_init(&ctx, key, key_size);
    hmac_sha1_160_update(&ctx, msg, msg_len);
    hmac_sha1_160_final(&ctx, mac, mac_size);
}
