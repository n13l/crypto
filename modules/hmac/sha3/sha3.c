/*
 * HMAC-SHA-3-224/256/384/512 implementation
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
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>

typedef struct {
    struct sha3 ctx_inside;
    struct sha3 ctx_outside;
    struct sha3 ctx_inside_reinit;
    struct sha3 ctx_outside_reinit;
    u8 block_ipad[SHA3_224_BLOCK_SIZE];
    u8 block_opad[SHA3_224_BLOCK_SIZE];
} hmac_sha3_224_ctx;

typedef struct {
    struct sha3 ctx_inside;
    struct sha3 ctx_outside;
    struct sha3 ctx_inside_reinit;
    struct sha3 ctx_outside_reinit;
    u8 block_ipad[SHA3_256_BLOCK_SIZE];
    u8 block_opad[SHA3_256_BLOCK_SIZE];
} hmac_sha3_256_ctx;

typedef struct {
    struct sha3 ctx_inside;
    struct sha3 ctx_outside;
    struct sha3 ctx_inside_reinit;
    struct sha3 ctx_outside_reinit;
    u8 block_ipad[SHA3_384_BLOCK_SIZE];
    u8 block_opad[SHA3_384_BLOCK_SIZE];
} hmac_sha3_384_ctx;

typedef struct {
    struct sha3 ctx_inside;
    struct sha3 ctx_outside;
    struct sha3 ctx_inside_reinit;
    struct sha3 ctx_outside_reinit;
    u8 block_ipad[SHA3_512_BLOCK_SIZE];
    u8 block_opad[SHA3_512_BLOCK_SIZE];
} hmac_sha3_512_ctx;

/* HMAC-SHA3-224 functions */

static void
hmac_sha3_224_init(hmac_sha3_224_ctx *ctx, const u8 *key, unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const u8 *key_used;
    u8 key_temp[SHA3_224_DIGEST_SIZE];
    int i;

    if (key_size == SHA3_224_BLOCK_SIZE) {
        key_used = key;
        num = SHA3_224_BLOCK_SIZE;
    } else {
        if (key_size > SHA3_224_BLOCK_SIZE){
            struct sha3 tmp;
            num = SHA3_224_DIGEST_SIZE;
            arch_sha3_init(&tmp, SHA3_224_DIGEST_SIZE);
            arch_sha3_256_update(&tmp, key, key_size);
            arch_sha3_256_final(&tmp, key_temp);
            key_used = key_temp;
        } else {
            key_used = key;
            num = key_size;
        }
        fill = SHA3_224_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    arch_sha3_init(&ctx->ctx_inside, SHA3_224_DIGEST_SIZE);
    arch_sha3_256_update(&ctx->ctx_inside, ctx->block_ipad, SHA3_224_BLOCK_SIZE);

    arch_sha3_init(&ctx->ctx_outside, SHA3_224_DIGEST_SIZE);
    arch_sha3_256_update(&ctx->ctx_outside, ctx->block_opad, SHA3_224_BLOCK_SIZE);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(struct sha3));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(struct sha3));
}

static void
hmac_sha3_224_reinit(hmac_sha3_224_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(struct sha3));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(struct sha3));
}

static void
hmac_sha3_224_update(hmac_sha3_224_ctx *ctx, const u8 *msg, unsigned int len)
{
    arch_sha3_256_update(&ctx->ctx_inside, msg, len);
}

static void
hmac_sha3_224_final(hmac_sha3_224_ctx *ctx, u8 *mac, unsigned int mac_size)
{
    u8 digest_inside[SHA3_224_DIGEST_SIZE];
    u8 mac_temp[SHA3_224_DIGEST_SIZE];

    arch_sha3_256_final(&ctx->ctx_inside, digest_inside);
    arch_sha3_256_update(&ctx->ctx_outside, digest_inside, SHA3_224_DIGEST_SIZE);
    arch_sha3_256_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

static void
hmac_sha3_224(const u8 *key, unsigned int key_size,
              const u8 *msg, unsigned int msg_len,
              u8 *mac, unsigned mac_size)
{
    hmac_sha3_224_ctx ctx;

    hmac_sha3_224_init(&ctx, key, key_size);
    hmac_sha3_224_update(&ctx, msg, msg_len);
    hmac_sha3_224_final(&ctx, mac, mac_size);
}

/* HMAC-SHA3-256 functions */

static void
hmac_sha3_256_init(hmac_sha3_256_ctx *ctx, const u8 *key, unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const u8 *key_used;
    u8 key_temp[SHA3_256_DIGEST_SIZE];
    int i;

    if (key_size == SHA3_256_BLOCK_SIZE) {
        key_used = key;
        num = SHA3_256_BLOCK_SIZE;
    } else {
        if (key_size > SHA3_256_BLOCK_SIZE){
            struct sha3 tmp;
            num = SHA3_256_DIGEST_SIZE;
            arch_sha3_init(&tmp, SHA3_256_DIGEST_SIZE);
            arch_sha3_256_update(&tmp, key, key_size);
            arch_sha3_256_final(&tmp, key_temp);
            key_used = key_temp;
        } else {
            key_used = key;
            num = key_size;
        }
        fill = SHA3_256_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    arch_sha3_init(&ctx->ctx_inside, SHA3_256_DIGEST_SIZE);
    arch_sha3_256_update(&ctx->ctx_inside, ctx->block_ipad, SHA3_256_BLOCK_SIZE);

    arch_sha3_init(&ctx->ctx_outside, SHA3_256_DIGEST_SIZE);
    arch_sha3_256_update(&ctx->ctx_outside, ctx->block_opad, SHA3_256_BLOCK_SIZE);

    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(struct sha3));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(struct sha3));
}

static void
hmac_sha3_256_reinit(hmac_sha3_256_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(struct sha3));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(struct sha3));
}

static void
hmac_sha3_256_update(hmac_sha3_256_ctx *ctx, const u8 *msg, unsigned int len)
{
    arch_sha3_256_update(&ctx->ctx_inside, msg, len);
}

static void
hmac_sha3_256_final(hmac_sha3_256_ctx *ctx, u8 *mac, unsigned int mac_size)
{
    u8 digest_inside[SHA3_256_DIGEST_SIZE];
    u8 mac_temp[SHA3_256_DIGEST_SIZE];

    arch_sha3_256_final(&ctx->ctx_inside, digest_inside);
    arch_sha3_256_update(&ctx->ctx_outside, digest_inside, SHA3_256_DIGEST_SIZE);
    arch_sha3_256_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

static void
hmac_sha3_256(const u8 *key, unsigned int key_size,
              const u8 *msg, unsigned int msg_len,
              u8 *mac, unsigned mac_size)
{
    hmac_sha3_256_ctx ctx;

    hmac_sha3_256_init(&ctx, key, key_size);
    hmac_sha3_256_update(&ctx, msg, msg_len);
    hmac_sha3_256_final(&ctx, mac, mac_size);
}

/* HMAC-SHA3-384 functions */

static void
hmac_sha3_384_init(hmac_sha3_384_ctx *ctx, const u8 *key, unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const u8 *key_used;
    u8 key_temp[SHA3_384_DIGEST_SIZE];
    int i;

    if (key_size == SHA3_384_BLOCK_SIZE) {
        key_used = key;
        num = SHA3_384_BLOCK_SIZE;
    } else {
        if (key_size > SHA3_384_BLOCK_SIZE){
            struct sha3 tmp;
            num = SHA3_384_DIGEST_SIZE;
            arch_sha3_init(&tmp, SHA3_384_DIGEST_SIZE);
            arch_sha3_256_update(&tmp, key, key_size);
            arch_sha3_256_final(&tmp, key_temp);
            key_used = key_temp;
        } else {
            key_used = key;
            num = key_size;
        }
        fill = SHA3_384_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    arch_sha3_init(&ctx->ctx_inside, SHA3_384_DIGEST_SIZE);
    arch_sha3_256_update(&ctx->ctx_inside, ctx->block_ipad, SHA3_384_BLOCK_SIZE);

    arch_sha3_init(&ctx->ctx_outside, SHA3_384_DIGEST_SIZE);
    arch_sha3_256_update(&ctx->ctx_outside, ctx->block_opad, SHA3_384_BLOCK_SIZE);

    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(struct sha3));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(struct sha3));
}

static void
hmac_sha3_384_reinit(hmac_sha3_384_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(struct sha3));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(struct sha3));
}

static void
hmac_sha3_384_update(hmac_sha3_384_ctx *ctx, const u8 *msg, unsigned int len)
{
    arch_sha3_256_update(&ctx->ctx_inside, msg, len);
}

static void
hmac_sha3_384_final(hmac_sha3_384_ctx *ctx, u8 *mac, unsigned int mac_size)
{
    u8 digest_inside[SHA3_384_DIGEST_SIZE];
    u8 mac_temp[SHA3_384_DIGEST_SIZE];

    arch_sha3_256_final(&ctx->ctx_inside, digest_inside);
    arch_sha3_256_update(&ctx->ctx_outside, digest_inside, SHA3_384_DIGEST_SIZE);
    arch_sha3_256_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

static void
hmac_sha3_384(const u8 *key, unsigned int key_size,
              const u8 *msg, unsigned int msg_len,
              u8 *mac, unsigned mac_size)
{
    hmac_sha3_384_ctx ctx;

    hmac_sha3_384_init(&ctx, key, key_size);
    hmac_sha3_384_update(&ctx, msg, msg_len);
    hmac_sha3_384_final(&ctx, mac, mac_size);
}

/* HMAC-SHA3-512 functions */

static void
hmac_sha3_512_init(hmac_sha3_512_ctx *ctx, const u8 *key, unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const u8 *key_used;
    u8 key_temp[SHA3_512_DIGEST_SIZE];
    int i;

    if (key_size == SHA3_512_BLOCK_SIZE) {
        key_used = key;
        num = SHA3_512_BLOCK_SIZE;
    } else {
        if (key_size > SHA3_512_BLOCK_SIZE){
            struct sha3 tmp;
            num = SHA3_512_DIGEST_SIZE;
            arch_sha3_init(&tmp, SHA3_512_DIGEST_SIZE);
            arch_sha3_256_update(&tmp, key, key_size);
            arch_sha3_256_final(&tmp, key_temp);
            key_used = key_temp;
        } else {
            key_used = key;
            num = key_size;
        }
        fill = SHA3_512_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    arch_sha3_init(&ctx->ctx_inside, SHA3_512_DIGEST_SIZE);
    arch_sha3_256_update(&ctx->ctx_inside, ctx->block_ipad, SHA3_512_BLOCK_SIZE);

    arch_sha3_init(&ctx->ctx_outside, SHA3_512_DIGEST_SIZE);
    arch_sha3_256_update(&ctx->ctx_outside, ctx->block_opad, SHA3_512_BLOCK_SIZE);

    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(struct sha3));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(struct sha3));
}

static void
hmac_sha3_512_reinit(hmac_sha3_512_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(struct sha3));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(struct sha3));
}

static void
hmac_sha3_512_update(hmac_sha3_512_ctx *ctx, const u8 *msg, unsigned int len)
{
    arch_sha3_256_update(&ctx->ctx_inside, msg, len);
}

static void
hmac_sha3_512_final(hmac_sha3_512_ctx *ctx, u8 *mac, unsigned int mac_size)
{
    u8 digest_inside[SHA3_512_DIGEST_SIZE];
    u8 mac_temp[SHA3_512_DIGEST_SIZE];

    arch_sha3_256_final(&ctx->ctx_inside, digest_inside);
    arch_sha3_256_update(&ctx->ctx_outside, digest_inside, SHA3_512_DIGEST_SIZE);
    arch_sha3_256_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

static void
hmac_sha3_512(const u8 *key, unsigned int key_size,
              const u8 *msg, unsigned int msg_len,
              u8 *mac, unsigned mac_size)
{
    hmac_sha3_512_ctx ctx;

    hmac_sha3_512_init(&ctx, key, key_size);
    hmac_sha3_512_update(&ctx, msg, msg_len);
    hmac_sha3_512_final(&ctx, mac, mac_size);
}
