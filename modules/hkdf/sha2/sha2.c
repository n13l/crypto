/*
 * HKDF-SHA-224/256/384/512 implementation (RFC 5869)
 *
 * Copyright (C) 2005 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>

/* HMAC-SHA-224 oneshot */

static inline void
hmac_sha224_oneshot(const u8 *key, unsigned int key_len,
                   const u8 *data, unsigned int data_len, u8 *out)
{
    struct sha256 ctx;
    u8 k[SHA224_BLOCK_SIZE];
    u8 inner[SHA224_DIGEST_SIZE];
    unsigned int i;

    memset(k, 0, SHA224_BLOCK_SIZE);

    if (key_len > SHA224_BLOCK_SIZE) {
        arch_sha2_224_init(&ctx);
        arch_sha2_224_update(&ctx, key, key_len);
        arch_sha2_224_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < SHA224_BLOCK_SIZE; i++)
        k[i] ^= 0x36;

    arch_sha2_224_init(&ctx);
    arch_sha2_224_update(&ctx, k, SHA224_BLOCK_SIZE);
    arch_sha2_224_update(&ctx, data, data_len);
    arch_sha2_224_final(&ctx, inner);

    for (i = 0; i < SHA224_BLOCK_SIZE; i++)
        k[i] ^= 0x36 ^ 0x5c;

    arch_sha2_224_init(&ctx);
    arch_sha2_224_update(&ctx, k, SHA224_BLOCK_SIZE);
    arch_sha2_224_update(&ctx, inner, SHA224_DIGEST_SIZE);
    arch_sha2_224_final(&ctx, out);
}

/* HKDF-SHA-224 */

static void
hkdf_sha224_extract(u8 *prk, unsigned int prk_len,
                    const u8 *salt, unsigned int salt_len,
                    const u8 *ikm, unsigned int ikm_len)
{
    u8 null_salt[SHA224_DIGEST_SIZE];

    if (salt == NULL || salt_len == 0) {
        memset(null_salt, 0, SHA224_DIGEST_SIZE);
        salt = null_salt;
        salt_len = SHA224_DIGEST_SIZE;
    }

    hmac_sha224_oneshot(salt, salt_len, ikm, ikm_len, prk);
    (void)prk_len;
}

static int
hkdf_sha224_expand(u8 *okm, unsigned int okm_len,
                   const u8 *prk, unsigned int prk_len,
                   const u8 *info, unsigned int info_len)
{
    unsigned int n = (okm_len + SHA224_DIGEST_SIZE - 1) / SHA224_DIGEST_SIZE;
    u8 t[SHA224_DIGEST_SIZE];
    struct sha256 ctx;
    u8 k[SHA224_BLOCK_SIZE];
    unsigned int i, j, done = 0, todo;

    if (n > 255)
        return -1;

    for (i = 1; i <= n; i++) {
        u8 c = (u8)i;

        memset(k, 0, SHA224_BLOCK_SIZE);
        if (prk_len > SHA224_BLOCK_SIZE) {
            arch_sha2_224_init(&ctx);
            arch_sha2_224_update(&ctx, prk, prk_len);
            arch_sha2_224_final(&ctx, k);
        } else {
            memcpy(k, prk, prk_len);
        }

        for (j = 0; j < SHA224_BLOCK_SIZE; j++)
            k[j] ^= 0x36;

        arch_sha2_224_init(&ctx);
        arch_sha2_224_update(&ctx, k, SHA224_BLOCK_SIZE);
        if (i > 1)
            arch_sha2_224_update(&ctx, t, SHA224_DIGEST_SIZE);
        if (info != NULL && info_len > 0)
            arch_sha2_224_update(&ctx, info, info_len);
        arch_sha2_224_update(&ctx, &c, 1);
        arch_sha2_224_final(&ctx, t);

        u8 inner[SHA224_DIGEST_SIZE];
        memcpy(inner, t, SHA224_DIGEST_SIZE);

        for (j = 0; j < SHA224_BLOCK_SIZE; j++)
            k[j] ^= 0x36 ^ 0x5c;

        arch_sha2_224_init(&ctx);
        arch_sha2_224_update(&ctx, k, SHA224_BLOCK_SIZE);
        arch_sha2_224_update(&ctx, inner, SHA224_DIGEST_SIZE);
        arch_sha2_224_final(&ctx, t);

        todo = okm_len - done;
        if (todo > SHA224_DIGEST_SIZE)
            todo = SHA224_DIGEST_SIZE;
        memcpy(okm + done, t, todo);
        done += todo;
    }

    return 0;
}

static void
hkdf_sha224(u8 *okm, unsigned int okm_len,
            const u8 *ikm, unsigned int ikm_len,
            const u8 *salt, unsigned int salt_len,
            const u8 *info, unsigned int info_len)
{
    u8 prk[SHA224_DIGEST_SIZE];

    hkdf_sha224_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
    hkdf_sha224_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}

/* HMAC-SHA-256 oneshot */

static inline void
hmac_sha256_oneshot(const u8 *key, unsigned int key_len,
                   const u8 *data, unsigned int data_len, u8 *out)
{
    struct sha256 ctx;
    u8 k[SHA256_BLOCK_SIZE];
    u8 inner[SHA256_DIGEST_SIZE];
    unsigned int i;

    memset(k, 0, SHA256_BLOCK_SIZE);

    if (key_len > SHA256_BLOCK_SIZE) {
        arch_sha2_256_init(&ctx);
        arch_sha2_256_update(&ctx, key, key_len);
        arch_sha2_256_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        k[i] ^= 0x36;

    arch_sha2_256_init(&ctx);
    arch_sha2_256_update(&ctx, k, SHA256_BLOCK_SIZE);
    arch_sha2_256_update(&ctx, data, data_len);
    arch_sha2_256_final(&ctx, inner);

    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        k[i] ^= 0x36 ^ 0x5c;

    arch_sha2_256_init(&ctx);
    arch_sha2_256_update(&ctx, k, SHA256_BLOCK_SIZE);
    arch_sha2_256_update(&ctx, inner, SHA256_DIGEST_SIZE);
    arch_sha2_256_final(&ctx, out);
}

/* HKDF-SHA-256 */

static void
hkdf_sha256_extract(u8 *prk, unsigned int prk_len,
                    const u8 *salt, unsigned int salt_len,
                    const u8 *ikm, unsigned int ikm_len)
{
    u8 null_salt[SHA256_DIGEST_SIZE];

    if (salt == NULL || salt_len == 0) {
        memset(null_salt, 0, SHA256_DIGEST_SIZE);
        salt = null_salt;
        salt_len = SHA256_DIGEST_SIZE;
    }

    hmac_sha256_oneshot(salt, salt_len, ikm, ikm_len, prk);
    (void)prk_len;
}

static int
hkdf_sha256_expand(u8 *okm, unsigned int okm_len,
                   const u8 *prk, unsigned int prk_len,
                   const u8 *info, unsigned int info_len)
{
    unsigned int n = (okm_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    u8 t[SHA256_DIGEST_SIZE];
    struct sha256 ctx;
    u8 k[SHA256_BLOCK_SIZE];
    unsigned int i, j, done = 0, todo;

    if (n > 255)
        return -1;

    for (i = 1; i <= n; i++) {
        u8 c = (u8)i;

        memset(k, 0, SHA256_BLOCK_SIZE);
        if (prk_len > SHA256_BLOCK_SIZE) {
            arch_sha2_256_init(&ctx);
            arch_sha2_256_update(&ctx, prk, prk_len);
            arch_sha2_256_final(&ctx, k);
        } else {
            memcpy(k, prk, prk_len);
        }

        for (j = 0; j < SHA256_BLOCK_SIZE; j++)
            k[j] ^= 0x36;

        arch_sha2_256_init(&ctx);
        arch_sha2_256_update(&ctx, k, SHA256_BLOCK_SIZE);
        if (i > 1)
            arch_sha2_256_update(&ctx, t, SHA256_DIGEST_SIZE);
        if (info != NULL && info_len > 0)
            arch_sha2_256_update(&ctx, info, info_len);
        arch_sha2_256_update(&ctx, &c, 1);
        arch_sha2_256_final(&ctx, t);

        u8 inner[SHA256_DIGEST_SIZE];
        memcpy(inner, t, SHA256_DIGEST_SIZE);

        for (j = 0; j < SHA256_BLOCK_SIZE; j++)
            k[j] ^= 0x36 ^ 0x5c;

        arch_sha2_256_init(&ctx);
        arch_sha2_256_update(&ctx, k, SHA256_BLOCK_SIZE);
        arch_sha2_256_update(&ctx, inner, SHA256_DIGEST_SIZE);
        arch_sha2_256_final(&ctx, t);

        todo = okm_len - done;
        if (todo > SHA256_DIGEST_SIZE)
            todo = SHA256_DIGEST_SIZE;
        memcpy(okm + done, t, todo);
        done += todo;
    }

    return 0;
}

static void
hkdf_sha256(u8 *okm, unsigned int okm_len,
            const u8 *ikm, unsigned int ikm_len,
            const u8 *salt, unsigned int salt_len,
            const u8 *info, unsigned int info_len)
{
    u8 prk[SHA256_DIGEST_SIZE];

    hkdf_sha256_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
    hkdf_sha256_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}

/* HMAC-SHA-384 oneshot */

static inline void
hmac_sha384_oneshot(const u8 *key, unsigned int key_len,
                   const u8 *data, unsigned int data_len, u8 *out)
{
    struct sha512 ctx;
    u8 k[SHA384_BLOCK_SIZE];
    u8 inner[SHA384_DIGEST_SIZE];
    unsigned int i;

    memset(k, 0, SHA384_BLOCK_SIZE);

    if (key_len > SHA384_BLOCK_SIZE) {
        arch_sha2_384_init(&ctx);
        arch_sha2_384_update(&ctx, key, key_len);
        arch_sha2_384_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < SHA384_BLOCK_SIZE; i++)
        k[i] ^= 0x36;

    arch_sha2_384_init(&ctx);
    arch_sha2_384_update(&ctx, k, SHA384_BLOCK_SIZE);
    arch_sha2_384_update(&ctx, data, data_len);
    arch_sha2_384_final(&ctx, inner);

    for (i = 0; i < SHA384_BLOCK_SIZE; i++)
        k[i] ^= 0x36 ^ 0x5c;

    arch_sha2_384_init(&ctx);
    arch_sha2_384_update(&ctx, k, SHA384_BLOCK_SIZE);
    arch_sha2_384_update(&ctx, inner, SHA384_DIGEST_SIZE);
    arch_sha2_384_final(&ctx, out);
}

/* HKDF-SHA-384 */

static void
hkdf_sha384_extract(u8 *prk, unsigned int prk_len,
                    const u8 *salt, unsigned int salt_len,
                    const u8 *ikm, unsigned int ikm_len)
{
    u8 null_salt[SHA384_DIGEST_SIZE];

    if (salt == NULL || salt_len == 0) {
        memset(null_salt, 0, SHA384_DIGEST_SIZE);
        salt = null_salt;
        salt_len = SHA384_DIGEST_SIZE;
    }

    hmac_sha384_oneshot(salt, salt_len, ikm, ikm_len, prk);
    (void)prk_len;
}

static int
hkdf_sha384_expand(u8 *okm, unsigned int okm_len,
                   const u8 *prk, unsigned int prk_len,
                   const u8 *info, unsigned int info_len)
{
    unsigned int n = (okm_len + SHA384_DIGEST_SIZE - 1) / SHA384_DIGEST_SIZE;
    u8 t[SHA384_DIGEST_SIZE];
    struct sha512 ctx;
    u8 k[SHA384_BLOCK_SIZE];
    unsigned int i, j, done = 0, todo;

    if (n > 255)
        return -1;

    for (i = 1; i <= n; i++) {
        u8 c = (u8)i;

        memset(k, 0, SHA384_BLOCK_SIZE);
        if (prk_len > SHA384_BLOCK_SIZE) {
            arch_sha2_384_init(&ctx);
            arch_sha2_384_update(&ctx, prk, prk_len);
            arch_sha2_384_final(&ctx, k);
        } else {
            memcpy(k, prk, prk_len);
        }

        for (j = 0; j < SHA384_BLOCK_SIZE; j++)
            k[j] ^= 0x36;

        arch_sha2_384_init(&ctx);
        arch_sha2_384_update(&ctx, k, SHA384_BLOCK_SIZE);
        if (i > 1)
            arch_sha2_384_update(&ctx, t, SHA384_DIGEST_SIZE);
        if (info != NULL && info_len > 0)
            arch_sha2_384_update(&ctx, info, info_len);
        arch_sha2_384_update(&ctx, &c, 1);
        arch_sha2_384_final(&ctx, t);

        u8 inner[SHA384_DIGEST_SIZE];
        memcpy(inner, t, SHA384_DIGEST_SIZE);

        for (j = 0; j < SHA384_BLOCK_SIZE; j++)
            k[j] ^= 0x36 ^ 0x5c;

        arch_sha2_384_init(&ctx);
        arch_sha2_384_update(&ctx, k, SHA384_BLOCK_SIZE);
        arch_sha2_384_update(&ctx, inner, SHA384_DIGEST_SIZE);
        arch_sha2_384_final(&ctx, t);

        todo = okm_len - done;
        if (todo > SHA384_DIGEST_SIZE)
            todo = SHA384_DIGEST_SIZE;
        memcpy(okm + done, t, todo);
        done += todo;
    }

    return 0;
}

static void
hkdf_sha384(u8 *okm, unsigned int okm_len,
            const u8 *ikm, unsigned int ikm_len,
            const u8 *salt, unsigned int salt_len,
            const u8 *info, unsigned int info_len)
{
    u8 prk[SHA384_DIGEST_SIZE];

    hkdf_sha384_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
    hkdf_sha384_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}

/* HMAC-SHA-512 oneshot */

static inline void
hmac_sha512_oneshot(const u8 *key, unsigned int key_len,
                   const u8 *data, unsigned int data_len, u8 *out)
{
    struct sha512 ctx;
    u8 k[SHA512_BLOCK_SIZE];
    u8 inner[SHA512_DIGEST_SIZE];
    unsigned int i;

    memset(k, 0, SHA512_BLOCK_SIZE);

    if (key_len > SHA512_BLOCK_SIZE) {
        arch_sha2_512_init(&ctx);
        arch_sha2_512_update(&ctx, key, key_len);
        arch_sha2_512_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < SHA512_BLOCK_SIZE; i++)
        k[i] ^= 0x36;

    arch_sha2_512_init(&ctx);
    arch_sha2_512_update(&ctx, k, SHA512_BLOCK_SIZE);
    arch_sha2_512_update(&ctx, data, data_len);
    arch_sha2_512_final(&ctx, inner);

    for (i = 0; i < SHA512_BLOCK_SIZE; i++)
        k[i] ^= 0x36 ^ 0x5c;

    arch_sha2_512_init(&ctx);
    arch_sha2_512_update(&ctx, k, SHA512_BLOCK_SIZE);
    arch_sha2_512_update(&ctx, inner, SHA512_DIGEST_SIZE);
    arch_sha2_512_final(&ctx, out);
}

/* HKDF-SHA-512 */

static void
hkdf_sha512_extract(u8 *prk, unsigned int prk_len,
                    const u8 *salt, unsigned int salt_len,
                    const u8 *ikm, unsigned int ikm_len)
{
    u8 null_salt[SHA512_DIGEST_SIZE];

    if (salt == NULL || salt_len == 0) {
        memset(null_salt, 0, SHA512_DIGEST_SIZE);
        salt = null_salt;
        salt_len = SHA512_DIGEST_SIZE;
    }

    hmac_sha512_oneshot(salt, salt_len, ikm, ikm_len, prk);
    (void)prk_len;
}

static int
hkdf_sha512_expand(u8 *okm, unsigned int okm_len,
                   const u8 *prk, unsigned int prk_len,
                   const u8 *info, unsigned int info_len)
{
    unsigned int n = (okm_len + SHA512_DIGEST_SIZE - 1) / SHA512_DIGEST_SIZE;
    u8 t[SHA512_DIGEST_SIZE];
    struct sha512 ctx;
    u8 k[SHA512_BLOCK_SIZE];
    unsigned int i, j, done = 0, todo;

    if (n > 255)
        return -1;

    for (i = 1; i <= n; i++) {
        u8 c = (u8)i;

        memset(k, 0, SHA512_BLOCK_SIZE);
        if (prk_len > SHA512_BLOCK_SIZE) {
            arch_sha2_512_init(&ctx);
            arch_sha2_512_update(&ctx, prk, prk_len);
            arch_sha2_512_final(&ctx, k);
        } else {
            memcpy(k, prk, prk_len);
        }

        for (j = 0; j < SHA512_BLOCK_SIZE; j++)
            k[j] ^= 0x36;

        arch_sha2_512_init(&ctx);
        arch_sha2_512_update(&ctx, k, SHA512_BLOCK_SIZE);
        if (i > 1)
            arch_sha2_512_update(&ctx, t, SHA512_DIGEST_SIZE);
        if (info != NULL && info_len > 0)
            arch_sha2_512_update(&ctx, info, info_len);
        arch_sha2_512_update(&ctx, &c, 1);
        arch_sha2_512_final(&ctx, t);

        u8 inner[SHA512_DIGEST_SIZE];
        memcpy(inner, t, SHA512_DIGEST_SIZE);

        for (j = 0; j < SHA512_BLOCK_SIZE; j++)
            k[j] ^= 0x36 ^ 0x5c;

        arch_sha2_512_init(&ctx);
        arch_sha2_512_update(&ctx, k, SHA512_BLOCK_SIZE);
        arch_sha2_512_update(&ctx, inner, SHA512_DIGEST_SIZE);
        arch_sha2_512_final(&ctx, t);

        todo = okm_len - done;
        if (todo > SHA512_DIGEST_SIZE)
            todo = SHA512_DIGEST_SIZE;
        memcpy(okm + done, t, todo);
        done += todo;
    }

    return 0;
}

static void
hkdf_sha512(u8 *okm, unsigned int okm_len,
            const u8 *ikm, unsigned int ikm_len,
            const u8 *salt, unsigned int salt_len,
            const u8 *info, unsigned int info_len)
{
    u8 prk[SHA512_DIGEST_SIZE];

    hkdf_sha512_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
    hkdf_sha512_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}
