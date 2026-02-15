/*
 * HKDF-SM3 (RFC 5869 over GB/T 32905)
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
 * The key derivation of the ShangMi TLS 1.3 suites (RFC 8998 sec 3): the
 * Extract and Expand of RFC 5869 with HMAC-SM3 as the PRF. The same file as
 * ../sha2/sha2.c's SHA-256 third, over the other 256-bit hash.
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>

#ifndef HKDF_SM3_SCOPE
#define HKDF_SM3_SCOPE
#endif

/* HMAC-SM3 oneshot */

static inline void
hmac_sm3_oneshot(const u8 *key, unsigned int key_len,
                 const u8 *data, unsigned int data_len, u8 *out)
{
	struct sm3 ctx;
	u8 k[SM3_BLOCK_SIZE];
	u8 inner[SM3_DIGEST_SIZE];
	unsigned int i;

	memset(k, 0, SM3_BLOCK_SIZE);

	if (key_len > SM3_BLOCK_SIZE) {
		arch_sm3_init(&ctx);
		arch_sm3_update(&ctx, key, key_len);
		arch_sm3_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SM3_BLOCK_SIZE; i++)
		k[i] ^= 0x36;

	arch_sm3_init(&ctx);
	arch_sm3_update(&ctx, k, SM3_BLOCK_SIZE);
	arch_sm3_update(&ctx, data, data_len);
	arch_sm3_final(&ctx, inner);

	for (i = 0; i < SM3_BLOCK_SIZE; i++)
		k[i] ^= 0x36 ^ 0x5c;

	arch_sm3_init(&ctx);
	arch_sm3_update(&ctx, k, SM3_BLOCK_SIZE);
	arch_sm3_update(&ctx, inner, SM3_DIGEST_SIZE);
	arch_sm3_final(&ctx, out);
}

HKDF_SM3_SCOPE void
hkdf_sm3_extract(u8 *prk, unsigned int prk_len,
                 const u8 *salt, unsigned int salt_len,
                 const u8 *ikm, unsigned int ikm_len)
{
	u8 null_salt[SM3_DIGEST_SIZE];

	if (salt == NULL || salt_len == 0) {
		memset(null_salt, 0, SM3_DIGEST_SIZE);
		salt = null_salt;
		salt_len = SM3_DIGEST_SIZE;
	}

	hmac_sm3_oneshot(salt, salt_len, ikm, ikm_len, prk);
	(void)prk_len;
}

HKDF_SM3_SCOPE int
hkdf_sm3_expand(u8 *okm, unsigned int okm_len,
                const u8 *prk, unsigned int prk_len,
                const u8 *info, unsigned int info_len)
{
	unsigned int n = (okm_len + SM3_DIGEST_SIZE - 1) / SM3_DIGEST_SIZE;
	u8 t[SM3_DIGEST_SIZE];
	struct sm3 ctx;
	u8 k[SM3_BLOCK_SIZE];
	unsigned int i, j, done = 0, todo;

	if (n > 255)
		return -1;

	for (i = 1; i <= n; i++) {
		u8 c = (u8)i;
		u8 inner[SM3_DIGEST_SIZE];

		memset(k, 0, SM3_BLOCK_SIZE);
		if (prk_len > SM3_BLOCK_SIZE) {
			arch_sm3_init(&ctx);
			arch_sm3_update(&ctx, prk, prk_len);
			arch_sm3_final(&ctx, k);
		} else {
			memcpy(k, prk, prk_len);
		}

		for (j = 0; j < SM3_BLOCK_SIZE; j++)
			k[j] ^= 0x36;

		arch_sm3_init(&ctx);
		arch_sm3_update(&ctx, k, SM3_BLOCK_SIZE);
		if (i > 1)
			arch_sm3_update(&ctx, t, SM3_DIGEST_SIZE);
		if (info != NULL && info_len > 0)
			arch_sm3_update(&ctx, info, info_len);
		arch_sm3_update(&ctx, &c, 1);
		arch_sm3_final(&ctx, inner);

		for (j = 0; j < SM3_BLOCK_SIZE; j++)
			k[j] ^= 0x36 ^ 0x5c;

		arch_sm3_init(&ctx);
		arch_sm3_update(&ctx, k, SM3_BLOCK_SIZE);
		arch_sm3_update(&ctx, inner, SM3_DIGEST_SIZE);
		arch_sm3_final(&ctx, t);

		todo = okm_len - done;
		if (todo > SM3_DIGEST_SIZE)
			todo = SM3_DIGEST_SIZE;
		memcpy(okm + done, t, todo);
		done += todo;
	}

	return 0;
}

HKDF_SM3_SCOPE int
hkdf_sm3(u8 *okm, unsigned int okm_len,
         const u8 *ikm, unsigned int ikm_len,
         const u8 *salt, unsigned int salt_len,
         const u8 *info, unsigned int info_len)
{
	u8 prk[SM3_DIGEST_SIZE];

	hkdf_sm3_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
	return hkdf_sm3_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}
