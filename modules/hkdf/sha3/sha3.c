/*
 * HKDF-SHA-3-224/256/384/512 implementation (RFC 5869)
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

/* HMAC-SHA3-224 oneshot */

static void
hmac_sha3_224_oneshot(const u8 *key, unsigned int key_len,
                      const u8 *data, unsigned int data_len, u8 *out)
{
	struct sha3 ctx;
	u8 k[SHA3_224_BLOCK_SIZE];
	u8 ipad[SHA3_224_BLOCK_SIZE];
	u8 opad[SHA3_224_BLOCK_SIZE];
	u8 inner[SHA3_224_DIGEST_SIZE];
	int i;

	memset(k, 0, SHA3_224_BLOCK_SIZE);

	if (key_len > SHA3_224_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, key, key_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA3_224_BLOCK_SIZE; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}

	arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, ipad, SHA3_224_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, data, data_len);
	arch_sha3_256_final(&ctx, inner);

	arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, opad, SHA3_224_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, inner, SHA3_224_DIGEST_SIZE);
	arch_sha3_256_final(&ctx, out);
}

/* HKDF-SHA3-224 */

static void
hkdf_sha3_224_extract(u8 *prk, unsigned int prk_len,
                      const u8 *salt, unsigned int salt_len,
                      const u8 *ikm, unsigned int ikm_len)
{
	u8 null_salt[SHA3_224_DIGEST_SIZE];

	if (!salt || salt_len == 0) {
		memset(null_salt, 0, SHA3_224_DIGEST_SIZE);
		salt = null_salt;
		salt_len = SHA3_224_DIGEST_SIZE;
	}

	hmac_sha3_224_oneshot(salt, salt_len, ikm, ikm_len, prk);
}

static int
hkdf_sha3_224_expand(u8 *okm, unsigned int okm_len,
                     const u8 *prk, unsigned int prk_len,
                     const u8 *info, unsigned int info_len)
{
	unsigned int n;
	unsigned int i;
	unsigned int done;
	unsigned int todo;
	u8 prev[SHA3_224_DIGEST_SIZE];
	u8 hmac_out[SHA3_224_DIGEST_SIZE];
	struct sha3 ctx;
	u8 k[SHA3_224_BLOCK_SIZE];
	u8 ipad[SHA3_224_BLOCK_SIZE];
	u8 opad[SHA3_224_BLOCK_SIZE];
	u8 inner[SHA3_224_DIGEST_SIZE];
	int j;
	u8 ctr;

	n = (okm_len + SHA3_224_DIGEST_SIZE - 1) / SHA3_224_DIGEST_SIZE;
	if (n > 255)
		return -1;

	memset(k, 0, SHA3_224_BLOCK_SIZE);
	if (prk_len > SHA3_224_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, prk, prk_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, prk, prk_len);
	}

	for (j = 0; j < SHA3_224_BLOCK_SIZE; j++) {
		ipad[j] = k[j] ^ 0x36;
		opad[j] = k[j] ^ 0x5c;
	}

	done = 0;
	for (i = 1; i <= n; i++) {
		ctr = (u8)i;

		arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, ipad, SHA3_224_BLOCK_SIZE);
		if (i > 1)
			arch_sha3_256_update(&ctx, prev, SHA3_224_DIGEST_SIZE);
		if (info && info_len > 0)
			arch_sha3_256_update(&ctx, info, info_len);
		arch_sha3_256_update(&ctx, &ctr, 1);
		arch_sha3_256_final(&ctx, inner);

		arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, opad, SHA3_224_BLOCK_SIZE);
		arch_sha3_256_update(&ctx, inner, SHA3_224_DIGEST_SIZE);
		arch_sha3_256_final(&ctx, hmac_out);

		memcpy(prev, hmac_out, SHA3_224_DIGEST_SIZE);

		todo = (okm_len - done < SHA3_224_DIGEST_SIZE) ?
		       okm_len - done : SHA3_224_DIGEST_SIZE;
		memcpy(okm + done, hmac_out, todo);
		done += todo;
	}

	return 0;
}

static void
hkdf_sha3_224(u8 *okm, unsigned int okm_len,
              const u8 *ikm, unsigned int ikm_len,
              const u8 *salt, unsigned int salt_len,
              const u8 *info, unsigned int info_len)
{
	u8 prk[SHA3_224_DIGEST_SIZE];

	hkdf_sha3_224_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
	hkdf_sha3_224_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}

/* HMAC-SHA3-256 oneshot */

static void
hmac_sha3_256_oneshot(const u8 *key, unsigned int key_len,
                      const u8 *data, unsigned int data_len, u8 *out)
{
	struct sha3 ctx;
	u8 k[SHA3_256_BLOCK_SIZE];
	u8 ipad[SHA3_256_BLOCK_SIZE];
	u8 opad[SHA3_256_BLOCK_SIZE];
	u8 inner[SHA3_256_DIGEST_SIZE];
	int i;

	memset(k, 0, SHA3_256_BLOCK_SIZE);

	if (key_len > SHA3_256_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, key, key_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA3_256_BLOCK_SIZE; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}

	arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, ipad, SHA3_256_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, data, data_len);
	arch_sha3_256_final(&ctx, inner);

	arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, opad, SHA3_256_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, inner, SHA3_256_DIGEST_SIZE);
	arch_sha3_256_final(&ctx, out);
}

/* HKDF-SHA3-256 */

static void
hkdf_sha3_256_extract(u8 *prk, unsigned int prk_len,
                      const u8 *salt, unsigned int salt_len,
                      const u8 *ikm, unsigned int ikm_len)
{
	u8 null_salt[SHA3_256_DIGEST_SIZE];

	if (!salt || salt_len == 0) {
		memset(null_salt, 0, SHA3_256_DIGEST_SIZE);
		salt = null_salt;
		salt_len = SHA3_256_DIGEST_SIZE;
	}

	hmac_sha3_256_oneshot(salt, salt_len, ikm, ikm_len, prk);
}

static int
hkdf_sha3_256_expand(u8 *okm, unsigned int okm_len,
                     const u8 *prk, unsigned int prk_len,
                     const u8 *info, unsigned int info_len)
{
	unsigned int n;
	unsigned int i;
	unsigned int done;
	unsigned int todo;
	u8 prev[SHA3_256_DIGEST_SIZE];
	u8 hmac_out[SHA3_256_DIGEST_SIZE];
	struct sha3 ctx;
	u8 k[SHA3_256_BLOCK_SIZE];
	u8 ipad[SHA3_256_BLOCK_SIZE];
	u8 opad[SHA3_256_BLOCK_SIZE];
	u8 inner[SHA3_256_DIGEST_SIZE];
	int j;
	u8 ctr;

	n = (okm_len + SHA3_256_DIGEST_SIZE - 1) / SHA3_256_DIGEST_SIZE;
	if (n > 255)
		return -1;

	memset(k, 0, SHA3_256_BLOCK_SIZE);
	if (prk_len > SHA3_256_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, prk, prk_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, prk, prk_len);
	}

	for (j = 0; j < SHA3_256_BLOCK_SIZE; j++) {
		ipad[j] = k[j] ^ 0x36;
		opad[j] = k[j] ^ 0x5c;
	}

	done = 0;
	for (i = 1; i <= n; i++) {
		ctr = (u8)i;

		arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, ipad, SHA3_256_BLOCK_SIZE);
		if (i > 1)
			arch_sha3_256_update(&ctx, prev, SHA3_256_DIGEST_SIZE);
		if (info && info_len > 0)
			arch_sha3_256_update(&ctx, info, info_len);
		arch_sha3_256_update(&ctx, &ctr, 1);
		arch_sha3_256_final(&ctx, inner);

		arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, opad, SHA3_256_BLOCK_SIZE);
		arch_sha3_256_update(&ctx, inner, SHA3_256_DIGEST_SIZE);
		arch_sha3_256_final(&ctx, hmac_out);

		memcpy(prev, hmac_out, SHA3_256_DIGEST_SIZE);

		todo = (okm_len - done < SHA3_256_DIGEST_SIZE) ?
		       okm_len - done : SHA3_256_DIGEST_SIZE;
		memcpy(okm + done, hmac_out, todo);
		done += todo;
	}

	return 0;
}

static void
hkdf_sha3_256(u8 *okm, unsigned int okm_len,
              const u8 *ikm, unsigned int ikm_len,
              const u8 *salt, unsigned int salt_len,
              const u8 *info, unsigned int info_len)
{
	u8 prk[SHA3_256_DIGEST_SIZE];

	hkdf_sha3_256_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
	hkdf_sha3_256_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}

/* HMAC-SHA3-384 oneshot */

static void
hmac_sha3_384_oneshot(const u8 *key, unsigned int key_len,
                      const u8 *data, unsigned int data_len, u8 *out)
{
	struct sha3 ctx;
	u8 k[SHA3_384_BLOCK_SIZE];
	u8 ipad[SHA3_384_BLOCK_SIZE];
	u8 opad[SHA3_384_BLOCK_SIZE];
	u8 inner[SHA3_384_DIGEST_SIZE];
	int i;

	memset(k, 0, SHA3_384_BLOCK_SIZE);

	if (key_len > SHA3_384_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, key, key_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA3_384_BLOCK_SIZE; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}

	arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, ipad, SHA3_384_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, data, data_len);
	arch_sha3_256_final(&ctx, inner);

	arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, opad, SHA3_384_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, inner, SHA3_384_DIGEST_SIZE);
	arch_sha3_256_final(&ctx, out);
}

/* HKDF-SHA3-384 */

static void
hkdf_sha3_384_extract(u8 *prk, unsigned int prk_len,
                      const u8 *salt, unsigned int salt_len,
                      const u8 *ikm, unsigned int ikm_len)
{
	u8 null_salt[SHA3_384_DIGEST_SIZE];

	if (!salt || salt_len == 0) {
		memset(null_salt, 0, SHA3_384_DIGEST_SIZE);
		salt = null_salt;
		salt_len = SHA3_384_DIGEST_SIZE;
	}

	hmac_sha3_384_oneshot(salt, salt_len, ikm, ikm_len, prk);
}

static int
hkdf_sha3_384_expand(u8 *okm, unsigned int okm_len,
                     const u8 *prk, unsigned int prk_len,
                     const u8 *info, unsigned int info_len)
{
	unsigned int n;
	unsigned int i;
	unsigned int done;
	unsigned int todo;
	u8 prev[SHA3_384_DIGEST_SIZE];
	u8 hmac_out[SHA3_384_DIGEST_SIZE];
	struct sha3 ctx;
	u8 k[SHA3_384_BLOCK_SIZE];
	u8 ipad[SHA3_384_BLOCK_SIZE];
	u8 opad[SHA3_384_BLOCK_SIZE];
	u8 inner[SHA3_384_DIGEST_SIZE];
	int j;
	u8 ctr;

	n = (okm_len + SHA3_384_DIGEST_SIZE - 1) / SHA3_384_DIGEST_SIZE;
	if (n > 255)
		return -1;

	memset(k, 0, SHA3_384_BLOCK_SIZE);
	if (prk_len > SHA3_384_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, prk, prk_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, prk, prk_len);
	}

	for (j = 0; j < SHA3_384_BLOCK_SIZE; j++) {
		ipad[j] = k[j] ^ 0x36;
		opad[j] = k[j] ^ 0x5c;
	}

	done = 0;
	for (i = 1; i <= n; i++) {
		ctr = (u8)i;

		arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, ipad, SHA3_384_BLOCK_SIZE);
		if (i > 1)
			arch_sha3_256_update(&ctx, prev, SHA3_384_DIGEST_SIZE);
		if (info && info_len > 0)
			arch_sha3_256_update(&ctx, info, info_len);
		arch_sha3_256_update(&ctx, &ctr, 1);
		arch_sha3_256_final(&ctx, inner);

		arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, opad, SHA3_384_BLOCK_SIZE);
		arch_sha3_256_update(&ctx, inner, SHA3_384_DIGEST_SIZE);
		arch_sha3_256_final(&ctx, hmac_out);

		memcpy(prev, hmac_out, SHA3_384_DIGEST_SIZE);

		todo = (okm_len - done < SHA3_384_DIGEST_SIZE) ?
		       okm_len - done : SHA3_384_DIGEST_SIZE;
		memcpy(okm + done, hmac_out, todo);
		done += todo;
	}

	return 0;
}

static void
hkdf_sha3_384(u8 *okm, unsigned int okm_len,
              const u8 *ikm, unsigned int ikm_len,
              const u8 *salt, unsigned int salt_len,
              const u8 *info, unsigned int info_len)
{
	u8 prk[SHA3_384_DIGEST_SIZE];

	hkdf_sha3_384_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
	hkdf_sha3_384_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}

/* HMAC-SHA3-512 oneshot */

static void
hmac_sha3_512_oneshot(const u8 *key, unsigned int key_len,
                      const u8 *data, unsigned int data_len, u8 *out)
{
	struct sha3 ctx;
	u8 k[SHA3_512_BLOCK_SIZE];
	u8 ipad[SHA3_512_BLOCK_SIZE];
	u8 opad[SHA3_512_BLOCK_SIZE];
	u8 inner[SHA3_512_DIGEST_SIZE];
	int i;

	memset(k, 0, SHA3_512_BLOCK_SIZE);

	if (key_len > SHA3_512_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, key, key_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA3_512_BLOCK_SIZE; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}

	arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, ipad, SHA3_512_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, data, data_len);
	arch_sha3_256_final(&ctx, inner);

	arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, opad, SHA3_512_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, inner, SHA3_512_DIGEST_SIZE);
	arch_sha3_256_final(&ctx, out);
}

/* HKDF-SHA3-512 */

static void
hkdf_sha3_512_extract(u8 *prk, unsigned int prk_len,
                      const u8 *salt, unsigned int salt_len,
                      const u8 *ikm, unsigned int ikm_len)
{
	u8 null_salt[SHA3_512_DIGEST_SIZE];

	if (!salt || salt_len == 0) {
		memset(null_salt, 0, SHA3_512_DIGEST_SIZE);
		salt = null_salt;
		salt_len = SHA3_512_DIGEST_SIZE;
	}

	hmac_sha3_512_oneshot(salt, salt_len, ikm, ikm_len, prk);
}

static int
hkdf_sha3_512_expand(u8 *okm, unsigned int okm_len,
                     const u8 *prk, unsigned int prk_len,
                     const u8 *info, unsigned int info_len)
{
	unsigned int n;
	unsigned int i;
	unsigned int done;
	unsigned int todo;
	u8 prev[SHA3_512_DIGEST_SIZE];
	u8 hmac_out[SHA3_512_DIGEST_SIZE];
	struct sha3 ctx;
	u8 k[SHA3_512_BLOCK_SIZE];
	u8 ipad[SHA3_512_BLOCK_SIZE];
	u8 opad[SHA3_512_BLOCK_SIZE];
	u8 inner[SHA3_512_DIGEST_SIZE];
	int j;
	u8 ctr;

	n = (okm_len + SHA3_512_DIGEST_SIZE - 1) / SHA3_512_DIGEST_SIZE;
	if (n > 255)
		return -1;

	memset(k, 0, SHA3_512_BLOCK_SIZE);
	if (prk_len > SHA3_512_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, prk, prk_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, prk, prk_len);
	}

	for (j = 0; j < SHA3_512_BLOCK_SIZE; j++) {
		ipad[j] = k[j] ^ 0x36;
		opad[j] = k[j] ^ 0x5c;
	}

	done = 0;
	for (i = 1; i <= n; i++) {
		ctr = (u8)i;

		arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, ipad, SHA3_512_BLOCK_SIZE);
		if (i > 1)
			arch_sha3_256_update(&ctx, prev, SHA3_512_DIGEST_SIZE);
		if (info && info_len > 0)
			arch_sha3_256_update(&ctx, info, info_len);
		arch_sha3_256_update(&ctx, &ctr, 1);
		arch_sha3_256_final(&ctx, inner);

		arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, opad, SHA3_512_BLOCK_SIZE);
		arch_sha3_256_update(&ctx, inner, SHA3_512_DIGEST_SIZE);
		arch_sha3_256_final(&ctx, hmac_out);

		memcpy(prev, hmac_out, SHA3_512_DIGEST_SIZE);

		todo = (okm_len - done < SHA3_512_DIGEST_SIZE) ?
		       okm_len - done : SHA3_512_DIGEST_SIZE;
		memcpy(okm + done, hmac_out, todo);
		done += todo;
	}

	return 0;
}

static void
hkdf_sha3_512(u8 *okm, unsigned int okm_len,
              const u8 *ikm, unsigned int ikm_len,
              const u8 *salt, unsigned int salt_len,
              const u8 *info, unsigned int info_len)
{
	u8 prk[SHA3_512_DIGEST_SIZE];

	hkdf_sha3_512_extract(prk, sizeof(prk), salt, salt_len, ikm, ikm_len);
	hkdf_sha3_512_expand(okm, okm_len, prk, sizeof(prk), info, info_len);
}
