/*
 * HKDF-SHA-1-160 implementation
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
 * https://tools.ietf.org/html/rfc5869
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>

static void
hkdf_sha1_160_hmac(const u8 *key, unsigned int key_len,
                   const u8 *msg, unsigned int msg_len,
                   u8 *mac)
{
	u8 k[SHA1_BLOCK_SIZE];
	u8 ipad[SHA1_BLOCK_SIZE];
	u8 opad[SHA1_BLOCK_SIZE];
	u8 inner[SHA1_DIGEST_SIZE];
	struct sha1 ctx;
	int i;

	memset(k, 0, SHA1_BLOCK_SIZE);

	if (key_len > SHA1_BLOCK_SIZE) {
		arch_sha1_160_init(&ctx);
		arch_sha1_160_update(&ctx, key, key_len);
		arch_sha1_160_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA1_BLOCK_SIZE; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}

	arch_sha1_160_init(&ctx);
	arch_sha1_160_update(&ctx, ipad, SHA1_BLOCK_SIZE);
	arch_sha1_160_update(&ctx, msg, msg_len);
	arch_sha1_160_final(&ctx, inner);

	arch_sha1_160_init(&ctx);
	arch_sha1_160_update(&ctx, opad, SHA1_BLOCK_SIZE);
	arch_sha1_160_update(&ctx, inner, SHA1_DIGEST_SIZE);
	arch_sha1_160_final(&ctx, mac);
}

static void
hkdf_sha1_160_extract(u8 *prk, unsigned int prk_len,
                      const u8 *salt, unsigned int salt_len,
                      const u8 *ikm, unsigned int ikm_len)
{
	u8 default_salt[SHA1_DIGEST_SIZE];
	u8 tmp[SHA1_DIGEST_SIZE];

	if (salt == NULL || salt_len == 0) {
		memset(default_salt, 0, SHA1_DIGEST_SIZE);
		salt = default_salt;
		salt_len = SHA1_DIGEST_SIZE;
	}

	hkdf_sha1_160_hmac(salt, salt_len, ikm, ikm_len, tmp);

	if (prk_len > SHA1_DIGEST_SIZE)
		prk_len = SHA1_DIGEST_SIZE;

	memcpy(prk, tmp, prk_len);
}

static int
hkdf_sha1_160_expand(u8 *okm, unsigned int okm_len,
                     const u8 *prk, unsigned int prk_len,
                     const u8 *info, unsigned int info_len)
{
	unsigned int n, i, pos, clen;
	u8 t[SHA1_DIGEST_SIZE];
	u8 k[SHA1_BLOCK_SIZE];
	u8 ipad[SHA1_BLOCK_SIZE];
	u8 opad[SHA1_BLOCK_SIZE];
	u8 inner[SHA1_DIGEST_SIZE];
	struct sha1 ctx;
	int j;
	u8 c;

	n = (okm_len + SHA1_DIGEST_SIZE - 1) / SHA1_DIGEST_SIZE;
	if (n > 255)
		return -1;

	memset(k, 0, SHA1_BLOCK_SIZE);

	if (prk_len > SHA1_BLOCK_SIZE) {
		arch_sha1_160_init(&ctx);
		arch_sha1_160_update(&ctx, prk, prk_len);
		arch_sha1_160_final(&ctx, k);
	} else {
		memcpy(k, prk, prk_len);
	}

	for (j = 0; j < SHA1_BLOCK_SIZE; j++) {
		ipad[j] = k[j] ^ 0x36;
		opad[j] = k[j] ^ 0x5c;
	}

	pos = 0;

	for (i = 1; i <= n; i++) {
		c = (u8)i;

		arch_sha1_160_init(&ctx);
		arch_sha1_160_update(&ctx, ipad, SHA1_BLOCK_SIZE);

		if (i > 1)
			arch_sha1_160_update(&ctx, t, SHA1_DIGEST_SIZE);

		if (info != NULL && info_len > 0)
			arch_sha1_160_update(&ctx, info, info_len);

		arch_sha1_160_update(&ctx, &c, 1);
		arch_sha1_160_final(&ctx, inner);

		arch_sha1_160_init(&ctx);
		arch_sha1_160_update(&ctx, opad, SHA1_BLOCK_SIZE);
		arch_sha1_160_update(&ctx, inner, SHA1_DIGEST_SIZE);
		arch_sha1_160_final(&ctx, t);

		clen = okm_len - pos;
		if (clen > SHA1_DIGEST_SIZE)
			clen = SHA1_DIGEST_SIZE;

		memcpy(okm + pos, t, clen);
		pos += clen;
	}

	return 0;
}

static int
hkdf_sha1_160(u8 *okm, unsigned int okm_len,
              const u8 *ikm, unsigned int ikm_len,
              const u8 *salt, unsigned int salt_len,
              const u8 *info, unsigned int info_len)
{
	u8 prk[SHA1_DIGEST_SIZE];

	hkdf_sha1_160_extract(prk, SHA1_DIGEST_SIZE, salt, salt_len, ikm, ikm_len);

	return hkdf_sha1_160_expand(okm, okm_len, prk, SHA1_DIGEST_SIZE,
	                            info, info_len);
}
