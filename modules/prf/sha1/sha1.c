/*
 * TLS 1.2 PRF, P_SHA-1 (RFC 5246, Section 5)
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

#ifndef PRF_SHA1_SCOPE
#define PRF_SHA1_SCOPE
#endif

struct prf_context;

/* HMAC-SHA-1 over a vector of message segments */

static inline void
hmac_sha1_vec(const u8 *key, unsigned int key_len, unsigned int num,
              const u8 **msg, const unsigned int *msg_len, u8 *mac)
{
	struct sha1 ctx;
	u8 k[SHA1_BLOCK_SIZE];
	u8 pad[SHA1_BLOCK_SIZE];
	u8 inner[SHA1_DIGEST_SIZE];
	unsigned int i;

	memset(k, 0, SHA1_BLOCK_SIZE);
	if (key_len > SHA1_BLOCK_SIZE) {
		arch_sha1_160_init(&ctx);
		arch_sha1_160_update(&ctx, key, key_len);
		arch_sha1_160_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA1_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x36;

	arch_sha1_160_init(&ctx);
	arch_sha1_160_update(&ctx, pad, SHA1_BLOCK_SIZE);
	for (i = 0; i < num; i++)
		arch_sha1_160_update(&ctx, msg[i], msg_len[i]);
	arch_sha1_160_final(&ctx, inner);

	for (i = 0; i < SHA1_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x5c;

	arch_sha1_160_init(&ctx);
	arch_sha1_160_update(&ctx, pad, SHA1_BLOCK_SIZE);
	arch_sha1_160_update(&ctx, inner, SHA1_DIGEST_SIZE);
	arch_sha1_160_final(&ctx, mac);
}

/* PRF-SHA-1 */

PRF_SHA1_SCOPE void
prf_sha1(struct prf_context *prf,
         const u8 *secret, unsigned int secret_len,
         const u8 *seed1, unsigned int seed1_len,
         const u8 *seed2, unsigned int seed2_len,
         u8 *output, unsigned int output_len)
{
	u8 A[SHA1_DIGEST_SIZE], P[SHA1_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int len[3];
	unsigned int pos, clen;

	(void)prf;

	addr[0] = A;
	len[0] = SHA1_DIGEST_SIZE;
	addr[1] = seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha1_vec(secret, secret_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha1_vec(secret, secret_len, 3, addr, len, P);
		hmac_sha1_vec(secret, secret_len, 1, addr, len, A);

		clen = output_len - pos;
		if (clen > SHA1_DIGEST_SIZE)
			clen = SHA1_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}
