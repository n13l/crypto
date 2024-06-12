/*
 * The MIT License (MIT)         Copyright (c) 2016 Daniel Kubec <niel@rtfm.cz>
 *
 *                                                 Pseudo-Random Function (PRF)
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
 */

#include <sys/compiler.h>
#include <crypto/digest/sha2.h>
#include <crypto/digest.h>
#include <crypto/hmac.h>
#include <crypto/prf.h>
#include <string.h>
#include <crypto/abi/ssl/prf.h>

#ifndef CONFIG_CRYPTO_INLINE

static struct hmac_algorithm *sha256_hmac = NULL;
static struct hmac_algorithm *sha384_hmac = NULL;

#define hmac_sha256(ctx, key, key_size, msg, msg_len, mac) \
  sha256_hmac->hmac(ctx, key, key_size, msg, msg_len, mac, SHA256_DIGEST_SIZE)

#define hmac_sha256_vector(ctx, key, key_size, num, msg, msg_len, mac) \
  sha256_hmac->vector(ctx, key, key_size, num, msg, msg_len, mac, SHA256_DIGEST_SIZE)

#define hmac_sha384(ctx, key, key_size, msg, msg_len, mac) \
  sha384_hmac->hmac(ctx, key, key_size, msg, msg_len, mac, SHA384_DIGEST_SIZE)

#define hmac_sha384_vector(ctx, key, key_size, num, msg, msg_len, mac) \
  sha384_hmac->vector(ctx, key, key_size, num, msg, msg_len, mac, SHA384_DIGEST_SIZE)

#endif

static void
prf_sha2_256(struct prf_context *prf,
           const u8 *seed0, unsigned int seed0_len,
           const u8 *seed1, unsigned int seed1_len,
           const u8 *seed2, unsigned int seed2_len,
           u8 *output, unsigned int output_len)
{
	prf_sha256(seed0, seed0_len, seed1, seed1_len, seed2, seed2_len, output, output_len);
	return;
	
	struct hmac_context *ctx = (struct hmac_context *)prf;
	u8 A[SHA256_DIGEST_SIZE], P[SHA256_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA256_DIGEST_SIZE;
	addr[1] = (u8*) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha256_vector(ctx, seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha256_vector(ctx, seed0, seed0_len, 3, addr, len, P);
		hmac_sha256(ctx, seed0, seed0_len, A, SHA256_DIGEST_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA256_DIGEST_SIZE)
			clen = SHA256_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

static void
prf_sha2_384(struct prf_context *prf,
           const u8 *seed0, unsigned int seed0_len,
           const u8 *seed1, unsigned int seed1_len,
           const u8 *seed2, unsigned int seed2_len,
           u8 *output, unsigned int output_len)
{
	prf_sha384(seed0, seed0_len, seed1, seed1_len, seed2, seed2_len, output, output_len);
	return;
	struct hmac_context *ctx = (struct hmac_context *)prf;
	u8 A[SHA384_DIGEST_SIZE], P[SHA384_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA384_DIGEST_SIZE;
	addr[1] = (u8*) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha384_vector(ctx, seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha384_vector(ctx, seed0, seed0_len, 3, addr, len, P);
		hmac_sha384(ctx, seed0, seed0_len, A, SHA384_DIGEST_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA384_DIGEST_SIZE)
			clen = SHA384_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}


static struct prf_algorithm prf_sha256_algorithm = {
	.name = "prf_sha256",
	.id = PRF_SHA2_256,
	.derive = prf_sha2_256
};

static struct prf_algorithm prf_sha384_algorithm = {
	.name = "prf_sha384",
	.id = PRF_SHA2_384,
	.derive = prf_sha2_384
};

void crypto_init_prf_sha2(void)
{
	sha256_hmac = crypto_hmac_by_id(HMAC_SHA256);
	sha384_hmac = crypto_hmac_by_id(HMAC_SHA384);
	assert(sha256_hmac != NULL);
	assert(sha384_hmac != NULL);
	crypto_prf_register(&prf_sha256_algorithm);
	crypto_prf_register(&prf_sha384_algorithm);
}
