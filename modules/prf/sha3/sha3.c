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

#include <hpc/compiler.h>
#include <crypto/digest.h>
#include <crypto/hmac.h>
#include <crypto/prf.h>
#include <string.h>

#ifndef CONFIG_CRYPTO_INLINE

static struct hmac_algorithm *sha3_224_hmac = NULL;
static struct hmac_algorithm *sha3_256_hmac = NULL;
static struct hmac_algorithm *sha3_384_hmac = NULL;
static struct hmac_algorithm *sha3_512_hmac = NULL;

#define hmac_sha3_224(ctx, key, key_size, msg, msg_len, mac) \
  sha3_224_hmac->hmac(ctx, key, key_size, msg, msg_len, mac, SHA3_224_DIGEST_SIZE)

#define hmac_sha3_224_vector(ctx, key, key_size, num, msg, msg_len, mac) \
  sha3_224_hmac->vector(ctx, key, key_size, num, msg, msg_len, mac, SHA3_224_DIGEST_SIZE)

#define hmac_sha3_256(ctx, key, key_size, msg, msg_len, mac) \
  sha3_256_hmac->hmac(ctx, key, key_size, msg, msg_len, mac, SHA3_256_DIGEST_SIZE)

#define hmac_sha3_256_vector(ctx, key, key_size, num, msg, msg_len, mac) \
  sha3_256_hmac->vector(ctx, key, key_size, num, msg, msg_len, mac, SHA3_256_DIGEST_SIZE)

#define hmac_sha3_384(ctx, key, key_size, msg, msg_len, mac) \
  sha3_384_hmac->hmac(ctx, key, key_size, msg, msg_len, mac, SHA3_384_DIGEST_SIZE)

#define hmac_sha3_384_vector(ctx, key, key_size, num, msg, msg_len, mac) \
  sha3_384_hmac->vector(ctx, key, key_size, num, msg, msg_len, mac, SHA3_384_DIGEST_SIZE)

#define hmac_sha3_512(ctx, key, key_size, msg, msg_len, mac) \
  sha3_512_hmac->hmac(ctx, key, key_size, msg, msg_len, mac, SHA3_512_DIGEST_SIZE)

#define hmac_sha3_512_vector(ctx, key, key_size, num, msg, msg_len, mac) \
  sha3_512_hmac->vector(ctx, key, key_size, num, msg, msg_len, mac, SHA3_512_DIGEST_SIZE)

#endif

static void
prf_sha3_224(struct prf_context *prf,
           const u8 *seed0, unsigned int seed0_len,
           const u8 *seed1, unsigned int seed1_len,
           const u8 *seed2, unsigned int seed2_len,
           u8 *output, unsigned int output_len)
{
	struct hmac_context *ctx = (struct hmac_context *)prf;
	u8 A[SHA3_224_DIGEST_SIZE], P[SHA3_224_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA3_224_DIGEST_SIZE;
	addr[1] = (u8*) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha3_224_vector(ctx, seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha3_224_vector(ctx, seed0, seed0_len, 3, addr, len, P);
		hmac_sha3_224(ctx, seed0, seed0_len, A, SHA3_224_DIGEST_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA3_224_DIGEST_SIZE)
			clen = SHA3_224_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

static void
prf_sha3_256(struct prf_context *prf,
           const u8 *seed0, unsigned int seed0_len,
           const u8 *seed1, unsigned int seed1_len,
           const u8 *seed2, unsigned int seed2_len,
           u8 *output, unsigned int output_len)
{
	struct hmac_context *ctx = (struct hmac_context *)prf;
	u8 A[SHA3_256_DIGEST_SIZE], P[SHA3_256_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA3_256_DIGEST_SIZE;
	addr[1] = (u8*) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha3_256_vector(ctx, seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha3_256_vector(ctx, seed0, seed0_len, 3, addr, len, P);
		hmac_sha3_256(ctx, seed0, seed0_len, A, SHA3_256_DIGEST_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA3_256_DIGEST_SIZE)
			clen = SHA3_256_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

static void
prf_sha3_384(struct prf_context *prf,
           const u8 *seed0, unsigned int seed0_len,
           const u8 *seed1, unsigned int seed1_len,
           const u8 *seed2, unsigned int seed2_len,
           u8 *output, unsigned int output_len)
{
	struct hmac_context *ctx = (struct hmac_context *)prf;
	u8 A[SHA3_384_DIGEST_SIZE], P[SHA3_384_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA3_384_DIGEST_SIZE;
	addr[1] = (u8*) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha3_384_vector(ctx, seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha3_384_vector(ctx, seed0, seed0_len, 3, addr, len, P);
		hmac_sha3_384(ctx, seed0, seed0_len, A, SHA3_384_DIGEST_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA3_384_DIGEST_SIZE)
			clen = SHA3_384_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

static void
prf_sha3_512(struct prf_context *prf,
           const u8 *seed0, unsigned int seed0_len,
           const u8 *seed1, unsigned int seed1_len,
           const u8 *seed2, unsigned int seed2_len,
           u8 *output, unsigned int output_len)
{
	struct hmac_context *ctx = (struct hmac_context *)prf;
	u8 A[SHA3_512_DIGEST_SIZE], P[SHA3_512_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA3_512_DIGEST_SIZE;
	addr[1] = (u8*) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha3_512_vector(ctx, seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha3_512_vector(ctx, seed0, seed0_len, 3, addr, len, P);
		hmac_sha3_512(ctx, seed0, seed0_len, A, SHA3_512_DIGEST_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA3_512_DIGEST_SIZE)
			clen = SHA3_512_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

static struct prf_algorithm prf_sha3_224_algorithm = {
	.name = "prf_sha3_224",
	.id = PRF_SHA3_224,
	.derive = prf_sha3_224
};

static struct prf_algorithm prf_sha3_256_algorithm = {
	.name = "prf_sha3_256",
	.id = PRF_SHA3_256,
	.derive = prf_sha3_256
};

static struct prf_algorithm prf_sha3_384_algorithm = {
	.name = "prf_sha3_384",
	.id = PRF_SHA3_384,
	.derive = prf_sha3_384
};

static struct prf_algorithm prf_sha3_512_algorithm = {
	.name = "prf_sha3_512",
	.id = PRF_SHA3_512,
	.derive = prf_sha3_512
};

void crypto_init_prf_sha3(void)
{
	sha3_224_hmac = crypto_hmac_by_id(HMAC_SHA3_224);
	sha3_256_hmac = crypto_hmac_by_id(HMAC_SHA3_256);
	sha3_384_hmac = crypto_hmac_by_id(HMAC_SHA3_384);
	sha3_512_hmac = crypto_hmac_by_id(HMAC_SHA3_512);
	assert(sha3_224_hmac != NULL);
	assert(sha3_256_hmac != NULL);
	assert(sha3_384_hmac != NULL);
	assert(sha3_512_hmac != NULL);
	crypto_prf_register(&prf_sha3_224_algorithm);
	crypto_prf_register(&prf_sha3_256_algorithm);
	crypto_prf_register(&prf_sha3_384_algorithm);
	crypto_prf_register(&prf_sha3_512_algorithm);
}
