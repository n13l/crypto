/*
 * TLS 1.2 style PRF, P_SHA3-224/256/384/512
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

#ifndef PRF_SHA3_SCOPE
#define PRF_SHA3_SCOPE
#endif

struct prf_context;

/* HMAC-SHA3-224 over a vector of message segments */

static inline void
hmac_sha3_224_vec(const u8 *key, unsigned int key_len, unsigned int num,
                  const u8 **msg, const unsigned int *msg_len, u8 *mac)
{
	struct sha3 ctx;
	u8 k[SHA3_224_BLOCK_SIZE];
	u8 pad[SHA3_224_BLOCK_SIZE];
	u8 inner[SHA3_224_DIGEST_SIZE];
	unsigned int i;

	memset(k, 0, SHA3_224_BLOCK_SIZE);
	if (key_len > SHA3_224_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, key, key_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA3_224_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x36;

	arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, pad, SHA3_224_BLOCK_SIZE);
	for (i = 0; i < num; i++)
		arch_sha3_256_update(&ctx, msg[i], msg_len[i]);
	arch_sha3_256_final(&ctx, inner);

	for (i = 0; i < SHA3_224_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x5c;

	arch_sha3_init(&ctx, SHA3_224_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, pad, SHA3_224_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, inner, SHA3_224_DIGEST_SIZE);
	arch_sha3_256_final(&ctx, mac);
}

/* PRF-SHA3-224 */

PRF_SHA3_SCOPE void
prf_sha3_224(struct prf_context *prf,
             const u8 *secret, unsigned int secret_len,
             const u8 *seed1, unsigned int seed1_len,
             const u8 *seed2, unsigned int seed2_len,
             u8 *output, unsigned int output_len)
{
	u8 A[SHA3_224_DIGEST_SIZE], P[SHA3_224_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int len[3];
	unsigned int pos, clen;

	(void)prf;

	addr[0] = A;
	len[0] = SHA3_224_DIGEST_SIZE;
	addr[1] = seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha3_224_vec(secret, secret_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha3_224_vec(secret, secret_len, 3, addr, len, P);
		hmac_sha3_224_vec(secret, secret_len, 1, addr, len, A);

		clen = output_len - pos;
		if (clen > SHA3_224_DIGEST_SIZE)
			clen = SHA3_224_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

/* HMAC-SHA3-256 over a vector of message segments */

static inline void
hmac_sha3_256_vec(const u8 *key, unsigned int key_len, unsigned int num,
                  const u8 **msg, const unsigned int *msg_len, u8 *mac)
{
	struct sha3 ctx;
	u8 k[SHA3_256_BLOCK_SIZE];
	u8 pad[SHA3_256_BLOCK_SIZE];
	u8 inner[SHA3_256_DIGEST_SIZE];
	unsigned int i;

	memset(k, 0, SHA3_256_BLOCK_SIZE);
	if (key_len > SHA3_256_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, key, key_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA3_256_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x36;

	arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, pad, SHA3_256_BLOCK_SIZE);
	for (i = 0; i < num; i++)
		arch_sha3_256_update(&ctx, msg[i], msg_len[i]);
	arch_sha3_256_final(&ctx, inner);

	for (i = 0; i < SHA3_256_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x5c;

	arch_sha3_init(&ctx, SHA3_256_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, pad, SHA3_256_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, inner, SHA3_256_DIGEST_SIZE);
	arch_sha3_256_final(&ctx, mac);
}

/* PRF-SHA3-256 */

PRF_SHA3_SCOPE void
prf_sha3_256(struct prf_context *prf,
             const u8 *secret, unsigned int secret_len,
             const u8 *seed1, unsigned int seed1_len,
             const u8 *seed2, unsigned int seed2_len,
             u8 *output, unsigned int output_len)
{
	u8 A[SHA3_256_DIGEST_SIZE], P[SHA3_256_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int len[3];
	unsigned int pos, clen;

	(void)prf;

	addr[0] = A;
	len[0] = SHA3_256_DIGEST_SIZE;
	addr[1] = seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha3_256_vec(secret, secret_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha3_256_vec(secret, secret_len, 3, addr, len, P);
		hmac_sha3_256_vec(secret, secret_len, 1, addr, len, A);

		clen = output_len - pos;
		if (clen > SHA3_256_DIGEST_SIZE)
			clen = SHA3_256_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

/* HMAC-SHA3-384 over a vector of message segments */

static inline void
hmac_sha3_384_vec(const u8 *key, unsigned int key_len, unsigned int num,
                  const u8 **msg, const unsigned int *msg_len, u8 *mac)
{
	struct sha3 ctx;
	u8 k[SHA3_384_BLOCK_SIZE];
	u8 pad[SHA3_384_BLOCK_SIZE];
	u8 inner[SHA3_384_DIGEST_SIZE];
	unsigned int i;

	memset(k, 0, SHA3_384_BLOCK_SIZE);
	if (key_len > SHA3_384_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, key, key_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA3_384_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x36;

	arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, pad, SHA3_384_BLOCK_SIZE);
	for (i = 0; i < num; i++)
		arch_sha3_256_update(&ctx, msg[i], msg_len[i]);
	arch_sha3_256_final(&ctx, inner);

	for (i = 0; i < SHA3_384_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x5c;

	arch_sha3_init(&ctx, SHA3_384_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, pad, SHA3_384_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, inner, SHA3_384_DIGEST_SIZE);
	arch_sha3_256_final(&ctx, mac);
}

/* PRF-SHA3-384 */

PRF_SHA3_SCOPE void
prf_sha3_384(struct prf_context *prf,
             const u8 *secret, unsigned int secret_len,
             const u8 *seed1, unsigned int seed1_len,
             const u8 *seed2, unsigned int seed2_len,
             u8 *output, unsigned int output_len)
{
	u8 A[SHA3_384_DIGEST_SIZE], P[SHA3_384_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int len[3];
	unsigned int pos, clen;

	(void)prf;

	addr[0] = A;
	len[0] = SHA3_384_DIGEST_SIZE;
	addr[1] = seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha3_384_vec(secret, secret_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha3_384_vec(secret, secret_len, 3, addr, len, P);
		hmac_sha3_384_vec(secret, secret_len, 1, addr, len, A);

		clen = output_len - pos;
		if (clen > SHA3_384_DIGEST_SIZE)
			clen = SHA3_384_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

/* HMAC-SHA3-512 over a vector of message segments */

static inline void
hmac_sha3_512_vec(const u8 *key, unsigned int key_len, unsigned int num,
                  const u8 **msg, const unsigned int *msg_len, u8 *mac)
{
	struct sha3 ctx;
	u8 k[SHA3_512_BLOCK_SIZE];
	u8 pad[SHA3_512_BLOCK_SIZE];
	u8 inner[SHA3_512_DIGEST_SIZE];
	unsigned int i;

	memset(k, 0, SHA3_512_BLOCK_SIZE);
	if (key_len > SHA3_512_BLOCK_SIZE) {
		arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
		arch_sha3_256_update(&ctx, key, key_len);
		arch_sha3_256_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < SHA3_512_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x36;

	arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, pad, SHA3_512_BLOCK_SIZE);
	for (i = 0; i < num; i++)
		arch_sha3_256_update(&ctx, msg[i], msg_len[i]);
	arch_sha3_256_final(&ctx, inner);

	for (i = 0; i < SHA3_512_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x5c;

	arch_sha3_init(&ctx, SHA3_512_DIGEST_SIZE);
	arch_sha3_256_update(&ctx, pad, SHA3_512_BLOCK_SIZE);
	arch_sha3_256_update(&ctx, inner, SHA3_512_DIGEST_SIZE);
	arch_sha3_256_final(&ctx, mac);
}

/* PRF-SHA3-512 */

PRF_SHA3_SCOPE void
prf_sha3_512(struct prf_context *prf,
             const u8 *secret, unsigned int secret_len,
             const u8 *seed1, unsigned int seed1_len,
             const u8 *seed2, unsigned int seed2_len,
             u8 *output, unsigned int output_len)
{
	u8 A[SHA3_512_DIGEST_SIZE], P[SHA3_512_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int len[3];
	unsigned int pos, clen;

	(void)prf;

	addr[0] = A;
	len[0] = SHA3_512_DIGEST_SIZE;
	addr[1] = seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha3_512_vec(secret, secret_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha3_512_vec(secret, secret_len, 3, addr, len, P);
		hmac_sha3_512_vec(secret, secret_len, 1, addr, len, A);

		clen = output_len - pos;
		if (clen > SHA3_512_DIGEST_SIZE)
			clen = SHA3_512_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}
