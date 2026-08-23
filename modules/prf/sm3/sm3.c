/*
 * PRF-SM3: the TLS 1.2 P_hash of RFC 5246 sec 5 over SM3
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
 * No IANA TLS 1.2 suite names SM3 as its PRF hash: the registered ShangMi
 * suites (RFC 8998) are TLS 1.3 only and key through HKDF. This is here so the
 * SM3 seam is the same shape as SHA-2's — digest, HMAC, PRF, HKDF — and so a
 * TLS 1.2-style ShangMi schedule (GB/T 38636 puts one under its own version
 * number) has the primitive waiting if a decoder for it lands.
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>
#include <crypto/prf.h>

#ifndef PRF_SM3_SCOPE
#define PRF_SM3_SCOPE
#endif

/* HMAC-SM3 over a vector of message segments */

static inline void
hmac_sm3_vec(const u8 *key, unsigned int key_len, unsigned int num,
             const u8 **msg, const unsigned int *msg_len, u8 *mac)
{
	struct sm3 ctx;
	u8 k[SM3_BLOCK_SIZE];
	u8 pad[SM3_BLOCK_SIZE];
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
		pad[i] = k[i] ^ 0x36;

	arch_sm3_init(&ctx);
	arch_sm3_update(&ctx, pad, SM3_BLOCK_SIZE);
	for (i = 0; i < num; i++)
		arch_sm3_update(&ctx, msg[i], msg_len[i]);
	arch_sm3_final(&ctx, inner);

	for (i = 0; i < SM3_BLOCK_SIZE; i++)
		pad[i] = k[i] ^ 0x5c;

	arch_sm3_init(&ctx);
	arch_sm3_update(&ctx, pad, SM3_BLOCK_SIZE);
	arch_sm3_update(&ctx, inner, SM3_DIGEST_SIZE);
	arch_sm3_final(&ctx, mac);
}

PRF_SM3_SCOPE void
prf_sm3(struct prf_context *prf,
        const u8 *secret, unsigned int secret_len,
        const u8 *seed1, unsigned int seed1_len,
        const u8 *seed2, unsigned int seed2_len,
        u8 *output, unsigned int output_len)
{
	u8 A[SM3_DIGEST_SIZE], P[SM3_DIGEST_SIZE];
	const u8 *addr[3];
	unsigned int len[3];
	unsigned int pos, clen;

	(void)prf;

	addr[0] = A;
	len[0] = SM3_DIGEST_SIZE;
	addr[1] = seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sm3_vec(secret, secret_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sm3_vec(secret, secret_len, 3, addr, len, P);
		hmac_sm3_vec(secret, secret_len, 1, addr, len, A);

		clen = output_len - pos;
		if (clen > SM3_DIGEST_SIZE)
			clen = SM3_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}
