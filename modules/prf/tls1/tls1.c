/*
 * TLS 1.0/1.1 PRF: P_MD5 exclusive-ored with P_SHA-1 (RFC 2246 sec 5,
 * unchanged by RFC 4346)
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
 * The one PRF in this directory that is not a P_hash. TLS 1.0 and 1.1 split
 * their secret in half and run two expansions over the same label and seed,
 * one keyed on each half, and exclusive-or the streams:
 *
 *     PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
 *                                P_SHA-1(S2, label + seed)
 *
 * The halves are each ceil(L/2) bytes, so an odd-length secret has its middle
 * byte in both of them (RFC 2246 sec 5, "L_S1 = L_S2 = ceil(L_S / 2)"); a
 * 48-byte master secret splits 24/24 and shares nothing. TLS 1.2 replaced the
 * whole construction with a single P_hash named by the suite, which is what
 * ../sha1, ../sha2 and ../sha3 are. Nothing above TLS 1.1 reaches this.
 *
 * The two HMACs are written here rather than taken from ../../hmac: a PRF
 * keys one from a caller's secret and iterates it, which is a different shape
 * from the streaming context that module offers, and ../sha1/sha1.c already
 * makes the same choice for the same reason. They carry a prf_tls1_ prefix
 * because every backend's built-in.h is read by the same translation unit.
 */

#include <hpc/compiler.h>
#include <string.h>
#include <crypto/digest.h>

#ifndef PRF_TLS1_SCOPE
#define PRF_TLS1_SCOPE
#endif

struct prf_context;

/* HMAC-MD5 over a vector of message segments */

static inline void
prf_tls1_hmac_md5(const u8 *key, unsigned int key_len, unsigned int num,
                  const u8 **msg, const unsigned int *msg_len, u8 *mac)
{
	struct md5 ctx;
	u8 k[MD5_BLOCK_SIZE];
	u8 pad[MD5_BLOCK_SIZE];
	u8 inner[MD5_DIGEST_SIZE];
	unsigned int i;

	memset(k, 0, MD5_BLOCK_SIZE);
	if (key_len > MD5_BLOCK_SIZE) {
		arch_md5_init(&ctx);
		arch_md5_update(&ctx, key, key_len);
		arch_md5_final(&ctx, k);
	} else {
		memcpy(k, key, key_len);
	}

	for (i = 0; i < MD5_BLOCK_SIZE; i++)
		pad[i] = (u8)(k[i] ^ 0x36);

	arch_md5_init(&ctx);
	arch_md5_update(&ctx, pad, MD5_BLOCK_SIZE);
	for (i = 0; i < num; i++)
		arch_md5_update(&ctx, msg[i], msg_len[i]);
	arch_md5_final(&ctx, inner);

	for (i = 0; i < MD5_BLOCK_SIZE; i++)
		pad[i] = (u8)(k[i] ^ 0x5c);

	arch_md5_init(&ctx);
	arch_md5_update(&ctx, pad, MD5_BLOCK_SIZE);
	arch_md5_update(&ctx, inner, MD5_DIGEST_SIZE);
	arch_md5_final(&ctx, mac);
}

/* HMAC-SHA-1 over a vector of message segments */

static inline void
prf_tls1_hmac_sha1(const u8 *key, unsigned int key_len, unsigned int num,
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
		pad[i] = (u8)(k[i] ^ 0x36);

	arch_sha1_160_init(&ctx);
	arch_sha1_160_update(&ctx, pad, SHA1_BLOCK_SIZE);
	for (i = 0; i < num; i++)
		arch_sha1_160_update(&ctx, msg[i], msg_len[i]);
	arch_sha1_160_final(&ctx, inner);

	for (i = 0; i < SHA1_BLOCK_SIZE; i++)
		pad[i] = (u8)(k[i] ^ 0x5c);

	arch_sha1_160_init(&ctx);
	arch_sha1_160_update(&ctx, pad, SHA1_BLOCK_SIZE);
	arch_sha1_160_update(&ctx, inner, SHA1_DIGEST_SIZE);
	arch_sha1_160_final(&ctx, mac);
}

/*
 * One half of the PRF: P_MD5 written into @output, then P_SHA-1 exclusive-ored
 * over it. The A(i) chain and the "expand to output_len and truncate" rule are
 * the same as every P_hash; only the digest and the secret differ, which is
 * why the two loops are written twice rather than parameterised — a function
 * pointer here would be the only indirect call in the schedule.
 */

PRF_TLS1_SCOPE void
prf_tls1(struct prf_context *prf,
         const u8 *secret, unsigned int secret_len,
         const u8 *seed1, unsigned int seed1_len,
         const u8 *seed2, unsigned int seed2_len,
         u8 *output, unsigned int output_len)
{
	unsigned int half = (secret_len + 1) / 2;
	const u8 *s1 = secret;
	const u8 *s2 = secret + secret_len - half;
	const u8 *addr[3];
	unsigned int len[3];
	unsigned int pos, clen, i;
	u8 A[SHA1_DIGEST_SIZE], P[SHA1_DIGEST_SIZE];

	(void)prf;

	addr[1] = seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	/* P_MD5(S1, label + seed) */
	addr[0] = A;
	len[0] = MD5_DIGEST_SIZE;
	prf_tls1_hmac_md5(s1, half, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		prf_tls1_hmac_md5(s1, half, 3, addr, len, P);
		prf_tls1_hmac_md5(s1, half, 1, addr, len, A);

		clen = output_len - pos;
		if (clen > MD5_DIGEST_SIZE)
			clen = MD5_DIGEST_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}

	/* ... XOR P_SHA-1(S2, label + seed) */
	addr[0] = A;
	len[0] = SHA1_DIGEST_SIZE;
	prf_tls1_hmac_sha1(s2, half, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		prf_tls1_hmac_sha1(s2, half, 3, addr, len, P);
		prf_tls1_hmac_sha1(s2, half, 1, addr, len, A);

		clen = output_len - pos;
		if (clen > SHA1_DIGEST_SIZE)
			clen = SHA1_DIGEST_SIZE;
		for (i = 0; i < clen; i++)
			output[pos + i] ^= P[i];
		pos += clen;
	}
}
