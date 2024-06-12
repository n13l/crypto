/*
 * The MIT License (MIT)                         (PRF) A Pseudo-Random Function 
 *                               Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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

#include <sys/compiler.h>
#include <string.h>
#include <crypto/abi/ssl/sha.h>
#include <crypto/abi/ssl/sha256.h>
#include <crypto/abi/ssl/sha384.h>
#include <crypto/abi/ssl/sha512.h>
#include <crypto/abi/ssl/prf.h>

void
prf_sha1(const u8 *seed0, size_t seed0_len,
           const u8 *seed1, size_t seed1_len,
           const u8 *seed2, size_t seed2_len,
           u8 *output, size_t output_len)
{
	u8 A[SHA_SIZE], P[SHA_SIZE];
	const unsigned char *addr[3];
	size_t pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA_SIZE;
	addr[1] = (unsigned char *) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha256_vector(seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha_vector(seed0, seed0_len, 3, addr, len, P);
		hmac_sha(seed0, seed0_len, A, SHA_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA_SIZE)
			clen = SHA_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

void
prf_sha256(const u8 *seed0, size_t seed0_len,
           const u8 *seed1, size_t seed1_len,
           const u8 *seed2, size_t seed2_len,
           u8 *output, size_t output_len)
{
	u8 A[SHA256_SIZE], P[SHA256_SIZE];
	const unsigned char *addr[3];
	size_t pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA256_SIZE;
	addr[1] = (unsigned char *) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha256_vector(seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha256_vector(seed0, seed0_len, 3, addr, len, P);
		hmac_sha256(seed0, seed0_len, A, SHA256_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA256_SIZE)
			clen = SHA256_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

void
prf_sha384(const u8 *seed0, size_t seed0_len,
           const u8 *seed1, size_t seed1_len,
           const u8 *seed2, size_t seed2_len,
           u8 *output, size_t output_len)
{
	u8 A[SHA384_SIZE], P[SHA384_SIZE];
	const unsigned char *addr[3];
	size_t pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA384_SIZE;
	addr[1] = (unsigned char *) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha384_vector(seed0, seed0_len, 2, &addr[1], &len[1], A);

	for (pos = 0; pos < output_len; ) {
		hmac_sha384_vector(seed0, seed0_len, 3, addr, len, P);
		hmac_sha384(seed0, seed0_len, A, SHA384_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA384_SIZE)
			clen = SHA384_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}

void
prf_sha512(const u8 *seed0, size_t seed0_len,
           const u8 *seed1, size_t seed1_len,
           const u8 *seed2, size_t seed2_len,
           u8 *output, size_t output_len)
{
	u8 A[SHA512_SIZE], P[SHA512_SIZE];
	const unsigned char *addr[3];
	size_t pos, clen, len[3];

	addr[0] = A;
	len[0] = SHA512_SIZE;
	addr[1] = (unsigned char *) seed1;
	len[1] = seed1_len;
	addr[2] = seed2;
	len[2] = seed2_len;

	hmac_sha512_vector(seed0, seed0_len, 2, &addr[1], &len[1], A);
	for (pos = 0; pos < output_len; ) {
		hmac_sha512_vector(seed0, seed0_len, 3, addr, len, P);
		hmac_sha512(seed0, seed0_len, A, SHA512_SIZE, A);

		clen = output_len - pos;
		if (clen > SHA512_SIZE)
			clen = SHA512_SIZE;
		memcpy(output + pos, P, clen);
		pos += clen;
	}
}
