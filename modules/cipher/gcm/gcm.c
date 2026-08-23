/*
 * GCM (NIST SP 800-38D) over a block cipher, written once.
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
 * GCM is a counter mode and a polynomial MAC over GF(2^128), and neither cares
 * what the block cipher under them is. The AES mode beside this (../aes/gcm.c)
 * is bound to its own AES; this is the same mode with the cipher behind a
 * seam, <gcm-backend.h>, which each backend puts on this file's include path
 * from its Kbuild along with the names it wants the entry points defined
 * under. SM4 (RFC 8998), ARIA (RFC 6209) and Camellia (RFC 6367) each compile
 * this once over their block, the way ../aes-ccm/ccm.c is compiled per cipher.
 *
 * The seam is three things: struct gcm_key, gcm_key_init(k, key, key_len)
 * returning nonzero for a key width the cipher does not have, and
 * gcm_block_encrypt(k, in, out) for one block.
 *
 * The multiplier is the 4-bit table method (Shoup's, with the reduction
 * constants folded into a 16-entry table): one 128-bit product per sixteen
 * table lookups, computed once per key. The counter is the 32-bit big-endian
 * one of a 96-bit nonce, and a nonce of another length is GHASHed into J0 as
 * the specification says. RFC 8998 Appendix A.1 is the known answer through
 * SM4; OpenSSL's ARIA-GCM is the oracle for ARIA.
 *
 * What a decrypt does about the tag follows CONFIG_CRYPTO_VERIFIED_DECRYPT_
 * AEAD the way the AES mode does: on, every record is authenticated; off, the
 * GHASH is not carried on decrypt and the tag is not compared.
 */

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>
#include <string.h>

#include <gcm-backend.h>

#if !defined(GCM_ENCRYPT_AAD) || !defined(GCM_DECRYPT_AAD) || \
    !defined(GCM_ENCRYPT) || !defined(GCM_DECRYPT)
#error "a GCM backend names its four entry points on the command line"
#endif

#ifndef GCM_AUTH_FAILURE
#define GCM_AUTH_FAILURE 0x55555555
#endif

#define GCM_BLOCK 16

struct gcm {
	struct gcm_key key;
	u64 hl[16];		/* the low halves of H * i, i = 0..15  */
	u64 hh[16];		/* ...and the high                     */
};

/* x^128 + x^7 + x^2 + x + 1: the reduction of the low nibble shifted out,
 * for each of its sixteen values */
static const u16 gcm_last4[16] = {
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

/* the hash key H = E_K(0^128), and the table of its multiples */
static int
gcm_setkey(struct gcm *g, const u8 *key, size_t key_len)
{
	u8 h[GCM_BLOCK] = { 0 };
	u64 vh, vl;
	unsigned int i, j;

	if (gcm_key_init(&g->key, key, key_len))
		return -1;
	gcm_block_encrypt(&g->key, h, h);

	vh = get_u64_be(h);
	vl = get_u64_be(h + 8);

	g->hl[8] = vl;			/* 8 = 1000b is 1 in GF(2^128) */
	g->hh[8] = vh;
	g->hl[0] = 0;
	g->hh[0] = 0;

	for (i = 4; i > 0; i >>= 1) {
		u32 t = (u32)(vl & 1) * 0xe1000000u;

		vl = (vh << 63) | (vl >> 1);
		vh = (vh >> 1) ^ ((u64)t << 32);
		g->hl[i] = vl;
		g->hh[i] = vh;
	}
	for (i = 2; i < 16; i <<= 1) {
		u64 *hil = g->hl + i, *hih = g->hh + i;

		vh = *hih;
		vl = *hil;
		for (j = 1; j < i; j++) {
			hih[j] = vh ^ g->hh[j];
			hil[j] = vl ^ g->hl[j];
		}
	}
	return 0;
}

/* x <- x * H */
static void
gcm_mult(const struct gcm *g, u8 x[GCM_BLOCK])
{
	u64 zh, zl;
	u8 lo, hi, rem;
	int i;

	lo = (u8)(x[15] & 0x0f);
	zh = g->hh[lo];
	zl = g->hl[lo];

	for (i = 15; i >= 0; i--) {
		lo = (u8)(x[i] & 0x0f);
		hi = (u8)(x[i] >> 4);

		if (i != 15) {
			rem = (u8)(zl & 0x0f);
			zl = (zh << 60) | (zl >> 4);
			zh = zh >> 4;
			zh ^= (u64)gcm_last4[rem] << 48;
			zh ^= g->hh[lo];
			zl ^= g->hl[lo];
		}
		rem = (u8)(zl & 0x0f);
		zl = (zh << 60) | (zl >> 4);
		zh = zh >> 4;
		zh ^= (u64)gcm_last4[rem] << 48;
		zh ^= g->hh[hi];
		zl ^= g->hl[hi];
	}
	put_u64_be(x, zh);
	put_u64_be(x + 8, zl);
}

/* GHASH of a byte string into the running value, zero-padded to a block */
static void
gcm_absorb(const struct gcm *g, u8 y[GCM_BLOCK], const u8 *p, size_t len)
{
	size_t use;
	unsigned int i;

	while (len) {
		use = len < GCM_BLOCK ? len : GCM_BLOCK;
		for (i = 0; i < use; i++)
			y[i] ^= p[i];
		gcm_mult(g, y);
		p += use;
		len -= use;
	}
}

/* J0 from the nonce: the 96-bit nonce with a counter of 1, else GHASH(IV) */
static void
gcm_j0(const struct gcm *g, u8 j0[GCM_BLOCK], const u8 *iv, size_t iv_len)
{
	u8 len[GCM_BLOCK] = { 0 };

	memset(j0, 0, GCM_BLOCK);
	if (iv_len == 12) {
		memcpy(j0, iv, 12);
		j0[15] = 1;
		return;
	}
	gcm_absorb(g, j0, iv, iv_len);
	put_u64_be(len + 8, (u64)iv_len * 8);
	gcm_absorb(g, j0, len, GCM_BLOCK);
}

/* the 32-bit big-endian increment of the counter block */
static inline void
gcm_inc(u8 ctr[GCM_BLOCK])
{
	unsigned int i;

	for (i = GCM_BLOCK; i > 12; i--)
		if (++ctr[i - 1] != 0)
			break;
}

/*
 * The whole operation in one pass: the counter stream over |len| bytes, the
 * GHASH over the associated data and the ciphertext (whichever side of the
 * pass the ciphertext is on), and the tag. |auth| says whether the hash is
 * carried at all, which is the knob a decrypt that will not check the tag
 * turns.
 */
static void
gcm_crypt(const struct gcm *g, int enc, int auth,
          const u8 *iv, size_t iv_len, const u8 *aad, size_t aad_len,
          const u8 *in, u8 *out, size_t len, u8 tag[GCM_BLOCK])
{
	u8 j0[GCM_BLOCK], ctr[GCM_BLOCK], ectr[GCM_BLOCK], y[GCM_BLOCK];
	u8 lens[GCM_BLOCK];
	size_t left = len, use;
	unsigned int i;

	gcm_j0(g, j0, iv, iv_len);
	memcpy(ctr, j0, GCM_BLOCK);
	memset(y, 0, GCM_BLOCK);

	if (auth)
		gcm_absorb(g, y, aad, aad_len);

	while (left) {
		use = left < GCM_BLOCK ? left : GCM_BLOCK;
		gcm_inc(ctr);
		gcm_block_encrypt(&g->key, ctr, ectr);
		if (enc) {
			for (i = 0; i < use; i++) {
				out[i] = (u8)(in[i] ^ ectr[i]);
				y[i] ^= out[i];
			}
		} else {
			for (i = 0; i < use; i++) {
				if (auth)
					y[i] ^= in[i];
				out[i] = (u8)(in[i] ^ ectr[i]);
			}
		}
		if (auth)
			gcm_mult(g, y);
		in += use;
		out += use;
		left -= use;
	}

	/* the tag: E_K(J0) xor GHASH(A, C, len(A) || len(C)) */
	gcm_block_encrypt(&g->key, j0, tag);
	if (!auth)
		return;
	put_u64_be(lens, (u64)aad_len * 8);
	put_u64_be(lens + 8, (u64)len * 8);
	for (i = 0; i < GCM_BLOCK; i++)
		y[i] ^= lens[i];
	gcm_mult(g, y);
	for (i = 0; i < GCM_BLOCK; i++)
		tag[i] ^= y[i];
}

int
GCM_ENCRYPT_AAD(u8 *output, const u8 *input, int input_length,
                const u8 *aad, size_t aad_len,
                const u8 *key, size_t key_len,
                const u8 *iv, size_t iv_len)
{
	struct gcm g;

	if (input_length < 0 || !iv_len || gcm_setkey(&g, key, key_len))
		return GCM_AUTH_FAILURE;
	gcm_crypt(&g, 1, 1, iv, iv_len, aad, aad_len, input, output,
	          (size_t)input_length, output + input_length);
	return 0;
}

int
GCM_DECRYPT_AAD(u8 *output, const u8 *input, int input_length,
                const u8 *aad, size_t aad_len,
                const u8 *key, size_t key_len,
                const u8 *iv, size_t iv_len)
{
	struct gcm g;
	u8 tag[GCM_BLOCK];
	size_t len;
	unsigned int i, diff = 0;

	if (input_length < GCM_BLOCK || !iv_len || gcm_setkey(&g, key, key_len))
		return GCM_AUTH_FAILURE;
	len = (size_t)input_length - GCM_BLOCK;

#ifdef CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD
	gcm_crypt(&g, 0, 1, iv, iv_len, aad, aad_len, input, output, len, tag);
	for (i = 0; i < GCM_BLOCK; i++)
		diff |= tag[i] ^ input[len + i];
	if (diff) {
		memset(output, 0, len);
		return GCM_AUTH_FAILURE;
	}
#else
	/* the keystream alone: no GHASH is carried and the tag is not read,
	 * which is the trade CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD=n states */
	gcm_crypt(&g, 0, 0, iv, iv_len, aad, aad_len, input, output, len, tag);
	(void)i; (void)diff;
#endif
	return 0;
}

int
GCM_ENCRYPT(u8 *output, const u8 *input, int input_length,
            const u8 *key, size_t key_len, const u8 *iv, size_t iv_len)
{
	return GCM_ENCRYPT_AAD(output, input, input_length, NULL, 0,
	                       key, key_len, iv, iv_len);
}

int
GCM_DECRYPT(u8 *output, const u8 *input, int input_length,
            const u8 *key, size_t key_len, const u8 *iv, size_t iv_len)
{
	return GCM_DECRYPT_AAD(output, input, input_length, NULL, 0,
	                       key, key_len, iv, iv_len);
}
