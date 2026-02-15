/*
 * DES and Triple DES in EDE mode, CBC (FIPS 46-3, RFC 1851)
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
 * Written from the standard's own tables, bit for bit, rather than from the
 * combined S-box-and-permutation tables a fast DES uses: it is here to read
 * captures of the *_WITH_3DES_EDE_CBC_SHA suites, and those are a handful of
 * records in a corpus rather than a throughput path. What that buys is a file
 * every table of which can be checked against FIPS 46-3 by eye; the unit test
 * (tools/testing/selftests/units/legacy.c) checks it against the known-answer
 * vectors instead.
 */

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>
#include <string.h>

#include <crypto/cipher.h>
#include <crypto/cipher/des3.h>

/* FIPS 46-3 initial permutation and its inverse */
static const u8 des_ip[64] = {
	58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
	57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7
};

static const u8 des_fp[64] = {
	40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};

/* the round function: expansion, then the S-box output's permutation */
static const u8 des_e[48] = {
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const u8 des_p[32] = {
	16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
	 2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

/* the key schedule: the two permuted choices and the rotation per round */
static const u8 des_pc1[56] = {
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static const u8 des_pc2[48] = {
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const u8 des_shifts[DES_ROUNDS] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const u8 des_sbox[8][64] = {
	{
	14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
	}, {
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
	}, {
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
	}, {
	 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
	}, {
	 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
	}, {
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
	}, {
	 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
	}, {
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
	}
};

/*
 * The standard numbers its bits from 1 at the most significant end, and every
 * table above is written in those numbers. This is the only place that
 * convention is turned into a shift, so a table can be read against the
 * standard without also reading a bit order out of the code.
 */
static u64
des_permute(u64 in, const u8 *table, unsigned int out_bits,
            unsigned int in_bits)
{
	u64 out = 0;
	unsigned int i;

	for (i = 0; i < out_bits; i++) {
		out <<= 1;
		out |= (in >> (in_bits - table[i])) & 1u;
	}
	return out;
}

static u32
des_round_f(u32 r, u64 subkey)
{
	u64 e = des_permute((u64)r, des_e, 48, 32) ^ subkey;
	u32 out = 0;
	unsigned int i;

	for (i = 0; i < 8; i++) {
		unsigned int six = (unsigned int)((e >> (42 - 6 * i)) & 0x3f);
		/* the row is the outer two bits, the column the inner four */
		unsigned int row = ((six >> 4) & 0x2) | (six & 0x1);
		unsigned int col = (six >> 1) & 0xf;

		out = (out << 4) | des_sbox[i][row * 16 + col];
	}
	return (u32)des_permute((u64)out, des_p, 32, 32);
}

static void
des_key_schedule(const u8 *key, u64 *sub)
{
	u64 pc1 = des_permute(get_u64_be(key), des_pc1, 56, 64);
	u32 c = (u32)((pc1 >> 28) & 0x0fffffffu);
	u32 d = (u32)(pc1 & 0x0fffffffu);
	unsigned int i;

	for (i = 0; i < DES_ROUNDS; i++) {
		unsigned int s = des_shifts[i];

		c = ((c << s) | (c >> (28 - s))) & 0x0fffffffu;
		d = ((d << s) | (d >> (28 - s))) & 0x0fffffffu;
		sub[i] = des_permute(((u64)c << 28) | d, des_pc2, 48, 56);
	}
}

/* One DES block through sixteen rounds. @sub is read forwards to encrypt and
 * backwards to decrypt, which is the whole difference between the two. */
static u64
des_block(u64 block, const u64 *sub, int decrypt)
{
	u64 ip = des_permute(block, des_ip, 64, 64);
	u32 l = (u32)(ip >> 32);
	u32 r = (u32)ip;
	unsigned int i;

	for (i = 0; i < DES_ROUNDS; i++) {
		u32 tmp = r;

		r = l ^ des_round_f(r, sub[decrypt ? DES_ROUNDS - 1 - i : i]);
		l = tmp;
	}
	/* the halves are swapped once more before the final permutation */
	return des_permute(((u64)r << 32) | l, des_fp, 64, 64);
}

void
des3_cbc_init_ctx_iv(struct des3_ctx *ctx, const u8 *key, const u8 *iv)
{
	unsigned int i;

	for (i = 0; i < 3; i++)
		des_key_schedule(key + i * DES_KEYLEN, ctx->k[i]);
	if (iv)
		memcpy(ctx->Iv, iv, DES3_BLOCKLEN);
	else
		memset(ctx->Iv, 0, DES3_BLOCKLEN);
}

void
des3_ecb_encrypt_block(const struct des3_ctx *ctx, const u8 *in, u8 *out)
{
	u64 b = get_u64_be(in);

	b = des_block(b, ctx->k[0], 0);
	b = des_block(b, ctx->k[1], 1);
	b = des_block(b, ctx->k[2], 0);
	put_u64_be(out, b);
}

void
des3_ecb_decrypt_block(const struct des3_ctx *ctx, const u8 *in, u8 *out)
{
	u64 b = get_u64_be(in);

	b = des_block(b, ctx->k[2], 1);
	b = des_block(b, ctx->k[1], 0);
	b = des_block(b, ctx->k[0], 1);
	put_u64_be(out, b);
}

void
des3_cbc_encrypt(struct des3_ctx *ctx, u8 *buf, u32 length)
{
	u8 *iv = ctx->Iv;
	u32 i, j;

	for (i = 0; i + DES3_BLOCKLEN <= length; i += DES3_BLOCKLEN) {
		for (j = 0; j < DES3_BLOCKLEN; j++)
			buf[i + j] ^= iv[j];
		des3_ecb_encrypt_block(ctx, buf + i, buf + i);
		iv = buf + i;
	}
	memcpy(ctx->Iv, iv, DES3_BLOCKLEN);
}

void
des3_cbc_decrypt(struct des3_ctx *ctx, u8 *buf, u32 length)
{
	u8 carry[DES3_BLOCKLEN];
	u32 i, j;

	for (i = 0; i + DES3_BLOCKLEN <= length; i += DES3_BLOCKLEN) {
		/* the block being decrypted is the next one's IV, and this is
		 * in place, so keep it before it is overwritten */
		memcpy(carry, buf + i, DES3_BLOCKLEN);
		des3_ecb_decrypt_block(ctx, buf + i, buf + i);
		for (j = 0; j < DES3_BLOCKLEN; j++)
			buf[i + j] ^= ctx->Iv[j];
		memcpy(ctx->Iv, carry, DES3_BLOCKLEN);
	}
}
