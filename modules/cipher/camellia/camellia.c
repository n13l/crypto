
#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>
#include <string.h>

#include <crypto/cipher.h>
#include <crypto/cipher/camellia.h>

static const u8 camellia_sbox1[256] = {
	0x70,0x82,0x2c,0xec,0xb3,0x27,0xc0,0xe5,0xe4,0x85,0x57,0x35,0xea,0x0c,0xae,0x41,
	0x23,0xef,0x6b,0x93,0x45,0x19,0xa5,0x21,0xed,0x0e,0x4f,0x4e,0x1d,0x65,0x92,0xbd,
	0x86,0xb8,0xaf,0x8f,0x7c,0xeb,0x1f,0xce,0x3e,0x30,0xdc,0x5f,0x5e,0xc5,0x0b,0x1a,
	0xa6,0xe1,0x39,0xca,0xd5,0x47,0x5d,0x3d,0xd9,0x01,0x5a,0xd6,0x51,0x56,0x6c,0x4d,
	0x8b,0x0d,0x9a,0x66,0xfb,0xcc,0xb0,0x2d,0x74,0x12,0x2b,0x20,0xf0,0xb1,0x84,0x99,
	0xdf,0x4c,0xcb,0xc2,0x34,0x7e,0x76,0x05,0x6d,0xb7,0xa9,0x31,0xd1,0x17,0x04,0xd7,
	0x14,0x58,0x3a,0x61,0xde,0x1b,0x11,0x1c,0x32,0x0f,0x9c,0x16,0x53,0x18,0xf2,0x22,
	0xfe,0x44,0xcf,0xb2,0xc3,0xb5,0x7a,0x91,0x24,0x08,0xe8,0xa8,0x60,0xfc,0x69,0x50,
	0xaa,0xd0,0xa0,0x7d,0xa1,0x89,0x62,0x97,0x54,0x5b,0x1e,0x95,0xe0,0xff,0x64,0xd2,
	0x10,0xc4,0x00,0x48,0xa3,0xf7,0x75,0xdb,0x8a,0x03,0xe6,0xda,0x09,0x3f,0xdd,0x94,
	0x87,0x5c,0x83,0x02,0xcd,0x4a,0x90,0x33,0x73,0x67,0xf6,0xf3,0x9d,0x7f,0xbf,0xe2,
	0x52,0x9b,0xd8,0x26,0xc8,0x37,0xc6,0x3b,0x81,0x96,0x6f,0x4b,0x13,0xbe,0x63,0x2e,
	0xe9,0x79,0xa7,0x8c,0x9f,0x6e,0xbc,0x8e,0x29,0xf5,0xf9,0xb6,0x2f,0xfd,0xb4,0x59,
	0x78,0x98,0x06,0x6a,0xe7,0x46,0x71,0xba,0xd4,0x25,0xab,0x42,0x88,0xa2,0x8d,0xfa,
	0x72,0x07,0xb9,0x55,0xf8,0xee,0xac,0x0a,0x36,0x49,0x2a,0x68,0x3c,0x38,0xf1,0xa4,
	0x40,0x28,0xd3,0x7b,0xbb,0xc9,0x43,0xc1,0x15,0xe3,0xad,0xf4,0x77,0xc7,0x80,0x9e
};

static u8 camellia_sbox2[256], camellia_sbox3[256], camellia_sbox4[256];

static void __init__ camellia_tables_init(void)
{
	unsigned int i;

	for (i = 0; i < 256; i++) {
		u8 s = camellia_sbox1[i];

		camellia_sbox2[i] = (u8)((s << 1) | (s >> 7));
		camellia_sbox3[i] = (u8)((s >> 1) | (s << 7));
		camellia_sbox4[i] = camellia_sbox1[(u8)((i << 1) | (i >> 7))];
	}
}

static const u64 camellia_sigma[6] = {
	0xa09e667f3bcc908bull, 0xb67ae8584caa73b2ull, 0xc6ef372fe94f82beull,
	0x54ff53a5f1d36f1cull, 0x10e527fade682d1dull, 0xb05688c2b3e6c1fdull
};

static u64
camellia_f(u64 in, u64 ke)
{
	u64 x = in ^ ke;
	u8 t[8], y[8];
	unsigned int i;

	for (i = 0; i < 8; i++)
		t[i] = (u8)(x >> (56 - 8 * i));
	t[0] = camellia_sbox1[t[0]];
	t[1] = camellia_sbox2[t[1]];
	t[2] = camellia_sbox3[t[2]];
	t[3] = camellia_sbox4[t[3]];
	t[4] = camellia_sbox2[t[4]];
	t[5] = camellia_sbox3[t[5]];
	t[6] = camellia_sbox4[t[6]];
	t[7] = camellia_sbox1[t[7]];

	y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
	y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
	y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
	y[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
	y[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
	y[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
	y[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
	y[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];

	x = 0;
	for (i = 0; i < 8; i++)
		x = (x << 8) | y[i];
	return x;
}

#define ROTL32(x, n) ((u32)(((x) << (n)) | ((x) >> (32 - (n)))))

static u64
camellia_fl(u64 in, u64 ke)
{
	u32 x1 = (u32)(in >> 32), x2 = (u32)in;
	u32 k1 = (u32)(ke >> 32), k2 = (u32)ke;

	x2 ^= ROTL32(x1 & k1, 1);
	x1 ^= (x2 | k2);
	return ((u64)x1 << 32) | x2;
}

static u64
camellia_flinv(u64 in, u64 ke)
{
	u32 y1 = (u32)(in >> 32), y2 = (u32)in;
	u32 k1 = (u32)(ke >> 32), k2 = (u32)ke;

	y1 ^= (y2 | k2);
	y2 ^= ROTL32(y1 & k1, 1);
	return ((u64)y1 << 32) | y2;
}

static void
camellia_rotl128(u64 hi, u64 lo, unsigned int n, u64 *rhi, u64 *rlo)
{
	if (n >= 64) {
		u64 t = hi; hi = lo; lo = t;
		n -= 64;
	}
	if (n) {
		*rhi = (hi << n) | (lo >> (64 - n));
		*rlo = (lo << n) | (hi >> (64 - n));
	} else {
		*rhi = hi;
		*rlo = lo;
	}
}

int
camellia_setkey(struct camellia_ctx *ctx, const u8 *key, size_t key_len)
{
	u64 kl[2], kr[2], ka[2], kb[2], d1, d2;
	unsigned int i;

	switch (key_len) {
	case 16:
		kl[0] = get_u64_be(key); kl[1] = get_u64_be(key + 8);
		kr[0] = kr[1] = 0;
		ctx->rounds = 18;
		break;
	case 24:
		kl[0] = get_u64_be(key); kl[1] = get_u64_be(key + 8);
		kr[0] = get_u64_be(key + 16); kr[1] = ~kr[0];
		ctx->rounds = 24;
		break;
	case 32:
		kl[0] = get_u64_be(key); kl[1] = get_u64_be(key + 8);
		kr[0] = get_u64_be(key + 16); kr[1] = get_u64_be(key + 24);
		ctx->rounds = 24;
		break;
	default:
		return -1;
	}

	d1 = kl[0] ^ kr[0];
	d2 = kl[1] ^ kr[1];
	d2 ^= camellia_f(d1, camellia_sigma[0]);
	d1 ^= camellia_f(d2, camellia_sigma[1]);
	d1 ^= kl[0];
	d2 ^= kl[1];
	d2 ^= camellia_f(d1, camellia_sigma[2]);
	d1 ^= camellia_f(d2, camellia_sigma[3]);
	ka[0] = d1; ka[1] = d2;

	d1 = ka[0] ^ kr[0];
	d2 = ka[1] ^ kr[1];
	d2 ^= camellia_f(d1, camellia_sigma[4]);
	d1 ^= camellia_f(d2, camellia_sigma[5]);
	kb[0] = d1; kb[1] = d2;

#define SUB(_dst, _src, _n) \
	camellia_rotl128((_src)[0], (_src)[1], (_n), &(_dst)[0], &(_dst)[1])

	if (ctx->rounds == 18) {
		u64 *k = ctx->k, *ke = ctx->ke, *kw = ctx->kw;

		SUB(kw,      kl,   0);
		SUB(k,       ka,   0);
		SUB(k + 2,   kl,  15);
		SUB(k + 4,   ka,  15);
		SUB(ke,      ka,  30);
		SUB(k + 6,   kl,  45);
		{ u64 t[2]; SUB(t, ka, 45); k[8] = t[0]; }
		{ u64 t[2]; SUB(t, kl, 60); k[9] = t[1]; }
		SUB(k + 10,  ka,  60);
		SUB(ke + 2,  kl,  77);
		SUB(k + 12,  kl,  94);
		SUB(k + 14,  ka,  94);
		SUB(k + 16,  kl, 111);
		SUB(kw + 2,  ka, 111);
	} else {
		u64 *k = ctx->k, *ke = ctx->ke, *kw = ctx->kw;

		SUB(kw,      kl,   0);
		SUB(k,       kb,   0);
		SUB(k + 2,   kr,  15);
		SUB(k + 4,   ka,  15);
		SUB(ke,      kr,  30);
		SUB(k + 6,   kb,  30);
		SUB(k + 8,   kl,  45);
		SUB(k + 10,  ka,  45);
		SUB(ke + 2,  kl,  60);
		SUB(k + 12,  kr,  60);
		SUB(k + 14,  kb,  60);
		SUB(k + 16,  kl,  77);
		SUB(ke + 4,  ka,  77);
		SUB(k + 18,  kr,  94);
		SUB(k + 20,  ka,  94);
		SUB(k + 22,  kl, 111);
		SUB(kw + 2,  kb, 111);
	}
#undef SUB
	(void)i;
	return 0;
}

static void
camellia_crypt_block(const struct camellia_ctx *ctx, int dec, const u8 *in,
                     u8 *out)
{
	u64 d1 = get_u64_be(in), d2 = get_u64_be(in + 8);
	unsigned int n = ctx->rounds, groups = n / 6, g, r;
	unsigned int nke = groups - 1;

	if (!dec) {
		d1 ^= ctx->kw[0];
		d2 ^= ctx->kw[1];
	} else {
		d1 ^= ctx->kw[2];
		d2 ^= ctx->kw[3];
	}

	for (g = 0; g < groups; g++) {
		for (r = 0; r < 6; r++) {
			unsigned int i = g * 6 + r;
			u64 k = dec ? ctx->k[n - 1 - i] : ctx->k[i];

			if (r & 1)
				d1 ^= camellia_f(d2, k);
			else
				d2 ^= camellia_f(d1, k);
		}
		if (g + 1 < groups) {
			u64 ke1, ke2;

			if (!dec) {
				ke1 = ctx->ke[2 * g];
				ke2 = ctx->ke[2 * g + 1];
			} else {
				ke1 = ctx->ke[2 * (nke - 1 - g) + 1];
				ke2 = ctx->ke[2 * (nke - 1 - g)];
			}
			d1 = camellia_fl(d1, ke1);
			d2 = camellia_flinv(d2, ke2);
		}
	}

	if (!dec) {
		d2 ^= ctx->kw[2];
		d1 ^= ctx->kw[3];
	} else {
		d2 ^= ctx->kw[0];
		d1 ^= ctx->kw[1];
	}
	put_u64_be(out, d2);
	put_u64_be(out + 8, d1);
}

void
camellia_encrypt_block(const struct camellia_ctx *ctx, const u8 *in, u8 *out)
{
	camellia_crypt_block(ctx, 0, in, out);
}

void
camellia_decrypt_block(const struct camellia_ctx *ctx, const u8 *in, u8 *out)
{
	camellia_crypt_block(ctx, 1, in, out);
}

int
camellia_cbc_init_ctx_iv(struct camellia_ctx *ctx, const u8 *key,
                         size_t key_len, const u8 *iv)
{
	if (camellia_setkey(ctx, key, key_len))
		return -1;
	if (iv)
		memcpy(ctx->Iv, iv, CAMELLIA_BLOCKLEN);
	else
		memset(ctx->Iv, 0, CAMELLIA_BLOCKLEN);
	return 0;
}

void
camellia_cbc_encrypt(struct camellia_ctx *ctx, u8 *buf, u32 length)
{
	unsigned int i;

	for (; length >= CAMELLIA_BLOCKLEN;
	     length -= CAMELLIA_BLOCKLEN, buf += CAMELLIA_BLOCKLEN) {
		for (i = 0; i < CAMELLIA_BLOCKLEN; i++)
			buf[i] ^= ctx->Iv[i];
		camellia_encrypt_block(ctx, buf, buf);
		memcpy(ctx->Iv, buf, CAMELLIA_BLOCKLEN);
	}
}

void
camellia_cbc_decrypt(struct camellia_ctx *ctx, u8 *buf, u32 length)
{
	u8 next[CAMELLIA_BLOCKLEN];
	unsigned int i;

	for (; length >= CAMELLIA_BLOCKLEN;
	     length -= CAMELLIA_BLOCKLEN, buf += CAMELLIA_BLOCKLEN) {
		memcpy(next, buf, CAMELLIA_BLOCKLEN);
		camellia_decrypt_block(ctx, buf, buf);
		for (i = 0; i < CAMELLIA_BLOCKLEN; i++)
			buf[i] ^= ctx->Iv[i];
		memcpy(ctx->Iv, next, CAMELLIA_BLOCKLEN);
	}
}
