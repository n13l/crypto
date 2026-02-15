
#include <hpc/compiler.h>
#include <hpc/cpu.h>
#include <hpc/mem/unaligned.h>
#include <string.h>

#ifndef SM3_SCOPE
#define SM3_SCOPE
#endif

#include "decl.h"

#define SM3_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define SM3_P0(x) ((x) ^ SM3_ROTL(x, 9) ^ SM3_ROTL(x, 17))
#define SM3_P1(x) ((x) ^ SM3_ROTL(x, 15) ^ SM3_ROTL(x, 23))

#define SM3_FF0(x, y, z) ((x) ^ (y) ^ (z))
#define SM3_FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define SM3_GG0(x, y, z) ((x) ^ (y) ^ (z))
#define SM3_GG1(x, y, z) (((x) & (y)) | (~(x) & (z)))

SM3_SCOPE void
sm3_init(struct sm3 *ctx)
{
	ctx->h[0] = 0x7380166f;
	ctx->h[1] = 0x4914b2b9;
	ctx->h[2] = 0x172442d7;
	ctx->h[3] = 0xda8a0600;
	ctx->h[4] = 0xa96f30bc;
	ctx->h[5] = 0x163138aa;
	ctx->h[6] = 0xe38dee4d;
	ctx->h[7] = 0xb0fb0e4e;
	ctx->len = 0;
	ctx->count = 0;
}

#define SM3_ROUND(ff, gg, a, b, c, d, e, f, g, h, tj, w, w1) do { \
	u32 ss1 = SM3_ROTL(SM3_ROTL(a, 12) + (e) + (tj), 7); \
	u32 ss2 = ss1 ^ SM3_ROTL(a, 12); \
	u32 tt1 = ff(a, b, c) + (d) + ss2 + (w1); \
	u32 tt2 = gg(e, f, g) + (h) + ss1 + (w); \
	(d) = (c); \
	(c) = SM3_ROTL(b, 9); \
	(b) = (a); \
	(a) = tt1; \
	(h) = (g); \
	(g) = SM3_ROTL(f, 19); \
	(f) = (e); \
	(e) = SM3_P0(tt2); \
} while (0)

static void
sm3_transform(struct sm3 *ctx, const u8 *data)
{
	u32 w[68];
	u32 a, b, c, d, e, f, g, h;
	unsigned int j;

	for (j = 0; j < 16; j++)
		w[j] = get_u32_be(data + 4 * j);
	for (j = 16; j < 68; j++)
		w[j] = SM3_P1(w[j - 16] ^ w[j - 9] ^ SM3_ROTL(w[j - 3], 15)) ^
		       SM3_ROTL(w[j - 13], 7) ^ w[j - 6];

	a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
	e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];

	for (j = 0; j < 16; j++) {
		u32 tj = SM3_ROTL(0x79cc4519u, j);

		SM3_ROUND(SM3_FF0, SM3_GG0, a, b, c, d, e, f, g, h, tj,
		          w[j], w[j] ^ w[j + 4]);
	}
	for (j = 16; j < 64; j++) {
		u32 tj = SM3_ROTL(0x7a879d8au, j & 31);

		SM3_ROUND(SM3_FF1, SM3_GG1, a, b, c, d, e, f, g, h, tj,
		          w[j], w[j] ^ w[j + 4]);
	}

	ctx->h[0] ^= a; ctx->h[1] ^= b; ctx->h[2] ^= c; ctx->h[3] ^= d;
	ctx->h[4] ^= e; ctx->h[5] ^= f; ctx->h[6] ^= g; ctx->h[7] ^= h;
}

SM3_SCOPE void
sm3_update(struct sm3 *ctx, const u8 *buf, unsigned int len)
{
	ctx->len += len;

	if (ctx->count) {
		unsigned int fill = SM3_BLK_SIZE - ctx->count;

		if (len < fill) {
			memcpy(ctx->buf + ctx->count, buf, len);
			ctx->count += len;
			return;
		}
		memcpy(ctx->buf + ctx->count, buf, fill);
		sm3_transform(ctx, ctx->buf);
		ctx->count = 0;
		buf += fill;
		len -= fill;
	}

	while (len >= SM3_BLK_SIZE) {
		sm3_transform(ctx, buf);
		buf += SM3_BLK_SIZE;
		len -= SM3_BLK_SIZE;
	}

	if (len) {
		memcpy(ctx->buf, buf, len);
		ctx->count = len;
	}
}

SM3_SCOPE void
sm3_final(struct sm3 *ctx, u8 *digest)
{
	u64 bits = ctx->len << 3;
	unsigned int i;

	ctx->buf[ctx->count++] = 0x80;
	if (ctx->count > SM3_BLK_SIZE - 8) {
		memset(ctx->buf + ctx->count, 0, SM3_BLK_SIZE - ctx->count);
		sm3_transform(ctx, ctx->buf);
		ctx->count = 0;
	}
	memset(ctx->buf + ctx->count, 0, SM3_BLK_SIZE - 8 - ctx->count);
	put_u64_be(ctx->buf + SM3_BLK_SIZE - 8, bits);
	sm3_transform(ctx, ctx->buf);

	for (i = 0; i < 8; i++)
		put_u32_be(digest + 4 * i, ctx->h[i]);
}

SM3_SCOPE void
sm3_hash(const u8 *buf, unsigned int len, u8 *out)
{
	struct sm3 ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, buf, len);
	sm3_final(&ctx, out);
}
