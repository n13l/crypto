#include <sys/compiler.h>
#include <sys/cpu.h>
#include <string.h>

#define MD5_MSG_SIZE       16
#define MD5_BLK_SIZE       64

struct md5 {
	u32 buf[4];
	u32 bits[2];
	u8 in[64];
};

#ifdef CPU_LITTLE_ENDIAN
#define u8rev(buf, len)
#else
static void
u8rev(u8 *buf, unsigned int len)
{
	do {
		u32 t = (u32) ((uint)buf[3] << 8 | buf[2]) << 16 |
		              ((uint)buf[1] << 8 | buf[0]);

		*(u32 *)buf = t;
		buf += 4;
	} while (--len);
}
#endif

static void
md5_transform(u32 buf[4], u32 const in[16]);

static void
md5_init(struct md5 *md5)
{
	md5->buf[0] = 0x67452301;
	md5->buf[1] = 0xefcdab89;
	md5->buf[2] = 0x98badcfe;
	md5->buf[3] = 0x10325476;

	md5->bits[0] = 0;
	md5->bits[1] = 0;
}

static void 
md5_update(struct md5 *md5, const u8 *buf, int len)
{
	u32 t = md5->bits[0];
	if ((md5->bits[0] = t + ((u32) len << 3)) < t)
		md5->bits[1]++;

	md5->bits[1] += len >> 29;
	t = (t >> 3) & 0x3f;

	if (t) {
		u8 *p = (u8 *) md5->in + t;

		t = MD5_BLK_SIZE - t;
		if (len < t) {
			memcpy(p, buf, len);
			return;
		}
		memcpy(p, buf, t);
		u8rev(md5->in, MD5_SIZE);
		md5_transform(md5->buf, (u32 *) md5->in);
		buf += t;
		len -= t;
	}

	while (len >= MD5_BLK_SIZE) {
		memcpy(md5->in, buf, MD5_BLK_SIZE);
		u8rev(md5->in, MD5_SIZE);
		md5_transform(md5->buf, (u32 *)md5->in);
		buf += MD5_BLK_SIZE;
		len -= MD5_BLK_SIZE;
	}

	memcpy(md5->in, buf, len);
}

static u8 *
md5_final(struct md5 *md5)
{
	unsigned int count;
	u8 *p;

	count = (md5->bits[0] >> 3) & 0x3F;

	p = md5->in + count;
	*p++ = 0x80;

	count = MD5_BLK_SIZE - 1 - count;

	if (count < 8) {
		memset(p, 0, count);
		u8rev(md5->in, MD5_SIZE);
		md5_transform(md5->buf, (u32 *) md5->in);

		memset(md5->in, 0, 56);
	} else {
		memset(p, 0, count - 8);
	}

	u8rev(md5->in, 14);

	memcpy(md5->in + 56, md5->bits, 8);
	md5_transform(md5->buf, (u32 *) md5->in);
	u8rev((u8 *) md5->buf, 4);
	return (u8 *) md5->buf;
}

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))
#define MD5STEP(f, w, x, y, z, data, s) \
               (w += f(x, y, z) + data, w = w << s | w >> (32 - s),  w += x)

static void
md5_transform(u32 buf[4], u32 const in[16])
{
	u32 a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

static void
md5_hash(const u8 *buf, int len, u8 *out)
{
	struct md5 *md5;
	md5_init(md5);
	md5_update(md5, buf, len);
	memcpy(out, md5_final(md5), MD5_SIZE);
}

static void
md5_hmac(struct md5 *md5, u8 *buf, int len, u8 *key, int klen)
{
	u8 ipad[MD5_BLK_SIZE], opad[MD5_BLK_SIZE], tk[MD5_SIZE], *digest;

	if (klen > MD5_BLK_SIZE) {
		struct md5 ctx;
		md5_init(&ctx);
		md5_update(&ctx, key, klen);
		memcpy(md5_final(&ctx), tk, MD5_SIZE);
		key = tk;
		klen = MD5_SIZE;
	}

	memset(ipad, 0, MD5_BLK_SIZE);
	memset(opad, 0, MD5_BLK_SIZE);
	memcpy(ipad, key, klen);
	memcpy(opad, key, klen);

	for (int i = 0; i < MD5_BLK_SIZE; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	md5_init(md5);
	md5_update(md5, ipad, MD5_BLK_SIZE);
	md5_update(md5, buf, len);
	digest = md5_final(md5);

	md5_init(md5);
	md5_update(md5, opad, MD5_BLK_SIZE);
	md5_update(md5, digest, MD5_SIZE);
}

struct digest_algorithm md5_160 = {
	.msg_size = MD5_MSG_SIZE,
	.blk_size = MD5_BLK_SIZE,
	.ctx_size = sizeof(struct md5),
	.name = "md5-generic",
	.id = DIGEST_MD5,
	.init = md5_init,
	.update = md5_update,
	.final = md5_final,
	.hash = md5_hash,
	.zero_hash = md5_zero
};

static void __init__ digest_md5_init(void)
{
	crypto_digest_register(&md5_160);
}
