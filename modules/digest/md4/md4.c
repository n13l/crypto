#include <sys/compiler.h>

#define MD4_DIGEST_SIZE		16
#define MD4_HMAC_BLOCK_SIZE	64
#define MD4_BLOCK_SIZE          64

struct md4 {
	u32 hash[MD4_HASH_WORDS];
	u32 block[MD4_BLOCK_WORDS];
	u64 byte_count;
};

static inline u32 lshift(u32 x, unsigned int s)
{
	x &= 0xFFFFFFFF;
	return ((x << s) & 0xFFFFFFFF) | (x >> (32 - s));
}

static inline u32 F(u32 x, u32 y, u32 z)
{
	return (x & y) | ((~x) & z);
}

static inline u32 G(u32 x, u32 y, u32 z)
{
	return (x & y) | (x & z) | (y & z);
}

static inline u32 H(u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

#define ROUND1(a,b,c,d,k,s) (a = lshift(a + F(b,c,d) + k, s))
#define ROUND2(a,b,c,d,k,s) (a = lshift(a + G(b,c,d) + k + (u32)0x5A827999,s))
#define ROUND3(a,b,c,d,k,s) (a = lshift(a + H(b,c,d) + k + (u32)0x6ED9EBA1,s))

static inline void le32_to_cpu_array(u32 *buf, unsigned int words)
{
	while (words--) {
		__le32_to_cpus(buf);
		buf++;
	}
}

static inline void cpu_to_le32_array(u32 *buf, unsigned int words)
{
	while (words--) {
		__cpu_to_le32s(buf);
		buf++;
	}
}

static void md4_transform(u32 *hash, u32 const *in)
{
	u32 a, b, c, d;

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];

	ROUND1(a, b, c, d, in[0], 3);
	ROUND1(d, a, b, c, in[1], 7);
	ROUND1(c, d, a, b, in[2], 11);
	ROUND1(b, c, d, a, in[3], 19);
	ROUND1(a, b, c, d, in[4], 3);
	ROUND1(d, a, b, c, in[5], 7);
	ROUND1(c, d, a, b, in[6], 11);
	ROUND1(b, c, d, a, in[7], 19);
	ROUND1(a, b, c, d, in[8], 3);
	ROUND1(d, a, b, c, in[9], 7);
	ROUND1(c, d, a, b, in[10], 11);
	ROUND1(b, c, d, a, in[11], 19);
	ROUND1(a, b, c, d, in[12], 3);
	ROUND1(d, a, b, c, in[13], 7);
	ROUND1(c, d, a, b, in[14], 11);
	ROUND1(b, c, d, a, in[15], 19);

	ROUND2(a, b, c, d,in[ 0], 3);
	ROUND2(d, a, b, c, in[4], 5);
	ROUND2(c, d, a, b, in[8], 9);
	ROUND2(b, c, d, a, in[12], 13);
	ROUND2(a, b, c, d, in[1], 3);
	ROUND2(d, a, b, c, in[5], 5);
	ROUND2(c, d, a, b, in[9], 9);
	ROUND2(b, c, d, a, in[13], 13);
	ROUND2(a, b, c, d, in[2], 3);
	ROUND2(d, a, b, c, in[6], 5);
	ROUND2(c, d, a, b, in[10], 9);
	ROUND2(b, c, d, a, in[14], 13);
	ROUND2(a, b, c, d, in[3], 3);
	ROUND2(d, a, b, c, in[7], 5);
	ROUND2(c, d, a, b, in[11], 9);
	ROUND2(b, c, d, a, in[15], 13);

	ROUND3(a, b, c, d,in[ 0], 3);
	ROUND3(d, a, b, c, in[8], 9);
	ROUND3(c, d, a, b, in[4], 11);
	ROUND3(b, c, d, a, in[12], 15);
	ROUND3(a, b, c, d, in[2], 3);
	ROUND3(d, a, b, c, in[10], 9);
	ROUND3(c, d, a, b, in[6], 11);
	ROUND3(b, c, d, a, in[14], 15);
	ROUND3(a, b, c, d, in[1], 3);
	ROUND3(d, a, b, c, in[9], 9);
	ROUND3(c, d, a, b, in[5], 11);
	ROUND3(b, c, d, a, in[13], 15);
	ROUND3(a, b, c, d, in[3], 3);
	ROUND3(d, a, b, c, in[11], 9);
	ROUND3(c, d, a, b, in[7], 11);
	ROUND3(b, c, d, a, in[15], 15);

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

static inline void md4_transform(struct md4 *ctx)
{
	le32_to_cpu_array(ctx->block, ARRAY_SIZE(ctx->block));
	md4_transform(ctx->hash, ctx->block);
}

int md4_init(struct shash_desc *desc)
{
	struct md4 *md4 = shash_desc_ctx(desc);

	md4->hash[0] = 0x67452301;
	md4->hash[1] = 0xefcdab89;
	md4->hash[2] = 0x98badcfe;
	md4->hash[3] = 0x10325476;
	md4->byte_count = 0;

	return 0;
}

int md4_update(struct shash_desc *desc, const u8 *data, unsigned int len)
{
	struct md4 *md4 = shash_desc_ctx(desc);
	const u32 avail = sizeof(md4->block) - (md4->byte_count & 0x3f);

	md4->byte_count += len;

	if (avail > len) {
		memcpy((char *)md4->block + (sizeof(md4->block) - avail),
		       data, len);
		return 0;
	}

	memcpy((char *)md4->block + (sizeof(md4->block) - avail),
	       data, avail);

	md4_transform(md4);
	data += avail;
	len -= avail;

	while (len >= sizeof(md4->block)) {
		memcpy(md4->block, data, sizeof(md4->block));
		md4_transform(md4);
		data += sizeof(md4->block);
		len -= sizeof(md4->block);
	}

	memcpy(md4->block, data, len);

	return 0;
}

int md4_final(struct shash_desc *desc, u8 *out)
{
	struct md4 *md4 = shash_desc_ctx(desc);
	const unsigned int offset = md4->byte_count & 0x3f;
	char *p = (char *)md4->block + offset;
	int padding = 56 - (offset + 1);

	*p++ = 0x80;
	if (padding < 0) {
		memset(p, 0x00, padding + sizeof (u64));
		md4_transform(md4);
		p = (char *)md4->block;
		padding = 56;
	}

	memset(p, 0, padding);
	md4->block[14] = md4->byte_count << 3;
	md4->block[15] = md4->byte_count >> 29;
	le32_to_cpu_array(md4->block, (sizeof(md4->block) -
	                  sizeof(u64)) / sizeof(u32));
	md4_transform(md4->hash, md4->block);
	cpu_to_le32_array(md4->hash, ARRAY_SIZE(md4->hash));
	memcpy(out, md4->hash, sizeof(md4->hash));
	memset(md4, 0, sizeof(*md4));

	return 0;
}


