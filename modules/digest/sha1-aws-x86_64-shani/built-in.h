#ifndef __OSS_CRYPTO_SHA1_AWS_X86_64_SHANI_BUILT_IN_H__
#define __OSS_CRYPTO_SHA1_AWS_X86_64_SHANI_BUILT_IN_H__

#define __CRYPTO_ARCH_SHA1_H__
#define __MODULES_DIGEST_SHA1_H__

#ifndef HAVE_DIGEST_SHA1_BUILT_IN
#define HAVE_DIGEST_SHA1_BUILT_IN 1
#endif

#ifndef CONFIG_SILENT
#define DIGEST_SHA1_IMPL_DESC "aws-lc, x86_64, SHA-NI"
#endif

#include "sha1_block.c"

#include <string.h>
#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64

struct sha1 {
	u32          h0, h1, h2, h3, h4;
	u32          Nl, Nh;
	u32          data[16];
	unsigned int num;
};

static inline void
arch_sha1_160_init(struct sha1 *c)
{
	c->h0  = 0x67452301;
	c->h1  = 0xefcdab89;
	c->h2  = 0x98badcfe;
	c->h3  = 0x10325476;
	c->h4  = 0xc3d2e1f0;
	c->Nl  = 0;
	c->Nh  = 0;
	c->num = 0;
}

#ifdef HAVE_DIGEST_SHA1_BUILT_IN

static inline void
arch_sha1_160_update(struct sha1 *c, const u8 *data, unsigned int len)
{
	u8 *p = (u8 *)c->data;
	u32 l;

	l = c->Nl + (((u32)len) << 3);
	if (l < c->Nl)
		c->Nh++;
	c->Nh += (u32)(len >> 29);
	c->Nl = l;

	if (c->num > 0) {
		unsigned int n = SHA1_BLOCK_SIZE - c->num;
		if (len < n) {
			memcpy(p + c->num, data, len);
			c->num += len;
			return;
		}
		memcpy(p + c->num, data, n);
		sha1_block_data_order(c, p, 1);
		data += n;
		len  -= n;
		c->num = 0;
	}

	if (len >= SHA1_BLOCK_SIZE) {
		unsigned int n = len / SHA1_BLOCK_SIZE;
		sha1_block_data_order(c, data, n);
		n    *= SHA1_BLOCK_SIZE;
		data += n;
		len  -= n;
	}

	if (len > 0) {
		memcpy(p, data, len);
		c->num = len;
	}
}

static inline void
arch_sha1_160_final(struct sha1 *c, u8 *out)
{
	u8 *p = (u8 *)c->data;
	unsigned int n = c->num;

	p[n++] = 0x80;

	if (n > 56) {
		memset(p + n, 0, SHA1_BLOCK_SIZE - n);
		sha1_block_data_order(c, p, 1);
		n = 0;
	}

	memset(p + n, 0, 56 - n);
	put_u32_be(p + 56, c->Nh);
	put_u32_be(p + 60, c->Nl);
	sha1_block_data_order(c, p, 1);

	put_u32_be(out,      c->h0);
	put_u32_be(out + 4,  c->h1);
	put_u32_be(out + 8,  c->h2);
	put_u32_be(out + 12, c->h3);
	put_u32_be(out + 16, c->h4);
}

#else

static inline void
arch_sha1_160_update(struct sha1 *c, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha1_160_final(struct sha1 *c, u8 *out)
{
}

#endif

#endif
