#ifndef __MODULES_DIGEST_SHA1_H__
#define __MODULES_DIGEST_SHA1_H__

#include <hpc/compiler.h>

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64

struct sha1 {
	u32          h0, h1, h2, h3, h4;
	u32          Nl, Nh;
	u32          data[16];
	unsigned int num;
};

#endif

#ifndef __CRYPTO_ARCH_SHA1_H__
#define __CRYPTO_ARCH_SHA1_H__

struct sha1;

static inline void
arch_sha1_160_init(struct sha1 *c)
{
}

static inline void
arch_sha1_160_update(struct sha1 *c, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha1_160_final(struct sha1 *c, u8 *out)
{
}

#endif
