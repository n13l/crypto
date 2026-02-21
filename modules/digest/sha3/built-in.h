#ifndef __OSS_CRYPTO_SHA3_GENERIC_BUILT_IN_H__
#define __OSS_CRYPTO_SHA3_GENERIC_BUILT_IN_H__

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)
#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)
#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)
#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

#define __CRYPTO_DIGEST_SHA3_H__
#define __MODULES_DIGEST_SHA3_H__
#define HAVE_DIGEST_SHA3_BUILT_IN 1

#ifndef CONFIG_SILENT
#define DIGEST_SHA3_IMPL_DESC "generic"
#endif

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

struct sha3_ctx;

void sha3_224_init(struct sha3_ctx *sctx);
void sha3_256_init(struct sha3_ctx *sctx);
void sha3_384_init(struct sha3_ctx *sctx);
void sha3_512_init(struct sha3_ctx *sctx);
int sha3_update(struct sha3_ctx *sctx, const u8 *data, unsigned int len);
void sha3_final(struct sha3_ctx *sctx);

#else

#define SHA3_SCOPE static inline
#include "sha3.c"

#endif

#define __CRYPTO_ARCH_SHA3_H__

struct sha3;

static inline void
arch_sha3_init(struct sha3 *s, unsigned int digest_sz)
{ sha3_init((struct sha3_ctx *)s, digest_sz); }

static inline int
arch_sha3_256_update(struct sha3 *s, const u8 *d, unsigned int l)
{ return sha3_update((struct sha3_ctx *)s, d, l); }

static inline void
arch_sha3_256_final(struct sha3 *s, u8 *out)
{
	struct sha3_ctx *c = (struct sha3_ctx *)s;
	c->sha = out;
	sha3_final(c);
}

#endif
