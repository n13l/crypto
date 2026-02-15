#ifndef __OSS_CRYPTO_SHA3_NULL_BUILT_IN_H__
#define __OSS_CRYPTO_SHA3_NULL_BUILT_IN_H__
#define __MODULES_DIGEST_SHA3_H__
#define __CRYPTO_ARCH_SHA3_H__

#ifndef CONFIG_SILENT
#define DIGEST_SHA3_IMPL_DESC "none"
#endif

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)
#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)
#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)
#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

struct sha3;

static inline void
arch_sha3_init(struct sha3 *sha3, unsigned int digest_sz)
{
}

static inline void
arch_sha3_224_init(struct sha3 *sha3)
{
}

static inline void
arch_sha3_224_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha3_224_final(struct sha3 *sha3, u8 *out)
{
}

static inline void
arch_sha3_256_init(struct sha3 *sha3)
{
}

static inline void
arch_sha3_256_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha3_256_final(struct sha3 *sha3, u8 *out)
{
}

static inline void
arch_sha3_384_init(struct sha3 *sha3)
{
}

static inline void
arch_sha3_384_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha3_384_final(struct sha3 *sha3, u8 *out)
{
}

static inline void
arch_sha3_512_init(struct sha3 *sha3)
{
}

static inline void
arch_sha3_512_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha3_512_final(struct sha3 *sha3, u8 *out)
{
}

#endif
