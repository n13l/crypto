#ifndef __OSS_CRYPTO_SHA1_NULL_BUILT_IN_H__
#define __OSS_CRYPTO_SHA1_NULL_BUILT_IN_H__
#define __CRYPTO_ARCH_SHA1_H__

#ifndef CONFIG_SILENT
#define DIGEST_SHA1_IMPL_DESC "null"
#endif

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64

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
