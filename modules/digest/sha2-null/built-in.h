#ifndef __OSS_CRYPTO_SHA2_NULL_BUILT_IN_H__
#define __OSS_CRYPTO_SHA2_NULL_BUILT_IN_H__
#define __CRYPTO_ARCH_SHA2_H__

#ifndef CONFIG_SILENT
#define DIGEST_SHA2_IMPL_DESC "none"
#endif

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

#define SHA2_224_DIGEST_SIZE 28
#define SHA2_224_BLOCK_SIZE  64
#define SHA2_224_MAC_LEN     28

#define SHA2_256_DIGEST_SIZE 32
#define SHA2_256_BLOCK_SIZE  64
#define SHA2_256_MAC_LEN     32

#define SHA2_384_DIGEST_SIZE 48
#define SHA2_384_BLOCK_SIZE  128
#define SHA2_384_MAC_LEN     48

#define SHA2_512_DIGEST_SIZE 64
#define SHA2_512_BLOCK_SIZE  128

struct sha256;
struct sha512;

static inline void
arch_sha2_224_init(struct sha256 *c)
{
}

static inline void
arch_sha2_224_update(struct sha512 *c, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha2_224_final(struct sha512 *c, u8 *md)
{
}

static inline void
arch_sha2_256_init(struct sha256 *c)
{
}

static inline void
arch_sha2_256_update(struct sha512 *c, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha2_256_final(struct sha512 *c, u8 *md)
{
}

static inline void
arch_sha2_384_init(struct sha512 *c)
{
}

static inline void
arch_sha2_384_update(struct sha512 *c, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha2_384_final(struct sha512 *c, u8 *md)
{
}

static inline void
arch_sha2_512_init(struct sha512 *c)
{
}

static inline void
arch_sha2_512_update(struct sha512 *c, const u8 *data, unsigned int len)
{
}

static inline void
arch_sha2_512_final(struct sha512 *c, u8 *md)
{
}

#endif
