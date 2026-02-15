#ifndef __MODULES_DIGEST_SHA3_H__
#define __MODULES_DIGEST_SHA3_H__

#include <hpc/compiler.h>

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)
#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)
#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)
#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

struct sha3 {
	u64             st[25];
	unsigned int    md_len;
	unsigned int    rsiz;
	unsigned int    rsizw;
	unsigned int    partial;
	u8              buf[SHA3_224_BLOCK_SIZE];
};

#endif

#ifndef __CRYPTO_ARCH_SHA3_H__
#define __CRYPTO_ARCH_SHA3_H__

struct sha3;

static inline void
arch_sha3_init(struct sha3 *sha3, unsigned int digest_sz)
{
}

static inline int
arch_sha3_256_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
	return 0;
}

static inline void
arch_sha3_256_final(struct sha3 *sha3, u8 *out)
{
}

#define arch_sha3_224_update arch_sha3_256_update
#define arch_sha3_224_final  arch_sha3_256_final
#define arch_sha3_384_update arch_sha3_256_update
#define arch_sha3_384_final  arch_sha3_256_final
#define arch_sha3_512_update arch_sha3_256_update
#define arch_sha3_512_final  arch_sha3_256_final

#endif
