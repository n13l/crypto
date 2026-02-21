#ifndef __OSS_CRYPTO_DIGEST_H__
#define __OSS_CRYPTO_DIGEST_H__

#include <hpc/compiler.h>
#include <hpc/array.h>
#include <hpc/mem/unaligned.h>
#include <crypto/digest/sha3.h>

enum digest_algorithm {
	SHA3_224 = 1,
	SHA3_256 = 2,
	SHA3_384 = 3,
	SHA3_512 = 4
};

struct digest {
	enum digest_algorithm algo;
	u8 data[512];
};

static inline void
sha3_224_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_224_DIGEST_SIZE);
}

static inline void
sha3_256_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_256_DIGEST_SIZE);
}

static inline void
sha3_384_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_384_DIGEST_SIZE);
}

static inline void
sha3_512_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_512_DIGEST_SIZE);
}

static inline int
sha3_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
	return arch_sha3_update(sha3, data, len);
}

static inline void
sha3_final(struct sha3 *sha3, u8 *out)
{
	arch_sha3_final(sha3, out);
}

static inline void
digest_init(struct digest *digest, enum digest_algorithm algo)
{
	digest->algo = algo;
}

static inline void
digest_update(struct digest *digest, const u8 *data, unsigned int len)
{
	STATIC_ARRAY_STREAMLINED(void *, dispatch, &&digest_undef,
		[SHA3_256] = &&sha3_256
	);

	goto ARRAY_STREAMLINED_AT(dispatch, digest->algo);

sha3_256:
	sha3_update((struct sha3 *)digest, data, len);
	return;
digest_undef:
	return;
}

static inline void
digest_final(struct digest *digest, u8 *out)
{
}


#endif
