#ifndef __OSS_CRYPTO_SHA3_AWS_ARMV8_BUILT_IN_H__
#define __OSS_CRYPTO_SHA3_AWS_ARMV8_BUILT_IN_H__

#define __CRYPTO_ARCH_SHA3_H__
#define __MODULES_DIGEST_SHA3_H__

#ifndef HAVE_DIGEST_SHA3_BUILT_IN
#define HAVE_DIGEST_SHA3_BUILT_IN 1
#endif

#ifndef CONFIG_SILENT
#define DIGEST_SHA3_IMPL_DESC "aws-lc, ARMv8"
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

struct sha3 {
	u64             st[25];
	unsigned int    md_len;
	unsigned int    rsiz;
	unsigned int    rsizw;
	unsigned int    partial;
	u8              buf[SHA3_224_BLOCK_SIZE];
};

/*
 * The sponge, shared by every SHA-3 backend whose assembly is the permutation
 * alone, and the permutation it calls, which goes in the same object as the
 * sponge. <modules/digest/sha3-arch/decl.h> says which build does what, and
 * why.
 */
#include <modules/digest/sha3-arch/decl.h>

#if !defined(CONFIG_CC_OPTIMIZE_FOR_SIZE) || \
    defined(__CRYPTO_DIGEST_SHA3_ARCH__)
#include "keccakf1600.c"
#include <modules/digest/sha3-arch/arch.h>
#endif

#define arch_sha3_256_update   arch_sha3_update
#define arch_sha3_256_final    arch_sha3_final

#endif
