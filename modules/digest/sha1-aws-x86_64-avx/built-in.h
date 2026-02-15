#ifndef __OSS_CRYPTO_SHA1_AWS_X86_64_AVX_BUILT_IN_H__
#define __OSS_CRYPTO_SHA1_AWS_X86_64_AVX_BUILT_IN_H__

#define __CRYPTO_ARCH_SHA1_H__
#define __MODULES_DIGEST_SHA1_H__

#ifndef HAVE_DIGEST_SHA1_BUILT_IN
#define HAVE_DIGEST_SHA1_BUILT_IN 1
#endif

#ifndef CONFIG_SILENT
#define DIGEST_SHA1_IMPL_DESC "aws-lc, x86_64, AVX"
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

/*
 * The block glue, shared by every SHA-1 backend and compiled either into each
 * caller or into one object: <modules/digest/sha1-arch/decl.h> says which build
 * does what, and why.
 */
#include <modules/digest/sha1-arch/decl.h>

#if !defined(CONFIG_CC_OPTIMIZE_FOR_SIZE) || \
    defined(__CRYPTO_DIGEST_SHA1_ARCH__)
#include <modules/digest/sha1-arch/arch.h>
#endif

#endif
