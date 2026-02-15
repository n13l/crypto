#ifndef __OSS_CRYPTO_SHA2_AWS_X86_64_BUILT_IN_H__
#define __OSS_CRYPTO_SHA2_AWS_X86_64_BUILT_IN_H__

#define __CRYPTO_ARCH_SHA2_H__
#define __MODULES_DIGEST_SHA2_H__

#ifndef HAVE_DIGEST_SHA2_BUILT_IN
#define HAVE_DIGEST_SHA2_BUILT_IN 1
#endif

#ifndef CONFIG_SILENT
#define DIGEST_SHA2_IMPL_DESC "aws-lc, x86_64"
#endif

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>
#include <string.h>

#define SHA224_DIGEST_SIZE 28
#define SHA224_BLOCK_SIZE  64
#define SHA224_MAC_LEN     28

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64
#define SHA256_MAC_LEN     32

#define SHA384_DIGEST_SIZE 48
#define SHA384_BLOCK_SIZE  128
#define SHA384_MAC_LEN     48

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128

struct sha256 {
	u32          h[8];
	u32          Nl, Nh;
	u32          data[16];
	unsigned int num, md_len;
};

struct sha512 {
	u64          h[8];
	u64          Nl, Nh;
	union {
		u64 d[16];
		u8  p[128];
	} u;
	unsigned int num, md_len;
};

extern void sha256_block_data_order_nohw(struct sha256 *ctx, const void *in, size_t num);

static inline void
sha256_block_data_order(void *ctx, const void *in, size_t num)
{
	sha256_block_data_order_nohw(ctx, in, num);
}

extern void sha512_block_data_order_nohw(struct sha512 *ctx, const void *in, size_t num);

static inline void
sha512_block_data_order(void *ctx, const void *in, size_t num)
{
	sha512_block_data_order_nohw(ctx, in, num);
}

/*
 * The block glue, shared by every SHA-2 backend and compiled either into each
 * caller or into one object: <modules/digest/sha2-arch/decl.h> says which build
 * does what, and why.
 */
#include <modules/digest/sha2-arch/decl.h>

#if !defined(CONFIG_CC_OPTIMIZE_FOR_SIZE) || \
    defined(__CRYPTO_DIGEST_SHA2_ARCH__)
#include <modules/digest/sha2-arch/arch.h>
#endif

typedef struct {
	u32          h[8];
	unsigned int len;
	unsigned int tot_len;
	u8           block[SHA256_BLOCK_SIZE * 2];
} sha256_ctx;

typedef sha256_ctx sha224_ctx;

typedef struct {
	u64          h[8];
	unsigned int len;
	unsigned int tot_len;
	u8           block[SHA512_BLOCK_SIZE * 2];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;

#define arch_sha2_224_init     arch_sha224_init
#define arch_sha2_224_update   arch_sha256_update
#define arch_sha2_224_final    arch_sha256_final
#define arch_sha2_256_init     arch_sha256_init
#define arch_sha2_256_update   arch_sha256_update
#define arch_sha2_256_final    arch_sha256_final
#define arch_sha2_384_init     arch_sha384_init
#define arch_sha2_384_update   arch_sha512_update
#define arch_sha2_384_final    arch_sha512_final
#define arch_sha2_512_init     arch_sha512_init
#define arch_sha2_512_update   arch_sha512_update
#define arch_sha2_512_final    arch_sha512_final

#define DIGEST_SHA224 SHA2_224
#define DIGEST_SHA256 SHA2_256
#define DIGEST_SHA384 SHA2_384
#define DIGEST_SHA512 SHA2_512

#endif
