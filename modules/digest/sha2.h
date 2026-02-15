#ifndef __MODULES_DIGEST_SHA2_H__
#define __MODULES_DIGEST_SHA2_H__

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

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

#endif

#ifndef __CRYPTO_ARCH_SHA2_H__
#define __CRYPTO_ARCH_SHA2_H__

struct sha256;
struct sha512;

static inline void arch_sha2_224_init(struct sha256 *c) {}
static inline void arch_sha2_256_init(struct sha256 *c) {}
static inline void arch_sha2_256_update(struct sha256 *c, const u8 *d, unsigned int l) {}
static inline void arch_sha2_256_final(struct sha256 *c, u8 *out) {}

static inline void arch_sha2_384_init(struct sha512 *c) {}
static inline void arch_sha2_512_init(struct sha512 *c) {}
static inline void arch_sha2_512_update(struct sha512 *c, const u8 *d, unsigned int l) {}
static inline void arch_sha2_512_final(struct sha512 *c, u8 *out) {}

#define arch_sha2_224_update arch_sha2_256_update
#define arch_sha2_224_final  arch_sha2_256_final
#define arch_sha2_384_update arch_sha2_512_update
#define arch_sha2_384_final  arch_sha2_512_final

#endif
