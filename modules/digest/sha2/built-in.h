#ifndef __OSS_CRYPTO_SHA2_GENERIC_BUILT_IN_H__
#define __OSS_CRYPTO_SHA2_GENERIC_BUILT_IN_H__

#define __CRYPTO_DIGEST_SHA2_H__
#define __MODULES_DIGEST_SHA2_H__
#define HAVE_DIGEST_SHA2_BUILT_IN 1

#ifndef CONFIG_SILENT
#define DIGEST_SHA2_IMPL_DESC "generic"
#endif

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

#include <hpc/compiler.h>

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

#define DIGEST_SHA224 SHA2_224
#define DIGEST_SHA256 SHA2_256
#define DIGEST_SHA384 SHA2_384
#define DIGEST_SHA512 SHA2_512

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

struct digest;

void sha224_init(struct digest *alg);
void sha224_update(struct digest *alg, const u8 *msg, unsigned int len);
void sha224_final(struct digest *alg, u8 *digest);
void sha224(const u8 *msg, unsigned int len, u8 *digest);

void sha256_init(struct digest *digest);
void sha256_update(struct digest *digest, const u8 *msg, unsigned int len);
void sha256_final(struct digest *alg, u8 *digest);
void sha256_copy(struct digest *dst, struct digest *src);
void sha256_digest(struct digest *alg, u8 *digest);
void sha256(const u8 *msg, unsigned int len, u8 *digest);

void sha384_init(struct digest *digest);
void sha384_update(struct digest *digest, const u8 *msg, unsigned int len);
void sha384_final(struct digest *alg, u8 *digest);
void sha384_copy(struct digest *dst, struct digest *src);
void sha384_digest(struct digest *alg, u8 *digest);
void sha384(const u8 *msg, unsigned int len, u8 *digest);

void sha512_init(struct digest *alg);
void sha512_update(struct digest *alg, const u8 *msg, unsigned int len);
void sha512_final(struct digest *alg, u8 *digest);
void sha512(const u8 *msg, unsigned int len, u8 *digest);

#else

#define SHA2_SCOPE static inline
#define __CRYPTO_ARCH_SHA2_H__
#include "sha2.c"

#endif

struct sha256;
struct sha512;

static inline void
arch_sha2_224_init(struct sha256 *c) { sha224_init((struct digest *)c); }

static inline void
arch_sha2_256_init(struct sha256 *c) { sha256_init((struct digest *)c); }

static inline void
arch_sha2_256_update(struct sha256 *c, const u8 *d, unsigned int l)
{ sha256_update((struct digest *)c, d, l); }

static inline void
arch_sha2_256_final(struct sha256 *c, u8 *o)
{ sha256_final((struct digest *)c, o); }

static inline void
arch_sha2_224_final(struct sha256 *c, u8 *o)
{ sha224_final((struct digest *)c, o); }

static inline void
arch_sha2_384_init(struct sha512 *c) { sha384_init((struct digest *)c); }

static inline void
arch_sha2_512_init(struct sha512 *c) { sha512_init((struct digest *)c); }

static inline void
arch_sha2_512_update(struct sha512 *c, const u8 *d, unsigned int l)
{ sha512_update((struct digest *)c, d, l); }

static inline void
arch_sha2_512_final(struct sha512 *c, u8 *o)
{ sha512_final((struct digest *)c, o); }

static inline void
arch_sha2_384_final(struct sha512 *c, u8 *o)
{ sha384_final((struct digest *)c, o); }

#define arch_sha2_224_update arch_sha2_256_update
#define arch_sha2_384_update arch_sha2_512_update

#endif
