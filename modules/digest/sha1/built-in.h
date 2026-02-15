#ifndef __OSS_CRYPTO_SHA1_GENERIC_BUILT_IN_H__
#define __OSS_CRYPTO_SHA1_GENERIC_BUILT_IN_H__

#define __CRYPTO_DIGEST_SHA1_H__
#define __MODULES_DIGEST_SHA1_H__
#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64
#define HAVE_DIGEST_SHA1_BUILT_IN 1

#ifndef CONFIG_SILENT
#define DIGEST_SHA1_IMPL_DESC "generic"
#endif

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

struct sha1;

void sha1_init(struct sha1 *ctx);
void sha1_update(struct sha1 *ctx, const u8 *buf, unsigned int len);
void sha1_final(struct sha1 *ctx, u8 *digest);
void sha1_hash(const u8 *buf, unsigned int len, u8 *out);

#else

#define SHA1_SCOPE static inline
#include "sha1.c"

#endif

#define __CRYPTO_ARCH_SHA1_H__

static inline void
arch_sha1_160_init(struct sha1 *c) { sha1_init(c); }

static inline void
arch_sha1_160_update(struct sha1 *c, const u8 *d, unsigned int l)
{ sha1_update(c, d, l); }

static inline void
arch_sha1_160_final(struct sha1 *c, u8 *o) { sha1_final(c, o); }

#endif
