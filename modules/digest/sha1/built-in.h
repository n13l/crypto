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

/*
 * Public context type embedded by callers (and by HMAC/PRF, which hold four of
 * them by value). The generic backend reinterprets it as its own struct
 * sha1_ctx working state, so it must mirror that layout exactly; this
 * definition is why the backend defines __MODULES_DIGEST_SHA1_H__ above, since
 * it fully supersedes the fallback struct in <modules/digest/sha1.h>.
 *
 * It is defined out here rather than left to sha1.c because under
 * CONFIG_CC_OPTIMIZE_FOR_SIZE that file is a translation unit of its own and
 * is not included: the functions go out of line, but the type every caller
 * embeds cannot.
 */
struct sha1 {
	u32          h0, h1, h2, h3, h4;
	u32          nblocks;
	u8           buf[SHA1_BLOCK_SIZE];
	int          count;
	u8           hash[SHA1_DIGEST_SIZE];
};

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

void sha1_init(struct sha1 *ctx);
void sha1_update(struct sha1 *ctx, const u8 *buf, unsigned int len);
void sha1_final(struct sha1 *ctx, u8 *digest);
void sha1_hash(const u8 *buf, unsigned int len, u8 *out);

#else

#define SHA1_SCOPE static inline
#include "sha1.c"

/* both shapes are visible on this branch, so let the compiler hold them to it */
STATIC_ASSERT(sizeof(struct sha1) == sizeof(struct sha1_ctx),
              "struct sha1 must mirror the generic backend's sha1_ctx");

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
