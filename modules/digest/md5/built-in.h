#ifndef __OSS_CRYPTO_MD5_GENERIC_BUILT_IN_H__
#define __OSS_CRYPTO_MD5_GENERIC_BUILT_IN_H__

#define __CRYPTO_DIGEST_MD5_H__
#define MD5_DIGEST_SIZE 16
#define MD5_BLOCK_SIZE  64
#define HAVE_DIGEST_MD5_BUILT_IN 1

#ifndef CONFIG_SILENT
#define DIGEST_MD5_IMPL_DESC "generic"
#endif

/* the context, in both builds: hmac/md5 and prf/tls1 keep one on the stack
 * and are compiled whichever way this is (decl.h says the rest) */
#include "decl.h"

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

void md5_init(struct md5 *ctx);
void md5_update(struct md5 *ctx, const u8 *buf, unsigned int len);
void md5_final(struct md5 *ctx, u8 *digest);
void md5_hash(const u8 *buf, unsigned int len, u8 *out);

#else

#define MD5_SCOPE static inline
#include "md5.c"

#endif

#define __CRYPTO_ARCH_MD5_H__

static inline void
arch_md5_init(struct md5 *c) { md5_init(c); }

static inline void
arch_md5_update(struct md5 *c, const u8 *d, unsigned int l)
{ md5_update(c, d, l); }

static inline void
arch_md5_final(struct md5 *c, u8 *o) { md5_final(c, o); }

#endif
