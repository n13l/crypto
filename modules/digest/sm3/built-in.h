#ifndef __OSS_CRYPTO_SM3_GENERIC_BUILT_IN_H__
#define __OSS_CRYPTO_SM3_GENERIC_BUILT_IN_H__

#define __CRYPTO_DIGEST_SM3_H__
#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE  64
#define HAVE_DIGEST_SM3_BUILT_IN 1

#ifndef CONFIG_SILENT
#define DIGEST_SM3_IMPL_DESC "generic"
#endif

/* the context, in both builds: hmac/sm3, hkdf/sm3 and prf/sm3 keep one on
 * the stack and are compiled whichever way this is (decl.h says the rest) */
#include "decl.h"

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

void sm3_init(struct sm3 *ctx);
void sm3_update(struct sm3 *ctx, const u8 *buf, unsigned int len);
void sm3_final(struct sm3 *ctx, u8 *digest);
void sm3_hash(const u8 *buf, unsigned int len, u8 *out);

#else

#define SM3_SCOPE static inline
#include "sm3.c"

#endif

#define __CRYPTO_ARCH_SM3_H__

static inline void
arch_sm3_init(struct sm3 *c) { sm3_init(c); }

static inline void
arch_sm3_update(struct sm3 *c, const u8 *d, unsigned int l)
{ sm3_update(c, d, l); }

static inline void
arch_sm3_final(struct sm3 *c, u8 *o) { sm3_final(c, o); }

#endif
