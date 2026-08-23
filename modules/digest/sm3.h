/*
 * The fallback for a build with no SM3 backend, which is every default build:
 * SM3 exists here for the ShangMi TLS 1.3 suites of RFC 8998 (sm3/sm3.c), so
 * CONFIG_CRYPTO_SM3 is off unless something asked for it.
 *
 * Read through <crypto/digest.h> after <modules/built-in.h>, so a configured
 * backend has already supplied the type and defined the guard below —
 * sm3/decl.h is the one that owns the layout — and this file then adds
 * nothing. It is what an unconfigured build gets instead: a complete type so a
 * caller's context still compiles, and no-op operations on it. The same
 * arrangement as md5.h, for the same reason.
 */
#ifndef __MODULES_DIGEST_SM3_H__
#define __MODULES_DIGEST_SM3_H__

#include <hpc/compiler.h>

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE  64

struct sm3 {
	u32          h[8];
	u64          len;
	u8           buf[SM3_BLOCK_SIZE];
	unsigned int count;
};

#endif

/*
 * ...and the operations on it. Every caller of these is behind a
 * HAVE_DIGEST_SM3_BUILT_IN or a CONFIG_CRYPTO_SM3 of its own, so nothing reads
 * what they leave behind; they exist so that a call site does not need an
 * #ifdef to compile.
 */
#ifndef __CRYPTO_ARCH_SM3_H__
#define __CRYPTO_ARCH_SM3_H__

struct sm3;

static inline void
arch_sm3_init(struct sm3 *c)
{
}

static inline void
arch_sm3_update(struct sm3 *c, const u8 *data, unsigned int len)
{
}

static inline void
arch_sm3_final(struct sm3 *c, u8 *out)
{
}

#endif
