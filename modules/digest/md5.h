/*
 * The fallback for a build with no MD5 backend, which is every default build:
 * MD5 exists here for the TLS 1.0/1.1 key schedule and nothing else
 * (md5/md5.c), so CONFIG_CRYPTO_MD5 is off unless something asked for it.
 *
 * Read through <crypto/digest.h> after <modules/built-in.h>, so a configured
 * backend has already supplied the type and defined the guard below —
 * md5/decl.h is the one that owns the layout — and this file then adds
 * nothing. It is what an unconfigured build gets instead: a complete type so a
 * caller's context still compiles, and no-op operations on it.
 */
#ifndef __MODULES_DIGEST_MD5_H__
#define __MODULES_DIGEST_MD5_H__

#include <hpc/compiler.h>

#define MD5_DIGEST_SIZE 16
#define MD5_BLOCK_SIZE  64

struct md5 {
	u32          h[4];
	u64          len;
	u8           buf[MD5_BLOCK_SIZE];
	unsigned int count;
};

#endif

/*
 * ...and the operations on it. Every caller of these is behind a
 * HAVE_DIGEST_MD5_BUILT_IN or a CONFIG_CRYPTO_MD5 of its own, so nothing reads
 * what they leave behind; they exist so that a call site does not need an
 * #ifdef to compile, which is the arrangement modules/digest/sha1.h uses for
 * the same reason.
 */
#ifndef __CRYPTO_ARCH_MD5_H__
#define __CRYPTO_ARCH_MD5_H__

struct md5;

static inline void
arch_md5_init(struct md5 *c)
{
}

static inline void
arch_md5_update(struct md5 *c, const u8 *data, unsigned int len)
{
}

static inline void
arch_md5_final(struct md5 *c, u8 *out)
{
}

#endif
