/*
 * What every includer of a SHA-1 backend's built-in.h gets, and in a size build
 * all it gets.
 *
 * The three functions below are the digest as the rest of the tree calls it:
 * <crypto/digest.h> dispatches to them, hmac_sha1() and the TLS 1.0/1.1 PRF
 * reach them through that, and each assembly backend supplies the compression
 * function they call. Their bodies are in <modules/digest/sha1-arch/arch.h>,
 * shared by every one of those backends.
 *
 * Optimizing for speed the backend's built-in.h includes that file too, the
 * bodies are static inlines, and every caller carries a copy with the assembly
 * call the only thing left of the boundary. That is what an inlined digest is
 * for and it is the default; CC_SZ_DEFINE is nothing at all in that build and
 * these lines vanish.
 *
 * Optimizing for size the bodies are compiled exactly once, by
 * <modules/digest/sha1-arch/arch.c> - a file whose entire content is the
 * include of the backend's built-in.h - which the backend's Kbuild builds as
 * arch.o for that build only. Every other includer stops here and calls them.
 * CC_SZ_DEFINE at the declaration and CC_SZ_DECLARE at the definition are the
 * two halves of it (<hpc/compiler.h>); modules/net/tls/module.h is the same
 * seam a layer up.
 */
#ifndef __CRYPTO_DIGEST_SHA1_ARCH_DECL_H__
#define __CRYPTO_DIGEST_SHA1_ARCH_DECL_H__

#include <hpc/compiler.h>

struct sha1;

CC_SZ_DEFINE(void arch_sha1_160_init(struct sha1 *c));
CC_SZ_DEFINE(void arch_sha1_160_update(struct sha1 *c, const u8 *data,
                                       unsigned int len));
CC_SZ_DEFINE(void arch_sha1_160_final(struct sha1 *c, u8 *out));

#endif
