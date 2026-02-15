/*
 * What every includer of a SHA-2 backend's built-in.h gets, and in a size build
 * all it gets.
 *
 * The eight functions below are the digest as the rest of the tree calls it:
 * <crypto/digest.h> dispatches to them, hmac_sha256(), the HKDF expand, the TLS
 * key schedule and the record layer reach them through that, and each assembly
 * backend supplies the compression functions they call. Their bodies are in
 * <modules/digest/sha2-arch/arch.h>, shared by every one of those backends.
 *
 * Optimizing for speed the backend's built-in.h includes that file too, the
 * bodies are static inlines, and every caller carries a copy with the assembly
 * call the only thing left of the boundary. That is what an inlined digest is
 * for and it is the default; CC_SZ_DEFINE is nothing at all in that build and
 * these lines vanish.
 *
 * Optimizing for size the bodies are compiled exactly once, by
 * <modules/digest/sha2-arch/arch.c> - a file whose entire content is the
 * include of the backend's built-in.h - which the backend's Kbuild builds as
 * arch.o for that build only. Every other includer stops here and calls them.
 * CC_SZ_DEFINE at the declaration and CC_SZ_DECLARE at the definition are the
 * two halves of it (<hpc/compiler.h>); modules/net/tls/module.h is the same
 * seam a layer up.
 */
#ifndef __CRYPTO_DIGEST_SHA2_ARCH_DECL_H__
#define __CRYPTO_DIGEST_SHA2_ARCH_DECL_H__

#include <hpc/compiler.h>

struct sha256;
struct sha512;

CC_SZ_DEFINE(void arch_sha224_init(struct sha256 *c));
CC_SZ_DEFINE(void arch_sha256_init(struct sha256 *c));
CC_SZ_DEFINE(void arch_sha384_init(struct sha512 *c));
CC_SZ_DEFINE(void arch_sha512_init(struct sha512 *c));
CC_SZ_DEFINE(void arch_sha256_update(struct sha256 *c, const u8 *data,
                                     unsigned int len));
CC_SZ_DEFINE(void arch_sha256_final(struct sha256 *c, u8 *md));
CC_SZ_DEFINE(void arch_sha512_update(struct sha512 *c, const u8 *data,
                                     unsigned int len));
CC_SZ_DEFINE(void arch_sha512_final(struct sha512 *c, u8 *md));

#endif
