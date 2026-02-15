/*
 * What every includer of a SHA-3 backend's built-in.h gets, and in a size build
 * all it gets.
 *
 * The seven functions below are the digest as the rest of the tree calls it:
 * <crypto/digest.h> dispatches to them and hmac_sha3_256() and the SHA-3 PRF
 * reach them through that. Every SHA-3 backend declares them through this file;
 * the bodies in <modules/digest/sha3-arch/arch.h> are shared by the ones whose
 * assembly is the Keccak permutation alone, which is all of them but
 * sha3-ossl-x86_64-avx2 - that one absorbs whole blocks in assembly and keeps
 * its own bodies in its built-in.h, behind the same guard.
 *
 * Optimizing for speed the backend's built-in.h includes the bodies too, they
 * are static inlines, and every caller carries a copy with the permutation call
 * the only thing left of the boundary. That is what an inlined digest is for
 * and it is the default; CC_SZ_DEFINE is nothing at all in that build and these
 * lines vanish.
 *
 * Optimizing for size the bodies are compiled exactly once, by
 * <modules/digest/sha3-arch/arch.c> - a file whose entire content is the
 * include of the backend's built-in.h - which the backend's Kbuild builds as
 * arch.o for that build only. Every other includer stops here and calls them,
 * and the permutation goes with the bodies: keccakf1600.c is a vendored
 * implementation in the OpenSSL backends, which is a whole permutation per
 * object when the sponge is inline and one when it is not.
 * CC_SZ_DEFINE at the declaration and CC_SZ_DECLARE at the definition are the
 * two halves of it (<hpc/compiler.h>); modules/net/tls/module.h is the same
 * seam a layer up.
 */
#ifndef __CRYPTO_DIGEST_SHA3_ARCH_DECL_H__
#define __CRYPTO_DIGEST_SHA3_ARCH_DECL_H__

#include <hpc/compiler.h>

struct sha3;

CC_SZ_DEFINE(void arch_sha3_init(struct sha3 *sha3, unsigned int digest_sz));
CC_SZ_DEFINE(void arch_sha3_224_init(struct sha3 *sha3));
CC_SZ_DEFINE(void arch_sha3_256_init(struct sha3 *sha3));
CC_SZ_DEFINE(void arch_sha3_384_init(struct sha3 *sha3));
CC_SZ_DEFINE(void arch_sha3_512_init(struct sha3 *sha3));
CC_SZ_DEFINE(int arch_sha3_update(struct sha3 *sha3, const u8 *data,
                                  unsigned int len));
CC_SZ_DEFINE(void arch_sha3_final(struct sha3 *sha3, u8 *out));

#endif
