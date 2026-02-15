/*
 * The one translation unit of a SHA-3 backend's sponge, and nothing else.
 *
 * Compiled once per backend rather than once: it is the backend's built-in.h
 * that this includes, resolved through the -I the backend's Kbuild gives this
 * object (modules/cipher/aes-ccm/ccm.c is the same arrangement, a mode written
 * once and compiled against each backend's block cipher). The object lands in
 * the backend's directory as arch.o, and it is the object the permutation ends
 * up in too - built-in.h includes keccakf1600.c under the same guard.
 *
 * The Kbuild builds it only under CONFIG_CC_OPTIMIZE_FOR_SIZE. In that build
 * built-in.h hands every other includer the declarations in decl.h and keeps
 * the bodies behind __CRYPTO_DIGEST_SHA3_ARCH__, which is defined here and
 * nowhere else, so the sponge exists once in the image and every caller of a
 * digest calls it instead of carrying a copy.
 *
 * Optimizing for speed this file is not built at all: every includer of
 * built-in.h has the bodies as static inlines, which is the point of that
 * build. decl.h says the rest of it.
 *
 * sha3-ossl-x86_64-avx2 has its own bodies (see arch.h) and builds this file
 * all the same: the include is the backend's built-in.h either way, and which
 * bodies are behind the guard is the backend's business, not this file's.
 */
#define __CRYPTO_DIGEST_SHA3_ARCH__
#include "built-in.h"
