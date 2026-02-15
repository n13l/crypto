/*
 * The one translation unit of a SHA-1 backend's block glue, and nothing else.
 *
 * Compiled once per backend rather than once: it is the backend's built-in.h
 * that this includes, resolved through the -I the backend's Kbuild gives this
 * object (modules/cipher/aes-ccm/ccm.c is the same arrangement, a mode written
 * once and compiled against each backend's block cipher). The object lands in
 * the backend's directory as arch.o.
 *
 * The Kbuild builds it only under CONFIG_CC_OPTIMIZE_FOR_SIZE. In that build
 * built-in.h hands every other includer the declarations in decl.h and keeps
 * the bodies in arch.h behind __CRYPTO_DIGEST_SHA1_ARCH__, which is defined
 * here and nowhere else, so the glue exists once in the image and every caller
 * of a digest calls it instead of carrying a copy.
 *
 * Optimizing for speed this file is not built at all: every includer of
 * built-in.h has the bodies as static inlines, which is the point of that
 * build. decl.h says the rest of it.
 */
#define __CRYPTO_DIGEST_SHA1_ARCH__
#include "built-in.h"
