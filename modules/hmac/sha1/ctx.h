/*
 * The context layout, apart from the implementation.
 *
 * A caller keeps one of these of its own - on its stack, usually - whichever
 * way the code that operates on it was built, so the layout has to be visible
 * in every build. Without CONFIG_CC_OPTIMIZE_FOR_SIZE that comes for free:
 * built-in.h includes sha1.c and gets the definition with the bodies. With it
 * the bodies are out of line in sha1.o and built-in.h declares the functions
 * only, and this is what it includes instead so a context is still a complete
 * type.
 *
 * The digest context this is built from comes from <crypto/digest.h>, which
 * every includer has already read - module.c redirects that name at its own
 * digest before including sha1.c, and would redirect it inside that header
 * too if it were first read from here.
 */
#ifndef __OSS_CRYPTO_HMAC_SHA1_CTX_H__
#define __OSS_CRYPTO_HMAC_SHA1_CTX_H__

#include <hpc/compiler.h>
#include <crypto/digest.h>

typedef struct hmac_sha1_ctx {
    struct sha1 ctx_inside;
    struct sha1 ctx_outside;
    struct sha1 ctx_inside_reinit;
    struct sha1 ctx_outside_reinit;
    u8 block_ipad[SHA1_BLOCK_SIZE];
    u8 block_opad[SHA1_BLOCK_SIZE];
} hmac_sha1_ctx;

#endif
