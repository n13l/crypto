/*
 * The context layouts, apart from the implementation.
 *
 * A caller keeps one of these of its own - on its stack, usually - whichever
 * way the code that operates on it was built, so the layouts have to be
 * visible in every build. Without CONFIG_CC_OPTIMIZE_FOR_SIZE that comes for
 * free: built-in.h includes sha2.c and gets the definitions with the bodies.
 * With it the bodies are out of line in sha2.o and built-in.h declares the
 * functions only, and this is what it includes instead so a context is still
 * a complete type.
 *
 * The digest contexts these are built from come from <crypto/digest.h>, which
 * every includer has already read - module.c redirects those names at its own
 * digest before including sha2.c, and would redirect them inside that header
 * too if it were first read from here.
 */
#ifndef __OSS_CRYPTO_HMAC_SHA2_CTX_H__
#define __OSS_CRYPTO_HMAC_SHA2_CTX_H__

#include <hpc/compiler.h>
#include <crypto/digest.h>

typedef struct hmac_sha224_ctx {
    struct sha256 ctx_inside;
    struct sha256 ctx_outside;
    struct sha256 ctx_inside_reinit;
    struct sha256 ctx_outside_reinit;
    u8 block_ipad[SHA224_BLOCK_SIZE];
    u8 block_opad[SHA224_BLOCK_SIZE];
} hmac_sha224_ctx;

typedef struct hmac_sha256_ctx {
    struct sha256 ctx_inside;
    struct sha256 ctx_outside;
    struct sha256 ctx_inside_reinit;
    struct sha256 ctx_outside_reinit;
    u8 block_ipad[SHA256_BLOCK_SIZE];
    u8 block_opad[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx;

typedef struct hmac_sha384_ctx {
    struct sha512 ctx_inside;
    struct sha512 ctx_outside;
    struct sha512 ctx_inside_reinit;
    struct sha512 ctx_outside_reinit;
    u8 block_ipad[SHA384_BLOCK_SIZE];
    u8 block_opad[SHA384_BLOCK_SIZE];
} hmac_sha384_ctx;

typedef struct hmac_sha512_ctx {
    struct sha512 ctx_inside;
    struct sha512 ctx_outside;
    struct sha512 ctx_inside_reinit;
    struct sha512 ctx_outside_reinit;
    u8 block_ipad[SHA512_BLOCK_SIZE];
    u8 block_opad[SHA512_BLOCK_SIZE];
} hmac_sha512_ctx;

#endif
