#ifdef __CRYPTO_CIPHER_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_CIPHER_CHACHA_BUILT_IN_H__
#define __OSS_CRYPTO_CIPHER_CHACHA_BUILT_IN_H__

#define HAVE_CIPHER_CHACHA20_BUILT_IN 1

/* ChaCha20-Poly1305 is always built as separate objects; the built-in
 * interface is the free-function API below. */
#include <crypto/cipher/chachapoly.h>

#endif

#endif
