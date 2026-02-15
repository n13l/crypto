#ifdef __CRYPTO_CIPHER_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_CIPHER_AES_BUILT_IN_H__
#define __OSS_CRYPTO_CIPHER_AES_BUILT_IN_H__

#define HAVE_CIPHER_AES_BUILT_IN 1

/* Table-based AES is always built as separate objects; the built-in
 * interface is the free-function API below. */
#include <crypto/cipher/aes.h>
#include <crypto/cipher/aes/gcm.h>

#endif

#endif
