#ifdef __CRYPTO_CIPHER_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_CIPHER_DES3_BUILT_IN_H__
#define __OSS_CRYPTO_CIPHER_DES3_BUILT_IN_H__

#define HAVE_CIPHER_DES3_BUILT_IN 1

/* Built as a separate object in both modes, like the table-based AES beside
 * it; the built-in interface is the free-function API of the header. */
#include <crypto/cipher/des3.h>

#endif

#endif
