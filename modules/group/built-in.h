#ifdef __CRYPTO_GROUP_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_GROUP_BUILT_IN_H__
#define __OSS_CRYPTO_GROUP_BUILT_IN_H__

#define HAVE_CRYPTO_GROUP_BUILT_IN 1

/* In built-in mode the selected backend's group table is compiled into the
 * image and registered by its __init__ constructor; the registry API declared
 * in <crypto/ecc.h> is the interface. No inline free-function surface is
 * needed here (unlike the cipher/digest primitives). */

#endif

#endif
