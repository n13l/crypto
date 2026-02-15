#ifdef __CRYPTO_PRF_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_PRF_SHA2_BUILT_IN_H__
#define __OSS_CRYPTO_PRF_SHA2_BUILT_IN_H__

#define HAVE_PRF_SHA2_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

#define PRF_SHA2_DECLARE(_name) \
void _name(struct prf_context *prf, \
	   const u8 *secret, unsigned int secret_len, \
	   const u8 *seed1, unsigned int seed1_len, \
	   const u8 *seed2, unsigned int seed2_len, \
	   u8 *output, unsigned int output_len)

PRF_SHA2_DECLARE(prf_sha224);
PRF_SHA2_DECLARE(prf_sha256);
PRF_SHA2_DECLARE(prf_sha384);
PRF_SHA2_DECLARE(prf_sha512);

#undef PRF_SHA2_DECLARE

#else

#define PRF_SHA2_SCOPE static inline
#include "sha2.c"
#undef PRF_SHA2_SCOPE

#endif

#endif

#endif
