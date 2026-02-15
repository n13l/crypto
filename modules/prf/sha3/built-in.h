#ifdef __CRYPTO_PRF_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_PRF_SHA3_BUILT_IN_H__
#define __OSS_CRYPTO_PRF_SHA3_BUILT_IN_H__

#define HAVE_PRF_SHA3_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

#define PRF_SHA3_DECLARE(_name) \
void _name(struct prf_context *prf, \
	   const u8 *secret, unsigned int secret_len, \
	   const u8 *seed1, unsigned int seed1_len, \
	   const u8 *seed2, unsigned int seed2_len, \
	   u8 *output, unsigned int output_len)

PRF_SHA3_DECLARE(prf_sha3_224);
PRF_SHA3_DECLARE(prf_sha3_256);
PRF_SHA3_DECLARE(prf_sha3_384);
PRF_SHA3_DECLARE(prf_sha3_512);

#undef PRF_SHA3_DECLARE

#else

#define PRF_SHA3_SCOPE static inline
#include "sha3.c"
#undef PRF_SHA3_SCOPE

#endif

#endif

#endif
