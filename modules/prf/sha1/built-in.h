#ifdef __CRYPTO_PRF_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_PRF_SHA1_BUILT_IN_H__
#define __OSS_CRYPTO_PRF_SHA1_BUILT_IN_H__

#define HAVE_PRF_SHA1_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

void prf_sha1(struct prf_context *prf,
	      const u8 *secret, unsigned int secret_len,
	      const u8 *seed1, unsigned int seed1_len,
	      const u8 *seed2, unsigned int seed2_len,
	      u8 *output, unsigned int output_len);

#else

#define PRF_SHA1_SCOPE static inline
#include "sha1.c"
#undef PRF_SHA1_SCOPE

#endif

#endif

#endif
