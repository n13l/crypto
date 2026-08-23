#ifdef __CRYPTO_HKDF_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HKDF_SM3_BUILT_IN_H__
#define __OSS_CRYPTO_HKDF_SM3_BUILT_IN_H__

#define HAVE_HKDF_SM3_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

void hkdf_sm3_extract(u8 *prk, unsigned int prk_len,
		      const u8 *salt, unsigned int salt_len,
		      const u8 *ikm, unsigned int ikm_len);
int hkdf_sm3_expand(u8 *okm, unsigned int okm_len,
		    const u8 *prk, unsigned int prk_len,
		    const u8 *info, unsigned int info_len);
int hkdf_sm3(u8 *okm, unsigned int okm_len,
	     const u8 *ikm, unsigned int ikm_len,
	     const u8 *salt, unsigned int salt_len,
	     const u8 *info, unsigned int info_len);

#else

#define HKDF_SM3_SCOPE static inline
#include "sm3.c"
#undef HKDF_SM3_SCOPE

#endif

#endif

#endif
