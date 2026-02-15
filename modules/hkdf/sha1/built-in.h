#ifdef __CRYPTO_HKDF_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HKDF_SHA1_BUILT_IN_H__
#define __OSS_CRYPTO_HKDF_SHA1_BUILT_IN_H__

#define HAVE_HKDF_SHA1_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

void hkdf_sha1_160_extract(u8 *prk, unsigned int prk_len,
			   const u8 *salt, unsigned int salt_len,
			   const u8 *ikm, unsigned int ikm_len);
int hkdf_sha1_160_expand(u8 *okm, unsigned int okm_len,
			 const u8 *prk, unsigned int prk_len,
			 const u8 *info, unsigned int info_len);
int hkdf_sha1_160(u8 *okm, unsigned int okm_len,
		  const u8 *ikm, unsigned int ikm_len,
		  const u8 *salt, unsigned int salt_len,
		  const u8 *info, unsigned int info_len);

#else

#define HKDF_SHA1_SCOPE static inline
#include "sha1.c"
#undef HKDF_SHA1_SCOPE

#endif

#endif

#endif
