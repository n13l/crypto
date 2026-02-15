#ifdef __CRYPTO_HKDF_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HKDF_SHA3_BUILT_IN_H__
#define __OSS_CRYPTO_HKDF_SHA3_BUILT_IN_H__

#define HAVE_HKDF_SHA3_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

#define HKDF_SHA3_DECLARE(_name) \
void _name##_extract(u8 *prk, unsigned int prk_len, \
		     const u8 *salt, unsigned int salt_len, \
		     const u8 *ikm, unsigned int ikm_len); \
int _name##_expand(u8 *okm, unsigned int okm_len, \
		   const u8 *prk, unsigned int prk_len, \
		   const u8 *info, unsigned int info_len); \
int _name(u8 *okm, unsigned int okm_len, \
	  const u8 *ikm, unsigned int ikm_len, \
	  const u8 *salt, unsigned int salt_len, \
	  const u8 *info, unsigned int info_len)

HKDF_SHA3_DECLARE(hkdf_sha3_224);
HKDF_SHA3_DECLARE(hkdf_sha3_256);
HKDF_SHA3_DECLARE(hkdf_sha3_384);
HKDF_SHA3_DECLARE(hkdf_sha3_512);

#undef HKDF_SHA3_DECLARE

#else

#define HKDF_SHA3_SCOPE static inline
#include "sha3.c"
#undef HKDF_SHA3_SCOPE

#endif

#endif

#endif
