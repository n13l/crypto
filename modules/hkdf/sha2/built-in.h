#ifdef __CRYPTO_HKDF_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HKDF_SHA2_BUILT_IN_H__
#define __OSS_CRYPTO_HKDF_SHA2_BUILT_IN_H__

#define HAVE_HKDF_SHA2_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

#define HKDF_SHA2_DECLARE(_name) \
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

HKDF_SHA2_DECLARE(hkdf_sha224);
HKDF_SHA2_DECLARE(hkdf_sha256);
HKDF_SHA2_DECLARE(hkdf_sha384);
HKDF_SHA2_DECLARE(hkdf_sha512);

#undef HKDF_SHA2_DECLARE

#else

#define HKDF_SHA2_SCOPE static inline
#include "sha2.c"
#undef HKDF_SHA2_SCOPE

#endif

#endif

#endif
