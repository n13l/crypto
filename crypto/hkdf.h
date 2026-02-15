#ifndef __CRYPTO_HKDF_H__
#define __CRYPTO_HKDF_H__

#include <hpc/compiler.h>
#include <crypto/digest.h>

enum algorithm_hkdf {
	HKDF_NONE = 0,
	HKDF_SHA1,
	HKDF_SHA224,
	HKDF_SHA256,
	HKDF_SHA384,
	HKDF_SHA512,
	HKDF_SHA3_224,
	HKDF_SHA3_256,
	HKDF_SHA3_384,
	HKDF_SHA3_512,
	HKDF_LAST
};

typedef void (*hkdf_extract_fn)(u8 *, unsigned int, const u8 *, unsigned int,
				const u8 *, unsigned int);
typedef int (*hkdf_expand_fn)(u8 *, unsigned int, const u8 *, unsigned int,
			      const u8 *, unsigned int);
typedef int (*hkdf_fn)(u8 *, unsigned int, const u8 *, unsigned int,
		       const u8 *, unsigned int, const u8 *, unsigned int);

struct hkdf_algorithm {
	unsigned int prk_size;
	unsigned int max_output_size;
	const char *name;
	const char *desc;
	unsigned int id;
	hkdf_extract_fn extract;
	hkdf_expand_fn expand;
	hkdf_fn hkdf;
};

void crypto_hkdf_register(struct hkdf_algorithm *alg);
struct hkdf_algorithm *crypto_hkdf_by_id(unsigned int id);

#if !defined(CONFIG_MODULES) && !defined(__CRYPTO_HKDF_MODULE__)
#define __CRYPTO_HKDF_BUILT_IN_READY__
#ifdef CONFIG_CRYPTO_HKDF_SHA1
#include <modules/hkdf/sha1/built-in.h>
#endif
#ifdef CONFIG_CRYPTO_HKDF_SHA2
#include <modules/hkdf/sha2/built-in.h>
#endif
#ifdef CONFIG_CRYPTO_HKDF_SHA3
#include <modules/hkdf/sha3/built-in.h>
#endif
#undef __CRYPTO_HKDF_BUILT_IN_READY__
#endif

#endif
