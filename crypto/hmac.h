#ifndef __CRYPTO_HMAC_H__
#define __CRYPTO_HMAC_H__

#include <hpc/compiler.h>
#include <crypto/digest.h>

#define HMAC_CTXT_SIZE_MAX 2560

enum algorithm_hmac {
	HMAC_NONE = 0,
	HMAC_SHA1,
	HMAC_SHA224,
	HMAC_SHA256,
	HMAC_SHA384,
	HMAC_SHA512,
	HMAC_SHA3_224,
	HMAC_SHA3_256,
	HMAC_SHA3_384,
	HMAC_SHA3_512,
	HMAC_LAST
};

struct hmac_context {
	u8 data[HMAC_CTXT_SIZE_MAX] _align_max;
};

typedef void (*hmac_fn)(struct hmac_context *, const u8 *, unsigned int,
			const u8 *, unsigned int, u8 *, unsigned int);
typedef void (*hmac_vector_fn)(struct hmac_context *, const u8 *, unsigned int,
			       unsigned int, const u8 **, unsigned int *,
			       u8 *, unsigned int);

struct hmac_algorithm {
	unsigned int msg_size;
	unsigned int blk_size;
	unsigned int mac_size;
	unsigned int ctx_size;
	const char *name;
	const char *desc;
	unsigned int id;
	void (*init)(struct hmac_context *, const u8 *, unsigned int);
	void (*reinit)(struct hmac_context *);
	void (*update)(struct hmac_context *, const u8 *, unsigned int);
	void (*final)(struct hmac_context *, u8 *, unsigned int);
	hmac_fn hmac;
	hmac_vector_fn vector;
};

void crypto_hmac_register(struct hmac_algorithm *alg);
struct hmac_algorithm *crypto_hmac_by_id(unsigned int id);

#if !defined(CONFIG_MODULES) && !defined(__CRYPTO_HMAC_MODULE__)
#define __CRYPTO_HMAC_BUILT_IN_READY__
#ifdef CONFIG_CRYPTO_HMAC_SHA1
#include <modules/hmac/sha1/built-in.h>
#endif
#ifdef CONFIG_CRYPTO_HMAC_SHA2
#include <modules/hmac/sha2/built-in.h>
#endif
#ifdef CONFIG_CRYPTO_HMAC_SHA3
#include <modules/hmac/sha3/built-in.h>
#endif
#undef __CRYPTO_HMAC_BUILT_IN_READY__
#endif

#endif
