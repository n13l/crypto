#ifndef __CRYPTO_PRF_H__
#define __CRYPTO_PRF_H__

#include <hpc/compiler.h>
#include <crypto/digest.h>

#define PRF_CTXT_SIZE_MAX 2560

enum algorithm_prf {
	PRF_NONE = 0,
	PRF_SHA1,
	PRF_SHA224,
	PRF_SHA256,
	PRF_SHA384,
	PRF_SHA512,
	PRF_SHA3_224,
	PRF_SHA3_256,
	PRF_SHA3_384,
	PRF_SHA3_512,
	PRF_LAST
};

struct prf_context {
	u8 data[PRF_CTXT_SIZE_MAX] _align_max;
};

/*
 * TLS 1.2 pseudo-random function (RFC 5246, Section 5):
 * P_hash(secret, seed1 + seed2) expanded to output_len bytes.
 */
typedef void (*prf_derive_fn)(struct prf_context *,
			      const u8 *secret, unsigned int secret_len,
			      const u8 *seed1, unsigned int seed1_len,
			      const u8 *seed2, unsigned int seed2_len,
			      u8 *output, unsigned int output_len);

struct prf_algorithm {
	unsigned int msg_size;
	unsigned int ctx_size;
	const char *name;
	const char *desc;
	unsigned int id;
	prf_derive_fn derive;
};

void crypto_prf_register(struct prf_algorithm *alg);
struct prf_algorithm *crypto_prf_by_id(unsigned int id);

#if !defined(CONFIG_MODULES) && !defined(__CRYPTO_PRF_MODULE__)
#define __CRYPTO_PRF_BUILT_IN_READY__
#ifdef CONFIG_CRYPTO_PRF_SHA1
#include <modules/prf/sha1/built-in.h>
#endif
#ifdef CONFIG_CRYPTO_PRF_SHA2
#include <modules/prf/sha2/built-in.h>
#endif
#ifdef CONFIG_CRYPTO_PRF_SHA3
#include <modules/prf/sha3/built-in.h>
#endif
#undef __CRYPTO_PRF_BUILT_IN_READY__
#endif

#endif
