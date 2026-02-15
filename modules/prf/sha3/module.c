#define __CRYPTO_PRF_MODULE__
#include <crypto/prf.h>
#include <modules/digest/module.h>

static void
prf_module_sha3_init(struct module_digest *ctx, unsigned int digest_size)
{
	unsigned int id;

	switch (digest_size) {
	case SHA3_224_DIGEST_SIZE: id = ALGORITHM_SHA3_224; break;
	case SHA3_256_DIGEST_SIZE: id = ALGORITHM_SHA3_256; break;
	case SHA3_384_DIGEST_SIZE: id = ALGORITHM_SHA3_384; break;
	default:                   id = ALGORITHM_SHA3_512; break;
	}
	module_digest_init(ctx, id);
}

#define sha3 module_digest
#define arch_sha3_init prf_module_sha3_init
#define arch_sha3_256_update module_digest_update
#define arch_sha3_256_final module_digest_final
#define PRF_SHA3_SCOPE static
#include "sha3.c"
#undef arch_sha3_256_final
#undef arch_sha3_256_update
#undef arch_sha3_init
#undef sha3

#define PRF_SHA3_ALGORITHM(_fn, _id, _size, _name, _desc) \
static struct prf_algorithm _fn##_algorithm = { \
	.msg_size = _size, \
	.ctx_size = _size, \
	.name = _name, \
	.desc = _desc, \
	.id = _id, \
	.derive = _fn, \
}

PRF_SHA3_ALGORITHM(prf_sha3_224, PRF_SHA3_224, SHA3_224_DIGEST_SIZE,
		   "prf-sha3-224", "PRF-SHA3-224");
PRF_SHA3_ALGORITHM(prf_sha3_256, PRF_SHA3_256, SHA3_256_DIGEST_SIZE,
		   "prf-sha3-256", "PRF-SHA3-256");
PRF_SHA3_ALGORITHM(prf_sha3_384, PRF_SHA3_384, SHA3_384_DIGEST_SIZE,
		   "prf-sha3-384", "PRF-SHA3-384");
PRF_SHA3_ALGORITHM(prf_sha3_512, PRF_SHA3_512, SHA3_512_DIGEST_SIZE,
		   "prf-sha3-512", "PRF-SHA3-512");

static void __init__ prf_sha3_init(void)
{
	crypto_prf_register(&prf_sha3_224_algorithm);
	crypto_prf_register(&prf_sha3_256_algorithm);
	crypto_prf_register(&prf_sha3_384_algorithm);
	crypto_prf_register(&prf_sha3_512_algorithm);
}
