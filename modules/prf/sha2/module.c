#define __CRYPTO_PRF_MODULE__
#include <crypto/prf.h>
#include <modules/digest/module.h>

#undef arch_sha2_224_update
#undef arch_sha2_224_final
#undef arch_sha2_384_update
#undef arch_sha2_384_final
#define sha256 module_digest
#define sha512 module_digest
#define arch_sha2_224_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA2_224)
#define arch_sha2_224_update module_digest_update
#define arch_sha2_224_final module_digest_final
#define arch_sha2_256_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA2_256)
#define arch_sha2_256_update module_digest_update
#define arch_sha2_256_final module_digest_final
#define arch_sha2_384_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA2_384)
#define arch_sha2_384_update module_digest_update
#define arch_sha2_384_final module_digest_final
#define arch_sha2_512_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA2_512)
#define arch_sha2_512_update module_digest_update
#define arch_sha2_512_final module_digest_final
#define PRF_SHA2_SCOPE static
#include "sha2.c"
#undef arch_sha2_512_final
#undef arch_sha2_512_update
#undef arch_sha2_512_init
#undef arch_sha2_384_final
#undef arch_sha2_384_update
#undef arch_sha2_384_init
#undef arch_sha2_256_final
#undef arch_sha2_256_update
#undef arch_sha2_256_init
#undef arch_sha2_224_final
#undef arch_sha2_224_update
#undef arch_sha2_224_init
#undef sha512
#undef sha256

#define PRF_SHA2_ALGORITHM(_fn, _id, _size, _name, _desc) \
static struct prf_algorithm _fn##_algorithm = { \
	.msg_size = _size, \
	.ctx_size = _size, \
	.name = _name, \
	.desc = _desc, \
	.id = _id, \
	.derive = _fn, \
}

PRF_SHA2_ALGORITHM(prf_sha224, PRF_SHA224, SHA224_DIGEST_SIZE,
		   "prf-sha2-224", "PRF-SHA2-224");
PRF_SHA2_ALGORITHM(prf_sha256, PRF_SHA256, SHA256_DIGEST_SIZE,
		   "prf-sha2-256", "PRF-SHA2-256");
PRF_SHA2_ALGORITHM(prf_sha384, PRF_SHA384, SHA384_DIGEST_SIZE,
		   "prf-sha2-384", "PRF-SHA2-384");
PRF_SHA2_ALGORITHM(prf_sha512, PRF_SHA512, SHA512_DIGEST_SIZE,
		   "prf-sha2-512", "PRF-SHA2-512");

static void __init__ prf_sha2_init(void)
{
	crypto_prf_register(&prf_sha224_algorithm);
	crypto_prf_register(&prf_sha256_algorithm);
	crypto_prf_register(&prf_sha384_algorithm);
	crypto_prf_register(&prf_sha512_algorithm);
}
