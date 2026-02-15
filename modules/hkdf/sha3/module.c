#define __CRYPTO_HKDF_MODULE__
#include <crypto/hkdf.h>
#include <modules/digest/module.h>

static void
hkdf_module_sha3_init(struct module_digest *ctx, unsigned int digest_size)
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
#define arch_sha3_init hkdf_module_sha3_init
#define arch_sha3_256_update module_digest_update
#define arch_sha3_256_final module_digest_final
#define HKDF_SHA3_SCOPE static
#include "sha3.c"
#undef arch_sha3_256_final
#undef arch_sha3_256_update
#undef arch_sha3_init
#undef sha3

#define HKDF_SHA3_ALGORITHM(_fn, _id, _size, _name, _desc) \
static struct hkdf_algorithm _fn##_algorithm = { \
	.prk_size = _size, \
	.max_output_size = 255 * (_size), \
	.name = _name, \
	.desc = _desc, \
	.id = _id, \
	.extract = _fn##_extract, \
	.expand = _fn##_expand, \
	.hkdf = _fn, \
}

HKDF_SHA3_ALGORITHM(hkdf_sha3_224, HKDF_SHA3_224, SHA3_224_DIGEST_SIZE,
		    "hkdf-sha3-224", "HKDF-SHA3-224");
HKDF_SHA3_ALGORITHM(hkdf_sha3_256, HKDF_SHA3_256, SHA3_256_DIGEST_SIZE,
		    "hkdf-sha3-256", "HKDF-SHA3-256");
HKDF_SHA3_ALGORITHM(hkdf_sha3_384, HKDF_SHA3_384, SHA3_384_DIGEST_SIZE,
		    "hkdf-sha3-384", "HKDF-SHA3-384");
HKDF_SHA3_ALGORITHM(hkdf_sha3_512, HKDF_SHA3_512, SHA3_512_DIGEST_SIZE,
		    "hkdf-sha3-512", "HKDF-SHA3-512");

static void __init__ hkdf_sha3_init(void)
{
	crypto_hkdf_register(&hkdf_sha3_224_algorithm);
	crypto_hkdf_register(&hkdf_sha3_256_algorithm);
	crypto_hkdf_register(&hkdf_sha3_384_algorithm);
	crypto_hkdf_register(&hkdf_sha3_512_algorithm);
}
