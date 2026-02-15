#define __CRYPTO_HKDF_MODULE__
#include <crypto/hkdf.h>
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
#define HKDF_SHA2_SCOPE static
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

#define HKDF_SHA2_ALGORITHM(_fn, _id, _size, _name, _desc) \
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

HKDF_SHA2_ALGORITHM(hkdf_sha224, HKDF_SHA224, SHA224_DIGEST_SIZE,
		    "hkdf-sha2-224", "HKDF-SHA2-224");
HKDF_SHA2_ALGORITHM(hkdf_sha256, HKDF_SHA256, SHA256_DIGEST_SIZE,
		    "hkdf-sha2-256", "HKDF-SHA2-256");
HKDF_SHA2_ALGORITHM(hkdf_sha384, HKDF_SHA384, SHA384_DIGEST_SIZE,
		    "hkdf-sha2-384", "HKDF-SHA2-384");
HKDF_SHA2_ALGORITHM(hkdf_sha512, HKDF_SHA512, SHA512_DIGEST_SIZE,
		    "hkdf-sha2-512", "HKDF-SHA2-512");

static void __init__ hkdf_sha2_init(void)
{
	crypto_hkdf_register(&hkdf_sha224_algorithm);
	crypto_hkdf_register(&hkdf_sha256_algorithm);
	crypto_hkdf_register(&hkdf_sha384_algorithm);
	crypto_hkdf_register(&hkdf_sha512_algorithm);
}
