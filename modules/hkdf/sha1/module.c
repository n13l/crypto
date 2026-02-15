#define __CRYPTO_HKDF_MODULE__
#include <crypto/hkdf.h>
#include <modules/digest/module.h>

#define sha1 module_digest
#define arch_sha1_160_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA1_160)
#define arch_sha1_160_update module_digest_update
#define arch_sha1_160_final module_digest_final
#define HKDF_SHA1_SCOPE static
#include "sha1.c"
#undef arch_sha1_160_final
#undef arch_sha1_160_update
#undef arch_sha1_160_init
#undef sha1

static struct hkdf_algorithm hkdf_sha1_160_algorithm = {
	.prk_size = SHA1_DIGEST_SIZE,
	.max_output_size = 255 * SHA1_DIGEST_SIZE,
	.name = "hkdf-sha1-160",
	.desc = "HKDF-SHA1-160",
	.id = HKDF_SHA1,
	.extract = hkdf_sha1_160_extract,
	.expand = hkdf_sha1_160_expand,
	.hkdf = hkdf_sha1_160,
};

static void __init__ hkdf_sha1_init(void)
{
	crypto_hkdf_register(&hkdf_sha1_160_algorithm);
}
