#define __CRYPTO_HKDF_MODULE__
#include <crypto/hkdf.h>
#include <modules/digest/module.h>

#define sm3 module_digest
#define arch_sm3_init(_ctx) module_digest_init((_ctx), ALGORITHM_SM3)
#define arch_sm3_update module_digest_update
#define arch_sm3_final module_digest_final
#define HKDF_SM3_SCOPE static
#include "sm3.c"
#undef arch_sm3_final
#undef arch_sm3_update
#undef arch_sm3_init
#undef sm3

static struct hkdf_algorithm hkdf_sm3_algorithm = {
	.prk_size = SM3_DIGEST_SIZE,
	.max_output_size = 255 * SM3_DIGEST_SIZE,
	.name = "hkdf-sm3",
	.desc = "HKDF-SM3",
	.id = HKDF_SM3,
	.extract = hkdf_sm3_extract,
	.expand = hkdf_sm3_expand,
	.hkdf = hkdf_sm3,
};

static void __init__ hkdf_sm3_init(void)
{
	crypto_hkdf_register(&hkdf_sm3_algorithm);
}
