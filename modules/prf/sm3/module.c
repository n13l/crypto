#define __CRYPTO_PRF_MODULE__
#include <crypto/prf.h>
#include <modules/digest/module.h>

#define sm3 module_digest
#define arch_sm3_init(_ctx) module_digest_init((_ctx), ALGORITHM_SM3)
#define arch_sm3_update module_digest_update
#define arch_sm3_final module_digest_final
#define PRF_SM3_SCOPE static
#include "sm3.c"
#undef arch_sm3_final
#undef arch_sm3_update
#undef arch_sm3_init
#undef sm3

static struct prf_algorithm prf_sm3_algorithm = {
	.msg_size = SM3_DIGEST_SIZE,
	.ctx_size = SM3_DIGEST_SIZE,
	.name = "prf-sm3",
	.desc = "PRF-SM3",
	.id = PRF_SM3,
	.derive = prf_sm3,
};

static void __init__ prf_sm3_init(void)
{
	crypto_prf_register(&prf_sm3_algorithm);
}
