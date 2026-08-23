#define __CRYPTO_HMAC_MODULE__
#include <crypto/hmac.h>
#include "../module.h"

#define sm3 module_digest
#define arch_sm3_init(_ctx) module_digest_init((_ctx), ALGORITHM_SM3)
#define arch_sm3_update module_digest_update
#define arch_sm3_final module_digest_final
#define HMAC_SM3_SCOPE static
#include "sm3.c"
#undef arch_sm3_final
#undef arch_sm3_update
#undef arch_sm3_init
#undef sm3

HMAC_ALGORITHM_WRAPPERS(hmac_sm3, hmac_sm3_ctx)

static struct hmac_algorithm hmac_sm3_algorithm = {
	.msg_size = SM3_DIGEST_SIZE,
	.blk_size = SM3_BLOCK_SIZE,
	.mac_size = SM3_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sm3_ctx),
	.name = "hmac-sm3",
	.desc = "HMAC-SM3",
	.id = HMAC_SM3,
	.init = hmac_sm3_algorithm_init,
	.reinit = hmac_sm3_algorithm_reinit,
	.update = hmac_sm3_algorithm_update,
	.final = hmac_sm3_algorithm_final,
	.hmac = hmac_sm3_algorithm_hmac,
	.vector = hmac_sm3_algorithm_vector,
};

static void __init__ hmac_sm3_module_init(void)
{
	crypto_hmac_register(&hmac_sm3_algorithm);
}
