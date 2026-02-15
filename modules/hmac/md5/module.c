#define __CRYPTO_HMAC_MODULE__
#include <crypto/hmac.h>
#include "../module.h"

#define md5 module_digest
#define arch_md5_init(_ctx) module_digest_init((_ctx), ALGORITHM_MD5)
#define arch_md5_update module_digest_update
#define arch_md5_final module_digest_final
#define HMAC_MD5_SCOPE static
#include "md5.c"
#undef arch_md5_final
#undef arch_md5_update
#undef arch_md5_init
#undef md5

HMAC_ALGORITHM_WRAPPERS(hmac_md5, hmac_md5_ctx)

static struct hmac_algorithm hmac_md5_algorithm = {
	.msg_size = MD5_DIGEST_SIZE,
	.blk_size = MD5_BLOCK_SIZE,
	.mac_size = MD5_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_md5_ctx),
	.name = "hmac-md5",
	.desc = "HMAC-MD5",
	.id = HMAC_MD5,
	.init = hmac_md5_algorithm_init,
	.reinit = hmac_md5_algorithm_reinit,
	.update = hmac_md5_algorithm_update,
	.final = hmac_md5_algorithm_final,
	.hmac = hmac_md5_algorithm_hmac,
	.vector = hmac_md5_algorithm_vector,
};

static void __init__ hmac_md5_module_init(void)
{
	crypto_hmac_register(&hmac_md5_algorithm);
}
