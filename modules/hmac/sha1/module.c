#define __CRYPTO_HMAC_MODULE__
#include <crypto/hmac.h>
#include "../module.h"

#define sha1 module_digest
#define arch_sha1_160_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA1_160)
#define arch_sha1_160_update module_digest_update
#define arch_sha1_160_final module_digest_final
#define HMAC_SHA1_SCOPE static
#include "sha1.c"
#undef arch_sha1_160_final
#undef arch_sha1_160_update
#undef arch_sha1_160_init
#undef sha1

HMAC_ALGORITHM_WRAPPERS(hmac_sha1_160, hmac_sha1_ctx)

static struct hmac_algorithm hmac_sha1_160_algorithm = {
	.msg_size = SHA1_DIGEST_SIZE,
	.blk_size = SHA1_BLOCK_SIZE,
	.mac_size = SHA1_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha1_ctx),
	.name = "hmac-sha1-160",
	.desc = "HMAC-SHA1-160",
	.id = HMAC_SHA1,
	.init = hmac_sha1_160_algorithm_init,
	.reinit = hmac_sha1_160_algorithm_reinit,
	.update = hmac_sha1_160_algorithm_update,
	.final = hmac_sha1_160_algorithm_final,
	.hmac = hmac_sha1_160_algorithm_hmac,
	.vector = hmac_sha1_160_algorithm_vector,
};

static void __init__ hmac_sha1_init(void)
{
	crypto_hmac_register(&hmac_sha1_160_algorithm);
}
