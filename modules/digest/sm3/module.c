#define __CRYPTO_DIGEST_SM3_H__
#include "decl.h"
#include <crypto/digest.h>

#define SM3_SCOPE static
#include "sm3.c"

struct digest_algorithm sm3_generic = {
	.msg_size = SM3_MSG_SIZE,
	.blk_size = SM3_BLK_SIZE,
	.ctx_size = sizeof(struct sm3),
	.name = "sm3-generic",
	.id = ALGORITHM_SM3,
	.init   = (void (*)(struct digest *))sm3_init,
	.update = (void (*)(struct digest *, const u8 *, unsigned int))sm3_update,
	.digest = (void (*)(struct digest *, u8 *))sm3_final,
	.hash   = sm3_hash,
};

static void __init__ digest_sm3_init(void)
{
	crypto_digest_register(&sm3_generic);
}
