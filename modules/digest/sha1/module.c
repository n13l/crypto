#define __MODULES_DIGEST_SHA1_H__
#define __CRYPTO_DIGEST_SHA1_H__
#include <crypto/digest.h>

#define SHA1_SCOPE static
#include "sha1.c"

struct digest_algorithm sha1_generic = {
	.msg_size = SHA1_MSG_SIZE,
	.blk_size = SHA1_BLK_SIZE,
	.ctx_size = sizeof(struct sha1),
	.name = "sha1-generic",
	.id = ALGORITHM_SHA1_160,
	.init   = (void (*)(struct digest *))sha1_init,
	.update = (void (*)(struct digest *, const u8 *, unsigned int))sha1_update,
	.digest = (void (*)(struct digest *, u8 *))sha1_final,
};

static void __init__ digest_sha1_init(void)
{
	crypto_digest_register(&sha1_generic);
}
