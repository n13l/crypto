#define __CRYPTO_DIGEST_MD5_H__
#include "decl.h"
#include <crypto/digest.h>

#define MD5_SCOPE static
#include "md5.c"

struct digest_algorithm md5_generic = {
	.msg_size = MD5_MSG_SIZE,
	.blk_size = MD5_BLK_SIZE,
	.ctx_size = sizeof(struct md5),
	.name = "md5-generic",
	.id = ALGORITHM_MD5,
	.init   = (void (*)(struct digest *))md5_init,
	.update = (void (*)(struct digest *, const u8 *, unsigned int))md5_update,
	.digest = (void (*)(struct digest *, u8 *))md5_final,
	.hash   = md5_hash,
};

static void __init__ digest_md5_init(void)
{
	crypto_digest_register(&md5_generic);
}
