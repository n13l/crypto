#define __MODULES_DIGEST_SHA3_H__
#define __CRYPTO_DIGEST_SHA3_H__
#include <crypto/digest.h>

#define SHA3_SCOPE static
#include "sha3.c"

struct digest_algorithm sha3_generic_224 = {
	.msg_size = SHA3_224_DIGEST_SIZE,
	.blk_size = SHA3_224_BLOCK_SIZE,
	.ctx_size = sizeof(struct sha3_ctx),
	.name = "sha3-224-generic",
	.id = ALGORITHM_SHA3_224,
	.init   = (void (*)(struct digest *))sha3_224_init,
	.update = (void (*)(struct digest *, const u8 *, unsigned int))sha3_update,
	.digest = (void (*)(struct digest *, u8 *))sha3_final,
};

struct digest_algorithm sha3_generic_256 = {
	.msg_size = SHA3_256_DIGEST_SIZE,
	.blk_size = SHA3_256_BLOCK_SIZE,
	.ctx_size = sizeof(struct sha3_ctx),
	.name = "sha3-256-generic",
	.id = ALGORITHM_SHA3_256,
	.init   = (void (*)(struct digest *))sha3_256_init,
	.update = (void (*)(struct digest *, const u8 *, unsigned int))sha3_update,
	.digest = (void (*)(struct digest *, u8 *))sha3_final,
};

struct digest_algorithm sha3_generic_384 = {
	.msg_size = SHA3_384_DIGEST_SIZE,
	.blk_size = SHA3_384_BLOCK_SIZE,
	.ctx_size = sizeof(struct sha3_ctx),
	.name = "sha3-384-generic",
	.id = ALGORITHM_SHA3_384,
	.init   = (void (*)(struct digest *))sha3_384_init,
	.update = (void (*)(struct digest *, const u8 *, unsigned int))sha3_update,
	.digest = (void (*)(struct digest *, u8 *))sha3_final,
};

struct digest_algorithm sha3_generic_512 = {
	.msg_size = SHA3_512_DIGEST_SIZE,
	.blk_size = SHA3_512_BLOCK_SIZE,
	.ctx_size = sizeof(struct sha3_ctx),
	.name = "sha3-512-generic",
	.id = ALGORITHM_SHA3_512,
	.init   = (void (*)(struct digest *))sha3_512_init,
	.update = (void (*)(struct digest *, const u8 *, unsigned int))sha3_update,
	.digest = (void (*)(struct digest *, u8 *))sha3_final,
};

static void __init__ digest_sha3_init(void)
{
	crypto_digest_register(&sha3_generic_224);
	crypto_digest_register(&sha3_generic_256);
	crypto_digest_register(&sha3_generic_384);
	crypto_digest_register(&sha3_generic_512);
}
