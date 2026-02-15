#define __CRYPTO_HMAC_MODULE__
#include <crypto/hmac.h>
#include "../module.h"

static void
hmac_module_sha3_init(struct module_digest *ctx, unsigned int digest_size)
{
	unsigned int id;

	switch (digest_size) {
	case SHA3_224_DIGEST_SIZE: id = ALGORITHM_SHA3_224; break;
	case SHA3_256_DIGEST_SIZE: id = ALGORITHM_SHA3_256; break;
	case SHA3_384_DIGEST_SIZE: id = ALGORITHM_SHA3_384; break;
	default:                   id = ALGORITHM_SHA3_512; break;
	}
	module_digest_init(ctx, id);
}

#define sha3 module_digest
#define arch_sha3_init hmac_module_sha3_init
#define arch_sha3_256_update module_digest_update
#define arch_sha3_256_final module_digest_final
#define HMAC_SHA3_SCOPE static
#include "sha3.c"
#undef arch_sha3_256_final
#undef arch_sha3_256_update
#undef arch_sha3_init
#undef sha3

HMAC_ALGORITHM_WRAPPERS(hmac_sha3_224, hmac_sha3_224_ctx)
HMAC_ALGORITHM_WRAPPERS(hmac_sha3_256, hmac_sha3_256_ctx)
HMAC_ALGORITHM_WRAPPERS(hmac_sha3_384, hmac_sha3_384_ctx)
HMAC_ALGORITHM_WRAPPERS(hmac_sha3_512, hmac_sha3_512_ctx)

static struct hmac_algorithm hmac_sha3_224_algorithm = {
	.msg_size = SHA3_224_DIGEST_SIZE,
	.blk_size = SHA3_224_BLOCK_SIZE,
	.mac_size = SHA3_224_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha3_224_ctx),
	.name = "hmac-sha3-224",
	.desc = "HMAC-SHA3-224",
	.id = HMAC_SHA3_224,
	.init = hmac_sha3_224_algorithm_init,
	.reinit = hmac_sha3_224_algorithm_reinit,
	.update = hmac_sha3_224_algorithm_update,
	.final = hmac_sha3_224_algorithm_final,
	.hmac = hmac_sha3_224_algorithm_hmac,
	.vector = hmac_sha3_224_algorithm_vector,
};

static struct hmac_algorithm hmac_sha3_256_algorithm = {
	.msg_size = SHA3_256_DIGEST_SIZE,
	.blk_size = SHA3_256_BLOCK_SIZE,
	.mac_size = SHA3_256_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha3_256_ctx),
	.name = "hmac-sha3-256",
	.desc = "HMAC-SHA3-256",
	.id = HMAC_SHA3_256,
	.init = hmac_sha3_256_algorithm_init,
	.reinit = hmac_sha3_256_algorithm_reinit,
	.update = hmac_sha3_256_algorithm_update,
	.final = hmac_sha3_256_algorithm_final,
	.hmac = hmac_sha3_256_algorithm_hmac,
	.vector = hmac_sha3_256_algorithm_vector,
};

static struct hmac_algorithm hmac_sha3_384_algorithm = {
	.msg_size = SHA3_384_DIGEST_SIZE,
	.blk_size = SHA3_384_BLOCK_SIZE,
	.mac_size = SHA3_384_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha3_384_ctx),
	.name = "hmac-sha3-384",
	.desc = "HMAC-SHA3-384",
	.id = HMAC_SHA3_384,
	.init = hmac_sha3_384_algorithm_init,
	.reinit = hmac_sha3_384_algorithm_reinit,
	.update = hmac_sha3_384_algorithm_update,
	.final = hmac_sha3_384_algorithm_final,
	.hmac = hmac_sha3_384_algorithm_hmac,
	.vector = hmac_sha3_384_algorithm_vector,
};

static struct hmac_algorithm hmac_sha3_512_algorithm = {
	.msg_size = SHA3_512_DIGEST_SIZE,
	.blk_size = SHA3_512_BLOCK_SIZE,
	.mac_size = SHA3_512_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha3_512_ctx),
	.name = "hmac-sha3-512",
	.desc = "HMAC-SHA3-512",
	.id = HMAC_SHA3_512,
	.init = hmac_sha3_512_algorithm_init,
	.reinit = hmac_sha3_512_algorithm_reinit,
	.update = hmac_sha3_512_algorithm_update,
	.final = hmac_sha3_512_algorithm_final,
	.hmac = hmac_sha3_512_algorithm_hmac,
	.vector = hmac_sha3_512_algorithm_vector,
};

static void __init__ hmac_sha3_init(void)
{
	crypto_hmac_register(&hmac_sha3_224_algorithm);
	crypto_hmac_register(&hmac_sha3_256_algorithm);
	crypto_hmac_register(&hmac_sha3_384_algorithm);
	crypto_hmac_register(&hmac_sha3_512_algorithm);
}
