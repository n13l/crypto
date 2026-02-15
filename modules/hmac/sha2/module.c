#define __CRYPTO_HMAC_MODULE__
#include <crypto/hmac.h>
#include "../module.h"

#undef arch_sha2_224_update
#undef arch_sha2_224_final
#undef arch_sha2_384_update
#undef arch_sha2_384_final
#define sha256 module_digest
#define sha512 module_digest
#define arch_sha2_224_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA2_224)
#define arch_sha2_224_update module_digest_update
#define arch_sha2_224_final module_digest_final
#define arch_sha2_256_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA2_256)
#define arch_sha2_256_update module_digest_update
#define arch_sha2_256_final module_digest_final
#define arch_sha2_384_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA2_384)
#define arch_sha2_384_update module_digest_update
#define arch_sha2_384_final module_digest_final
#define arch_sha2_512_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA2_512)
#define arch_sha2_512_update module_digest_update
#define arch_sha2_512_final module_digest_final
#define HMAC_SHA2_SCOPE static
#include "sha2.c"
#undef arch_sha2_512_final
#undef arch_sha2_512_update
#undef arch_sha2_512_init
#undef arch_sha2_384_final
#undef arch_sha2_384_update
#undef arch_sha2_384_init
#undef arch_sha2_256_final
#undef arch_sha2_256_update
#undef arch_sha2_256_init
#undef arch_sha2_224_final
#undef arch_sha2_224_update
#undef arch_sha2_224_init
#undef sha512
#undef sha256

HMAC_ALGORITHM_WRAPPERS(hmac_sha224, hmac_sha224_ctx)
HMAC_ALGORITHM_WRAPPERS(hmac_sha256, hmac_sha256_ctx)
HMAC_ALGORITHM_WRAPPERS(hmac_sha384, hmac_sha384_ctx)
HMAC_ALGORITHM_WRAPPERS(hmac_sha512, hmac_sha512_ctx)

static struct hmac_algorithm hmac_sha224_algorithm = {
	.msg_size = SHA224_DIGEST_SIZE,
	.blk_size = SHA224_BLOCK_SIZE,
	.mac_size = SHA224_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha224_ctx),
	.name = "hmac-sha2-224",
	.desc = "HMAC-SHA2-224",
	.id = HMAC_SHA224,
	.init = hmac_sha224_algorithm_init,
	.reinit = hmac_sha224_algorithm_reinit,
	.update = hmac_sha224_algorithm_update,
	.final = hmac_sha224_algorithm_final,
	.hmac = hmac_sha224_algorithm_hmac,
	.vector = hmac_sha224_algorithm_vector,
};

static struct hmac_algorithm hmac_sha256_algorithm = {
	.msg_size = SHA256_DIGEST_SIZE,
	.blk_size = SHA256_BLOCK_SIZE,
	.mac_size = SHA256_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha256_ctx),
	.name = "hmac-sha2-256",
	.desc = "HMAC-SHA2-256",
	.id = HMAC_SHA256,
	.init = hmac_sha256_algorithm_init,
	.reinit = hmac_sha256_algorithm_reinit,
	.update = hmac_sha256_algorithm_update,
	.final = hmac_sha256_algorithm_final,
	.hmac = hmac_sha256_algorithm_hmac,
	.vector = hmac_sha256_algorithm_vector,
};

static struct hmac_algorithm hmac_sha384_algorithm = {
	.msg_size = SHA384_DIGEST_SIZE,
	.blk_size = SHA384_BLOCK_SIZE,
	.mac_size = SHA384_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha384_ctx),
	.name = "hmac-sha2-384",
	.desc = "HMAC-SHA2-384",
	.id = HMAC_SHA384,
	.init = hmac_sha384_algorithm_init,
	.reinit = hmac_sha384_algorithm_reinit,
	.update = hmac_sha384_algorithm_update,
	.final = hmac_sha384_algorithm_final,
	.hmac = hmac_sha384_algorithm_hmac,
	.vector = hmac_sha384_algorithm_vector,
};

static struct hmac_algorithm hmac_sha512_algorithm = {
	.msg_size = SHA512_DIGEST_SIZE,
	.blk_size = SHA512_BLOCK_SIZE,
	.mac_size = SHA512_DIGEST_SIZE,
	.ctx_size = sizeof(hmac_sha512_ctx),
	.name = "hmac-sha2-512",
	.desc = "HMAC-SHA2-512",
	.id = HMAC_SHA512,
	.init = hmac_sha512_algorithm_init,
	.reinit = hmac_sha512_algorithm_reinit,
	.update = hmac_sha512_algorithm_update,
	.final = hmac_sha512_algorithm_final,
	.hmac = hmac_sha512_algorithm_hmac,
	.vector = hmac_sha512_algorithm_vector,
};

static void __init__ hmac_sha2_init(void)
{
	crypto_hmac_register(&hmac_sha224_algorithm);
	crypto_hmac_register(&hmac_sha256_algorithm);
	crypto_hmac_register(&hmac_sha384_algorithm);
	crypto_hmac_register(&hmac_sha512_algorithm);
}
