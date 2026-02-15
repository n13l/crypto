#define __CRYPTO_DIGEST_SHA2_H__
#include <crypto/digest.h>
#include <modules/digest/sha2.h>

#define SHA2_SCOPE static
#include "sha2.c"

struct digest_algorithm sha2_224 = {
	.msg_size = SHA224_DIGEST_SIZE,
	.blk_size = SHA224_BLOCK_SIZE,
	.mac_size = SHA224_MAC_LEN,
	.ctx_size = sizeof(sha224_ctx),
	.name = "sha2-224-generic",
	.id = ALGORITHM_SHA2_224,
	.init = sha224_init,
	.update = sha224_update,
	.digest = sha224_final,
	.hash = sha224
};

struct digest_algorithm sha2_256 = {
	.msg_size = SHA256_DIGEST_SIZE,
	.blk_size = SHA256_BLOCK_SIZE,
	.mac_size = SHA256_MAC_LEN,
	.ctx_size = sizeof(sha256_ctx),
	.name = "sha2-256",
	.desc = "sha2-256-generic",
	.id = ALGORITHM_SHA2_256,
	.init = sha256_init,
	.copy = sha256_copy,
	.update = sha256_update,
	.digest = sha256_digest,
	.hash = sha256
};

struct digest_algorithm sha2_384 = {
	.msg_size = SHA384_DIGEST_SIZE,
	.blk_size = SHA384_BLOCK_SIZE,
	.mac_size = SHA384_MAC_LEN,
	.ctx_size = sizeof(sha384_ctx),
	.name = "sha2-384",
	.desc = "sha2-384-generic",
	.id = ALGORITHM_SHA2_384,
	.init = sha384_init,
	.copy = sha384_copy,
	.update = sha384_update,
	.digest = sha384_digest,
	.hash = sha384
};

struct digest_algorithm sha2_512 = {
	.msg_size = SHA512_DIGEST_SIZE,
	.blk_size = SHA512_BLOCK_SIZE,
	.mac_size = SHA512_DIGEST_SIZE,
	.ctx_size = sizeof(sha512_ctx),
	.name = "sha2-512",
	.desc = "sha2-512-generic",
	.id = ALGORITHM_SHA2_512,
	.init = sha512_init,
	.update = sha512_update,
	.digest = sha512_final,
	.hash = sha512
};

static void __init__ digest_sha2_init(void)
{
	crypto_digest_register(&sha2_224);
	crypto_digest_register(&sha2_256);
	crypto_digest_register(&sha2_384);
	crypto_digest_register(&sha2_512);
}
