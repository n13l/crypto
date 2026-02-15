#include <crypto/digest.h>

static struct digest_algorithm digest_sha2_224_null = {
	.name = "sha2-224",
	.desc = "SHA2-224 (null)",
	.id = ALGORITHM_SHA2_224,
};

static struct digest_algorithm digest_sha2_256_null = {
	.name = "sha2-256",
	.desc = "SHA2-256 (null)",
	.id = ALGORITHM_SHA2_256,
};

static struct digest_algorithm digest_sha2_384_null = {
	.name = "sha2-384",
	.desc = "SHA2-384 (null)",
	.id = ALGORITHM_SHA2_384,
};

static struct digest_algorithm digest_sha2_512_null = {
	.name = "sha2-512",
	.desc = "SHA2-512 (null)",
	.id = ALGORITHM_SHA2_512,
};
