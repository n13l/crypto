#include <crypto/digest.h>

static struct digest_algorithm sha2_aws_armv8_224 = {
	.name = "sha2-224",
	.desc = "SHA2-224 (aws-lc, ARMv8)",
	.id = ALGORITHM_SHA2_224,
};

static struct digest_algorithm sha2_aws_armv8_256 = {
	.name = "sha2-256",
	.desc = "SHA2-256 (aws-lc, ARMv8)",
	.id = ALGORITHM_SHA2_256,
};

static struct digest_algorithm sha2_aws_armv8_384 = {
	.name = "sha2-384",
	.desc = "SHA2-384 (aws-lc, ARMv8)",
	.id = ALGORITHM_SHA2_384,
};

static struct digest_algorithm sha2_aws_armv8_512 = {
	.name = "sha2-512",
	.desc = "SHA2-512 (aws-lc, ARMv8)",
	.id = ALGORITHM_SHA2_512,
};

static void __init__ digest_sha2_aws_armv8_init(void)
{
	crypto_digest_register(&sha2_aws_armv8_224);
	crypto_digest_register(&sha2_aws_armv8_256);
	crypto_digest_register(&sha2_aws_armv8_384);
	crypto_digest_register(&sha2_aws_armv8_512);
}
