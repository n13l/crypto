#include <crypto/digest.h>

static struct digest_algorithm sha2_aws_x86_64_shani_224 = {
	.name = "sha2-224",
	.desc = "SHA2-224 (aws-lc, x86_64, SHA-NI)",
	.id = ALGORITHM_SHA2_224,
};

static struct digest_algorithm sha2_aws_x86_64_shani_256 = {
	.name = "sha2-256",
	.desc = "SHA2-256 (aws-lc, x86_64, SHA-NI)",
	.id = ALGORITHM_SHA2_256,
};

static struct digest_algorithm sha2_aws_x86_64_shani_384 = {
	.name = "sha2-384",
	.desc = "SHA2-384 (aws-lc, x86_64, SHA-NI)",
	.id = ALGORITHM_SHA2_384,
};

static struct digest_algorithm sha2_aws_x86_64_shani_512 = {
	.name = "sha2-512",
	.desc = "SHA2-512 (aws-lc, x86_64, SHA-NI)",
	.id = ALGORITHM_SHA2_512,
};

static void __init__ digest_sha2_aws_x86_64_shani_init(void)
{
	crypto_digest_register(&sha2_aws_x86_64_shani_224);
	crypto_digest_register(&sha2_aws_x86_64_shani_256);
	crypto_digest_register(&sha2_aws_x86_64_shani_384);
	crypto_digest_register(&sha2_aws_x86_64_shani_512);
}
