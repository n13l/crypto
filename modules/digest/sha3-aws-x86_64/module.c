#include <crypto/digest.h>

static struct digest_algorithm sha3_aws_x86_64_224 = {
	.name = "sha3-224",
	.desc = "SHA3-224 (aws-lc, x86_64)",
	.id = ALGORITHM_SHA3_224,
};

static struct digest_algorithm sha3_aws_x86_64_256 = {
	.name = "sha3-256",
	.desc = "SHA3-256 (aws-lc, x86_64)",
	.id = ALGORITHM_SHA3_256,
};

static struct digest_algorithm sha3_aws_x86_64_384 = {
	.name = "sha3-384",
	.desc = "SHA3-384 (aws-lc, x86_64)",
	.id = ALGORITHM_SHA3_384,
};

static struct digest_algorithm sha3_aws_x86_64_512 = {
	.name = "sha3-512",
	.desc = "SHA3-512 (aws-lc, x86_64)",
	.id = ALGORITHM_SHA3_512,
};

static void __init__ digest_sha3_aws_x86_64_init(void)
{
	crypto_digest_register(&sha3_aws_x86_64_224);
	crypto_digest_register(&sha3_aws_x86_64_256);
	crypto_digest_register(&sha3_aws_x86_64_384);
	crypto_digest_register(&sha3_aws_x86_64_512);
}
