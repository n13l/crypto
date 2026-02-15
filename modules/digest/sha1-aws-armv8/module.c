#include <crypto/digest.h>

static struct digest_algorithm sha1_aws_armv8 = {
	.name = "sha1-160",
	.desc = "SHA1-160 (aws-lc, ARMv8)",
	.id = ALGORITHM_SHA1_160,
};

static void __init__ digest_sha1_aws_armv8_init(void)
{
	crypto_digest_register(&sha1_aws_armv8);
}
