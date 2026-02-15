#include <crypto/digest.h>

static struct digest_algorithm sha1_aws_x86_64_shani = {
	.name = "sha1-160",
	.desc = "SHA1-160 (aws-lc, x86_64, SHA-NI)",
	.id = ALGORITHM_SHA1_160,
};

static void __init__ digest_sha1_aws_x86_64_shani_init(void)
{
	crypto_digest_register(&sha1_aws_x86_64_shani);
}
