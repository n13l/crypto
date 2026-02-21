#include <crypto/digest.h>

static struct digest_algorithm sha1_null = {
	.name = "sha1-160",
	.desc = "SHA1-160 (null)",
	.id = ALGORITHM_SHA1_160,
};

static void __init__ digest_sha1_null_init(void)
{
	crypto_digest_register(&sha1_null);
}
