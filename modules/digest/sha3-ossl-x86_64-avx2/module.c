#include <crypto/digest.h>

static struct digest_algorithm sha3_ossl_x86_64_avx2_224 = {
	.name = "sha3-224",
	.desc = "SHA3-224 (OpenSSL, x86_64, AVX2)",
	.id = ALGORITHM_SHA3_224,
};

static struct digest_algorithm sha3_ossl_x86_64_avx2_256 = {
	.name = "sha3-256",
	.desc = "SHA3-256 (OpenSSL, x86_64, AVX2)",
	.id = ALGORITHM_SHA3_256,
};

static struct digest_algorithm sha3_ossl_x86_64_avx2_384 = {
	.name = "sha3-384",
	.desc = "SHA3-384 (OpenSSL, x86_64, AVX2)",
	.id = ALGORITHM_SHA3_384,
};

static struct digest_algorithm sha3_ossl_x86_64_avx2_512 = {
	.name = "sha3-512",
	.desc = "SHA3-512 (OpenSSL, x86_64, AVX2)",
	.id = ALGORITHM_SHA3_512,
};

static void __init__ digest_sha3_ossl_x86_64_avx2_init(void)
{
	crypto_digest_register(&sha3_ossl_x86_64_avx2_224);
	crypto_digest_register(&sha3_ossl_x86_64_avx2_256);
	crypto_digest_register(&sha3_ossl_x86_64_avx2_384);
	crypto_digest_register(&sha3_ossl_x86_64_avx2_512);
}
