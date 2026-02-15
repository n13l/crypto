#include <hpc/compiler.h>

enum algorithm_digest {
	ALGORITHM_SHA1_160 = 1,
	ALGORITHM_SHA2_224 = 2,
	ALGORITHM_SHA2_256 = 3,
	ALGORITHM_SHA2_384 = 4,
	ALGORITHM_SHA2_512 = 5,
	ALGORITHM_SHA3_224 = 6,
	ALGORITHM_SHA3_256 = 7,
	ALGORITHM_SHA3_384 = 8,
	ALGORITHM_SHA3_512 = 9,
	ALGORITHM_DIGEST_LAST
};

#ifdef CONFIG_SILENT

const char *
digest_get_name(enum algorithm_digest id)
{
	(void)id;
	return "";
}

const char *
digest_get_desc(enum algorithm_digest id)
{
	(void)id;
	return "";
}

#else

/* SHA-1 implementation descriptor */
#if defined(CONFIG_CRYPTO_SHA1_OSSL_X86_64)
#define DIGEST_SHA1_IMPL_DESC "OpenSSL, x86_64"
#elif defined(CONFIG_CRYPTO_SHA1_OSSL_ARMV8)
#define DIGEST_SHA1_IMPL_DESC "OpenSSL, ARMv8"
#elif defined(CONFIG_CRYPTO_SHA1_AWS_X86_64)
#define DIGEST_SHA1_IMPL_DESC "aws-lc, x86_64"
#elif defined(CONFIG_CRYPTO_SHA1_AWS_X86_64_AVX)
#define DIGEST_SHA1_IMPL_DESC "aws-lc, x86_64, AVX"
#elif defined(CONFIG_CRYPTO_SHA1_AWS_X86_64_AVX2)
#define DIGEST_SHA1_IMPL_DESC "aws-lc, x86_64, AVX2"
#elif defined(CONFIG_CRYPTO_SHA1_AWS_X86_64_SHANI)
#define DIGEST_SHA1_IMPL_DESC "aws-lc, x86_64, SHA-NI"
#elif defined(CONFIG_CRYPTO_SHA1_AWS_ARMV8)
#define DIGEST_SHA1_IMPL_DESC "aws-lc, ARMv8"
#elif defined(CONFIG_CRYPTO_SHA1_GENERIC)
#define DIGEST_SHA1_IMPL_DESC "generic"
#else
#define DIGEST_SHA1_IMPL_DESC "none"
#endif

/* SHA-2 implementation descriptor */
#if defined(CONFIG_CRYPTO_SHA2_OSSL_X86_64)
#define DIGEST_SHA2_IMPL_DESC "OpenSSL, x86_64"
#elif defined(CONFIG_CRYPTO_SHA2_OSSL_ARMV8)
#define DIGEST_SHA2_IMPL_DESC "OpenSSL, ARMv8"
#elif defined(CONFIG_CRYPTO_SHA2_AWS_X86_64)
#define DIGEST_SHA2_IMPL_DESC "aws-lc, x86_64"
#elif defined(CONFIG_CRYPTO_SHA2_AWS_X86_64_AVX)
#define DIGEST_SHA2_IMPL_DESC "aws-lc, x86_64, AVX"
#elif defined(CONFIG_CRYPTO_SHA2_AWS_X86_64_SHANI)
#define DIGEST_SHA2_IMPL_DESC "aws-lc, x86_64, SHA-NI"
#elif defined(CONFIG_CRYPTO_SHA2_AWS_ARMV8)
#define DIGEST_SHA2_IMPL_DESC "aws-lc, ARMv8"
#elif defined(CONFIG_CRYPTO_SHA2_GENERIC)
#define DIGEST_SHA2_IMPL_DESC "generic"
#else
#define DIGEST_SHA2_IMPL_DESC "none"
#endif

/* SHA-3 implementation descriptor */
#if defined(CONFIG_CRYPTO_SHA3_OSSL_X86_64)
#define DIGEST_SHA3_IMPL_DESC "OpenSSL, x86_64"
#elif defined(CONFIG_CRYPTO_SHA3_OSSL_X86_64_AVX2)
#define DIGEST_SHA3_IMPL_DESC "OpenSSL, x86_64, AVX2"
#elif defined(CONFIG_CRYPTO_SHA3_OSSL_ARMV8)
#define DIGEST_SHA3_IMPL_DESC "OpenSSL, ARMv8"
#elif defined(CONFIG_CRYPTO_SHA3_AWS_X86_64)
#define DIGEST_SHA3_IMPL_DESC "aws-lc, x86_64"
#elif defined(CONFIG_CRYPTO_SHA3_AWS_ARMV8)
#define DIGEST_SHA3_IMPL_DESC "aws-lc, ARMv8"
#elif defined(CONFIG_CRYPTO_SHA3)
#define DIGEST_SHA3_IMPL_DESC "generic"
#else
#define DIGEST_SHA3_IMPL_DESC "none"
#endif

const char *
digest_get_name(enum algorithm_digest id)
{
	switch (id) {
	case ALGORITHM_SHA1_160: return "sha1-160";
	case ALGORITHM_SHA2_224: return "sha2-224";
	case ALGORITHM_SHA2_256: return "sha2-256";
	case ALGORITHM_SHA2_384: return "sha2-384";
	case ALGORITHM_SHA2_512: return "sha2-512";
	case ALGORITHM_SHA3_224: return "sha3-224";
	case ALGORITHM_SHA3_256: return "sha3-256";
	case ALGORITHM_SHA3_384: return "sha3-384";
	case ALGORITHM_SHA3_512: return "sha3-512";
	default:                return "";
	}
}

const char *
digest_get_desc(enum algorithm_digest id)
{
	switch (id) {
	case ALGORITHM_SHA1_160: return "SHA1-160 (" DIGEST_SHA1_IMPL_DESC ")";
	case ALGORITHM_SHA2_224: return "SHA2-224 (" DIGEST_SHA2_IMPL_DESC ")";
	case ALGORITHM_SHA2_256: return "SHA2-256 (" DIGEST_SHA2_IMPL_DESC ")";
	case ALGORITHM_SHA2_384: return "SHA2-384 (" DIGEST_SHA2_IMPL_DESC ")";
	case ALGORITHM_SHA2_512: return "SHA2-512 (" DIGEST_SHA2_IMPL_DESC ")";
	case ALGORITHM_SHA3_224: return "SHA3-224 (" DIGEST_SHA3_IMPL_DESC ")";
	case ALGORITHM_SHA3_256: return "SHA3-256 (" DIGEST_SHA3_IMPL_DESC ")";
	case ALGORITHM_SHA3_384: return "SHA3-384 (" DIGEST_SHA3_IMPL_DESC ")";
	case ALGORITHM_SHA3_512: return "SHA3-512 (" DIGEST_SHA3_IMPL_DESC ")";
	default:                return "";
	}
}

#endif
