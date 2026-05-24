#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <hpc/compiler.h>
#include <crypto/digest.h>

static const u8 sha3_256_empty[SHA3_256_DIGEST_SIZE] = {
	0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56,
	0xa0, 0x61, 0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
	0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
};

static void
test_sha3_256_empty_message(void **state)
{
	(void)state;
	u8 digest[SHA3_256_DIGEST_SIZE] = {};

#ifdef __CRYPTO_DIGEST_SHA3_H__
	struct sha3_ctx sha3;
	sha3.sha = digest;
	sha3_256_init(&sha3);
	sha3_update(&sha3, (const u8 *)"", 0);
	sha3_final(&sha3);
#else
	struct sha3 sha3;
	sha3_256_init(&sha3);
	sha3_update(&sha3, (const u8 *)"", 0);
	sha3_final(&sha3, digest);
#endif

	assert_memory_equal(digest, sha3_256_empty, SHA3_256_DIGEST_SIZE);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sha3_256_empty_message),
	};
	return cmocka_run_group_tests_name("digest", tests, NULL, NULL);
}
