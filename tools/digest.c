#include <hpc/compiler.h>
#include <crypto/digest.h>

#ifdef CONFIG_CC_CLIB
#include <unistd.h>
#else
#include "nolibc.h"
#endif

static const u8 sha3_256_empty[SHA3_256_DIGEST_SIZE] = {
	0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56,
	0xa0, 0x61, 0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
	0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
};

static int
test_sha3_256(void)
{
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

	for (unsigned int i = 0; i < SHA3_256_DIGEST_SIZE; i++)
		if (digest[i] != sha3_256_empty[i])
			return -1;
	return 0;
}

/* SM3 (GB/T 32905), the standard's own "abc" vector. A build without the
 * backend reports it as skipped rather than failing the no-op fallback. */
static const u8 sm3_abc[32] = {
	0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b,
	0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
	0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
};

static int
test_sm3(void)
{
	u8 digest[32] = {};
	struct sm3 ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, (const u8 *)"abc", 3);
	sm3_final(&ctx, digest);

	for (unsigned int i = 0; i < 32; i++)
		if (digest[i] != sm3_abc[i])
			return -1;
	return 0;
}

int
main(int argc, char *argv[])
{
	int rc = 0;

	if (test_sha3_256() == 0) {
		if (write(1, "sha3-256: ok\n", 13)) {}
	} else {
		if (write(1, "sha3-256: FAIL\n", 15)) {}
		rc = 1;
	}

#ifdef HAVE_DIGEST_SM3_BUILT_IN
	if (test_sm3() == 0) {
		if (write(1, "sm3: ok\n", 8)) {}
	} else {
		if (write(1, "sm3: FAIL\n", 10)) {}
		rc = 1;
	}
#else
	if (write(1, "sm3: skip\n", 10)) {}
#endif

	return rc;
}
