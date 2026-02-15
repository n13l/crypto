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
	struct sha3 sha3;
	u8 digest[SHA3_256_DIGEST_SIZE] = {};

	sha3_256_init(&sha3);
	sha3_update(&sha3, (const u8 *)"", 0);
	sha3_final(&sha3, digest);

	for (unsigned int i = 0; i < SHA3_256_DIGEST_SIZE; i++)
		if (digest[i] != sha3_256_empty[i])
			return -1;
	return 0;
}

int
main(int argc, char *argv[])
{
	if (test_sha3_256() == 0) {
		if (write(1, "sha3-256: ok\n", 13)) {}
	} else {
		if (write(1, "sha3-256: FAIL\n", 15)) {}
	}

	return 0;
}
