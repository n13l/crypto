/*
 * Standalone HKDF selftest (RFC 5869). Exercises HKDF-SHA256 (Test Case 1,
 * both the one-shot API and the extract/expand split) and HKDF-SHA1 (Test
 * Case 4), linked against whichever digest backend the crypto build selected.
 * One "<name>: ok/FAIL" line is printed per case; non-zero exit on failure.
 */
#include <hpc/compiler.h>
#include <crypto/hkdf.h>

#ifdef CONFIG_CC_CLIB
#include <unistd.h>
#else
#include "nolibc.h"
#endif

static unsigned int slen(const char *s)
{
	unsigned int n = 0;
	while (s[n])
		n++;
	return n;
}

static int _unused report(const char *name, int ok)
{
	if (write(1, name, slen(name))) {}
	if (write(1, ok ? ": ok\n" : ": FAIL\n", ok ? 5 : 7)) {}
	return ok ? 0 : 1;
}

static int _unused eq(const u8 *a, const u8 *b, unsigned int n)
{
	for (unsigned int i = 0; i < n; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

/* RFC 5869 shared salt/info for Test Cases 1 and 4. */
static const u8 _unused salt[13] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c };
static const u8 _unused info[10] = {
	0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };

#if defined(CONFIG_CRYPTO_HKDF_SHA2)
/* RFC 5869 Test Case 1 (SHA-256): IKM = 0x0b x 22. */
static int test_hkdf_sha256(void)
{
	static const u8 ikm[22] = {
		0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
		0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
	static const u8 want_prk[32] = {
		0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,0x3f,0x0d,
		0xc4,0x7b,0xba,0x63,0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,
		0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5 };
	static const u8 want_okm[42] = {
		0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,
		0xd0,0x36,0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
		0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,
		0xd5,0xb8,0x87,0x18,0x58,0x65 };
	u8 prk[32], okm[42];

	/* one-shot */
	if (hkdf_sha256(okm, sizeof(okm), ikm, sizeof(ikm), salt, sizeof(salt),
			info, sizeof(info)) != 0)
		return 0;
	if (!eq(okm, want_okm, sizeof(want_okm)))
		return 0;

	/* extract + expand split must reproduce the same PRK and OKM */
	hkdf_sha256_extract(prk, sizeof(prk), salt, sizeof(salt), ikm, sizeof(ikm));
	if (!eq(prk, want_prk, sizeof(want_prk)))
		return 0;
	for (unsigned int i = 0; i < sizeof(okm); i++)
		okm[i] = 0;
	if (hkdf_sha256_expand(okm, sizeof(okm), prk, sizeof(prk), info,
			       sizeof(info)) != 0)
		return 0;
	return eq(okm, want_okm, sizeof(want_okm));
}
#endif /* CONFIG_CRYPTO_HKDF_SHA2 */

#if defined(CONFIG_CRYPTO_HKDF_SHA1)
/* RFC 5869 Test Case 4 (SHA-1): IKM = 0x0b x 11. */
static int test_hkdf_sha1(void)
{
	static const u8 ikm[11] = {
		0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
	static const u8 want_okm[42] = {
		0x08,0x5a,0x01,0xea,0x1b,0x10,0xf3,0x69,0x33,0x06,0x8b,0x56,
		0xef,0xa5,0xad,0x81,0xa4,0xf1,0x4b,0x82,0x2f,0x5b,0x09,0x15,
		0x68,0xa9,0xcd,0xd4,0xf1,0x55,0xfd,0xa2,0xc2,0x2e,0x42,0x24,
		0x78,0xd3,0x05,0xf3,0xf8,0x96 };
	u8 okm[42];

	if (hkdf_sha1_160(okm, sizeof(okm), ikm, sizeof(ikm), salt, sizeof(salt),
			  info, sizeof(info)) != 0)
		return 0;
	return eq(okm, want_okm, sizeof(want_okm));
}
#endif /* CONFIG_CRYPTO_HKDF_SHA1 */

int
main(int argc, char *argv[])
{
	int rc = 0;

	(void)argc; (void)argv;
#if defined(CONFIG_CRYPTO_HKDF_SHA2)
	rc |= report("hkdf-sha256", test_hkdf_sha256());
#endif
#if defined(CONFIG_CRYPTO_HKDF_SHA1)
	rc |= report("hkdf-sha1", test_hkdf_sha1());
#endif
#if !defined(CONFIG_CRYPTO_HKDF_SHA1) && !defined(CONFIG_CRYPTO_HKDF_SHA2)
	if (write(1, "hkdf: disabled (skip)\n", 22)) {}
#endif
	return rc;
}
