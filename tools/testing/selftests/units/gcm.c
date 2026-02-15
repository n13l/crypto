/*
 * Unit tests for AES-GCM (crypto/cipher/aes/gcm.h), against whichever backend
 * the build selected.
 *
 * The record layer opens TLS 1.2 and 1.3 AEAD records through these two
 * functions, so they carry the same obligation the ChaCha20-Poly1305 tests
 * next door do: the answer has to be the standard's answer, on every backend
 * and at every record length.
 *
 * They also carry one the other tests cannot state as directly. A build may be
 * configured not to compute the tag at all (CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD
 * off), and the whole argument for that option is that it changes what is
 * *checked*
 * without changing what is *produced*. The spec vectors below are what makes
 * that checkable: they fix the plaintext for a known ciphertext, so a decrypt
 * that skipped the authenticator still has to land on the written-down answer
 * rather than merely on something self-consistent.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include <crypto/cipher/aes/gcm.h>

#define TAG_LEN		16
#define BULK_MAX	16384u

/*
 * What a decrypt of a record that has been tampered with returns. Without the
 * tag there is nothing to detect it with, so such a build accepts everything
 * and these cases assert that it says so. See
 * CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD.
 */
#ifdef CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD
#define EXPECT_ON_TAMPER	GCM_AUTH_FAILURE
#else
#define EXPECT_ON_TAMPER	0
#endif

static const u8 zero_key32[32] = { 0 };
static const u8 zero_iv[12] = { 0 };

/*
 * The GCM specification's own test cases (McGrew & Viega, "The Galois/Counter
 * Mode of Operation", appendix B): the all-zero key and IV, which is the pair
 * every GCM implementation is first checked against.
 */
static void
test_spec_vectors(void **state)
{
	/* case 1: AES-128, empty plaintext */
	static const u8 t1[TAG_LEN] = {
		0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
		0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a };
	/* case 2: AES-128, one zero block */
	static const u8 c2[16] = {
		0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
		0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78 };
	static const u8 t2[TAG_LEN] = {
		0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
		0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf };
	/* case 13: AES-256, empty plaintext */
	static const u8 t13[TAG_LEN] = {
		0x53,0x0f,0x8a,0xfb,0xc7,0x45,0x36,0xb9,
		0xa9,0x63,0xb4,0xf1,0xc4,0xcb,0x73,0x8b };
	/* case 14: AES-256, one zero block */
	static const u8 c14[16] = {
		0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,
		0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18 };
	static const u8 t14[TAG_LEN] = {
		0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,
		0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19 };

	u8 zero_block[16] = { 0 };
	u8 out[16 + TAG_LEN], back[16];

	(void)state;

	/* case 1 */
	assert_int_equal(aes_gcm_encrypt(out, zero_block, 0, zero_key32, 16,
					 zero_iv, sizeof(zero_iv)), 0);
	assert_memory_equal(out, t1, TAG_LEN);

	/* case 2 */
	assert_int_equal(aes_gcm_encrypt(out, zero_block, 16, zero_key32, 16,
					 zero_iv, sizeof(zero_iv)), 0);
	assert_memory_equal(out, c2, sizeof(c2));
	assert_memory_equal(out + 16, t2, TAG_LEN);

	/* and back: the plaintext is written down, tag or no tag */
	assert_int_equal(aes_gcm_decrypt(back, out, 16 + TAG_LEN, zero_key32,
					 16, zero_iv, sizeof(zero_iv)), 0);
	assert_memory_equal(back, zero_block, sizeof(zero_block));

	/* case 13 */
	assert_int_equal(aes_gcm_encrypt(out, zero_block, 0, zero_key32, 32,
					 zero_iv, sizeof(zero_iv)), 0);
	assert_memory_equal(out, t13, TAG_LEN);

	/* case 14 */
	assert_int_equal(aes_gcm_encrypt(out, zero_block, 16, zero_key32, 32,
					 zero_iv, sizeof(zero_iv)), 0);
	assert_memory_equal(out, c14, sizeof(c14));
	assert_memory_equal(out + 16, t14, TAG_LEN);

	assert_int_equal(aes_gcm_decrypt(back, out, 16 + TAG_LEN, zero_key32,
					 32, zero_iv, sizeof(zero_iv)), 0);
	assert_memory_equal(back, zero_block, sizeof(zero_block));
}

/*
 * A decrypt of a valid record has to reproduce the plaintext exactly. This is
 * the property turning CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD off must not
 * disturb: the counter half is the whole of the answer, and the tag only ever
 * decided whether to believe it.
 */
static void
roundtrip(size_t key_len, unsigned int n, size_t aad_len)
{
	static u8 pt[BULK_MAX], ct[BULK_MAX + TAG_LEN], back[BULK_MAX];
	u8 key[32], iv[12], aad[64];
	unsigned int i;

	for (i = 0; i < sizeof(key); i++)
		key[i] = (u8)(i * 17u + 3u);
	for (i = 0; i < sizeof(iv); i++)
		iv[i] = (u8)(i * 29u + 11u);
	for (i = 0; i < sizeof(aad); i++)
		aad[i] = (u8)(i + 1);
	for (i = 0; i < n; i++)
		pt[i] = (u8)(i * 251u + 13u);

	assert_int_equal(aes_gcm_encrypt_aad(ct, pt, (int)n, aad, aad_len,
					     key, key_len, iv, sizeof(iv)), 0);
	assert_int_equal(aes_gcm_decrypt_aad(back, ct, (int)(n + TAG_LEN), aad,
					     aad_len, key, key_len, iv,
					     sizeof(iv)), 0);
	if (n)
		assert_memory_equal(back, pt, n);

	/* a flipped ciphertext bit */
	if (n) {
		ct[n / 2] ^= 0x40;
		assert_int_equal(aes_gcm_decrypt_aad(back, ct,
						     (int)(n + TAG_LEN), aad,
						     aad_len, key, key_len, iv,
						     sizeof(iv)),
				 EXPECT_ON_TAMPER);
		ct[n / 2] ^= 0x40;
	}

	/* a flipped tag bit */
	ct[n] ^= 1;
	assert_int_equal(aes_gcm_decrypt_aad(back, ct, (int)(n + TAG_LEN), aad,
					     aad_len, key, key_len, iv,
					     sizeof(iv)),
			 EXPECT_ON_TAMPER);
	ct[n] ^= 1;

	/* a flipped associated-data bit: the header is authenticated too */
	if (aad_len) {
		aad[0] ^= 1;
		assert_int_equal(aes_gcm_decrypt_aad(back, ct,
						     (int)(n + TAG_LEN), aad,
						     aad_len, key, key_len, iv,
						     sizeof(iv)),
				 EXPECT_ON_TAMPER);
		aad[0] ^= 1;
	}
}

/* the AES block, the assembly's unrolled runs, and a maximal TLS record */
static const unsigned int lens[] = {
	0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
	255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097,
	BULK_MAX - 1, BULK_MAX };

static void
test_aes128_lengths(void **state)
{
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
		roundtrip(16, lens[i], 13);	/* 13 == the TLS 1.2 AAD */
}

static void
test_aes256_lengths(void **state)
{
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
		roundtrip(32, lens[i], 13);
}

/* no associated data, and an AAD longer than one block */
static void
test_aad_lengths(void **state)
{
	static const size_t aads[] = { 0, 1, 5, 13, 16, 17, 31, 32, 33, 64 };
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(aads) / sizeof(aads[0]); i++) {
		roundtrip(16, 1024, aads[i]);
		roundtrip(32, 1024, aads[i]);
	}
}

/* a record too short to hold a tag is refused rather than read past */
static void
test_truncated_record(void **state)
{
	u8 buf[TAG_LEN], out[TAG_LEN];

	(void)state;
	memset(buf, 0, sizeof(buf));
	assert_int_equal(aes_gcm_decrypt_aad(out, buf, TAG_LEN - 1, NULL, 0,
					     zero_key32, 16, zero_iv,
					     sizeof(zero_iv)),
			 GCM_AUTH_FAILURE);
	assert_int_equal(aes_gcm_decrypt(out, buf, -1, zero_key32, 16, zero_iv,
					 sizeof(zero_iv)), GCM_AUTH_FAILURE);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_spec_vectors),
		cmocka_unit_test(test_aes128_lengths),
		cmocka_unit_test(test_aes256_lengths),
		cmocka_unit_test(test_aad_lengths),
		cmocka_unit_test(test_truncated_record),
	};

	return cmocka_run_group_tests_name("gcm", tests, NULL, NULL);
}
