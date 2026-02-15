/*
 * Unit tests for AES-CCM (crypto/cipher/aes/ccm.h), against whichever backend
 * the build selected.
 *
 * CCM is the third record protection the TLS layer opens with, and the one
 * whose formatting is easiest to get subtly wrong: the flags byte encodes the
 * tag length and the length field's width, the associated data carries a
 * length prefix that shares its first block with the data, and each of the
 * three regions is padded to a block boundary on its own. None of that shows
 * up as a wrong plaintext - it shows up as a tag that does not verify, which
 * is why the vectors below matter more here than a round trip does.
 *
 * The published vectors do not fit. NIST SP 800-38C appendix C and RFC 3610
 * both use nonces of 13 bytes and shorter, and this API only accepts the 12
 * TLS fixes; running them would mean an entry point nothing else in the tree
 * wants. So the absolute vector below was produced by OpenSSL's
 * EVP_aes_128_ccm at the TLS parameterisation - 12-byte nonce, L=3, 13 bytes
 * of associated data - and is here to pin this implementation to another one
 * rather than only to itself. Its real corroboration is elsewhere and is much
 * stronger: the CCM fixture captures under tools/testing/fixture/pcap were
 * written by OpenSSL and this decoder opens every record in them.
 *
 * Everything else is checked by construction: encrypt then decrypt, at every
 * length a block boundary or the assembly's bulk path could get wrong, with
 * each single-bit change refused. Round trips alone would not be enough - a
 * formatting bug symmetric between the two directions survives them, which is
 * what the vector and test_tag_depends_on_everything are for.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include <crypto/cipher/aes/ccm.h>

#define BULK_MAX	16384u

/*
 * What a decrypt of a record that has been tampered with returns. Without the
 * tag there is nothing to detect it with. See CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD.
 */
#ifdef CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD
#define EXPECT_ON_TAMPER	CCM_AUTH_FAILURE
#else
#define EXPECT_ON_TAMPER	0
#endif

static const u8 key128[16] = {
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
	0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f };
static const u8 key256[32] = {
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
	0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
	0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
	0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f };
static const u8 nonce12[12] = {
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b };

/*
 * AES-128-CCM at the TLS parameterisation, from OpenSSL's EVP_aes_128_ccm:
 * key128, nonce12, 13 bytes of associated data aad[i] = 3i + 1, and 40 bytes
 * of plaintext pt[i] = 251i + 13, all as the helpers below build them.
 */
static void
test_openssl_vector(void **state)
{
	static const u8 want_ct[40] = {
		0xce,0x9b,0x20,0x74,0x28,0x66,0xd3,0xb7,
		0x56,0xd5,0x1b,0x11,0x30,0x76,0x0e,0xe6,
		0xec,0xff,0x2b,0x44,0x39,0xd3,0x23,0x08,
		0xf9,0xb2,0x60,0x69,0xab,0xbb,0x45,0xae,
		0xc1,0x1e,0x8e,0x3d,0x73,0x73,0x71,0xa3 };
	static const u8 want_tag[16] = {
		0x0a,0xf3,0x53,0xcc,0xe1,0x99,0x1b,0xf7,
		0xb1,0x68,0x81,0x57,0x7d,0xd6,0x3e,0x95 };
	u8 pt[40], aad[13], ct[40 + 16], back[40];
	unsigned int i;

	(void)state;
	for (i = 0; i < sizeof(aad); i++)
		aad[i] = (u8)(i * 3u + 1u);
	for (i = 0; i < sizeof(pt); i++)
		pt[i] = (u8)(i * 251u + 13u);

	assert_int_equal(aes_ccm_encrypt_aad(ct, pt, (int)sizeof(pt), aad,
					     sizeof(aad), key128, 16, nonce12,
					     sizeof(nonce12), 16), 0);
	assert_memory_equal(ct, want_ct, sizeof(want_ct));
	assert_memory_equal(ct + sizeof(pt), want_tag, sizeof(want_tag));

	/* and the other way, from the bytes OpenSSL wrote */
	memcpy(ct, want_ct, sizeof(want_ct));
	memcpy(ct + sizeof(pt), want_tag, sizeof(want_tag));
	assert_int_equal(aes_ccm_decrypt_aad(back, ct, (int)sizeof(ct), aad,
					     sizeof(aad), key128, 16, nonce12,
					     sizeof(nonce12), 16), 0);
	assert_memory_equal(back, pt, sizeof(pt));
}

/*
 * Round-trip @n bytes under @key_len/@tag_len with @aad_len of associated
 * data, then require every single-bit change to be answered the way this
 * build is supposed to answer it.
 */
static void
roundtrip(size_t key_len, size_t tag_len, unsigned int n, size_t aad_len)
{
	static u8 pt[BULK_MAX], ct[BULK_MAX + AES_CCM_TAG_LEN], back[BULK_MAX];
	const u8 *key = key_len == 16 ? key128 : key256;
	u8 aad[64];
	unsigned int i;

	for (i = 0; i < sizeof(aad); i++)
		aad[i] = (u8)(i * 3u + 1u);
	for (i = 0; i < n; i++)
		pt[i] = (u8)(i * 251u + 13u);

	assert_int_equal(aes_ccm_encrypt_aad(ct, pt, (int)n, aad, aad_len, key,
					     key_len, nonce12, sizeof(nonce12),
					     tag_len), 0);
	assert_int_equal(aes_ccm_decrypt_aad(back, ct, (int)(n + tag_len), aad,
					     aad_len, key, key_len, nonce12,
					     sizeof(nonce12), tag_len), 0);
	if (n)
		assert_memory_equal(back, pt, n);

	if (n) {
		ct[n / 2] ^= 0x40;
		assert_int_equal(aes_ccm_decrypt_aad(back, ct,
						     (int)(n + tag_len), aad,
						     aad_len, key, key_len,
						     nonce12, sizeof(nonce12),
						     tag_len),
				 EXPECT_ON_TAMPER);
		ct[n / 2] ^= 0x40;
	}

	ct[n] ^= 1;					/* the tag */
	assert_int_equal(aes_ccm_decrypt_aad(back, ct, (int)(n + tag_len), aad,
					     aad_len, key, key_len, nonce12,
					     sizeof(nonce12), tag_len),
			 EXPECT_ON_TAMPER);
	ct[n] ^= 1;

	if (aad_len) {					/* the header */
		aad[0] ^= 1;
		assert_int_equal(aes_ccm_decrypt_aad(back, ct,
						     (int)(n + tag_len), aad,
						     aad_len, key, key_len,
						     nonce12, sizeof(nonce12),
						     tag_len),
				 EXPECT_ON_TAMPER);
		aad[0] ^= 1;
	}
}

/* the AES block, the bulk path's runs, and a maximal TLS record */
static const unsigned int lens[] = {
	0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
	255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097,
	BULK_MAX - 1, BULK_MAX };

static void
test_aes128_ccm(void **state)
{
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
		roundtrip(16, AES_CCM_TAG_LEN, lens[i], 13);
}

static void
test_aes256_ccm(void **state)
{
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
		roundtrip(32, AES_CCM_TAG_LEN, lens[i], 13);
}

/* CCM_8: the same construction with the tag cut to 8 */
static void
test_ccm_8(void **state)
{
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		roundtrip(16, AES_CCM_8_TAG_LEN, lens[i], 13);
		roundtrip(32, AES_CCM_8_TAG_LEN, lens[i], 5);
	}
}

/*
 * The associated-data lengths that move the encoding: none at all (which
 * clears the Adata flag in B0 and skips the region entirely), the 5 bytes a
 * TLS 1.3 header is, the 13 a TLS 1.2 one is, and the boundaries where the
 * two-byte prefix stops sharing its block with the data.
 */
static void
test_aad_lengths(void **state)
{
	static const size_t aads[] = { 0, 1, 5, 13, 14, 15, 16, 17, 31, 32, 33, 64 };
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(aads) / sizeof(aads[0]); i++) {
		roundtrip(16, AES_CCM_TAG_LEN, 1024, aads[i]);
		roundtrip(16, AES_CCM_8_TAG_LEN, 100, aads[i]);
	}
}

/*
 * The tag has to depend on the associated data, the nonce and the key
 * separately. A formatting bug that dropped the AAD region would still round
 * trip - both directions would drop it - so it has to be caught by showing
 * that changing it changes the tag.
 */
static void
test_tag_depends_on_everything(void **state)
{
	u8 ct_a[64 + 16], ct_b[64 + 16], pt[64], aad[13], nonce[12];
	unsigned int i;

	(void)state;
	for (i = 0; i < sizeof(pt); i++)
		pt[i] = (u8)i;
	for (i = 0; i < sizeof(aad); i++)
		aad[i] = (u8)(i + 1);
	memcpy(nonce, nonce12, sizeof(nonce));

	assert_int_equal(aes_ccm_encrypt_aad(ct_a, pt, sizeof(pt), aad,
					     sizeof(aad), key128, 16, nonce,
					     sizeof(nonce), 16), 0);

	/* a different AAD: same ciphertext, different tag */
	aad[7] ^= 0x80;
	assert_int_equal(aes_ccm_encrypt_aad(ct_b, pt, sizeof(pt), aad,
					     sizeof(aad), key128, 16, nonce,
					     sizeof(nonce), 16), 0);
	assert_memory_equal(ct_a, ct_b, sizeof(pt));
	assert_memory_not_equal(ct_a + sizeof(pt), ct_b + sizeof(pt), 16);
	aad[7] ^= 0x80;

	/* a different nonce: both change */
	nonce[11] ^= 1;
	assert_int_equal(aes_ccm_encrypt_aad(ct_b, pt, sizeof(pt), aad,
					     sizeof(aad), key128, 16, nonce,
					     sizeof(nonce), 16), 0);
	assert_memory_not_equal(ct_a, ct_b, sizeof(pt));
	nonce[11] ^= 1;

	/*
	 * The 8-byte tag is NOT the 16-byte one cut in half. CCM puts the tag
	 * length into the flags byte of B0 (SP 800-38C A.2.1), so it is an
	 * input to the CBC-MAC and the two tags are unrelated - which is the
	 * one visible consequence of that byte being encoded at all, and so
	 * the thing to assert. The ciphertext is untouched by it, because the
	 * counter pass never sees the tag length.
	 */
	assert_int_equal(aes_ccm_encrypt_aad(ct_b, pt, sizeof(pt), aad,
					     sizeof(aad), key128, 16, nonce,
					     sizeof(nonce), 8), 0);
	assert_memory_equal(ct_a, ct_b, sizeof(pt));
	assert_memory_not_equal(ct_a + sizeof(pt), ct_b + sizeof(pt), 8);
}

/* parameters outside the TLS parameterisation are refused, not assumed */
static void
test_refused_parameters(void **state)
{
	u8 in[32] = { 0 }, out[64];

	(void)state;
	/* a nonce that is not 12 bytes */
	assert_int_equal(aes_ccm_encrypt_aad(out, in, 16, NULL, 0, key128, 16,
					     nonce12, 13, 16), CCM_AUTH_FAILURE);
	/* a tag length that is neither 16 nor 8 */
	assert_int_equal(aes_ccm_encrypt_aad(out, in, 16, NULL, 0, key128, 16,
					     nonce12, 12, 12), CCM_AUTH_FAILURE);
	/* a 192-bit key, which no TLS suite names */
	assert_int_equal(aes_ccm_encrypt_aad(out, in, 16, NULL, 0, key256, 24,
					     nonce12, 12, 16), CCM_AUTH_FAILURE);
	/* a record too short to hold its own tag */
	assert_int_equal(aes_ccm_decrypt_aad(out, in, 8, NULL, 0, key128, 16,
					     nonce12, 12, 16), CCM_AUTH_FAILURE);
	assert_int_equal(aes_ccm_decrypt_aad(out, in, -1, NULL, 0, key128, 16,
					     nonce12, 12, 16), CCM_AUTH_FAILURE);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_openssl_vector),
		cmocka_unit_test(test_aes128_ccm),
		cmocka_unit_test(test_aes256_ccm),
		cmocka_unit_test(test_ccm_8),
		cmocka_unit_test(test_aad_lengths),
		cmocka_unit_test(test_tag_depends_on_everything),
		cmocka_unit_test(test_refused_parameters),
	};

	return cmocka_run_group_tests_name("ccm", tests, NULL, NULL);
}
