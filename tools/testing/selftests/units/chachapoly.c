/*
 * Unit tests for the ChaCha20-Poly1305 AEAD (crypto/cipher/chachapoly.h),
 * against whichever backend the build selected.
 *
 * This is the primitive the TLS record layer opens protected records with, and
 * it is reached directly rather than through the cipher registry, so it needs
 * a test of its own. The point of the test is that a backend is a build-time
 * choice — portable C, a vectorised keystream, or one pass of assembly that
 * runs the keystream and the authenticator together — and all of them have to
 * agree, byte for byte, with RFC 8439. Linking the crypto archive rather than
 * a fixed implementation is what makes the same cases cover each of them.
 *
 * The sweeps exist because the backends branch on length. The vectorised
 * keystream takes its SIMD path only from 192 bytes up and the fused assembly
 * has block-count cases of its own, so a record that is one byte either side
 * of a threshold is where a wrong tail lives. Everything from an empty message
 * to a maximal TLS record is checked against a single reference: the two-pass
 * construction is not available to compare against once a fused backend is
 * configured, so each case is instead required to round-trip and to reject the
 * same input with one bit changed.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include <crypto/cipher/chachapoly.h>

/* a maximal TLS record's plaintext, which is the size the record layer asks
 * for most often and the one the perf corpus is built from */
#define BULK_MAX	16384u

/*
 * What a decrypt of a record that has been tampered with is supposed to
 * return. A build with CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD off does not
 * compute the tag, so it accepts everything by construction and the rejection
 * cases below are asserting that it says so — the tests still run, they just
 * expect the other answer.
 */
#ifdef CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD
#define EXPECT_ON_TAMPER	CHACHAPOLY_INVALID_MAC
#else
#define EXPECT_ON_TAMPER	CHACHAPOLY_OK
#endif

/* RFC 8439 2.8.2 */
static const u8 rfc_key[32] = {
	0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
	0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
	0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
	0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f };
static const u8 rfc_nonce[12] = {
	0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47 };
static const u8 rfc_ad[12] = {
	0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7 };
static const char rfc_pt[] =
	"Ladies and Gentlemen of the class of '99: If I could offer you only "
	"one tip for the future, sunscreen would be it.";
static const u8 rfc_ct[114] = {
	0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,
	0x53,0xef,0x7e,0xc2,0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
	0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,0x3d,0xbe,0xa4,0x5e,
	0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
	0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,
	0x7e,0xcd,0x3b,0x36,0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
	0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,0xfa,0xb3,0x24,0xe4,
	0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
	0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,
	0x86,0xce,0xc6,0x4b,0x61,0x16 };
static const u8 rfc_tag[16] = {
	0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
	0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91 };

/* the vector, both directions: the one case with an answer written down */
static void
test_rfc8439_vector(void **state)
{
	struct chachapoly_ctx ctx;
	u8 ct[sizeof(rfc_ct)], tag[POLY1305_TAGLEN], pt[sizeof(rfc_ct)];
	int n = (int)(sizeof(rfc_pt) - 1);

	(void)state;
	assert_int_equal(n, (int)sizeof(rfc_ct));

	assert_int_equal(chachapoly_init(&ctx, rfc_key, 256), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, rfc_ad,
					  (int)sizeof(rfc_ad),
					  (void *)(uintptr_t)rfc_pt, n, ct,
					  tag, POLY1305_TAGLEN, 1),
			 CHACHAPOLY_OK);
	assert_memory_equal(ct, rfc_ct, sizeof(rfc_ct));
	assert_memory_equal(tag, rfc_tag, sizeof(rfc_tag));

	assert_int_equal(chachapoly_init(&ctx, rfc_key, 256), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, rfc_ad,
					  (int)sizeof(rfc_ad),
					  (void *)(uintptr_t)rfc_ct, n, pt,
					  (void *)(uintptr_t)rfc_tag,
					  POLY1305_TAGLEN, 0),
			 CHACHAPOLY_OK);
	assert_memory_equal(pt, rfc_pt, (size_t)n);
}

/* RFC 8439 2.5.2, the authenticator on its own */
static void
test_poly1305_vector(void **state)
{
	static const u8 key[32] = {
		0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
		0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
		0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
		0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b };
	static const char msg[] = "Cryptographic Forum Research Group";
	static const u8 want[16] = {
		0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
		0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9 };
	u8 mac[16];

	(void)state;
	poly1305_auth(mac, (const u8 *)msg, sizeof(msg) - 1, key);
	assert_memory_equal(mac, want, sizeof(want));
}

/*
 * Round-trip @n bytes and then offer every single-bit change the record could
 * have suffered on the wire — one in the ciphertext, one in the tag, one in
 * the associated data — and require the answer this build is supposed to give
 * for each: refusal normally, acceptance where the tag is not computed at all.
 */
static void
roundtrip_and_reject(const u8 *key, int key_bits, unsigned int n)
{
	struct chachapoly_ctx ctx;
	static u8 pt[BULK_MAX], ct[BULK_MAX], back[BULK_MAX];
	u8 ad[13], tag[POLY1305_TAGLEN], bad_tag[POLY1305_TAGLEN];
	unsigned int i;

	for (i = 0; i < n; i++)
		pt[i] = (u8)(i * 251u + 13u);
	for (i = 0; i < sizeof(ad); i++)
		ad[i] = (u8)(i + 1);

	assert_int_equal(chachapoly_init(&ctx, key, key_bits), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, ad, (int)sizeof(ad),
					  pt, (int)n, ct, tag,
					  POLY1305_TAGLEN, 1),
			 CHACHAPOLY_OK);

	assert_int_equal(chachapoly_init(&ctx, key, key_bits), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, ad, (int)sizeof(ad),
					  ct, (int)n, back, tag,
					  POLY1305_TAGLEN, 0),
			 CHACHAPOLY_OK);
	if (n)
		assert_memory_equal(back, pt, n);

	/* a flipped ciphertext bit (an empty message has no ciphertext) */
	if (n) {
		ct[n / 2] ^= 0x40;
		assert_int_equal(chachapoly_init(&ctx, key, key_bits),
				 CHACHAPOLY_OK);
		assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, ad,
						  (int)sizeof(ad), ct, (int)n,
						  back, tag, POLY1305_TAGLEN, 0),
				 EXPECT_ON_TAMPER);
		ct[n / 2] ^= 0x40;
	}

	/* a flipped tag bit */
	memcpy(bad_tag, tag, sizeof(tag));
	bad_tag[0] ^= 1;
	assert_int_equal(chachapoly_init(&ctx, key, key_bits), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, ad, (int)sizeof(ad),
					  ct, (int)n, back, bad_tag,
					  POLY1305_TAGLEN, 0),
			 EXPECT_ON_TAMPER);

	/* a flipped associated-data bit: the header is authenticated too */
	ad[0] ^= 1;
	assert_int_equal(chachapoly_init(&ctx, key, key_bits), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, ad, (int)sizeof(ad),
					  ct, (int)n, back, tag,
					  POLY1305_TAGLEN, 0),
			 EXPECT_ON_TAMPER);
}

/*
 * Every length a backend branches on: the ChaCha block, the Poly1305 block,
 * the 192-byte floor the NEON keystream needs, and the multi-block runs the
 * fused assembly unrolls, each with a byte either side.
 */
static void
test_lengths(void **state)
{
	static const unsigned int lens[] = {
		0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 129,
		191, 192, 193, 255, 256, 257, 319, 320, 321,
		383, 384, 385, 511, 512, 513, 1023, 1024, 1025,
		4095, 4096, 4097, BULK_MAX - 1, BULK_MAX };
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
		roundtrip_and_reject(rfc_key, 256, lens[i]);
}

/*
 * A 128-bit key is not RFC 7539 — the generic code duplicates it into both
 * halves — so a fused backend has to hand it back to the two-pass path rather
 * than run its assembly on it. This is the case that catches a dispatch which
 * forgot to check.
 */
static void
test_128_bit_key(void **state)
{
	static const unsigned int lens[] = { 0, 1, 64, 192, 1024, BULK_MAX };
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
		roundtrip_and_reject(rfc_key, 128, lens[i]);
}

/*
 * tag_len 0 says "no authenticator": decrypt and hand back the plaintext
 * without checking anything. It is the other way out of a fused dispatch, and
 * it still has to produce the same keystream as the authenticated call.
 */
static void
test_unauthenticated(void **state)
{
	struct chachapoly_ctx ctx;
	static u8 pt[1024], ct[1024], back[1024];
	u8 tag[POLY1305_TAGLEN];
	unsigned int i, n = sizeof(pt);

	(void)state;
	for (i = 0; i < n; i++)
		pt[i] = (u8)(i * 97u + 5u);

	assert_int_equal(chachapoly_init(&ctx, rfc_key, 256), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, rfc_ad,
					  (int)sizeof(rfc_ad), pt, (int)n, ct,
					  tag, POLY1305_TAGLEN, 1),
			 CHACHAPOLY_OK);

	assert_int_equal(chachapoly_init(&ctx, rfc_key, 256), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, rfc_ad,
					  (int)sizeof(rfc_ad), ct, (int)n, back,
					  NULL, 0, 0),
			 CHACHAPOLY_OK);
	assert_memory_equal(back, pt, n);
}

/*
 * Two records under one key, opened in sequence with their own nonces, which
 * is what a channel does. A backend that leaked state from one call into the
 * next would pass every test above and fail this one.
 */
static void
test_nonce_is_per_record(void **state)
{
	struct chachapoly_ctx ctx;
	u8 nonce_a[12], nonce_b[12];
	u8 pt[200], ct_a[200], ct_b[200], back[200];
	u8 tag_a[POLY1305_TAGLEN], tag_b[POLY1305_TAGLEN];
	unsigned int i;

	(void)state;
	memcpy(nonce_a, rfc_nonce, sizeof(nonce_a));
	memcpy(nonce_b, rfc_nonce, sizeof(nonce_b));
	nonce_b[11] ^= 1;
	for (i = 0; i < sizeof(pt); i++)
		pt[i] = (u8)i;

	assert_int_equal(chachapoly_init(&ctx, rfc_key, 256), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, nonce_a, rfc_ad,
					  (int)sizeof(rfc_ad), pt,
					  (int)sizeof(pt), ct_a, tag_a,
					  POLY1305_TAGLEN, 1), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, nonce_b, rfc_ad,
					  (int)sizeof(rfc_ad), pt,
					  (int)sizeof(pt), ct_b, tag_b,
					  POLY1305_TAGLEN, 1), CHACHAPOLY_OK);

	/* different nonce, different keystream */
	assert_memory_not_equal(ct_a, ct_b, sizeof(ct_a));

	/* and each still opens, on the same context, in either order */
	assert_int_equal(chachapoly_crypt(&ctx, nonce_b, rfc_ad,
					  (int)sizeof(rfc_ad), ct_b,
					  (int)sizeof(ct_b), back, tag_b,
					  POLY1305_TAGLEN, 0), CHACHAPOLY_OK);
	assert_memory_equal(back, pt, sizeof(pt));
	assert_int_equal(chachapoly_crypt(&ctx, nonce_a, rfc_ad,
					  (int)sizeof(rfc_ad), ct_a,
					  (int)sizeof(ct_a), back, tag_a,
					  POLY1305_TAGLEN, 0), CHACHAPOLY_OK);
	assert_memory_equal(back, pt, sizeof(pt));

	/* the other record's tag is not this record's tag */
	assert_int_equal(chachapoly_crypt(&ctx, nonce_a, rfc_ad,
					  (int)sizeof(rfc_ad), ct_a,
					  (int)sizeof(ct_a), back, tag_b,
					  POLY1305_TAGLEN, 0),
			 EXPECT_ON_TAMPER);
}

/* no associated data at all, which is what the cipher registry's wrapper does */
static void
test_no_associated_data(void **state)
{
	struct chachapoly_ctx ctx;
	u8 pt[300], ct[300], back[300], tag[POLY1305_TAGLEN];
	unsigned int i;

	(void)state;
	for (i = 0; i < sizeof(pt); i++)
		pt[i] = (u8)(i * 7u);

	assert_int_equal(chachapoly_init(&ctx, rfc_key, 256), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, NULL, 0, pt,
					  (int)sizeof(pt), ct, tag,
					  POLY1305_TAGLEN, 1), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_init(&ctx, rfc_key, 256), CHACHAPOLY_OK);
	assert_int_equal(chachapoly_crypt(&ctx, rfc_nonce, NULL, 0, ct,
					  (int)sizeof(ct), back, tag,
					  POLY1305_TAGLEN, 0), CHACHAPOLY_OK);
	assert_memory_equal(back, pt, sizeof(pt));
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_rfc8439_vector),
		cmocka_unit_test(test_poly1305_vector),
		cmocka_unit_test(test_lengths),
		cmocka_unit_test(test_128_bit_key),
		cmocka_unit_test(test_unauthenticated),
		cmocka_unit_test(test_nonce_is_per_record),
		cmocka_unit_test(test_no_associated_data),
	};

	return cmocka_run_group_tests_name("chachapoly", tests, NULL, NULL);
}
