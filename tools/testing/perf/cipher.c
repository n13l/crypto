/*
 * Cipher throughput benchmark. Sweeps plaintext sizes small -> large over the
 * AEAD/CBC primitives, one message per operation with a fixed key/IV, against
 * whichever backend the crypto build selected. Run with -b <bytes> for a
 * single fixed size, -t <secs> to change the per-point budget, -d to time the
 * open direction instead of the seal, and algorithm names to run only those.
 *
 * -d is the side a record layer is on: it opens what a peer sealed. So what
 * the loop opens is sealed once per point, outside the clock, and opened with
 * its tag on every iteration — a build with CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD
 * checks that tag each time, a build without it runs the keystream alone, and
 * the row measures whichever this build is. The first open of a point is
 * checked and a refusal reported rather than timed, because a rate over
 * failing opens (GCM zeroes its output on failure) is a number about nothing.
 * CBC works in place and its bytes stop being plaintext after the first pass;
 * the cost does not care.
 */
#include <hpc/compiler.h>
#include <crypto/cipher.h>
#include <crypto/cipher/aes.h>
#include <crypto/cipher/aes/gcm.h>
#include <crypto/cipher/aes/ccm.h>
#include <crypto/cipher/chachapoly.h>
#include <crypto/init.h>
#include "bench.h"

static const u8 key32[32] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
static const u8 iv16[16] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
static const u8 nonce12[12] = {
	0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47 };
static const u8 aad12[12] = {
	0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7 };

static u8 pt[BENCH_MAX_SIZE];
static u8 ct[BENCH_MAX_SIZE + 16];		/* sealed once per point: the
						 * ciphertext, then a 16-byte tag */
static u8 out[BENCH_MAX_SIZE + 16];		/* what an open writes */
static u8 cbc[BENCH_MAX_SIZE];			/* CBC works in place, both ways */
static u8 tag16[16];				/* chacha20-poly1305 keeps its tag
						 * apart from the ciphertext */

static int open_dir;				/* -d: time the open, not the seal */

/* one operation over @size bytes; an open returns the backend's verdict */
typedef int (*op_fn)(unsigned int size);

static int
seal_aes128_gcm(unsigned int size)
{
	return aes_gcm_encrypt(ct, pt, (int)size, key32, 16, iv16, 12);
}

static int
open_aes128_gcm(unsigned int size)
{
	return aes_gcm_decrypt(out, ct, (int)size + 16, key32, 16, iv16, 12);
}

static int
seal_aes256_gcm(unsigned int size)
{
	return aes_gcm_encrypt(ct, pt, (int)size, key32, 32, iv16, 12);
}

static int
open_aes256_gcm(unsigned int size)
{
	return aes_gcm_decrypt(out, ct, (int)size + 16, key32, 32, iv16, 12);
}

static int
seal_aes128_ccm(unsigned int size)
{
	return aes_ccm_encrypt_aad(ct, pt, (int)size, aad12, sizeof(aad12),
				   key32, 16, nonce12, AES_CCM_NONCE_LEN,
				   AES_CCM_TAG_LEN);
}

static int
open_aes128_ccm(unsigned int size)
{
	return aes_ccm_decrypt_aad(out, ct, (int)size + AES_CCM_TAG_LEN,
				   aad12, sizeof(aad12), key32, 16, nonce12,
				   AES_CCM_NONCE_LEN, AES_CCM_TAG_LEN);
}

static int
seal_aes256_ccm(unsigned int size)
{
	return aes_ccm_encrypt_aad(ct, pt, (int)size, aad12, sizeof(aad12),
				   key32, 32, nonce12, AES_CCM_NONCE_LEN,
				   AES_CCM_TAG_LEN);
}

static int
open_aes256_ccm(unsigned int size)
{
	return aes_ccm_decrypt_aad(out, ct, (int)size + AES_CCM_TAG_LEN,
				   aad12, sizeof(aad12), key32, 32, nonce12,
				   AES_CCM_NONCE_LEN, AES_CCM_TAG_LEN);
}

static int
seal_aes128_cbc(unsigned int size)
{
	struct aes128_ctx ctx;

	aes128_cbc_init_ctx_iv(&ctx, key32, iv16);
	aes128_cbc_encrypt(&ctx, cbc, size & ~15u);	/* CBC needs whole blocks */
	return 0;
}

static int
open_aes128_cbc(unsigned int size)
{
	struct aes128_ctx ctx;

	aes128_cbc_init_ctx_iv(&ctx, key32, iv16);
	aes128_cbc_decrypt(&ctx, cbc, size & ~15u);
	return 0;
}

static int
seal_aes256_cbc(unsigned int size)
{
	struct aes256_ctx ctx;

	aes256_cbc_init_ctx_iv(&ctx, key32, iv16);
	aes256_cbc_encrypt(&ctx, cbc, size & ~15u);
	return 0;
}

static int
open_aes256_cbc(unsigned int size)
{
	struct aes256_ctx ctx;

	aes256_cbc_init_ctx_iv(&ctx, key32, iv16);
	aes256_cbc_decrypt(&ctx, cbc, size & ~15u);
	return 0;
}

static int
seal_chacha20_poly1305(unsigned int size)
{
	struct chachapoly_ctx ctx;

	chachapoly_init(&ctx, key32, 256);
	return chachapoly_crypt(&ctx, nonce12, aad12, sizeof(aad12), pt,
				(int)size, ct, tag16, 16, 1);
}

static int
open_chacha20_poly1305(unsigned int size)
{
	struct chachapoly_ctx ctx;

	chachapoly_init(&ctx, key32, 256);
	return chachapoly_crypt(&ctx, nonce12, aad12, sizeof(aad12), ct,
				(int)size, out, tag16, 16, 0);
}

static const struct {
	const char *name;
	op_fn seal, open;
} algorithms[] = {
	{ "aes-128-gcm",       seal_aes128_gcm,        open_aes128_gcm        },
	{ "aes-256-gcm",       seal_aes256_gcm,        open_aes256_gcm        },
	{ "aes-128-ccm",       seal_aes128_ccm,        open_aes128_ccm        },
	{ "aes-256-ccm",       seal_aes256_ccm,        open_aes256_ccm        },
	{ "aes-128-cbc",       seal_aes128_cbc,        open_aes128_cbc        },
	{ "aes-256-cbc",       seal_aes256_cbc,        open_aes256_cbc        },
	{ "chacha20-poly1305", seal_chacha20_poly1305, open_chacha20_poly1305 },
};
#define NUM_ALGOS  (sizeof(algorithms) / sizeof(algorithms[0]))

static void
bench(const char *name, op_fn seal, op_fn open, unsigned int size)
{
	op_fn op = open_dir ? open : seal;
	unsigned long long bytes = 0;
	unsigned long iters = 0;
	double t0, t1;

	if (open_dir) {
		int rc;

		seal(size);		/* what every iteration below opens */
		rc = open(size);
		if (rc) {
			printf("  %-12s %10u  open refused (%d): not measured\n",
			       name, size, rc);
			return;
		}
	}

	t0 = bench_now();
	do {
		op(size);
		bytes += size;
		iters++;
		t1 = bench_now();
	} while (t1 - t0 < bench_secs);

	bench_row(name, size, iters, t1 - t0, bytes);
}

int
main(int argc, char *argv[])
{
	unsigned int sizes[BENCH_NUM_SIZES];
	unsigned int nsizes;

	for (int i = 1; i < argc; i++)
		if (!strcmp(argv[i], "-d"))
			open_dir = 1;
	bench_parse_args(argc, argv);
	crypto_init();
	aes_init_keygen_tables();
	memset(pt, 0x5a, sizeof(pt));
	memset(cbc, 0x5a, sizeof(cbc));

	nsizes = bench_chunks(BENCH_MAX_SIZE, sizes);
	bench_header(open_dir ? "Cipher open" : "Cipher seal");

	for (unsigned int i = 0; i < NUM_ALGOS; i++) {
		if (!bench_selected(algorithms[i].name))
			continue;
		printf("  %-18s  Supported\n", algorithms[i].name);
		for (unsigned int s = 0; s < nsizes; s++)
			bench(algorithms[i].name, algorithms[i].seal,
			      algorithms[i].open, sizes[s]);
	}

	return 0;
}
