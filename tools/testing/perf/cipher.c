/*
 * Cipher throughput benchmark. Sweeps plaintext sizes small -> large over the
 * AEAD/CBC primitives, encrypting one message per operation with a fixed
 * key/IV, against whichever backend the crypto build selected. Run with
 * -b <bytes> for a single fixed size, -t <secs> to change the per-point budget.
 */
#include <hpc/compiler.h>
#include <crypto/cipher.h>
#include <crypto/cipher/aes.h>
#include <crypto/cipher/aes/gcm.h>
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
static u8 ct[BENCH_MAX_SIZE + 16];		/* room for a 16-byte GCM tag */
static u8 cbc[BENCH_MAX_SIZE];			/* CBC encrypts in place */

typedef void (*op_fn)(unsigned int size);

static void
op_aes128_gcm(unsigned int size)
{
	aes_gcm_encrypt(ct, pt, (int)size, key32, 16, iv16, 12);
}

static void
op_aes256_gcm(unsigned int size)
{
	aes_gcm_encrypt(ct, pt, (int)size, key32, 32, iv16, 12);
}

static void
op_aes128_cbc(unsigned int size)
{
	struct aes128_ctx ctx;

	aes128_cbc_init_ctx_iv(&ctx, key32, iv16);
	aes128_cbc_encrypt(&ctx, cbc, size & ~15u);	/* CBC needs whole blocks */
}

static void
op_aes256_cbc(unsigned int size)
{
	struct aes256_ctx ctx;

	aes256_cbc_init_ctx_iv(&ctx, key32, iv16);
	aes256_cbc_encrypt(&ctx, cbc, size & ~15u);
}

static void
op_chacha20_poly1305(unsigned int size)
{
	struct chachapoly_ctx ctx;
	u8 tag[16];

	chachapoly_init(&ctx, key32, 256);
	chachapoly_crypt(&ctx, nonce12, aad12, sizeof(aad12), pt, (int)size,
			 ct, tag, 16, 1);
}

static const struct {
	const char *name;
	op_fn op;
} algorithms[] = {
	{ "aes-128-gcm",       op_aes128_gcm        },
	{ "aes-256-gcm",       op_aes256_gcm        },
	{ "aes-128-cbc",       op_aes128_cbc        },
	{ "aes-256-cbc",       op_aes256_cbc        },
	{ "chacha20-poly1305", op_chacha20_poly1305 },
};
#define NUM_ALGOS  (sizeof(algorithms) / sizeof(algorithms[0]))

static void
bench(op_fn op, const char *name, unsigned int size)
{
	unsigned long long bytes = 0;
	unsigned long iters = 0;
	double t0 = bench_now(), t1;

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

	bench_parse_args(argc, argv);
	crypto_init();
	aes_init_keygen_tables();
	memset(pt, 0x5a, sizeof(pt));
	memset(cbc, 0x5a, sizeof(cbc));

	nsizes = bench_chunks(BENCH_MAX_SIZE, sizes);
	bench_header("Cipher");

	for (unsigned int i = 0; i < NUM_ALGOS; i++) {
		printf("  %-18s  Supported\n", algorithms[i].name);
		for (unsigned int s = 0; s < nsizes; s++)
			bench(algorithms[i].op, algorithms[i].name, sizes[s]);
	}

	return 0;
}
