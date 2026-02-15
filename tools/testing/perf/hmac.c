/*
 * HMAC throughput benchmark. Sweeps message sizes (small -> large) over every
 * configured HMAC algorithm, computing one MAC per operation over a fixed key,
 * against whichever digest backend the crypto build selected. Only algorithms
 * enabled in the build (CONFIG_CRYPTO_HMAC_*) are compiled in. Run with
 * -b <bytes> for a single fixed size, -t <secs> to change the per-point budget.
 */
#include <hpc/compiler.h>
#include <crypto/hmac.h>
#include <crypto/init.h>
#include "bench.h"

#if defined(CONFIG_CRYPTO_HMAC_SHA1) || defined(CONFIG_CRYPTO_HMAC_SHA2) || \
    defined(CONFIG_CRYPTO_HMAC_SHA3)
#define HMAC_ANY 1
#endif

#ifdef HMAC_ANY
typedef void (*hmac_oneshot)(const u8 *, unsigned int, const u8 *,
			     unsigned int, u8 *, unsigned int);

static const u8 key[32] = {
	0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
	0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };

static u8 bench_data[BENCH_MAX_SIZE];
static unsigned int sizes[BENCH_NUM_SIZES];
static unsigned int nsizes;

static void
run(const char *name, hmac_oneshot fn, unsigned int mac_size)
{
	printf("  %-12s  Supported\n", name);
	for (unsigned int s = 0; s < nsizes; s++) {
		u8 mac[64];
		unsigned long long bytes = 0;
		unsigned long iters = 0;
		unsigned int size = sizes[s];
		double t0 = bench_now(), t1;

		do {
			fn(key, sizeof(key), bench_data, size, mac, mac_size);
			bytes += size;
			iters++;
			t1 = bench_now();
		} while (t1 - t0 < bench_secs);

		bench_row(name, size, iters, t1 - t0, bytes);
	}
}
#endif /* HMAC_ANY */

int
main(int argc, char *argv[])
{
	int found = 0;

	bench_parse_args(argc, argv);
	crypto_init();
	memset(bench_data, 0x5a, sizeof(bench_data));

	nsizes = bench_chunks(BENCH_MAX_SIZE, sizes);
	bench_header("HMAC");

#ifdef CONFIG_CRYPTO_HMAC_SHA1
	run("HMAC-SHA1",     hmac_sha1_160, 20); found = 1;
#endif
#ifdef CONFIG_CRYPTO_HMAC_SHA2
	run("HMAC-SHA224",   hmac_sha224,   28);
	run("HMAC-SHA256",   hmac_sha256,   32);
	run("HMAC-SHA384",   hmac_sha384,   48);
	run("HMAC-SHA512",   hmac_sha512,   64); found = 1;
#endif
#ifdef CONFIG_CRYPTO_HMAC_SHA3
	run("HMAC-SHA3-224", hmac_sha3_224, 28);
	run("HMAC-SHA3-256", hmac_sha3_256, 32);
	run("HMAC-SHA3-384", hmac_sha3_384, 48);
	run("HMAC-SHA3-512", hmac_sha3_512, 64); found = 1;
#endif

	if (!found)
		printf("  No HMAC algorithms configured.\n");

	return 0;
}
