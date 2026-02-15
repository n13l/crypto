/*
 * TLS 1.2 PRF throughput benchmark (RFC 5246, P_hash). Sweeps output sizes
 * small -> large over every configured PRF algorithm, deriving one output block
 * per operation from a fixed secret/label/seed, against whichever digest
 * backend the crypto build selected. The sweep is capped at 64 KiB of output.
 * Only algorithms enabled in the build (CONFIG_CRYPTO_PRF_*) are compiled in.
 * Run with -b <bytes> for a single fixed size, -t <secs> to change the
 * per-point budget.
 */
#include <hpc/compiler.h>
#include <crypto/prf.h>
#include <crypto/init.h>
#include "bench.h"

#define PRF_MAX_OUTPUT  (64u * 1024u)

#if defined(CONFIG_CRYPTO_PRF_SHA1) || defined(CONFIG_CRYPTO_PRF_SHA2) || \
    defined(CONFIG_CRYPTO_PRF_SHA3)
#define PRF_ANY 1
#endif

#ifdef PRF_ANY
typedef void (*prf_oneshot)(struct prf_context *, const u8 *, unsigned int,
			    const u8 *, unsigned int, const u8 *, unsigned int,
			    u8 *, unsigned int);

static const u8 secret[16] = {
	0x9b,0xbe,0x43,0x6b,0xa9,0x40,0xf0,0x17,
	0xb1,0x76,0x52,0x84,0x9a,0x71,0xdb,0x35 };
static const u8 label[10] = {
	0x74,0x65,0x73,0x74,0x20,0x6c,0x61,0x62,0x65,0x6c };
static const u8 seed[16] = {
	0xa0,0xba,0x9f,0x93,0x6c,0xda,0x31,0x18,
	0x27,0xa6,0xf7,0x96,0xff,0xd5,0x19,0x8c };

static u8 out[PRF_MAX_OUTPUT];
static unsigned int sizes[BENCH_NUM_SIZES];
static unsigned int nsizes;

static void
run(const char *name, prf_oneshot fn)
{
	printf("  %-12s  Supported\n", name);
	for (unsigned int s = 0; s < nsizes; s++) {
		struct prf_context ctx;
		unsigned long long bytes = 0;
		unsigned long iters = 0;
		unsigned int size = sizes[s];
		double t0 = bench_now(), t1;

		do {
			fn(&ctx, secret, sizeof(secret), label, sizeof(label),
			   seed, sizeof(seed), out, size);
			bytes += size;
			iters++;
			t1 = bench_now();
		} while (t1 - t0 < bench_secs);

		bench_row(name, size, iters, t1 - t0, bytes);
	}
}
#endif /* PRF_ANY */

int
main(int argc, char *argv[])
{
	int found = 0;

	bench_parse_args(argc, argv);
	crypto_init();

	nsizes = bench_chunks(PRF_MAX_OUTPUT, sizes);
	bench_header("PRF");

#ifdef CONFIG_CRYPTO_PRF_SHA1
	run("PRF-SHA1",     prf_sha1);   found = 1;
#endif
#ifdef CONFIG_CRYPTO_PRF_SHA2
	run("PRF-SHA224",   prf_sha224);
	run("PRF-SHA256",   prf_sha256);
	run("PRF-SHA384",   prf_sha384);
	run("PRF-SHA512",   prf_sha512); found = 1;
#endif
#ifdef CONFIG_CRYPTO_PRF_SHA3
	run("PRF-SHA3-224", prf_sha3_224);
	run("PRF-SHA3-256", prf_sha3_256);
	run("PRF-SHA3-384", prf_sha3_384);
	run("PRF-SHA3-512", prf_sha3_512); found = 1;
#endif

	if (!found)
		printf("  No PRF algorithms configured.\n");

	return 0;
}
