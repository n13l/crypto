/*
 * HKDF throughput benchmark (RFC 5869). Sweeps output (OKM) sizes small ->
 * large over every configured HKDF algorithm, running one extract+expand per
 * operation from fixed IKM/salt/info, against whichever digest backend the
 * crypto build selected. The sweep is capped per-algorithm at HKDF's maximum
 * output (255 * HashLen). Only algorithms enabled in the build
 * (CONFIG_CRYPTO_HKDF_*) are compiled in. Run with -b <bytes> for a single
 * fixed size, -t <secs> to change the per-point budget.
 */
#include <hpc/compiler.h>
#include <crypto/hkdf.h>
#include <crypto/init.h>
#include "bench.h"

#if defined(CONFIG_CRYPTO_HKDF_SHA1) || defined(CONFIG_CRYPTO_HKDF_SHA2) || \
    defined(CONFIG_CRYPTO_HKDF_SHA3)
#define HKDF_ANY 1
#endif

#ifdef HKDF_ANY
typedef int (*hkdf_oneshot)(u8 *, unsigned int, const u8 *, unsigned int,
			    const u8 *, unsigned int, const u8 *, unsigned int);

/* RFC 5869 Test Case 1 inputs (backend-independent). */
static const u8 ikm[22] = {
	0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
	0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
static const u8 salt[13] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c };
static const u8 info[10] = {
	0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };

/* Large enough for 255 * HashLen (max HKDF output, HashLen <= 64). */
static u8 okm[255 * 64];

static void
run(const char *name, hkdf_oneshot fn, unsigned int hashlen)
{
	unsigned int sizes[BENCH_NUM_SIZES];
	unsigned int cap = 255u * hashlen;
	unsigned int n;

	if (cap > sizeof(okm))
		cap = sizeof(okm);
	n = bench_chunks(cap, sizes);

	printf("  %-12s  Supported\n", name);
	for (unsigned int s = 0; s < n; s++) {
		unsigned long long bytes = 0;
		unsigned long iters = 0;
		unsigned int size = sizes[s];
		double t0 = bench_now(), t1;

		do {
			fn(okm, size, ikm, sizeof(ikm), salt, sizeof(salt),
			   info, sizeof(info));
			bytes += size;
			iters++;
			t1 = bench_now();
		} while (t1 - t0 < bench_secs);

		bench_row(name, size, iters, t1 - t0, bytes);
	}
}
#endif /* HKDF_ANY */

int
main(int argc, char *argv[])
{
	int found = 0;

	bench_parse_args(argc, argv);
	crypto_init();
	bench_header("HKDF");

#ifdef CONFIG_CRYPTO_HKDF_SHA1
	run("HKDF-SHA1",     hkdf_sha1_160, 20); found = 1;
#endif
#ifdef CONFIG_CRYPTO_HKDF_SHA2
	run("HKDF-SHA224",   hkdf_sha224,   28);
	run("HKDF-SHA256",   hkdf_sha256,   32);
	run("HKDF-SHA384",   hkdf_sha384,   48);
	run("HKDF-SHA512",   hkdf_sha512,   64); found = 1;
#endif
#ifdef CONFIG_CRYPTO_HKDF_SHA3
	run("HKDF-SHA3-224", hkdf_sha3_224, 28);
	run("HKDF-SHA3-256", hkdf_sha3_256, 32);
	run("HKDF-SHA3-384", hkdf_sha3_384, 48);
	run("HKDF-SHA3-512", hkdf_sha3_512, 64); found = 1;
#endif

	if (!found)
		printf("  No HKDF algorithms configured (HKDF disabled).\n");

	return 0;
}
