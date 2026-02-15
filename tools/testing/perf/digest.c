/*
 * Digest throughput benchmark. Sweeps data-chunk sizes (small -> large) over
 * every configured digest algorithm, hashing one chunk per operation (init +
 * update + final), against whichever backend the crypto build selected. Run
 * with -b <bytes> for a single fixed size, -t <secs> to change the per-point
 * budget.
 */
#include <hpc/compiler.h>
#include <crypto/digest.h>
#include <crypto/init.h>
#include "bench.h"

struct algo_info {
	enum algorithm_digest id;
	const char *name;
	unsigned int digest_size;
};

static const struct algo_info algorithms[] = {
	{ ALGORITHM_SHA1_160, "SHA1-160",  SHA1_DIGEST_SIZE     },
	{ ALGORITHM_SHA2_224, "SHA2-224",  SHA224_DIGEST_SIZE   },
	{ ALGORITHM_SHA2_256, "SHA2-256",  SHA256_DIGEST_SIZE   },
	{ ALGORITHM_SHA2_384, "SHA2-384",  SHA384_DIGEST_SIZE   },
	{ ALGORITHM_SHA2_512, "SHA2-512",  SHA512_DIGEST_SIZE   },
	{ ALGORITHM_SHA3_224, "SHA3-224",  SHA3_224_DIGEST_SIZE },
	{ ALGORITHM_SHA3_256, "SHA3-256",  SHA3_256_DIGEST_SIZE },
	{ ALGORITHM_SHA3_384, "SHA3-384",  SHA3_384_DIGEST_SIZE },
	{ ALGORITHM_SHA3_512, "SHA3-512",  SHA3_512_DIGEST_SIZE },
};
#define NUM_ALGOS  (sizeof(algorithms) / sizeof(algorithms[0]))

static u8 bench_data[BENCH_MAX_SIZE];

static int
is_zero(const u8 *buf, unsigned int len)
{
	for (unsigned int i = 0; i < len; i++)
		if (buf[i])
			return 0;
	return 1;
}

/* Return 1 if the algorithm produces a real (non-null) empty-message hash. */
static int
configured(const struct algo_info *a)
{
	struct digest ctx;
	u8 out[SHA512_DIGEST_SIZE] = {};

	digest_init(&ctx, a->id);
	digest_update(&ctx, (const u8 *)"", 0);
	digest_final(&ctx, out);
	return !is_zero(out, a->digest_size);
}

static void
bench(const struct algo_info *a, unsigned int size)
{
	struct digest ctx;
	u8 out[SHA512_DIGEST_SIZE];
	unsigned long long bytes = 0;
	unsigned long iters = 0;
	double t0 = bench_now(), t1;

	do {
		digest_init(&ctx, a->id);
		digest_update(&ctx, bench_data, size);
		digest_final(&ctx, out);
		bytes += size;
		iters++;
		t1 = bench_now();
	} while (t1 - t0 < bench_secs);

	bench_row(a->name, size, iters, t1 - t0, bytes);
}

int
main(int argc, char *argv[])
{
	unsigned int sizes[BENCH_NUM_SIZES];
	unsigned int nsizes;
	int found = 0;

	bench_parse_args(argc, argv);
	crypto_init();
	memset(bench_data, 0x5a, sizeof(bench_data));

	nsizes = bench_chunks(BENCH_MAX_SIZE, sizes);
	bench_header("Digest");

	for (unsigned int i = 0; i < NUM_ALGOS; i++) {
		const struct algo_info *a = &algorithms[i];
		const char *desc;

		if (!configured(a)) {
			printf("  %-12s  (not configured)\n", a->name);
			continue;
		}
		desc = digest_get_desc(a->id);
		printf("  %-12s  %s\n", a->name, desc[0] ? desc : "Supported");
		found++;
		for (unsigned int s = 0; s < nsizes; s++)
			bench(a, sizes[s]);
	}

	if (!found)
		printf("  No supported algorithms configured.\n");

	return 0;
}
