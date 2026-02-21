#include <hpc/compiler.h>
#include <crypto/digest.h>
#include <crypto/init.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct algo_info {
	enum algorithm_digest id;
	const char *name;
	unsigned int digest_size;
};

static const struct algo_info algorithms[] = {
	{ ALGORITHM_SHA1_160, "SHA1-160",  SHA1_DIGEST_SIZE   },
	{ ALGORITHM_SHA2_224, "SHA2-224",  SHA224_DIGEST_SIZE  },
	{ ALGORITHM_SHA2_256, "SHA2-256",  SHA256_DIGEST_SIZE  },
	{ ALGORITHM_SHA2_384, "SHA2-384",  SHA384_DIGEST_SIZE  },
	{ ALGORITHM_SHA2_512, "SHA2-512",  SHA512_DIGEST_SIZE  },
	{ ALGORITHM_SHA3_224, "SHA3-224",  SHA3_224_DIGEST_SIZE },
	{ ALGORITHM_SHA3_256, "SHA3-256",  SHA3_256_DIGEST_SIZE },
	{ ALGORITHM_SHA3_384, "SHA3-384",  SHA3_384_DIGEST_SIZE },
	{ ALGORITHM_SHA3_512, "SHA3-512",  SHA3_512_DIGEST_SIZE },
};

#define DEFAULT_BLOCK_SIZE  (64 * 1024)
#define MAX_BLOCK_SIZE      (4096 * 1024)
#define BENCH_SECS  3
#define UPDATES     16
#define NUM_ALGOS   (sizeof(algorithms) / sizeof(algorithms[0]))

static u8 bench_data[MAX_BLOCK_SIZE];
static unsigned int block_size = DEFAULT_BLOCK_SIZE;

static int
is_zero(const u8 *buf, unsigned int len)
{
	for (unsigned int i = 0; i < len; i++)
		if (buf[i])
			return 0;
	return 1;
}

static void
bench(const struct algo_info *info)
{
	struct digest ctx;
	struct timespec t0, t1;
	unsigned long long bytes = 0;
	unsigned long iters = 0;
	int i = 0;
	u8 out[SHA512_DIGEST_SIZE];

	clock_gettime(CLOCK_MONOTONIC, &t0);

	do {
		digest_init(&ctx, info->id);

		for (i = 0; i < UPDATES; i++)
			digest_update(&ctx, bench_data, block_size);

		digest_final(&ctx, out);

		bytes += (unsigned long long)block_size * UPDATES;
		iters++;

		clock_gettime(CLOCK_MONOTONIC, &t1);
	} while ((t1.tv_sec - t0.tv_sec) < BENCH_SECS);

	double elapsed = (t1.tv_sec - t0.tv_sec) +
	                 (t1.tv_nsec - t0.tv_nsec) / 1e9;
	double mbps = bytes / (elapsed * 1e6);
	double gbps = bytes * 8.0 / (elapsed * 1e9);

	printf("  %-12s %8lu iters  %10.2f MB/s  %8.4f Gbps\n",
	       info->name, iters, mbps, gbps);
}

int
main(int argc, char *argv[])
{
	int found = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-b") && i + 1 < argc) {
			block_size = (unsigned int)atoi(argv[++i]) * 1024;
			if (block_size == 0 || block_size > MAX_BLOCK_SIZE) {
				fprintf(stderr, "block size must be 1..%d KB\n",
				        MAX_BLOCK_SIZE / 1024);
				return 1;
			}
		}
	}

	crypto_init();
	memset(bench_data, 0x5a, block_size);

	printf("Digest Performance Test (%d KB x %d updates, %d seconds)\n",
	       block_size / 1024, UPDATES, BENCH_SECS);
	printf("%-14s %8s  %12s  %10s\n",
	       "  Algorithm", "Iters", "Throughput", "Speed");
	printf("--------------------------------------------------------------\n");

	for (unsigned int i = 0; i < NUM_ALGOS; i++) {
		const struct algo_info *a = &algorithms[i];
		struct digest ctx;
		u8 out[SHA512_DIGEST_SIZE] = {};
		const char *desc = digest_get_desc(a->id);

		digest_init(&ctx, a->id);
		digest_update(&ctx, (const u8 *)"", 0);
		digest_final(&ctx, out);

		if (is_zero(out, a->digest_size)) {
			printf("  %-12s  (not configured)\n", a->name);
			continue;
		}

		if (desc[0])
			printf("  %-12s  %s\n", a->name, desc);
		else
			printf("  %-12s  Supported\n", a->name);
		found++;
		bench(a);
	}

	if (!found)
		printf("  No supported algorithms configured.\n");

	return 0;
}
