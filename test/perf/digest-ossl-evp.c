/*
 * Benchmark digest algorithms using the standard OpenSSL EVP API.
 *
 * Mirrors test/perf/digest.c so that results are directly comparable.
 *
 */

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

struct algo_info {
	const char *name;
	const char *evp_name;
	unsigned int digest_size;
};

static const struct algo_info algorithms[] = {
	{ "SHA1-160",  "SHA1",      20 },
	{ "SHA2-224",  "SHA224",    28 },
	{ "SHA2-256",  "SHA256",    32 },
	{ "SHA2-384",  "SHA384",    48 },
	{ "SHA2-512",  "SHA512",    64 },
	{ "SHA3-224",  "SHA3-224",  28 },
	{ "SHA3-256",  "SHA3-256",  32 },
	{ "SHA3-384",  "SHA3-384",  48 },
	{ "SHA3-512",  "SHA3-512",  64 },
};

#define DEFAULT_BLOCK_SIZE  32
#define MAX_BLOCK_SIZE      (4096 * 1024)
#define BENCH_SECS  3
#define UPDATES     16
#define NUM_ALGOS   (sizeof(algorithms) / sizeof(algorithms[0]))

static unsigned char bench_data[MAX_BLOCK_SIZE];
static unsigned int block_size = DEFAULT_BLOCK_SIZE;

static void
bench(const struct algo_info *info, const EVP_MD *md)
{
	EVP_MD_CTX *ctx;
	struct timespec t0, t1;
	unsigned long long bytes = 0;
	unsigned long iters = 0;
	unsigned char out[EVP_MAX_MD_SIZE];
	unsigned int out_len;

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "  %-12s  EVP_MD_CTX_new failed\n", info->name);
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &t0);

	do {
		EVP_DigestInit_ex(ctx, md, NULL);

		for (int i = 0; i < UPDATES; i++)
			EVP_DigestUpdate(ctx, bench_data, block_size);

		EVP_DigestFinal_ex(ctx, out, &out_len);

		bytes += (unsigned long long)block_size * UPDATES;
		iters++;

		clock_gettime(CLOCK_MONOTONIC, &t1);
	} while ((t1.tv_sec - t0.tv_sec) < BENCH_SECS);

	EVP_MD_CTX_free(ctx);

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
			block_size = (unsigned int)atoi(argv[++i]);
			if (block_size == 0 || block_size > MAX_BLOCK_SIZE) {
				fprintf(stderr, "block size must be 1..%d bytes\n",
				        MAX_BLOCK_SIZE);
				return 1;
			}
		}
	}

	memset(bench_data, 0x5a, block_size);

	printf("Digest Performance Test — OpenSSL EVP dynamic (%u bytes x %d updates, %d seconds)\n",
	       block_size, UPDATES, BENCH_SECS);
	printf("%-14s %8s  %12s  %10s\n",
	       "  Algorithm", "Iters", "Throughput", "Speed");
	printf("--------------------------------------------------------------\n");

	for (unsigned int i = 0; i < NUM_ALGOS; i++) {
		const struct algo_info *a = &algorithms[i];
		const EVP_MD *md;
		EVP_MD_CTX *ctx;
		unsigned char out[EVP_MAX_MD_SIZE];
		unsigned int out_len;

		md = EVP_get_digestbyname(a->evp_name);
		if (!md) {
			printf("  %-12s  (not available)\n", a->name);
			continue;
		}

		ctx = EVP_MD_CTX_new();
		if (!ctx)
			continue;

		EVP_DigestInit_ex(ctx, md, NULL);
		EVP_DigestUpdate(ctx, "", 0);
		EVP_DigestFinal_ex(ctx, out, &out_len);
		EVP_MD_CTX_free(ctx);

		printf("  %-12s  Supported\n", a->name);

		found++;
		bench(a, md);
	}

	if (!found)
		printf("  No supported algorithms available.\n");

	return 0;
}
