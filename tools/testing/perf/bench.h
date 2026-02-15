/*
 * bench.h - shared size-sweep benchmark harness for the crypto perf tools.
 *
 * Every perf tool measures one primitive over a geometric range of data-chunk
 * sizes, from the smallest to the largest, so throughput can be compared across
 * builds (different CONFIG backends / implementations). This header carries the
 * common bits: the size table, option parsing (-b <bytes>, -t <secs>), a
 * monotonic clock, and the table formatting. Each tool supplies the per-chunk
 * operation and the list of algorithms.
 *
 * Tools link libc (timing + stdio), so they build only under CONFIG_CC_CLIB.
 */
#ifndef __CRYPTO_PERF_BENCH_H__
#define __CRYPTO_PERF_BENCH_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Geometric data-chunk sweep: 16 B .. 1 MiB. */
static const unsigned int bench_sizes[] = {
	16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576,
};
#define BENCH_NUM_SIZES  (sizeof(bench_sizes) / sizeof(bench_sizes[0]))
#define BENCH_MAX_SIZE   (1024u * 1024u)

/* Per-measurement wall-clock budget in seconds (override with -t). */
static double bench_secs = 0.3;
/* When non-zero (set by -b) a single fixed chunk size is used, not the sweep. */
static unsigned int bench_fixed;

static inline double
bench_now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Parse the options shared by every tool. Unknown args are ignored. */
static inline void
bench_parse_args(int argc, char *argv[])
{
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-b") && i + 1 < argc) {
			long v = atol(argv[++i]);

			if (v <= 0 || (unsigned long)v > BENCH_MAX_SIZE) {
				fprintf(stderr, "block size must be 1..%u bytes\n",
				        BENCH_MAX_SIZE);
				exit(1);
			}
			bench_fixed = (unsigned int)v;
		} else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
			bench_secs = atof(argv[++i]);
			if (bench_secs <= 0.0)
				bench_secs = 0.3;
		}
	}
}

/*
 * Yield the sweep of chunk sizes into caller storage, clamped to [0, cap].
 * In fixed mode (-b) the single requested size is returned (if <= cap).
 * Returns the number of sizes written.
 */
static inline unsigned int
bench_chunks(unsigned int cap, unsigned int out[BENCH_NUM_SIZES])
{
	unsigned int n = 0;

	if (bench_fixed) {
		if (bench_fixed <= cap)
			out[n++] = bench_fixed;
		return n;
	}
	for (unsigned int i = 0; i < BENCH_NUM_SIZES; i++)
		if (bench_sizes[i] <= cap)
			out[n++] = bench_sizes[i];
	return n;
}

static inline void
bench_header(const char *title)
{
	printf("%s Performance Test", title);
	if (bench_fixed)
		printf(" (%u bytes, %.3gs/point)\n", bench_fixed, bench_secs);
	else
		printf(" (chunk sweep %u B..%u B, %.3gs/point)\n",
		       bench_sizes[0], BENCH_MAX_SIZE, bench_secs);
	printf("%-14s %10s  %10s  %12s  %10s\n",
	       "  Algorithm", "Chunk", "Iters", "Throughput", "Speed");
	printf("--------------------------------------------------------------------------\n");
}

/* Run one algorithm's chunk over the budget and print a result row. The caller
 * passes the number of completed iterations, elapsed seconds and bytes moved. */
static inline void
bench_row(const char *name, unsigned int size, unsigned long iters,
          double elapsed, unsigned long long bytes)
{
	double mbps = (double)bytes / (elapsed * 1e6);
	double gbps = (double)bytes * 8.0 / (elapsed * 1e9);
	char chunk[16];

	if (size >= 1024 && (size % 1024) == 0)
		snprintf(chunk, sizeof(chunk), "%u KiB", size / 1024);
	else
		snprintf(chunk, sizeof(chunk), "%u B", size);

	printf("  %-12s %10s  %10lu  %10.2f MB/s  %8.4f Gbps\n",
	       name, chunk, iters, mbps, gbps);
}

#endif /* __CRYPTO_PERF_BENCH_H__ */
