/*
 * What the wire cursor (crypto/wire.h) is for, measured.
 *
 * The claim the cursor makes is that separating "prove the field is there"
 * from "load it" is worth the API: a run of fixed fields costs one bounds test
 * instead of one each, and a list whose length was already checked against the
 * message costs none at all. The second half is the one that matters, because
 * a per-field bounds test inside a loop is a test per element - and a client
 * hello's cipher suite list is the loop every TLS channel on the wire makes
 * this decoder run.
 *
 * So both shapes are timed here over the same input: a per-field-checked walk,
 * which is what the SAFE_READ_* macros in crypto/bb.h and crypto/lv.h give,
 * against a split-then-walk, which is what crypto/wire.h gives. A client hello
 * is the layout, because it is the message this library's callers parse most
 * and it has both shapes in it - a fixed-width prefix and two vectors.
 *
 * Both walks are written out here rather than linked: the real parsers are
 * static inline in their callers, so what is compared is the pattern, and
 * writing both in one file keeps them compiled by the same flags.
 *
 * Numbers move with the suite count on purpose. At one suite the two do the
 * same work and should measure the same, which is the control; the vector is
 * where the difference lives, so the sweep runs out to sixty-four.
 */

#include <hpc/compiler.h>
#include <mem/unaligned.h>
#include <crypto/wire.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* kept in a global so the compiler cannot fold a parse away as dead */
static volatile unsigned int sink;

/* a class per suite, standing in for tls_suite_alarm(): the same work in both
 * walks, so what is left between them is the bounds testing */
static inline unsigned int
suite_class(unsigned int cs)
{
	return (cs ^ (cs >> 8)) & 7u;
}

/*
 * The per-field-checked walk: every read tests the bound it needs, including
 * every read inside the list. This is the shape the SAFE_READ_* macros give.
 */
static unsigned int
walk_checked(const u8 *p, unsigned int avail)
{
	unsigned int alarm = 0, n;

	if (avail < 2) return 0;
	p += 2; avail -= 2;			/* legacy_version */
	if (avail < 32) return 0;
	p += 32; avail -= 32;			/* random          */
	if (avail < 1) return 0;
	n = *p++; avail -= 1;			/* session id      */
	if (n > 32 || n > avail) return 0;
	p += n; avail -= n;

	if (avail < 2) return 0;
	n = (unsigned int)get_u16_be(p); p += 2; avail -= 2;
	if (!n || (n & 1) || n > avail) return 0;
	while (n >= 2) {
		unsigned int cs;

		if (avail < 2) return 0;	/* the test that cannot fail */
		cs = (unsigned int)get_u16_be(p); p += 2; avail -= 2;
		n -= 2;
		alarm |= suite_class(cs);
	}

	if (avail < 1) return 0;
	n = *p++; avail -= 1;			/* compression     */
	if (!n || n > avail) return 0;
	for (unsigned int i = 0; i < n; i++)
		alarm |= p[i] ? 8u : 0u;
	p += n; avail -= n;

	if (!avail) return alarm;
	if (avail < 2) return 0;
	n = (unsigned int)get_u16_be(p); p += 2; avail -= 2;
	if (n > avail) return 0;
	return alarm | (n ? 16u : 0u);
}

/* The wire walk: one test for the fixed prefix, one per length-prefixed
 * body, and none inside either list. */
static unsigned int
walk_wire(const u8 *pdu, unsigned int avail)
{
	struct wire c, suites, comps, ex;
	unsigned int alarm = 0, n;
	const u8 *q;

	wire_init(&c, pdu, avail);

	if (!wire_has(&c, 2 + 32 + 1))
		return 0;
	wire_advance_unchecked(&c, 2 + 32);
	n = wire_get_u8_unchecked(&c);
	if (n > 32 || !wire_advance(&c, n))
		return 0;

	if (!wire_split_u16(&c, &suites))
		return 0;
	n = wire_left(&suites);
	if (!n || (n & 1))
		return 0;
	for (q = suites.p; q != suites.e; q += 2)
		alarm |= suite_class(get_u16_be(q));

	if (!wire_split_u8(&c, &comps) || wire_done(&comps))
		return 0;
	for (q = comps.p; q != comps.e; q++)
		alarm |= *q ? 8u : 0u;

	if (wire_done(&c))
		return alarm;
	if (!wire_split_u16(&c, &ex))
		return 0;
	return alarm | (wire_left(&ex) ? 16u : 0u);
}

/* a client hello carrying @nsuite cipher suites and one extension */
static unsigned int
make_hello(u8 *b, unsigned int nsuite)
{
	unsigned int i, o = 0;

	b[o++] = 3; b[o++] = 3;
	for (i = 0; i < 32; i++)
		b[o++] = (u8)(i * 7 + 1);
	b[o++] = 0;					/* no session id */
	b[o++] = (u8)((nsuite * 2) >> 8);
	b[o++] = (u8)(nsuite * 2);
	for (i = 0; i < nsuite; i++) {
		b[o++] = 0xc0;
		b[o++] = (u8)(0x20 + (i & 0x1f));
	}
	b[o++] = 1; b[o++] = 0;				/* compression: null */
	b[o++] = 0; b[o++] = 4;				/* one 4-byte extension */
	b[o++] = 0; b[o++] = 23; b[o++] = 0; b[o++] = 0;
	return o;
}

static double
now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/*
 * Both walks are pure functions of arguments that do not change, so without
 * this the compiler runs one of them once and the loop measures nothing. The
 * barrier makes the buffer address opaque and the memory it points at unknown
 * at each iteration, which is also the truth on the real path: every hello is
 * a different record that nothing has read yet.
 */
#define opaque(p) __asm__ volatile("" : "+r"(p) : : "memory")

static double
time_walk(unsigned int (*fn)(const u8 *, unsigned int),
          const u8 *p, unsigned int len, unsigned long iters)
{
	double t0;
	unsigned int acc = 0;

	for (unsigned long i = 0; i < iters / 16; i++) {	/* warm */
		const u8 *q = p;

		opaque(q);
		acc |= fn(q, len);
	}
	t0 = now();
	for (unsigned long i = 0; i < iters; i++) {
		const u8 *q = p;

		opaque(q);
		acc |= fn(q, len);
	}
	sink |= acc;
	return (now() - t0) / (double)iters * 1e9;
}

int
main(int argc, char **argv)
{
	static u8 buf[8192];
	/* 1 is the control: one suite, one iteration of the list, so the two
	 * walks are the same work. openssl s_client offers one; a browser
	 * offers between fifteen and thirty-odd. */
	const unsigned int nsuite[] = { 1, 4, 17, 32, 64 };
	unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 0) : 2000000;

	printf("client hello parse, ns per hello (%lu iterations each)\n\n",
	       iters);
	printf("  %-7s %-7s %10s %10s %9s\n",
	       "suites", "bytes", "per-field", "wire", "delta");

	for (unsigned int i = 0; i < sizeof(nsuite) / sizeof(*nsuite); i++) {
		unsigned int len = make_hello(buf, nsuite[i]);
		double a, b;

		if (walk_checked(buf, len) != walk_wire(buf, len)) {
			fprintf(stderr, "walks disagree at %u suites\n",
			        nsuite[i]);
			return 1;
		}
		a = time_walk(walk_checked, buf, len, iters);
		b = time_walk(walk_wire, buf, len, iters);
		printf("  %-7u %-7u %10.1f %10.1f %8.0f%%\n",
		       nsuite[i], len, a, b, (b - a) / a * 100.0);
	}

	return 0;
}
