/*
 * Unit tests for the wire cursor (crypto/wire.h): the bounds tests
 * every wire-format parser above it stands on.
 *
 * The cursor exists to separate proving a field is there from loading it, so
 * that a run of fields costs one test instead of one each. That is only worth
 * having if the proving half is exactly right, and "exactly" here means two
 * things that a normal test cannot tell apart:
 *
 *   it must refuse what does not fit   an off-by-one the other way is a read
 *                                      past the end of a record, on bytes that
 *                                      arrived from the network
 *   it must accept what does fit       an off-by-one this way is a decoder
 *                                      that quietly stops parsing valid input
 *
 * So the run under test is placed flush against an unmapped page. Every
 * accessor is then offered every length from zero to past the end, and both
 * halves are checked at once: the answer the accessor gives is compared
 * against the arithmetic, and any read it performs past the end takes the
 * process down with SIGSEGV rather than passing quietly. A test that merely
 * malloc()s a buffer would catch the first kind of error and not the second.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cmocka.h>

#include <crypto/wire.h>

/* the longest run the sweeps use, and how far past it they ask */
#define RUN_MAX		64u
#define WANT_MAX	80u

/*
 * A page of readable bytes with an unmapped page immediately after it. A run
 * of @n bytes ending at the boundary is @guard_end - n, so the byte after the
 * run's last is the first byte of the guard.
 */
static const u8 *guard_end;

static int
group_setup(void **state)
{
	long ps = sysconf(_SC_PAGESIZE);
	u8 *m = mmap(NULL, (size_t)ps * 2, PROT_READ | PROT_WRITE,
	             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	(void)state;
	if (m == MAP_FAILED)
		return -1;
	if (mprotect(m + ps, (size_t)ps, PROT_NONE))
		return -1;

	/* nothing in the run may be zero: a zero length byte would make the
	 * split tests trivially succeed and hide an off-by-one */
	for (long i = 0; i < ps; i++)
		m[i] = (u8)(i * 7 + 1);

	guard_end = m + ps;
	return 0;
}

/* a run of @n bytes whose last byte is the last readable byte before the guard */
static const u8 *
run(unsigned int n)
{
	return guard_end - n;
}

/* --- asking ----------------------------------------------------------- */

static void
test_bounds_are_exact(void **state)
{
	(void)state;

	for (unsigned int len = 0; len <= RUN_MAX; len++) {
		const u8 *p = run(len);
		struct wire c;

		wire_init(&c, p, len);
		assert_int_equal(wire_left(&c), len);
		assert_int_equal(wire_off(&c), 0);
		assert_true(wire_done(&c) == (len == 0));

		for (unsigned int want = 0; want <= WANT_MAX; want++) {
			wire_init(&c, p, len);
			assert_true(!!wire_has(&c, want) == (want <= len));
		}
	}
}

/* --- moving ----------------------------------------------------------- */

static void
test_advance_and_seek(void **state)
{
	(void)state;

	for (unsigned int len = 0; len <= RUN_MAX; len++) {
		const u8 *p = run(len);

		for (unsigned int want = 0; want <= WANT_MAX; want++) {
			struct wire c;
			int fits = want <= len;

			wire_init(&c, p, len);
			assert_true(!!wire_advance(&c, want) == fits);
			/* a refusal leaves the cursor where it was */
			assert_int_equal(wire_off(&c), fits ? want : 0);
			assert_int_equal(wire_left(&c), fits ? len - want : len);

			wire_init(&c, p, len);
			assert_true(!!wire_seek(&c, want) == fits);
			assert_int_equal(wire_off(&c), fits ? want : 0);

			wire_init(&c, p, len);
			assert_true((wire_consume(&c, want) != NULL) == fits);
			assert_int_equal(wire_off(&c), fits ? want : 0);
		}
	}
}

/* --- loading ---------------------------------------------------------- */

static void
test_get_needs_its_width(void **state)
{
	(void)state;

	for (unsigned int len = 0; len <= RUN_MAX; len++) {
		const u8 *p = run(len);
		struct wire c;
		u8 v8;
		u16 v16;
		u32 v32;

		wire_init(&c, p, len);
		assert_true(!!wire_get_u8(&c, &v8) == (len >= 1));
		wire_init(&c, p, len);
		assert_true(!!wire_get_u16(&c, &v16) == (len >= 2));
		wire_init(&c, p, len);
		assert_true(!!wire_get_u24(&c, &v32) == (len >= 3));
	}
}

/*
 * The unchecked loads, driven right up to the boundary: each is given exactly
 * its own width and no more, so a load one byte wide of its field reads the
 * guard page. The values are checked too - an accessor that stays in bounds by
 * reading the wrong bytes is still wrong.
 */
static void
test_unchecked_stop_at_the_end(void **state)
{
	const u8 *p = run(4);
	struct wire c;

	(void)state;

	wire_init(&c, p, 1);
	assert_int_equal(wire_get_u8_unchecked(&c), p[0]);
	assert_true(wire_done(&c));

	wire_init(&c, p + 2, 2);
	assert_int_equal(wire_get_u16_unchecked(&c),
	                 ((u16)p[2] << 8) | p[3]);
	assert_true(wire_done(&c));

	wire_init(&c, p + 1, 3);
	assert_int_equal(wire_get_u24_unchecked(&c),
	                 ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3]);
	assert_true(wire_done(&c));

	wire_init(&c, p, 4);
	assert_int_equal(wire_get_u32_unchecked(&c),
	                 ((u32)p[0] << 24) | ((u32)p[1] << 16) |
	                 ((u32)p[2] << 8) | p[3]);
	assert_true(wire_done(&c));

	/* peek reads without moving, and reads the same bytes get would */
	wire_init(&c, p, 4);
	assert_int_equal(wire_peek_u8_unchecked(&c), p[0]);
	assert_int_equal(wire_peek_u16_unchecked(&c), ((u16)p[0] << 8) | p[1]);
	assert_int_equal(wire_peek_u32_unchecked(&c),
	                 ((u32)p[0] << 24) | ((u32)p[1] << 16) |
	                 ((u32)p[2] << 8) | p[3]);
	assert_int_equal(wire_off(&c), 0);
}

/* --- length-prefixed bodies ------------------------------------------- */

static void
test_split_bounds_the_child(void **state)
{
	(void)state;

	for (unsigned int len = 0; len <= RUN_MAX; len++) {
		const u8 *p = run(len);

		for (unsigned int want = 0; want <= WANT_MAX; want++) {
			struct wire c, out;

			wire_init(&c, p, len);
			if (wire_split(&c, want, &out)) {
				assert_true(want <= len);
				/* the child is the body and nothing past it */
				assert_int_equal(wire_left(&out), want);
				assert_ptr_equal(out.e, p + want);
				/* the parent has stepped over the whole body */
				assert_int_equal(wire_off(&c), want);
			} else {
				assert_true(want > len);
				assert_int_equal(wire_off(&c), 0);
			}
		}
	}
}

/*
 * The length-prefixed forms, where the length is whatever the bytes say. The
 * run is filled with non-zero bytes, so most lengths overrun and the test is
 * mostly about refusing: the body must fit in what is left *after* the length
 * field, which is the subtraction an overflow would get wrong.
 */
static void
test_split_by_length_prefix(void **state)
{
	unsigned int taken = 0, refused = 0;

	(void)state;

	for (unsigned int len = 0; len <= RUN_MAX; len++) {
		const u8 *p = run(len);
		struct wire c, out;

		wire_init(&c, p, len);
		if (wire_split_u8(&c, &out)) {
			assert_true(len >= 1);
			assert_int_equal(wire_left(&out), p[0]);
			assert_true(1u + p[0] <= len);
			assert_int_equal(wire_off(&c), 1u + p[0]);
			taken++;
		} else {
			assert_true(len < 1 || 1u + p[0] > len);
			refused++;
		}

		wire_init(&c, p, len);
		if (wire_split_u16(&c, &out)) {
			unsigned int n = ((unsigned int)p[0] << 8) | p[1];

			assert_true(len >= 2);
			assert_int_equal(wire_left(&out), n);
			assert_true(2u + n <= len);
			assert_int_equal(wire_off(&c), 2u + n);
		} else {
			assert_true(len < 2 ||
			            2u + (((unsigned int)p[0] << 8) | p[1]) > len);
		}

		wire_init(&c, p, len);
		if (wire_split_u24(&c, &out)) {
			unsigned int n = ((unsigned int)p[0] << 16) |
			                 ((unsigned int)p[1] << 8) | p[2];

			assert_true(len >= 3);
			assert_int_equal(wire_left(&out), n);
			assert_true(3u + n <= len);
		}
	}

	/* the sweep is only meaningful if it exercised both answers */
	assert_true(taken > 0);
	assert_true(refused > 0);
}

/*
 * A length prefix whose body is exactly the rest of the run, and one byte more
 * than the rest: the boundary the subtraction in wire_split_*() is there for.
 */
static void
test_split_at_the_boundary(void **state)
{
	u8 buf[8];
	struct wire c, out;

	(void)state;

	/* u8 length: 3 bytes of body in a 4-byte run - exact */
	buf[0] = 3;
	wire_init(&c, buf, 4);
	assert_true(wire_split_u8(&c, &out));
	assert_int_equal(wire_left(&out), 3);
	assert_true(wire_done(&c));

	/* the same body one byte short */
	wire_init(&c, buf, 3);
	assert_false(wire_split_u8(&c, &out));

	/* u16 length: 2 bytes of body in a 4-byte run - exact */
	buf[0] = 0; buf[1] = 2;
	wire_init(&c, buf, 4);
	assert_true(wire_split_u16(&c, &out));
	assert_int_equal(wire_left(&out), 2);
	assert_true(wire_done(&c));

	wire_init(&c, buf, 3);
	assert_false(wire_split_u16(&c, &out));

	/* a zero-length body is a body, and leaves the parent past the length */
	buf[0] = 0; buf[1] = 0;
	wire_init(&c, buf, 2);
	assert_true(wire_split_u16(&c, &out));
	assert_true(wire_done(&out));
	assert_true(wire_done(&c));

	/*
	 * A length that cannot fit in the run at all. 0xffff bytes claimed out
	 * of four is the shape of a truncated record, and the subtraction that
	 * checks it must not wrap.
	 */
	buf[0] = 0xff; buf[1] = 0xff;
	wire_init(&c, buf, 4);
	assert_false(wire_split_u16(&c, &out));
	assert_int_equal(wire_off(&c), 0);

	/* ... including when there is nothing after the length at all */
	wire_init(&c, buf, 2);
	assert_false(wire_split_u16(&c, &out));
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_bounds_are_exact),
		cmocka_unit_test(test_advance_and_seek),
		cmocka_unit_test(test_get_needs_its_width),
		cmocka_unit_test(test_unchecked_stop_at_the_end),
		cmocka_unit_test(test_split_bounds_the_child),
		cmocka_unit_test(test_split_by_length_prefix),
		cmocka_unit_test(test_split_at_the_boundary),
	};

	return cmocka_run_group_tests_name("wire", tests, group_setup, NULL);
}
