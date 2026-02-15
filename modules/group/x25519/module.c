/*
 * X25519 (RFC 7748) generic C backend.
 *
 * Portable, constant-time Montgomery ladder over the field GF(2^255-19). The
 * field arithmetic is the dependency-free fiat-crypto code shipped with aws-lc
 * (third_party/fiat/curve25519_64.h, vendored here); the field-element
 * wrappers and the ladder are transcribed from aws-lc's own portable
 * implementation (crypto/fipsmodule/curve25519/curve25519_nohw.c), which is
 * the Coq-verified reference. No OpenSSL / libcrypto dependency.
 *
 * keygen derives the public value as X25519(scalar, 9) — the RFC 7748 base
 * point u=9 run through the same ladder — so no Edwards base-point tables are
 * needed.
 */

#define __CRYPTO_GROUP_MODULE__
#include <crypto/ecc.h>
#include <string.h>

#include "curve25519_64.h"
#include "../random.h"

#define X25519_KEY_LEN 32

/* fe: tight field element; fe_loose: loose field element (see fiat header). */
typedef struct fe { uint64_t v[5]; } fe;
typedef struct fe_loose { uint64_t v[5]; } fe_loose;

#define FE_NUM_LIMBS 5

static void fe_frombytes(fe *h, const uint8_t s[32])
{
	uint8_t t[32];

	memcpy(t, s, 32);
	t[31] &= 0x7f;
	fiat_25519_from_bytes(h->v, t);
}

static void fe_tobytes(uint8_t s[32], const fe *f)
{
	fiat_25519_to_bytes(s, f->v);
}

static void fe_0(fe *h) { memset(h, 0, sizeof(*h)); }
static void fe_1(fe *h) { memset(h, 0, sizeof(*h)); h->v[0] = 1; }

static void fe_copy(fe *h, const fe *f) { memmove(h, f, sizeof(fe)); }

static void fe_add(fe_loose *h, const fe *f, const fe *g)
{
	fiat_25519_add(h->v, f->v, g->v);
}

static void fe_sub(fe_loose *h, const fe *f, const fe *g)
{
	fiat_25519_sub(h->v, f->v, g->v);
}

static void fe_mul_ttt(fe *h, const fe *f, const fe *g)
{
	fiat_25519_carry_mul(h->v, f->v, g->v);
}

static void fe_mul_tlt(fe *h, const fe_loose *f, const fe *g)
{
	fiat_25519_carry_mul(h->v, f->v, g->v);
}

static void fe_mul_tll(fe *h, const fe_loose *f, const fe_loose *g)
{
	fiat_25519_carry_mul(h->v, f->v, g->v);
}

static void fe_sq_tl(fe *h, const fe_loose *f)
{
	fiat_25519_carry_square(h->v, f->v);
}

static void fe_sq_tt(fe *h, const fe *f)
{
	fiat_25519_carry_square(h->v, f->v);
}

static void fe_mul121666(fe *h, const fe_loose *f)
{
	fiat_25519_carry_scmul_121666(h->v, f->v);
}

/* Constant-time conditional swap of two tight elements. */
static void fe_cswap(fe *f, fe *g, uint64_t b)
{
	unsigned int i;

	b = 0 - b;
	for (i = 0; i < FE_NUM_LIMBS; i++) {
		uint64_t x = (f->v[i] ^ g->v[i]) & b;

		f->v[i] ^= x;
		g->v[i] ^= x;
	}
}

/* out = z^(-1) mod p, via the standard curve25519 addition chain. */
static void fe_invert(fe *out, const fe *z)
{
	fe t0, t1, t2, t3;
	fe_loose l;
	int i;

	/* fe_sq_tl on a loose copy of z, matching the reference chain. */
	memmove(&l, z, sizeof(l));
	fe_sq_tl(&t0, &l);
	fe_sq_tt(&t1, &t0);
	for (i = 1; i < 2; ++i)
		fe_sq_tt(&t1, &t1);
	fe_mul_tlt(&t1, &l, &t1);
	fe_mul_ttt(&t0, &t0, &t1);
	fe_sq_tt(&t2, &t0);
	fe_mul_ttt(&t1, &t1, &t2);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 5; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 10; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t2, &t2, &t1);
	fe_sq_tt(&t3, &t2);
	for (i = 1; i < 20; ++i)
		fe_sq_tt(&t3, &t3);
	fe_mul_ttt(&t2, &t3, &t2);
	fe_sq_tt(&t2, &t2);
	for (i = 1; i < 10; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 50; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t2, &t2, &t1);
	fe_sq_tt(&t3, &t2);
	for (i = 1; i < 100; ++i)
		fe_sq_tt(&t3, &t3);
	fe_mul_ttt(&t2, &t3, &t2);
	fe_sq_tt(&t2, &t2);
	for (i = 1; i < 50; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t1, &t1);
	for (i = 1; i < 5; ++i)
		fe_sq_tt(&t1, &t1);
	fe_mul_ttt(out, &t1, &t0);
}

/*
 * out = scalar * point (u-coordinate), constant-time. Transcribed from the
 * Coq-verified ladder in aws-lc's curve25519_nohw.c.
 */
static void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32],
                               const uint8_t point[32])
{
	fe x1, x2, z2, x3, z3, tmp0, tmp1;
	fe_loose x2l, z2l, x3l, tmp0l, tmp1l;
	uint8_t e[32];
	unsigned int swap = 0;
	int pos;

	memcpy(e, scalar, 32);
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	fe_frombytes(&x1, point);
	fe_1(&x2);
	fe_0(&z2);
	fe_copy(&x3, &x1);
	fe_1(&z3);

	for (pos = 254; pos >= 0; --pos) {
		unsigned int b = 1 & (e[pos / 8] >> (pos & 7));

		swap ^= b;
		fe_cswap(&x2, &x3, swap);
		fe_cswap(&z2, &z3, swap);
		swap = b;

		fe_sub(&tmp0l, &x3, &z3);
		fe_sub(&tmp1l, &x2, &z2);
		fe_add(&x2l, &x2, &z2);
		fe_add(&z2l, &x3, &z3);
		fe_mul_tll(&z3, &tmp0l, &x2l);
		fe_mul_tll(&z2, &z2l, &tmp1l);
		fe_sq_tl(&tmp0, &tmp1l);
		fe_sq_tl(&tmp1, &x2l);
		fe_add(&x3l, &z3, &z2);
		fe_sub(&z2l, &z3, &z2);
		fe_mul_ttt(&x2, &tmp1, &tmp0);
		fe_sub(&tmp1l, &tmp1, &tmp0);
		fe_sq_tl(&z2, &z2l);
		fe_mul121666(&z3, &tmp1l);
		fe_sq_tl(&x3, &x3l);
		fe_add(&tmp0l, &tmp0, &z3);
		fe_mul_ttt(&z3, &x1, &z2);
		fe_mul_tll(&z2, &tmp1l, &tmp0l);
	}

	fe_cswap(&x2, &x3, swap);
	fe_cswap(&z2, &z3, swap);

	fe_invert(&z2, &z2);
	fe_mul_ttt(&x2, &x2, &z2);
	fe_tobytes(out, &x2);
}

static int
x25519_generic_derive(const struct group_algorithm *g, const u8 *priv,
                      const u8 *peer, unsigned int peer_len, u8 *ss)
{
	(void)g;
	if (peer_len != X25519_KEY_LEN)
		return -1;
	x25519_scalar_mult(ss, priv, peer);
	return 0;
}

static int
x25519_generic_keygen(const struct group_algorithm *g, u8 *priv, u8 *pub)
{
	static const u8 basepoint[X25519_KEY_LEN] = { 9 };

	(void)g;
	if (group_random(priv, X25519_KEY_LEN) != 0)
		return -1;
	x25519_scalar_mult(pub, priv, basepoint);
	return 0;
}

#define X25519_KEYGEN  x25519_generic_keygen
#define X25519_DERIVE  x25519_generic_derive
#define X25519_DESC    "X25519 (generic C, fiat)"
#define X25519_INIT_FN group_x25519_generic_init
#include "../x25519.h"
