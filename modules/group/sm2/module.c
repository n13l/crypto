/*
 * curveSM2 (GB/T 32918) ECDHE, generic C.
 *
 * The MIT License (MIT)                     Copyright (c) 2026
 *                                                  Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * The named group the ShangMi TLS 1.3 suites are keyed over: curveSM2 (IANA
 * 41, RFC 8998 sec 2), the 256-bit prime curve of GB/T 32918.5. The key_share
 * is the SEC1 uncompressed point 0x04 || X || Y and the shared secret is the X
 * coordinate of the scalar product, the same shape as secp256r1's.
 *
 * Arithmetic: four 64-bit limbs in Montgomery form, CIOS multiplication with
 * the two constants the form needs (R^2 mod p and -p^-1 mod 2^64) computed
 * once at start-up from p itself rather than transcribed; Jacobian points with
 * the a = -3 doubling the curve allows; a Montgomery ladder over the scalar
 * bits with a constant-time swap, so the sequence of field operations does not
 * depend on the key. What is not constant time is the handling of the point
 * at infinity and of a doubling reached through the addition, both of which a
 * ladder over a valid point never takes. The peer's point is checked to be on
 * the curve before it is used.
 *
 * s2n-bignum has no SM2 routines, so unlike the NIST curves beside it this
 * group has one backend and it is this one. GB/T 32918.5's parameters are what
 * the unit test (tools/testing/selftests/units in un) holds it to, alongside a
 * key agreement cross-checked against OpenSSL.
 */

#define __CRYPTO_GROUP_MODULE__
#include <crypto/ecc.h>
#include <string.h>
#include "../random.h"
#include "../pcurve.h"

#define SM2_LIMBS  4
#define SM2_FELEM  32
#define SM2_SCALAR 32
#define SM2_POINT  65

typedef u64 fe[SM2_LIMBS];
typedef unsigned __int128 u128;

/* GB/T 32918.5 sec 2: p, n, b, G. a is p - 3. Little-endian limbs. */
static const fe sm2_p = {
	0xffffffffffffffffull, 0xffffffff00000000ull,
	0xffffffffffffffffull, 0xfffffffeffffffffull
};
static const fe sm2_n = {
	0x53bbf40939d54123ull, 0x7203df6b21c6052bull,
	0xffffffffffffffffull, 0xfffffffeffffffffull
};
static const fe sm2_b = {
	0xddbcbd414d940e93ull, 0xf39789f515ab8f92ull,
	0x4d5a9e4bcf6509a7ull, 0x28e9fa9e9d9f5e34ull
};
static const fe sm2_gx = {
	0x715a4589334c74c7ull, 0x8fe30bbff2660be1ull,
	0x5f9904466a39c994ull, 0x32c4ae2c1f198119ull
};
static const fe sm2_gy = {
	0x02df32e52139f0a0ull, 0xd0a9877cc62a4740ull,
	0x59bdcee36b692153ull, 0xbc3736a2f4f6779cull
};

/* the Montgomery constants, computed at start-up (sm2_setup) */
static fe sm2_r2;		/* R^2 mod p, R = 2^256      */
static fe sm2_one;		/* R mod p: 1 in the form    */
static fe sm2_a;		/* -3 in the form            */
static fe sm2_bm;		/* b in the form             */
static u64 sm2_n0;		/* -p^-1 mod 2^64            */
static int sm2_ready;

/* --- plain arithmetic ----------------------------------------------------- */

static inline void
fe_copy(fe r, const fe a)
{
	memcpy(r, a, sizeof(fe));
}

static inline int
fe_is_zero(const fe a)
{
	return (a[0] | a[1] | a[2] | a[3]) == 0;
}

static inline int
fe_eq(const fe a, const fe b)
{
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
}

/* r = a - b, the borrow returned */
static inline u64
fe_sub_raw(fe r, const fe a, const fe b)
{
	u128 c = 0;
	unsigned int i;

	for (i = 0; i < SM2_LIMBS; i++) {
		c = (u128)a[i] - b[i] - (u64)(c >> 127 ? 1 : 0);
		r[i] = (u64)c;
		c = (c >> 64) ? (u128)1 << 127 : 0;
	}
	return c ? 1 : 0;
}

/* r = a + b, the carry returned */
static inline u64
fe_add_raw(fe r, const fe a, const fe b)
{
	u128 c = 0;
	unsigned int i;

	for (i = 0; i < SM2_LIMBS; i++) {
		c += (u128)a[i] + b[i];
		r[i] = (u64)c;
		c >>= 64;
	}
	return (u64)c;
}

/* r = mask ? a : b, bit for bit, mask all ones or all zeros */
static inline void
fe_select(fe r, const fe a, const fe b, u64 mask)
{
	unsigned int i;

	for (i = 0; i < SM2_LIMBS; i++)
		r[i] = (a[i] & mask) | (b[i] & ~mask);
}

/* a >= m, as a full-word mask */
static inline u64
fe_ge_mask(const fe a, const fe m)
{
	fe t;
	u64 borrow = fe_sub_raw(t, a, m);

	return 0 - (1 - borrow);
}

/* r = (a + b) mod m, for a, b < m */
static void
fe_add_mod(fe r, const fe a, const fe b, const fe m)
{
	fe t, u;
	u64 carry = fe_add_raw(t, a, b);
	u64 borrow = fe_sub_raw(u, t, m);
	/* subtract m when the sum carried or is at least m */
	u64 take = 0 - ((carry | (1 - borrow)) & 1);

	fe_select(r, u, t, take);
}

/* r = (a - b) mod m, for a, b < m */
static void
fe_sub_mod(fe r, const fe a, const fe b, const fe m)
{
	fe t, u;
	u64 borrow = fe_sub_raw(t, a, b);

	fe_add_raw(u, t, m);
	fe_select(r, u, t, 0 - borrow);
}

/* r = a * b * R^-1 mod p: CIOS Montgomery multiplication */
static void
fe_mul(fe r, const fe a, const fe b)
{
	u64 t[SM2_LIMBS + 2] = { 0 };
	unsigned int i, j;

	for (i = 0; i < SM2_LIMBS; i++) {
		u128 c = 0;
		u64 m;

		for (j = 0; j < SM2_LIMBS; j++) {
			c += (u128)t[j] + (u128)a[j] * b[i];
			t[j] = (u64)c;
			c >>= 64;
		}
		c += t[SM2_LIMBS];
		t[SM2_LIMBS] = (u64)c;
		t[SM2_LIMBS + 1] = (u64)(c >> 64);

		m = t[0] * sm2_n0;
		c = (u128)t[0] + (u128)m * sm2_p[0];
		c >>= 64;
		for (j = 1; j < SM2_LIMBS; j++) {
			c += (u128)t[j] + (u128)m * sm2_p[j];
			t[j - 1] = (u64)c;
			c >>= 64;
		}
		c += t[SM2_LIMBS];
		t[SM2_LIMBS - 1] = (u64)c;
		c >>= 64;
		t[SM2_LIMBS] = t[SM2_LIMBS + 1] + (u64)c;
	}

	/* t < 2p here: one conditional subtraction */
	{
		fe u;
		u64 borrow = fe_sub_raw(u, t, sm2_p);
		u64 take = 0 - ((t[SM2_LIMBS] | (1 - borrow)) & 1);

		fe_select(r, u, t, take);
	}
}

static inline void
fe_sqr(fe r, const fe a)
{
	fe_mul(r, a, a);
}

/* r = a^-1 in the form, by Fermat: a^(p-2), the exponent fixed */
static void
fe_inv(fe r, const fe a)
{
	fe e, acc;
	int i;

	/* p - 2 */
	fe_copy(e, sm2_p);
	e[0] -= 2;

	fe_copy(acc, sm2_one);
	for (i = 255; i >= 0; i--) {
		fe_sqr(acc, acc);
		if ((e[i >> 6] >> (i & 63)) & 1)
			fe_mul(acc, acc, a);
	}
	fe_copy(r, acc);
}

static inline void
fe_to_mont(fe r, const fe a)
{
	fe_mul(r, a, sm2_r2);
}

static inline void
fe_from_mont(fe r, const fe a)
{
	static const fe one = { 1, 0, 0, 0 };

	fe_mul(r, a, one);
}

/*
 * The constants, from p. R^2 mod p is 1 doubled 512 times modulo p; -p^-1
 * mod 2^64 is Newton's iteration on the low limb, six steps being enough for
 * 64 bits from the 5 a correct low limb guarantees for an odd modulus.
 */
static void
sm2_setup(void)
{
	fe x;
	u64 inv = 1;
	unsigned int i;
	static const fe three = { 3, 0, 0, 0 };

	if (sm2_ready)
		return;

	memset(x, 0, sizeof(x));
	x[0] = 1;
	for (i = 0; i < 512; i++)
		fe_add_mod(x, x, x, sm2_p);
	fe_copy(sm2_r2, x);

	for (i = 0; i < 6; i++)
		inv *= 2 - sm2_p[0] * inv;
	sm2_n0 = 0 - inv;

	memset(x, 0, sizeof(x));
	x[0] = 1;
	fe_to_mont(sm2_one, x);
	fe_sub_mod(x, sm2_p, three, sm2_p);		/* p - 3 = -3 */
	fe_to_mont(sm2_a, x);
	fe_to_mont(sm2_bm, sm2_b);
	sm2_ready = 1;
}

/* --- the curve ------------------------------------------------------------ */

struct pt {
	fe x, y, z;		/* Jacobian, in the form; z = 0 is infinity */
};

static inline int
pt_is_inf(const struct pt *p)
{
	return fe_is_zero(p->z);
}

static void
pt_set_inf(struct pt *p)
{
	memset(p, 0, sizeof(*p));
	fe_copy(p->x, sm2_one);
	fe_copy(p->y, sm2_one);
}

/* 2P, a = -3 (dbl-2001-b) */
static void
pt_double(struct pt *r, const struct pt *p)
{
	fe delta, gamma, beta, alpha, t, u;

	if (pt_is_inf(p)) {
		pt_set_inf(r);
		return;
	}

	fe_sqr(delta, p->z);				/* Z^2            */
	fe_sqr(gamma, p->y);				/* Y^2            */
	fe_mul(beta, p->x, gamma);			/* X Y^2          */
	fe_sub_mod(t, p->x, delta, sm2_p);		/* X - Z^2        */
	fe_add_mod(u, p->x, delta, sm2_p);		/* X + Z^2        */
	fe_mul(alpha, t, u);
	fe_add_mod(t, alpha, alpha, sm2_p);
	fe_add_mod(alpha, t, alpha, sm2_p);		/* 3 (X-Z^2)(X+Z^2) */

	fe_sqr(t, alpha);
	fe_add_mod(u, beta, beta, sm2_p);
	fe_add_mod(u, u, u, sm2_p);
	fe_add_mod(u, u, u, sm2_p);			/* 8 beta         */
	fe_sub_mod(r->x, t, u, sm2_p);			/* X3             */

	fe_add_mod(t, p->y, p->z, sm2_p);
	fe_sqr(t, t);
	fe_sub_mod(t, t, gamma, sm2_p);
	fe_sub_mod(r->z, t, delta, sm2_p);		/* Z3 = (Y+Z)^2 - gamma - delta */

	fe_add_mod(t, beta, beta, sm2_p);
	fe_add_mod(t, t, t, sm2_p);			/* 4 beta         */
	fe_sub_mod(t, t, r->x, sm2_p);
	fe_mul(t, alpha, t);				/* alpha (4beta - X3) */
	fe_sqr(u, gamma);
	fe_add_mod(u, u, u, sm2_p);
	fe_add_mod(u, u, u, sm2_p);
	fe_add_mod(u, u, u, sm2_p);			/* 8 gamma^2      */
	fe_sub_mod(r->y, t, u, sm2_p);			/* Y3             */
}

/* P + Q, general Jacobian (add-2007-bl), with the two degenerate cases */
static void
pt_add(struct pt *r, const struct pt *p, const struct pt *q)
{
	fe z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, t;

	if (pt_is_inf(p)) {
		*r = *q;
		return;
	}
	if (pt_is_inf(q)) {
		*r = *p;
		return;
	}

	fe_sqr(z1z1, p->z);
	fe_sqr(z2z2, q->z);
	fe_mul(u1, p->x, z2z2);
	fe_mul(u2, q->x, z1z1);
	fe_mul(t, q->z, z2z2);
	fe_mul(s1, p->y, t);
	fe_mul(t, p->z, z1z1);
	fe_mul(s2, q->y, t);

	if (fe_eq(u1, u2)) {
		if (fe_eq(s1, s2))
			pt_double(r, p);
		else
			pt_set_inf(r);
		return;
	}

	fe_sub_mod(h, u2, u1, sm2_p);			/* H = U2 - U1    */
	fe_add_mod(i, h, h, sm2_p);
	fe_sqr(i, i);					/* I = (2H)^2     */
	fe_mul(j, h, i);				/* J = H I        */
	fe_sub_mod(rr, s2, s1, sm2_p);
	fe_add_mod(rr, rr, rr, sm2_p);			/* r = 2 (S2-S1)  */
	fe_mul(v, u1, i);				/* V = U1 I       */

	fe_sqr(t, rr);
	fe_sub_mod(t, t, j, sm2_p);
	fe_sub_mod(t, t, v, sm2_p);
	fe_sub_mod(r->x, t, v, sm2_p);			/* X3 = r^2 - J - 2V */

	fe_sub_mod(t, v, r->x, sm2_p);
	fe_mul(t, rr, t);
	fe_mul(j, s1, j);
	fe_add_mod(j, j, j, sm2_p);
	fe_sub_mod(r->y, t, j, sm2_p);			/* Y3 = r (V-X3) - 2 S1 J */

	fe_add_mod(t, p->z, q->z, sm2_p);
	fe_sqr(t, t);
	fe_sub_mod(t, t, z1z1, sm2_p);
	fe_sub_mod(t, t, z2z2, sm2_p);
	fe_mul(r->z, t, h);				/* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) H */
}

static void
pt_cswap(struct pt *a, struct pt *b, u64 mask)
{
	u64 *x = (u64 *)a, *y = (u64 *)b;
	unsigned int i;

	for (i = 0; i < sizeof(*a) / sizeof(u64); i++) {
		u64 d = (x[i] ^ y[i]) & mask;

		x[i] ^= d;
		y[i] ^= d;
	}
}

/* r = k P, Montgomery ladder over the 256 scalar bits, top down */
static void
pt_mul(struct pt *r, const fe k, const struct pt *p)
{
	struct pt r0, r1;
	int i;
	u64 prev = 0;

	pt_set_inf(&r0);
	r1 = *p;
	for (i = 255; i >= 0; i--) {
		u64 bit = (k[i >> 6] >> (i & 63)) & 1;
		u64 swap = 0 - (bit ^ prev);

		pt_cswap(&r0, &r1, swap);
		pt_add(&r1, &r0, &r1);
		pt_double(&r0, &r0);
		prev = bit;
	}
	pt_cswap(&r0, &r1, 0 - prev);
	*r = r0;
}

/* affine X, Y (plain, big-endian) out of a Jacobian point; -1 at infinity */
static int
pt_affine(const struct pt *p, u8 *x, u8 *y)
{
	fe zi, zi2, zi3, t;

	if (pt_is_inf(p))
		return -1;
	fe_inv(zi, p->z);
	fe_sqr(zi2, zi);
	fe_mul(zi3, zi2, zi);
	fe_mul(t, p->x, zi2);
	fe_from_mont(t, t);
	limbs_to_be(x, t, SM2_LIMBS);
	if (y) {
		fe_mul(t, p->y, zi3);
		fe_from_mont(t, t);
		limbs_to_be(y, t, SM2_LIMBS);
	}
	return 0;
}

/* a point from its SEC1 uncompressed encoding, refused unless on the curve */
static int
pt_load(struct pt *p, const u8 *enc, unsigned int len)
{
	fe x, y, lhs, rhs, t;

	if (len != SM2_POINT || enc[0] != 0x04)
		return -1;
	be_to_limbs(x, enc + 1, SM2_LIMBS);
	be_to_limbs(y, enc + 1 + SM2_FELEM, SM2_LIMBS);
	if (fe_ge_mask(x, sm2_p) || fe_ge_mask(y, sm2_p))
		return -1;

	fe_to_mont(p->x, x);
	fe_to_mont(p->y, y);
	fe_copy(p->z, sm2_one);

	/* y^2 == x^3 - 3x + b */
	fe_sqr(lhs, p->y);
	fe_sqr(t, p->x);
	fe_mul(rhs, t, p->x);
	fe_mul(t, sm2_a, p->x);
	fe_add_mod(rhs, rhs, t, sm2_p);
	fe_add_mod(rhs, rhs, sm2_bm, sm2_p);
	return fe_eq(lhs, rhs) ? 0 : -1;
}

/* --- the registry entry --------------------------------------------------- */

static int
sm2_derive(const struct group_algorithm *g, const u8 *priv,
           const u8 *peer, unsigned int peer_len, u8 *ss)
{
	struct pt p, r;
	fe k;

	(void)g;
	sm2_setup();
	if (pt_load(&p, peer, peer_len))
		return -1;
	be_to_limbs(k, priv, SM2_LIMBS);
	if (fe_is_zero(k) || fe_ge_mask(k, sm2_n))
		return -1;
	pt_mul(&r, k, &p);
	return pt_affine(&r, ss, NULL);
}

static int
sm2_keygen(const struct group_algorithm *g, u8 *priv, u8 *pub)
{
	struct pt base, r;
	fe k, t;
	u8 raw[SM2_SCALAR];

	(void)g;
	sm2_setup();
	if (group_random(raw, sizeof(raw)) != 0)
		return -1;
	be_to_limbs(k, raw, SM2_LIMBS);
	/* n > 2^255, so a 256-bit value is under 2n: one subtraction reduces */
	{
		u64 borrow = fe_sub_raw(t, k, sm2_n);

		fe_select(k, t, k, 0 - (1 - borrow));
	}
	if (fe_is_zero(k))
		k[0] = 1;
	limbs_to_be(priv, k, SM2_LIMBS);

	fe_to_mont(base.x, sm2_gx);
	fe_to_mont(base.y, sm2_gy);
	fe_copy(base.z, sm2_one);
	pt_mul(&r, k, &base);

	pub[0] = 0x04;
	return pt_affine(&r, pub + 1, pub + 1 + SM2_FELEM);
}

static struct group_algorithm sm2_algorithm = {
	.id                 = GROUP_CURVESM2,
	.category           = GROUP_CAT_ECDHE,
	.private_key_size   = SM2_SCALAR,
	.public_key_size    = SM2_POINT,
	.shared_secret_size = SM2_FELEM,
	.tls12              = 1,
	.tls13              = 1,
	.name               = "curveSM2",
	.desc               = "curveSM2 (GB/T 32918) ECDHE (generic C)",
	.keygen             = sm2_keygen,
	.derive             = sm2_derive,
};

static void __init__ group_sm2_init(void)
{
	sm2_setup();
	crypto_group_register(&sm2_algorithm);
}
