/*
 * Shared glue for the aws-lc accelerated secp384r1 (NIST P-384) ECDHE
 * backends. P-384 has no complete affine scalar-mult leaf in s2n-bignum, so
 * this drives the Montgomery-Jacobian routine p384_montjscalarmul and does the
 * affine<->Jacobian and Montgomery-domain conversions with the s2n-bignum
 * field leaves (tomont/demont/montmul/montinv). All assembly is copied
 * per-arch into the secp384r1-aws-x86_64 / secp384r1-aws-armv8 module
 * directories. No OpenSSL / libcrypto dependency.
 *
 * key_share is the SEC1 uncompressed point 0x04 || X(48) || Y(48); the shared
 * secret is the X coordinate of the scalar product.
 *
 * An arch module.c defines SECP384R1_DESC and SECP384R1_INIT_FN, then includes
 * this.
 */

#ifndef __CRYPTO_GROUP_SECP384R1_AWS_H__
#define __CRYPTO_GROUP_SECP384R1_AWS_H__

#include <crypto/ecc.h>
#include <string.h>
#include "random.h"
#include "pcurve.h"

#define P384_LIMBS  6
#define P384_FELEM  48
#define P384_SCALAR 48
#define P384_POINT  97           /* 0x04 || X || Y */

/*
 * s2n-bignum, little-endian limbs (Montgomery domain where noted):
 *   p384_montjscalarmul(res[18], scalar[6], point[18])  Jacobian/Montgomery
 *   bignum_tomont_p384(z[6], x[6])   z = x * 2^384         (into Montgomery)
 *   bignum_demont_p384(z[6], x[6])   z = x * 2^-384        (out of Montgomery)
 *   bignum_montmul_p384(z[6],x,y)    z = x*y*2^-384        (Montgomery mul)
 *   bignum_montinv_p384(z[6], x[6])  x*z == 2^768          (Montgomery inverse)
 *   bignum_mod_n384_6(z[6], x[6])    z = x mod group-order n
 */
extern void p384_montjscalarmul(u64 res[18], const u64 scalar[6],
                                const u64 point[18]);
extern void bignum_tomont_p384(u64 z[6], const u64 x[6]);
extern void bignum_demont_p384(u64 z[6], const u64 x[6]);
extern void bignum_montmul_p384(u64 z[6], const u64 x[6], const u64 y[6]);
extern void bignum_montinv_p384(u64 z[6], const u64 x[6]);
extern void bignum_mod_n384_6(u64 z[6], const u64 x[6]);

/* NIST P-384 base point G (affine, big-endian X || Y). */
static const u8 p384_base[96] = {
	0xaa,0x87,0xca,0x22,0xbe,0x8b,0x05,0x37,0x8e,0xb1,0xc7,0x1e,0xf3,0x20,0xad,0x74,
	0x6e,0x1d,0x3b,0x62,0x8b,0xa7,0x9b,0x98,0x59,0xf7,0x41,0xe0,0x82,0x54,0x2a,0x38,
	0x55,0x02,0xf2,0x5d,0xbf,0x55,0x29,0x6c,0x3a,0x54,0x5e,0x38,0x72,0x76,0x0a,0xb7,
	0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,0x98,0xbf,0x92,0x92,0xdc,0x29,
	0xf8,0xf4,0x1d,0xbd,0x28,0x9a,0x14,0x7c,0xe9,0xda,0x31,0x13,0xb5,0xf0,0xb8,0xc0,
	0x0a,0x60,0xb1,0xce,0x1d,0x7e,0x81,0x9d,0x7a,0x43,0x1d,0x7c,0x90,0xea,0x0e,0x5f };

static inline int
p384_limbs_zero(const u64 *a)
{
	return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]) == 0;
}

/* affine (X,Y big-endian) -> Montgomery-Jacobian point[18] (Z = Mont(1)) */
static void
p384_to_montjac(u64 pj[18], const u8 *x_be, const u8 *y_be)
{
	static const u64 one[6] = { 1, 0, 0, 0, 0, 0 };
	u64 t[6];

	be_to_limbs(t, x_be, P384_LIMBS);
	bignum_tomont_p384(&pj[0], t);
	be_to_limbs(t, y_be, P384_LIMBS);
	bignum_tomont_p384(&pj[6], t);
	bignum_tomont_p384(&pj[12], one);
}

/* Montgomery-Jacobian point[18] -> affine X (and Y if ya != NULL), both as
 * big-endian byte strings. Returns -1 for the point at infinity. */
static int
p384_jac_to_affine(u8 *xa, u8 *ya, const u64 pj[18])
{
	u64 zinv[6], zinv2[6], zinv3[6], m[6], out[6];

	if (p384_limbs_zero(&pj[12]))
		return -1;
	bignum_montinv_p384(zinv, &pj[12]);        /* Mont(Z^-1)  */
	bignum_montmul_p384(zinv2, zinv, zinv);     /* Mont(Z^-2)  */
	bignum_montmul_p384(m, &pj[0], zinv2);      /* Mont(x_aff) */
	bignum_demont_p384(out, m);
	limbs_to_be(xa, out, P384_LIMBS);
	if (ya) {
		bignum_montmul_p384(zinv3, zinv2, zinv); /* Mont(Z^-3)  */
		bignum_montmul_p384(m, &pj[6], zinv3);   /* Mont(y_aff) */
		bignum_demont_p384(out, m);
		limbs_to_be(ya, out, P384_LIMBS);
	}
	return 0;
}

static int
secp384r1_derive(const struct group_algorithm *g, const u8 *priv,
                 const u8 *peer, unsigned int peer_len, u8 *ss)
{
	u64 scalar[P384_LIMBS], pj[18], res[18];

	(void)g;
	if (peer_len != P384_POINT || peer[0] != 0x04)
		return -1;
	be_to_limbs(scalar, priv, P384_LIMBS);
	p384_to_montjac(pj, peer + 1, peer + 1 + P384_FELEM);
	p384_montjscalarmul(res, scalar, pj);
	return p384_jac_to_affine(ss, NULL, res);
}

static int
secp384r1_keygen(const struct group_algorithm *g, u8 *priv, u8 *pub)
{
	u64 scalar[P384_LIMBS], pj[18], res[18];
	u8 raw[P384_SCALAR];

	(void)g;
	if (group_random(raw, sizeof(raw)) != 0)
		return -1;
	be_to_limbs(scalar, raw, P384_LIMBS);
	bignum_mod_n384_6(scalar, scalar);
	if (p384_limbs_zero(scalar))
		scalar[0] = 1;
	limbs_to_be(priv, scalar, P384_LIMBS);

	p384_to_montjac(pj, p384_base, p384_base + P384_FELEM);
	p384_montjscalarmul(res, scalar, pj);

	pub[0] = 0x04;
	return p384_jac_to_affine(pub + 1, pub + 1 + P384_FELEM, res);
}

#ifndef SECP384R1_INIT_FN
#error "secp384r1 backend must define SECP384R1_DESC and SECP384R1_INIT_FN"
#endif

static struct group_algorithm secp384r1_algorithm = {
	.id                 = GROUP_SECP384R1,
	.category           = GROUP_CAT_ECDHE,
	.private_key_size   = P384_SCALAR,
	.public_key_size    = P384_POINT,
	.shared_secret_size = P384_FELEM,
	.tls12              = 1,
	.tls13              = 1,
	.name               = "secp384r1",
	.desc               = SECP384R1_DESC,
	.keygen             = secp384r1_keygen,
	.derive             = secp384r1_derive,
};

static void __init__ SECP384R1_INIT_FN(void)
{
	crypto_group_register(&secp384r1_algorithm);
}

#endif
