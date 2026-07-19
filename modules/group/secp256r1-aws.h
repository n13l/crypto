/*
 * Shared glue for the aws-lc accelerated secp256r1 (NIST P-256) ECDHE
 * backends. The scalar multiplication is s2n-bignum assembly (p256_scalarmul,
 * a complete affine-in/affine-out routine) copied per-arch into the
 * secp256r1-aws-x86_64 / secp256r1-aws-armv8 module directories. No OpenSSL /
 * libcrypto dependency.
 *
 * key_share is the SEC1 uncompressed point 0x04 || X(32) || Y(32); the shared
 * secret is the X coordinate of the scalar product (RFC 8446 / SEC1).
 *
 * An arch module.c defines SECP256R1_DESC and SECP256R1_INIT_FN, then includes
 * this.
 */

#ifndef __CRYPTO_GROUP_SECP256R1_AWS_H__
#define __CRYPTO_GROUP_SECP256R1_AWS_H__

#include <crypto/ecc.h>
#include <string.h>
#include "random.h"
#include "pcurve.h"

#define P256_LIMBS  4
#define P256_FELEM  32           /* field element bytes            */
#define P256_SCALAR 32           /* private scalar bytes           */
#define P256_POINT  65           /* 0x04 || X || Y                 */

/*
 * s2n-bignum, little-endian limbs:
 *   p256_scalarmul(res[8], scalar[4], point[8])  res = scalar * point (affine)
 *   bignum_mod_n256_4(z[4], x[4])                z = x mod group-order n
 */
extern void p256_scalarmul(u64 res[8], const u64 scalar[4], const u64 point[8]);
extern void bignum_mod_n256_4(u64 z[4], const u64 x[4]);

/* NIST P-256 base point G (affine, big-endian X || Y). */
static const u8 p256_base[64] = {
	0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
	0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
	0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
	0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5 };

/* out(8 limbs affine) = scalar * point(8 limbs affine) */
static void
p256_mul_point(u64 out[8], const u64 scalar[4], const u64 point[8])
{
	p256_scalarmul(out, scalar, point);
}

static int
secp256r1_derive(const struct group_algorithm *g, const u8 *priv,
                 const u8 *peer, unsigned int peer_len, u8 *ss)
{
	u64 scalar[P256_LIMBS], point[8], res[8];

	(void)g;
	if (peer_len != P256_POINT || peer[0] != 0x04)
		return -1;
	be_to_limbs(scalar, priv, P256_LIMBS);
	be_to_limbs(&point[0], peer + 1,             P256_LIMBS); /* X */
	be_to_limbs(&point[4], peer + 1 + P256_FELEM, P256_LIMBS); /* Y */
	p256_mul_point(res, scalar, point);
	limbs_to_be(ss, &res[0], P256_LIMBS);                    /* shared X */
	return 0;
}

static int
secp256r1_keygen(const struct group_algorithm *g, u8 *priv, u8 *pub)
{
	u64 scalar[P256_LIMBS], base[8], res[8];
	u8 raw[P256_SCALAR];

	(void)g;
	if (group_random(raw, sizeof(raw)) != 0)
		return -1;
	be_to_limbs(scalar, raw, P256_LIMBS);
	bignum_mod_n256_4(scalar, scalar);          /* canonical d in [0, n) */
	if ((scalar[0] | scalar[1] | scalar[2] | scalar[3]) == 0)
		scalar[0] = 1;                      /* avoid the zero scalar */
	limbs_to_be(priv, scalar, P256_LIMBS);      /* store the reduced key */

	be_to_limbs(&base[0], p256_base,      P256_LIMBS);
	be_to_limbs(&base[4], p256_base + 32, P256_LIMBS);
	p256_mul_point(res, scalar, base);

	pub[0] = 0x04;
	limbs_to_be(pub + 1,             &res[0], P256_LIMBS);
	limbs_to_be(pub + 1 + P256_FELEM, &res[4], P256_LIMBS);
	return 0;
}

#ifndef SECP256R1_INIT_FN
#error "secp256r1 backend must define SECP256R1_DESC and SECP256R1_INIT_FN"
#endif

static struct group_algorithm secp256r1_algorithm = {
	.id                 = GROUP_SECP256R1,
	.category           = GROUP_CAT_ECDHE,
	.private_key_size   = P256_SCALAR,
	.public_key_size    = P256_POINT,
	.shared_secret_size = P256_FELEM,
	.tls12              = 1,
	.tls13              = 1,
	.name               = "secp256r1",
	.desc               = SECP256R1_DESC,
	.keygen             = secp256r1_keygen,
	.derive             = secp256r1_derive,
};

static void __init__ SECP256R1_INIT_FN(void)
{
	crypto_group_register(&secp256r1_algorithm);
}

#endif
