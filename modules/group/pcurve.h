/*
 * Shared helpers for the NIST prime-curve (secp*r1) aws-lc backends.
 *
 * s2n-bignum operates on little-endian 64-bit limb arrays; TLS/SEC1 point and
 * scalar encodings are big-endian byte strings. These helpers convert between
 * the two. No OpenSSL / libcrypto dependency.
 */

#ifndef __CRYPTO_GROUP_PCURVE_H__
#define __CRYPTO_GROUP_PCURVE_H__

#include <hpc/compiler.h>

/* big-endian byte string (nlimbs*8 bytes) -> little-endian limb array */
static inline void
be_to_limbs(u64 *limbs, const u8 *be, unsigned int nlimbs)
{
	unsigned int i, j;

	for (i = 0; i < nlimbs; i++) {
		const u8 *p = be + (nlimbs - 1 - i) * 8;
		u64 v = 0;

		for (j = 0; j < 8; j++)
			v = (v << 8) | p[j];
		limbs[i] = v;
	}
}

/* little-endian limb array -> big-endian byte string (nlimbs*8 bytes) */
static inline void
limbs_to_be(u8 *be, const u64 *limbs, unsigned int nlimbs)
{
	unsigned int i, j;

	for (i = 0; i < nlimbs; i++) {
		u8 *p = be + (nlimbs - 1 - i) * 8;
		u64 v = limbs[i];

		for (j = 0; j < 8; j++)
			p[7 - j] = (u8)(v >> (8 * j));
	}
}

#endif
