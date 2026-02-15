/*
 * Shared glue for the aws-lc accelerated X25519 backends. The scalar
 * multiplication is s2n-bignum assembly (bundled with aws-lc under
 * third_party/s2n-bignum), copied per-arch into the x25519-aws-x86_64 /
 * x25519-aws-armv8 module directories and linked here through its clean C ABI.
 * No OpenSSL / libcrypto dependency.
 *
 * The s2n-bignum primitives mangle the scalar/point per RFC 7748 internally
 * (they set the low three bits of the scalar to zero, etc.), so the glue does
 * no clamping of its own.
 *
 * An arch module.c defines X25519_DESC and X25519_INIT_FN, then includes this.
 */

#ifndef __CRYPTO_GROUP_X25519_AWS_H__
#define __CRYPTO_GROUP_X25519_AWS_H__

#include <crypto/ecc.h>
#include "random.h"

#define X25519_KEY_LEN 32

/*
 * s2n-bignum, byte-array ABI (identical on x86_64 and ARMv8):
 *   curve25519_x25519_byte(res[32], scalar[32], point[32])  res = scalar*point
 *   curve25519_x25519base_byte(res[32], scalar[32])         res = scalar*base
 */
extern void curve25519_x25519_byte(u8 res[32], const u8 scalar[32],
                                   const u8 point[32]);
extern void curve25519_x25519base_byte(u8 res[32], const u8 scalar[32]);

static int
x25519_aws_derive(const struct group_algorithm *g, const u8 *priv,
                  const u8 *peer, unsigned int peer_len, u8 *ss)
{
	(void)g;
	if (peer_len != X25519_KEY_LEN)
		return -1;
	curve25519_x25519_byte(ss, priv, peer);
	return 0;
}

static int
x25519_aws_keygen(const struct group_algorithm *g, u8 *priv, u8 *pub)
{
	(void)g;
	if (group_random(priv, X25519_KEY_LEN) != 0)
		return -1;
	curve25519_x25519base_byte(pub, priv);
	return 0;
}

#define X25519_KEYGEN x25519_aws_keygen
#define X25519_DERIVE x25519_aws_derive
#include "x25519.h"

#endif
