/*
 * X25519 aws-lc accelerated backend, ARMv8 (s2n-bignum assembly).
 * See ../x25519-aws.h for the shared glue; the assembly leaves
 * curve25519_x25519_byte.S / curve25519_x25519base_byte.S are compiled
 * alongside.
 */

#define __CRYPTO_GROUP_MODULE__
#define X25519_DESC    "X25519 (aws-lc s2n-bignum, ARMv8)"
#define X25519_INIT_FN group_x25519_aws_armv8_init
#include "../x25519-aws.h"
