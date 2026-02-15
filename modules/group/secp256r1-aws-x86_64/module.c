/*
 * secp256r1 (NIST P-256) aws-lc accelerated ECDHE backend, x86_64.
 * See ../secp256r1-aws.h; the s2n-bignum assembly leaves p256_scalarmul.S /
 * bignum_mod_n256_4.S are compiled alongside.
 */

#define __CRYPTO_GROUP_MODULE__
#define SECP256R1_DESC    "secp256r1 (aws-lc s2n-bignum, x86_64)"
#define SECP256R1_INIT_FN group_secp256r1_aws_x86_64_init
#include "../secp256r1-aws.h"
