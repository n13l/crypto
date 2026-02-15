/*
 * secp384r1 (NIST P-384) aws-lc accelerated ECDHE backend, ARMv8.
 * See ../secp384r1-aws.h; the s2n-bignum assembly leaves are compiled
 * alongside.
 */

#define __CRYPTO_GROUP_MODULE__
#define SECP384R1_DESC    "secp384r1 (aws-lc s2n-bignum, ARMv8)"
#define SECP384R1_INIT_FN group_secp384r1_aws_armv8_init
#include "../secp384r1-aws.h"
