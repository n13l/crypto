/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#include <hpc/compiler.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHACHA_MINKEYLEN	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

/* use memcpy() to copy blocks of memory (typically faster) */
#define USE_MEMCPY          1
/* use unaligned little-endian load/store (can be faster) */
#define USE_UNALIGNED       0

/*
 * Accelerated backends reinterpret this storage as their own running state
 * (key words + 32-bit counter + a 96-bit nonce + a leftover keystream block).
 * The generic implementation only uses input[16]; the trailing headroom lets
 * the aws-lc ChaCha20_ctr32 glue keep its extra state within the same ctx.
 * Keep in sync with the _Static_assert in the aws-lc glue.
 */
#define CHACHA_CTX_ACCEL_HEADROOM 64

struct chacha_ctx {
	u32 input[16];
	u8  _accel_headroom[CHACHA_CTX_ACCEL_HEADROOM];
};

void chacha_keysetup(struct chacha_ctx *x, const u8 *k, u32 kbits);
void chacha_ivsetup(struct chacha_ctx *x, const u8 *iv, const u8 *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const u8 *m, u8 *c, u32 bytes);

#endif	/* CHACHA_H */
