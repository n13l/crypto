/*
 * The SM3 context layout, apart from the bodies.
 *
 * The same arrangement as ../md5/decl.h, for the same reason: a caller keeps
 * one of these of its own — hmac/sm3, hkdf/sm3 and prf/sm3 on their stacks —
 * whichever way the code that operates on it was built, so the layout has to
 * be visible in every build and this file owns it. Optimizing for speed
 * built-in.h includes sm3.c and gets the bodies with it; optimizing for size
 * the bodies are compiled once into sm3.o and built-in.h declares them only,
 * and either way both sides read the struct from here.
 *
 * Defining __MODULES_DIGEST_SM3_H__ tells <modules/digest/sm3.h> — the
 * fallback every build reads through <crypto/digest.h> — that a real backend
 * has already supplied the type, so its own stub definition stays out of the
 * way.
 */
#ifndef __OSS_CRYPTO_SM3_DECL_H__
#define __OSS_CRYPTO_SM3_DECL_H__

#define __MODULES_DIGEST_SM3_H__

#include <hpc/compiler.h>

#define SM3_MSG_SIZE 32
#define SM3_BLK_SIZE 64

struct sm3 {
	u32 h[8];
	u64 len;			/* message bytes absorbed so far     */
	u8 buf[SM3_BLK_SIZE];
	unsigned int count;		/* of those, bytes still unhashed    */
};

#endif
