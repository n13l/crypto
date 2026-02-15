/*
 * The MD5 context layout, apart from the bodies.
 *
 * A caller keeps one of these of its own — on its stack, usually — whichever
 * way the code that operates on it was built, so the layout has to be visible
 * in every build and this is the file that owns it. Optimizing for speed
 * built-in.h includes md5.c and gets the bodies with it; optimizing for size
 * the bodies are compiled once into md5.o and built-in.h declares them only,
 * and either way both sides read the struct from here.
 *
 * That is the arrangement an assembly-backed digest reaches by a different
 * route: each SHA backend defines its own state in its own built-in.h, because
 * the state *is* what makes it that backend. MD5 has one backend and no
 * assembly anywhere, so there is nothing to vary and one header can say it.
 *
 * Defining __MODULES_DIGEST_MD5_H__ is what tells <modules/digest/md5.h> — the
 * fallback every build reads through <crypto/digest.h> — that a real backend
 * has already supplied the type, so its own stub definition stays out of the
 * way. See the top of that file for what a build with no MD5 backend gets
 * instead.
 */
#ifndef __OSS_CRYPTO_MD5_DECL_H__
#define __OSS_CRYPTO_MD5_DECL_H__

#define __MODULES_DIGEST_MD5_H__

#include <hpc/compiler.h>

#define MD5_MSG_SIZE 16
#define MD5_BLK_SIZE 64

struct md5 {
	u32 h[4];
	u64 len;			/* message bytes absorbed so far     */
	u8 buf[MD5_BLK_SIZE];
	unsigned int count;		/* of those, bytes still unhashed    */
};

#endif
