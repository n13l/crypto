#ifndef __CRYPTO_CIPHER_DES3_H__
#define __CRYPTO_CIPHER_DES3_H__

#include <hpc/compiler.h>

/*
 * Triple DES in EDE mode, CBC (FIPS 46-3, RFC 1851), for the
 * *_WITH_3DES_EDE_CBC_SHA suites of TLS 1.0/1.1 and for nothing newer.
 *
 * A 3DES key is three DES keys in a row, so 24 bytes, and every TLS suite
 * that names it uses all three (keying option 1). The block is eight bytes,
 * which is what Sweet32 is about and why the suites are dated rather than
 * merely old; the decoder counts a channel that chose one
 * (net.tls.sec_weak_ciphersuite) and opens it anyway, because reading the
 * traffic is the point.
 *
 * The context carries its chaining block the way struct aesN_ctx does, so a
 * caller decrypting a record at a time hands over successive buffers and the
 * IV follows by itself — which is what TLS 1.0 needs, its records having no
 * explicit IV of their own.
 */

#define DES3_BLOCKLEN 8
#define DES3_KEYLEN  24
#define DES_KEYLEN    8
#define DES_ROUNDS   16

struct des3_ctx {
	u64 k[3][DES_ROUNDS];		/* the three key schedules, in order */
	u8 Iv[DES3_BLOCKLEN];
};

void
des3_cbc_init_ctx_iv(struct des3_ctx *ctx, const u8 *key, const u8 *iv);

void
des3_cbc_encrypt(struct des3_ctx *ctx, u8 *buf, u32 length);

void
des3_cbc_decrypt(struct des3_ctx *ctx, u8 *buf, u32 length);

/* One block, no chaining: what the CBC above is built from, and what a test
 * vector is stated in. */
void
des3_ecb_encrypt_block(const struct des3_ctx *ctx, const u8 *in, u8 *out);

void
des3_ecb_decrypt_block(const struct des3_ctx *ctx, const u8 *in, u8 *out);

#endif
