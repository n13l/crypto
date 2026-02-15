/*
 * The context layout, apart from the implementation — the arrangement
 * ../sha1/ctx.h describes, for the same reason. See that file.
 */
#ifndef __OSS_CRYPTO_HMAC_SM3_CTX_H__
#define __OSS_CRYPTO_HMAC_SM3_CTX_H__

#include <hpc/compiler.h>
#include <crypto/digest.h>

typedef struct hmac_sm3_ctx {
	struct sm3 ctx_inside;
	struct sm3 ctx_outside;
	struct sm3 ctx_inside_reinit;
	struct sm3 ctx_outside_reinit;
	u8 block_ipad[SM3_BLOCK_SIZE];
	u8 block_opad[SM3_BLOCK_SIZE];
} hmac_sm3_ctx;

#endif
