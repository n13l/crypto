/*
 * The context layout, apart from the implementation — the arrangement
 * ../sha1/ctx.h describes, for the same reason. See that file.
 */
#ifndef __OSS_CRYPTO_HMAC_MD5_CTX_H__
#define __OSS_CRYPTO_HMAC_MD5_CTX_H__

#include <hpc/compiler.h>
#include <crypto/digest.h>

typedef struct hmac_md5_ctx {
	struct md5 ctx_inside;
	struct md5 ctx_outside;
	struct md5 ctx_inside_reinit;
	struct md5 ctx_outside_reinit;
	u8 block_ipad[MD5_BLOCK_SIZE];
	u8 block_opad[MD5_BLOCK_SIZE];
} hmac_md5_ctx;

#endif
