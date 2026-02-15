#ifdef __CRYPTO_HMAC_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HMAC_SM3_BUILT_IN_H__
#define __OSS_CRYPTO_HMAC_SM3_BUILT_IN_H__

#define HAVE_HMAC_SM3_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

#include "ctx.h"

void hmac_sm3_init(struct hmac_sm3_ctx *ctx, const u8 *key,
		   unsigned int key_size);
void hmac_sm3_reinit(struct hmac_sm3_ctx *ctx);
void hmac_sm3_update(struct hmac_sm3_ctx *ctx, const u8 *msg,
		     unsigned int len);
void hmac_sm3_final(struct hmac_sm3_ctx *ctx, u8 *mac, unsigned int mac_size);
void hmac_sm3(const u8 *key, unsigned int key_size, const u8 *msg,
	      unsigned int msg_len, u8 *mac, unsigned int mac_size);

#else

#define HMAC_SM3_SCOPE static inline
#include "sm3.c"
#undef HMAC_SM3_SCOPE

#endif

#endif

#endif
