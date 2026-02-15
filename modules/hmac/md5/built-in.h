#ifdef __CRYPTO_HMAC_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HMAC_MD5_BUILT_IN_H__
#define __OSS_CRYPTO_HMAC_MD5_BUILT_IN_H__

#define HAVE_HMAC_MD5_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

#include "ctx.h"

void hmac_md5_init(struct hmac_md5_ctx *ctx, const u8 *key,
		   unsigned int key_size);
void hmac_md5_reinit(struct hmac_md5_ctx *ctx);
void hmac_md5_update(struct hmac_md5_ctx *ctx, const u8 *msg,
		     unsigned int len);
void hmac_md5_final(struct hmac_md5_ctx *ctx, u8 *mac, unsigned int mac_size);
void hmac_md5(const u8 *key, unsigned int key_size, const u8 *msg,
	      unsigned int msg_len, u8 *mac, unsigned int mac_size);

#else

#define HMAC_MD5_SCOPE static inline
#include "md5.c"
#undef HMAC_MD5_SCOPE

#endif

#endif

#endif
