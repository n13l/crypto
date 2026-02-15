#ifdef __CRYPTO_HMAC_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HMAC_SHA1_BUILT_IN_H__
#define __OSS_CRYPTO_HMAC_SHA1_BUILT_IN_H__

#define HAVE_HMAC_SHA1_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

struct hmac_sha1_ctx;

void hmac_sha1_160_init(struct hmac_sha1_ctx *ctx, const u8 *key,
			unsigned int key_size);
void hmac_sha1_160_reinit(struct hmac_sha1_ctx *ctx);
void hmac_sha1_160_update(struct hmac_sha1_ctx *ctx, const u8 *msg,
			  unsigned int len);
void hmac_sha1_160_final(struct hmac_sha1_ctx *ctx, u8 *mac,
			 unsigned int mac_size);
void hmac_sha1_160(const u8 *key, unsigned int key_size, const u8 *msg,
		   unsigned int msg_len, u8 *mac, unsigned int mac_size);

#else

#define HMAC_SHA1_SCOPE static inline
#include "sha1.c"
#undef HMAC_SHA1_SCOPE

#endif

#endif

#endif
