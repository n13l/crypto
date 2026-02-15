#ifdef __CRYPTO_HMAC_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HMAC_SHA2_BUILT_IN_H__
#define __OSS_CRYPTO_HMAC_SHA2_BUILT_IN_H__

#define HAVE_HMAC_SHA2_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

struct hmac_sha224_ctx;
struct hmac_sha256_ctx;
struct hmac_sha384_ctx;
struct hmac_sha512_ctx;

void hmac_sha224_init(struct hmac_sha224_ctx *ctx, const u8 *key,
		      unsigned int key_size);
void hmac_sha224_reinit(struct hmac_sha224_ctx *ctx);
void hmac_sha224_update(struct hmac_sha224_ctx *ctx, const u8 *msg,
			unsigned int len);
void hmac_sha224_final(struct hmac_sha224_ctx *ctx, u8 *mac,
		       unsigned int mac_size);
void hmac_sha224(const u8 *key, unsigned int key_size, const u8 *msg,
		 unsigned int msg_len, u8 *mac, unsigned int mac_size);

void hmac_sha256_init(struct hmac_sha256_ctx *ctx, const u8 *key,
		      unsigned int key_size);
void hmac_sha256_reinit(struct hmac_sha256_ctx *ctx);
void hmac_sha256_update(struct hmac_sha256_ctx *ctx, const u8 *msg,
			unsigned int len);
void hmac_sha256_final(struct hmac_sha256_ctx *ctx, u8 *mac,
		       unsigned int mac_size);
void hmac_sha256(const u8 *key, unsigned int key_size, const u8 *msg,
		 unsigned int msg_len, u8 *mac, unsigned int mac_size);

void hmac_sha384_init(struct hmac_sha384_ctx *ctx, const u8 *key,
		      unsigned int key_size);
void hmac_sha384_reinit(struct hmac_sha384_ctx *ctx);
void hmac_sha384_update(struct hmac_sha384_ctx *ctx, const u8 *msg,
			unsigned int len);
void hmac_sha384_final(struct hmac_sha384_ctx *ctx, u8 *mac,
		       unsigned int mac_size);
void hmac_sha384(const u8 *key, unsigned int key_size, const u8 *msg,
		 unsigned int msg_len, u8 *mac, unsigned int mac_size);

void hmac_sha512_init(struct hmac_sha512_ctx *ctx, const u8 *key,
		      unsigned int key_size);
void hmac_sha512_reinit(struct hmac_sha512_ctx *ctx);
void hmac_sha512_update(struct hmac_sha512_ctx *ctx, const u8 *msg,
			unsigned int len);
void hmac_sha512_final(struct hmac_sha512_ctx *ctx, u8 *mac,
		       unsigned int mac_size);
void hmac_sha512(const u8 *key, unsigned int key_size, const u8 *msg,
		 unsigned int msg_len, u8 *mac, unsigned int mac_size);

#else

#define HMAC_SHA2_SCOPE static inline
#include "sha2.c"
#undef HMAC_SHA2_SCOPE

#endif

#endif

#endif
