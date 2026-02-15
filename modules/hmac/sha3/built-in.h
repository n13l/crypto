#ifdef __CRYPTO_HMAC_BUILT_IN_READY__

#ifndef __OSS_CRYPTO_HMAC_SHA3_BUILT_IN_H__
#define __OSS_CRYPTO_HMAC_SHA3_BUILT_IN_H__

#define HAVE_HMAC_SHA3_BUILT_IN 1

#ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE

struct hmac_sha3_224_ctx;
struct hmac_sha3_256_ctx;
struct hmac_sha3_384_ctx;
struct hmac_sha3_512_ctx;

void hmac_sha3_224_init(struct hmac_sha3_224_ctx *ctx, const u8 *key,
			unsigned int key_size);
void hmac_sha3_224_reinit(struct hmac_sha3_224_ctx *ctx);
void hmac_sha3_224_update(struct hmac_sha3_224_ctx *ctx, const u8 *msg,
			  unsigned int len);
void hmac_sha3_224_final(struct hmac_sha3_224_ctx *ctx, u8 *mac,
			 unsigned int mac_size);
void hmac_sha3_224(const u8 *key, unsigned int key_size, const u8 *msg,
		   unsigned int msg_len, u8 *mac, unsigned int mac_size);

void hmac_sha3_256_init(struct hmac_sha3_256_ctx *ctx, const u8 *key,
			unsigned int key_size);
void hmac_sha3_256_reinit(struct hmac_sha3_256_ctx *ctx);
void hmac_sha3_256_update(struct hmac_sha3_256_ctx *ctx, const u8 *msg,
			  unsigned int len);
void hmac_sha3_256_final(struct hmac_sha3_256_ctx *ctx, u8 *mac,
			 unsigned int mac_size);
void hmac_sha3_256(const u8 *key, unsigned int key_size, const u8 *msg,
		   unsigned int msg_len, u8 *mac, unsigned int mac_size);

void hmac_sha3_384_init(struct hmac_sha3_384_ctx *ctx, const u8 *key,
			unsigned int key_size);
void hmac_sha3_384_reinit(struct hmac_sha3_384_ctx *ctx);
void hmac_sha3_384_update(struct hmac_sha3_384_ctx *ctx, const u8 *msg,
			  unsigned int len);
void hmac_sha3_384_final(struct hmac_sha3_384_ctx *ctx, u8 *mac,
			 unsigned int mac_size);
void hmac_sha3_384(const u8 *key, unsigned int key_size, const u8 *msg,
		   unsigned int msg_len, u8 *mac, unsigned int mac_size);

void hmac_sha3_512_init(struct hmac_sha3_512_ctx *ctx, const u8 *key,
			unsigned int key_size);
void hmac_sha3_512_reinit(struct hmac_sha3_512_ctx *ctx);
void hmac_sha3_512_update(struct hmac_sha3_512_ctx *ctx, const u8 *msg,
			  unsigned int len);
void hmac_sha3_512_final(struct hmac_sha3_512_ctx *ctx, u8 *mac,
			 unsigned int mac_size);
void hmac_sha3_512(const u8 *key, unsigned int key_size, const u8 *msg,
		   unsigned int msg_len, u8 *mac, unsigned int mac_size);

#else

#define HMAC_SHA3_SCOPE static inline
#include "sha3.c"
#undef HMAC_SHA3_SCOPE

#endif

#endif

#endif
