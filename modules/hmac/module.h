#ifndef __MODULES_HMAC_MODULE_H__
#define __MODULES_HMAC_MODULE_H__

#include <modules/digest/module.h>

#define HMAC_ALGORITHM_WRAPPERS(_name, _ctx) \
_Static_assert(sizeof(_ctx) <= HMAC_CTXT_SIZE_MAX, "HMAC context is too large"); \
static void _name##_algorithm_init(struct hmac_context *ctx, const u8 *key, \
				   unsigned int key_size) \
{ \
	_name##_init((_ctx *)ctx->data, key, key_size); \
} \
static void _name##_algorithm_reinit(struct hmac_context *ctx) \
{ \
	_name##_reinit((_ctx *)ctx->data); \
} \
static void _name##_algorithm_update(struct hmac_context *ctx, const u8 *msg, \
				     unsigned int msg_len) \
{ \
	_name##_update((_ctx *)ctx->data, msg, msg_len); \
} \
static void _name##_algorithm_final(struct hmac_context *ctx, u8 *mac, \
				    unsigned int mac_size) \
{ \
	_name##_final((_ctx *)ctx->data, mac, mac_size); \
} \
static void _name##_algorithm_hmac(struct hmac_context *ctx, const u8 *key, \
				   unsigned int key_size, const u8 *msg, \
				   unsigned int msg_len, u8 *mac, \
				   unsigned int mac_size) \
{ \
	(void)ctx; \
	_name(key, key_size, msg, msg_len, mac, mac_size); \
} \
static void _name##_algorithm_vector(struct hmac_context *ctx, const u8 *key, \
				     unsigned int key_size, unsigned int num, \
				     const u8 **msg, unsigned int *msg_len, \
				     u8 *mac, unsigned int mac_size) \
{ \
	unsigned int i; \
	_name##_init((_ctx *)ctx->data, key, key_size); \
	for (i = 0; i < num; i++) \
		_name##_update((_ctx *)ctx->data, msg[i], msg_len[i]); \
	_name##_final((_ctx *)ctx->data, mac, mac_size); \
}

#endif
