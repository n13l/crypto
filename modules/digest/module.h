#ifndef __MODULES_DIGEST_MODULE_H__
#define __MODULES_DIGEST_MODULE_H__

struct module_digest {
	struct digest context _align_max;
	struct digest_algorithm *algorithm;
};

static void
module_digest_init(struct module_digest *ctx, unsigned int id)
{
	ctx->algorithm = crypto_digest_by_id(id);
	assert(ctx->algorithm != NULL);
	assert(ctx->algorithm->ctx_size <= sizeof(ctx->context.data));
	assert(ctx->algorithm->init != NULL);
	assert(ctx->algorithm->update != NULL);
	assert(ctx->algorithm->digest != NULL);
	ctx->algorithm->init(&ctx->context);
}

static void
module_digest_update(struct module_digest *ctx, const u8 *msg,
		     unsigned int msg_len)
{
	ctx->algorithm->update(&ctx->context, msg, msg_len);
}

static void
module_digest_final(struct module_digest *ctx, u8 *digest)
{
	ctx->algorithm->digest(&ctx->context, digest);
}

#endif
