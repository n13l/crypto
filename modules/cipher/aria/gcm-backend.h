/* The block-cipher seam ../gcm/gcm.c is written against, over ARIA. */
#ifndef GCM_BACKEND_H
#define GCM_BACKEND_H

#include <hpc/compiler.h>
#include <crypto/cipher/aria.h>

struct gcm_key {
	struct aria_ctx ctx;
};

static inline int
gcm_key_init(struct gcm_key *k, const u8 *key, size_t key_len)
{
	return aria_setkey(&k->ctx, key, key_len);
}

static inline void
gcm_block_encrypt(const struct gcm_key *k, const u8 in[16], u8 out[16])
{
	aria_encrypt_block(&k->ctx, in, out);
}

#endif /* GCM_BACKEND_H */
