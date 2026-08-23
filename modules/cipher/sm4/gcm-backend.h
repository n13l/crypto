/* The block-cipher seam ../gcm/gcm.c is written against, over SM4. */
#ifndef GCM_BACKEND_H
#define GCM_BACKEND_H

#include <hpc/compiler.h>
#include <crypto/cipher/sm4.h>

struct gcm_key {
	struct sm4_ctx ctx;
};

static inline int
gcm_key_init(struct gcm_key *k, const u8 *key, size_t key_len)
{
	if (key_len != SM4_KEYLEN)
		return -1;
	sm4_setkey(&k->ctx, key);
	return 0;
}

static inline void
gcm_block_encrypt(const struct gcm_key *k, const u8 in[16], u8 out[16])
{
	sm4_encrypt_block(&k->ctx, in, out);
}

#endif /* GCM_BACKEND_H */
