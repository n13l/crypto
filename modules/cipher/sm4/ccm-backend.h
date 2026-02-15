/*
 * The block-cipher seam ../aes-ccm/ccm.c is written against, over SM4.
 *
 * The same three operations the AES backends supply (../aes/ccm-backend.h):
 * a key schedule, one block encrypted, and the CBC-MAC and CTR passes as
 * loops over it, because this backend is a block at a time whichever way it
 * is asked. What differs is the key: SM4 has one width, so a 32-byte key the
 * mode would otherwise accept is refused here.
 */
#ifndef CCM_BACKEND_H
#define CCM_BACKEND_H

#include <hpc/compiler.h>
#include <crypto/cipher/sm4.h>

struct ccm_key {
	struct sm4_ctx ctx;
};

static inline int
ccm_key_init(struct ccm_key *k, const u8 *key, size_t key_len)
{
	if (key_len != SM4_KEYLEN)
		return -1;
	sm4_setkey(&k->ctx, key);
	return 0;
}

static inline void
ccm_block_encrypt(const struct ccm_key *k, const u8 in[16], u8 out[16])
{
	sm4_encrypt_block(&k->ctx, in, out);
}

static inline void
ccm_mac_blocks(const struct ccm_key *k, u8 x[16], const u8 *p, size_t len)
{
	unsigned int i;

	while (len) {
		for (i = 0; i < 16; i++)
			x[i] ^= p[i];
		ccm_block_encrypt(k, x, x);
		p += 16;
		len -= 16;
	}
}

static inline void
ccm_ctr_encrypt(const struct ccm_key *k, const u8 *in, u8 *out, size_t len,
		u8 ctr[16])
{
	u8 s[16];
	u32 i;
	unsigned int j;

	i = ((u32)ctr[13] << 16) | ((u32)ctr[14] << 8) | ctr[15];

	while (len) {
		size_t take = len < 16 ? len : 16;

		ctr[13] = (u8)(i >> 16);
		ctr[14] = (u8)(i >> 8);
		ctr[15] = (u8)i;
		ccm_block_encrypt(k, ctr, s);

		for (j = 0; j < take; j++)
			out[j] = in[j] ^ s[j];

		in += take;
		out += take;
		len -= take;
		i++;
	}
}

#endif /* CCM_BACKEND_H */
