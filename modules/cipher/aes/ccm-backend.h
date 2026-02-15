/*
 * The block-cipher seam ../aes-ccm/ccm.c is written against, over the portable
 * table-based AES in gcm.c.
 */
#ifndef CCM_BACKEND_H
#define CCM_BACKEND_H

#include <hpc/compiler.h>
#include <crypto/cipher/aes/gcm.h>

struct ccm_key {
	aes_context ctx;
};

static inline int
ccm_key_init(struct ccm_key *k, const u8 *key, size_t key_len)
{
	/* the AES keying tables are built by the constructor in gcm.c */
	return aes_setkey(&k->ctx, ENCRYPT, key, (uint)key_len);
}

static inline void
ccm_block_encrypt(const struct ccm_key *k, const u8 in[16], u8 out[16])
{
	/* aes_cipher() does not modify the schedule, but takes it by
	 * non-const pointer as the rest of this backend does */
	aes_cipher((aes_context *)(uintptr_t)&k->ctx, in, out);
}

/*
 * The CBC-MAC over a run of whole blocks. This backend's AES is a block at a
 * time whichever way it is asked, so the loop is here rather than in an
 * assembly routine, and it is the same work either way.
 */
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

/*
 * The CTR pass, from the counter block |ctr| forward: one block at a time,
 * because this backend has no bulk counter entry point. The counter is CCM's
 * low 24 bits, which ccm.c has already refused to let overflow.
 */
static inline void
ccm_ctr_encrypt(const struct ccm_key *k, const u8 *in, u8 *out, size_t len,
		u8 ctr[16])
{
	u8 s[16];
	uint32_t i;
	unsigned int j;

	i = ((uint32_t)ctr[13] << 16) | ((uint32_t)ctr[14] << 8) | ctr[15];

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
