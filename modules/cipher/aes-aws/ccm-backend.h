/*
 * The block-cipher seam ../aes-ccm/ccm.c is written against, over the aws-lc
 * AES-NI / ARMv8 assembly.
 */
#ifndef CCM_BACKEND_H
#define CCM_BACKEND_H

#include <hpc/compiler.h>
#include <string.h>
#include "internal.h"

struct ccm_key {
	AES_KEY ks;
};

static inline int
ccm_key_init(struct ccm_key *k, const u8 *key, size_t key_len)
{
	return aes_hw_set_encrypt_key(key, (int)(key_len * 8), &k->ks);
}

static inline void
ccm_block_encrypt(const struct ccm_key *k, const u8 in[16], u8 out[16])
{
	aes_hw_encrypt(in, out, &k->ks);
}

/*
 * The CBC-MAC over a run of whole blocks: a CBC encryption from |x| whose
 * ciphertext is discarded and whose final block is the running MAC, which is
 * what aes_hw_cbc_encrypt leaves in the IV it was given. The scratch buffer
 * only exists because the assembly has nowhere else to put the ciphertext
 * nobody wants; it is sized to amortise the call without putting a record on
 * the stack.
 */
static inline void
ccm_mac_blocks(const struct ccm_key *k, u8 x[16], const u8 *p, size_t len)
{
	u8 scratch[256];

	while (len) {
		size_t take = len < sizeof(scratch) ? len : sizeof(scratch);

		aes_hw_cbc_encrypt(p, scratch, take, &k->ks, x, 1);
		p += take;
		len -= take;
	}
}

/*
 * The CTR pass, from the counter block |ctr| forward.
 *
 * aes_hw_ctr32_encrypt_blocks increments the low 32 bits of the block, and
 * CCM's counter is the low 24 with the last nonce byte above it. Those agree
 * as long as the counter does not carry out of its 24 bits into that byte,
 * which needs 2^24 blocks - ccm.c refuses a payload that long, and a TLS
 * record is about a thousand. Beyond the whole blocks the assembly wants, the
 * tail is one more block generated and XORed by hand.
 */
static inline void
ccm_ctr_encrypt(const struct ccm_key *k, const u8 *in, u8 *out, size_t len,
		u8 ctr[16])
{
	size_t full = len & ~(size_t)15;
	size_t rem = len - full;

	if (full) {
		aes_hw_ctr32_encrypt_blocks(in, out, full / 16, &k->ks, ctr);
		in += full;
		out += full;
	}
	if (rem) {
		u8 s[16], a[16];
		uint32_t i;
		unsigned int j;

		/* the counter the assembly would have gone on to use */
		memcpy(a, ctr, 16);
		i = ((uint32_t)a[13] << 16) | ((uint32_t)a[14] << 8) | a[15];
		i += (uint32_t)(full / 16);
		a[13] = (u8)(i >> 16);
		a[14] = (u8)(i >> 8);
		a[15] = (u8)i;

		aes_hw_encrypt(a, s, &k->ks);
		for (j = 0; j < rem; j++)
			out[j] = in[j] ^ s[j];
	}
}

#endif /* CCM_BACKEND_H */
