/*
 * AES-128/256-GCM AEAD over the aws-lc AES-NI / ARMv8 assembly. One-shot,
 * 12-byte IV, no associated data, 16-byte tag. Provides the same
 * aes_gcm_encrypt/aes_gcm_decrypt free functions as the generic backend
 * (see the contract in <crypto/cipher/aes/gcm.h>): encrypt appends the tag to
 * the ciphertext, decrypt expects and verifies a trailing tag.
 *
 * The counter/GHASH/tag sequence mirrors aws-lc crypto/fipsmodule/modes/gcm.c
 * (CRYPTO_ghash_init / CRYPTO_gcm128_setiv / _encrypt_ctr32 / _finish) so the
 * output is byte-identical to a standard GCM implementation.
 */
#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>
#include <string.h>
#include <crypto/cipher/aes.h>
#include <crypto/cipher/aes/gcm.h>
#include "internal.h"

#define AES_GCM_TAG_LEN 16

static void
xor_block(u8 *dst, const u8 *a, const u8 *b)
{
	for (unsigned int i = 0; i < AES_BLOCKLEN; i++)
		dst[i] = a[i] ^ b[i];
}

/*
 * CTR-encrypt |len| bytes src->dst and GHASH the ciphertext in |ghash_ct|
 * (== dst for seal, == src for open), producing the authentication tag.
 */
static void
aes_gcm_core(const u8 *key, int key_bits, const u8 *iv,
	     const u8 *src, u8 *dst, size_t len,
	     const u8 *ghash_ct, u8 tag[AES_GCM_TAG_LEN])
{
	AES_KEY ks;
	u128 Htable[16];
	u8 H[AES_BLOCKLEN];
	u8 Yi[AES_BLOCKLEN];
	u8 EK0[AES_BLOCKLEN];
	u8 Xi[AES_BLOCKLEN];
	uint64_t H64[2];
	uint32_t ctr;
	size_t full, rem, i;

	aes_hw_set_encrypt_key(key, key_bits, &ks);

	/* Hash subkey H = AES_K(0^128); passed to gcm_init as two BE words. */
	memset(H, 0, sizeof(H));
	aes_hw_encrypt(H, H, &ks);
	H64[0] = get_u64_be(H);
	H64[1] = get_u64_be(H + 8);
	AES_AWS_GHASH_INIT(Htable, H64);

	/* J0 = IV || 0^31 || 1; EK0 = AES_K(J0) is the tag mask. */
	memcpy(Yi, iv, 12);
	put_u32_be(Yi + 12, 1);
	aes_hw_encrypt(Yi, EK0, &ks);

	/* Data starts at counter 2. */
	ctr = 2;
	put_u32_be(Yi + 12, ctr);

	full = len & ~(size_t)(AES_BLOCKLEN - 1);
	rem = len - full;

	if (full) {
		aes_hw_ctr32_encrypt_blocks(src, dst, full / AES_BLOCKLEN, &ks,
					    Yi);
		ctr += (uint32_t)(full / AES_BLOCKLEN);
		put_u32_be(Yi + 12, ctr);
	}
	if (rem) {
		u8 EKi[AES_BLOCKLEN];

		aes_hw_encrypt(Yi, EKi, &ks);
		for (i = 0; i < rem; i++)
			dst[full + i] = src[full + i] ^ EKi[i];
	}

	/* GHASH(ciphertext) then the length block (aad_bits=0 || msg_bits). */
	memset(Xi, 0, sizeof(Xi));
	if (full)
		AES_AWS_GHASH_GHASH(Xi, Htable, ghash_ct, full);
	if (rem) {
		for (i = 0; i < rem; i++)
			Xi[i] ^= ghash_ct[full + i];
		AES_AWS_GHASH_GMULT(Xi, Htable);
	}
	{
		u8 lb[AES_BLOCKLEN];

		put_u64_be(lb, 0);
		put_u64_be(lb + 8, (uint64_t)len << 3);
		for (i = 0; i < AES_BLOCKLEN; i++)
			Xi[i] ^= lb[i];
		AES_AWS_GHASH_GMULT(Xi, Htable);
	}

	xor_block(tag, Xi, EK0);
}

int
aes_gcm_encrypt(u8 *output, const u8 *input, int input_length,
		const u8 *key, const size_t key_len, const u8 *iv,
		const size_t iv_len)
{
	u8 tag[AES_GCM_TAG_LEN];

	(void)iv_len;
	aes_gcm_core(key, (int)(key_len * 8), iv, input, output,
		     (size_t)input_length, output, tag);
	memcpy(output + input_length, tag, AES_GCM_TAG_LEN);
	return 0;
}

int
aes_gcm_decrypt(u8 *output, const u8 *input, int input_length,
		const u8 *key, const size_t key_len, const u8 *iv,
		const size_t iv_len)
{
	u8 tag[AES_GCM_TAG_LEN];
	int ct_len = input_length - AES_GCM_TAG_LEN;
	unsigned int diff = 0;
	int i;

	(void)iv_len;
	if (ct_len < 0)
		return GCM_AUTH_FAILURE;

	aes_gcm_core(key, (int)(key_len * 8), iv, input, output,
		     (size_t)ct_len, input, tag);

	/* Constant-time compare against the trailing tag. */
	for (i = 0; i < AES_GCM_TAG_LEN; i++)
		diff |= (unsigned int)(tag[i] ^ input[ct_len + i]);

	if (diff != 0) {
		memset(output, 0, (size_t)ct_len);
		return GCM_AUTH_FAILURE;
	}
	return 0;
}
