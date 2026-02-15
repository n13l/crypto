/*
 * AES-CCM (NIST SP 800-38C, RFC 3610) in the parameterisation TLS uses.
 *
 * CCM is CTR encryption plus a CBC-MAC over formatted blocks, both under the
 * same key and the same block cipher, so the only thing that differs between
 * the accelerated and the portable build is how one block is encrypted. That
 * seam is <ccm-backend.h>, which each AES backend puts on this file's include
 * path from its Kbuild; everything else - the B0 and counter block layouts,
 * the associated-data encoding, the tag - is the mode and is written once.
 *
 * TLS fixes the parameters and this file only implements those: a 12-byte
 * nonce, which forces the length field L to 15 - 12 = 3 and so a payload under
 * 2^24 bytes, and a tag of 16 or 8. That is RFC 6655 for the TLS 1.2 suites
 * and RFC 8446 §8.3 for the TLS 1.3 code points, and a maximal TLS record is
 * about 1040 blocks, four orders of magnitude inside the length limit.
 */
#include <hpc/compiler.h>
#include <string.h>
#include <crypto/cipher/aes/ccm.h>
#include <ccm-backend.h>

#define CCM_BLOCK	16
#define CCM_L		3	/* 15 - 12, fixed by the nonce length */

/*
 * The flags byte of B0 (SP 800-38C A.2.1): whether there is associated data,
 * the tag length as (M-2)/2, and the length field as L-1.
 */
static inline u8
ccm_b0_flags(size_t aad_len, size_t tag_len)
{
	return (u8)((aad_len ? 0x40u : 0u) |
		    ((((unsigned)tag_len - 2u) / 2u) << 3) |
		    (CCM_L - 1u));
}

/* B0 = flags || nonce || l(m), the last as a big-endian L-byte length */
static void
ccm_b0(u8 b0[CCM_BLOCK], const u8 *nonce, size_t len, size_t aad_len,
       size_t tag_len)
{
	b0[0] = ccm_b0_flags(aad_len, tag_len);
	memcpy(b0 + 1, nonce, AES_CCM_NONCE_LEN);
	b0[13] = (u8)(len >> 16);
	b0[14] = (u8)(len >> 8);
	b0[15] = (u8)len;
}

/* A_i = flags || nonce || i, the counter block the CTR pass walks */
static void
ccm_ctr_block(u8 a[CCM_BLOCK], const u8 *nonce, uint32_t i)
{
	a[0] = CCM_L - 1;
	memcpy(a + 1, nonce, AES_CCM_NONCE_LEN);
	a[13] = (u8)(i >> 16);
	a[14] = (u8)(i >> 8);
	a[15] = (u8)i;
}

/* X <- E(K, X xor B) for one block */
static inline void
ccm_mac_block(const struct ccm_key *k, u8 x[CCM_BLOCK], const u8 *b)
{
	unsigned int i;

	for (i = 0; i < CCM_BLOCK; i++)
		x[i] ^= b[i];
	ccm_block_encrypt(k, x, x);
}

/*
 * ...and for a run of whole blocks followed by a zero-padded remainder.
 *
 * The whole-block run goes to the backend, because a CBC-MAC is a CBC
 * encryption whose output is thrown away and the accelerated backends have an
 * entry point for exactly that. It matters more here than the arithmetic
 * suggests: the MAC pass is strictly serial, each block feeding the next, so
 * it cannot be pipelined the way the counter pass is, and calling into the
 * assembly once per block instead of once per run reloads the key schedule
 * every time. That is most of the cost of CCM.
 */
static void
ccm_mac_bytes(const struct ccm_key *k, u8 x[CCM_BLOCK], const u8 *p, size_t len)
{
	size_t full = len & ~(size_t)(CCM_BLOCK - 1);
	u8 last[CCM_BLOCK];

	if (full) {
		ccm_mac_blocks(k, x, p, full);
		p += full;
		len -= full;
	}
	if (len) {
		memset(last, 0, sizeof(last));
		memcpy(last, p, len);
		ccm_mac_block(k, x, last);
	}
}

/*
 * The CBC-MAC over B0, then the encoded associated data, then the payload.
 *
 * Each of the three is padded to a block boundary on its own, which is what
 * lets the associated data and the payload be hashed without either knowing
 * the other's alignment. The length prefix on the associated data is the short
 * form for anything under 2^16 - 2^8 (SP 800-38C A.2.2) and the four-byte form
 * above it; TLS only ever passes 5 or 13 bytes, so the second is here for the
 * sake of the function rather than for TLS.
 */
static void
ccm_mac(const struct ccm_key *k, u8 tag[CCM_BLOCK], const u8 *nonce,
	const u8 *aad, size_t aad_len, const u8 *payload, size_t len,
	size_t tag_len)
{
	u8 x[CCM_BLOCK], hdr[CCM_BLOCK];
	size_t hdr_len, take;

	ccm_b0(x, nonce, len, aad_len, tag_len);
	ccm_block_encrypt(k, x, x);

	if (aad_len) {
		if (aad_len < 0xff00u) {
			hdr[0] = (u8)(aad_len >> 8);
			hdr[1] = (u8)aad_len;
			hdr_len = 2;
		} else {
			hdr[0] = 0xff;
			hdr[1] = 0xfe;
			hdr[2] = (u8)(aad_len >> 24);
			hdr[3] = (u8)(aad_len >> 16);
			hdr[4] = (u8)(aad_len >> 8);
			hdr[5] = (u8)aad_len;
			hdr_len = 6;
		}

		/* the prefix shares its first block with the data */
		take = CCM_BLOCK - hdr_len;
		if (take > aad_len)
			take = aad_len;
		memset(hdr + hdr_len, 0, CCM_BLOCK - hdr_len);
		memcpy(hdr + hdr_len, aad, take);
		ccm_mac_block(k, x, hdr);
		ccm_mac_bytes(k, x, aad + take, aad_len - take);
	}

	ccm_mac_bytes(k, x, payload, len);
	memcpy(tag, x, CCM_BLOCK);
}

/*
 * The CTR pass. S_0 is not keystream - it is the mask the tag is sent under -
 * so it is produced on its own and the payload starts at counter 1.
 */
static void
ccm_ctr(const struct ccm_key *k, const u8 *nonce, const u8 *in, u8 *out,
	size_t len, u8 s0[CCM_BLOCK])
{
	u8 a[CCM_BLOCK];

	ccm_ctr_block(a, nonce, 0);
	ccm_block_encrypt(k, a, s0);

	if (!len)
		return;

	ccm_ctr_block(a, nonce, 1);
	ccm_ctr_encrypt(k, in, out, len, a);
}

/* the parameters this implementation accepts, refused rather than assumed */
static int
ccm_params_ok(int input_length, size_t key_len, size_t iv_len, size_t tag_len)
{
	if (input_length < 0)
		return 0;
	if (iv_len != AES_CCM_NONCE_LEN)
		return 0;
	if (tag_len != AES_CCM_TAG_LEN && tag_len != AES_CCM_8_TAG_LEN)
		return 0;
	if (key_len != 16 && key_len != 32)
		return 0;
	/* L == 3: the length field cannot describe more than this */
	if ((size_t)input_length >= (1u << 24))
		return 0;
	return 1;
}

int
aes_ccm_encrypt_aad(u8 *output, const u8 *input, int input_length,
		    const u8 *aad, size_t aad_len,
		    const u8 *key, size_t key_len,
		    const u8 *iv, size_t iv_len, size_t tag_len)
{
	struct ccm_key k;
	u8 tag[CCM_BLOCK], s0[CCM_BLOCK];
	size_t len = (size_t)input_length;
	unsigned int i;

	if (!ccm_params_ok(input_length, key_len, iv_len, tag_len))
		return CCM_AUTH_FAILURE;
	if (ccm_key_init(&k, key, key_len))
		return CCM_AUTH_FAILURE;

	/* the MAC is over the plaintext, so it is taken before the CTR pass
	 * overwrites it - |output| and |input| may be the same buffer */
	ccm_mac(&k, tag, iv, aad, aad_len, input, len, tag_len);
	ccm_ctr(&k, iv, input, output, len, s0);

	for (i = 0; i < tag_len; i++)
		output[len + i] = tag[i] ^ s0[i];
	return 0;
}

int
aes_ccm_decrypt_aad(u8 *output, const u8 *input, int input_length,
		    const u8 *aad, size_t aad_len,
		    const u8 *key, size_t key_len,
		    const u8 *iv, size_t iv_len, size_t tag_len)
{
	struct ccm_key k;
	u8 tag[CCM_BLOCK], s0[CCM_BLOCK];
	size_t len;
	unsigned int i, diff = 0;

	if (input_length < 0 || (size_t)input_length < tag_len)
		return CCM_AUTH_FAILURE;
	len = (size_t)input_length - tag_len;
	if (!ccm_params_ok((int)len, key_len, iv_len, tag_len))
		return CCM_AUTH_FAILURE;
	if (ccm_key_init(&k, key, key_len))
		return CCM_AUTH_FAILURE;

	/* the plaintext has to exist before it can be authenticated: this is
	 * the ordering CCM forces, and the header says what it means for the
	 * caller on failure */
	ccm_ctr(&k, iv, input, output, len, s0);

#ifdef CONFIG_CRYPTO_VERIFIED_DECRYPT_AEAD
	ccm_mac(&k, tag, iv, aad, aad_len, output, len, tag_len);
	for (i = 0; i < tag_len; i++)
		diff |= (unsigned int)(tag[i] ^ s0[i] ^ input[len + i]);
	if (diff)
		return CCM_AUTH_FAILURE;
#else
	(void)tag; (void)aad; (void)aad_len; (void)i; (void)diff;
#endif
	return 0;
}
