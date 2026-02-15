/*
 * ChaCha20 glue over the aws-lc ChaCha20_ctr32 assembly. Provides the same
 * chacha_keysetup / chacha_ivsetup / chacha_encrypt_bytes free-function API as
 * the generic implementation (<crypto/cipher/chacha.h>); Poly1305 and the
 * AEAD wrapper stay in portable C. The backend is chosen at build time by
 * Kconfig.
 *
 * The nonce/counter layout follows RFC 7539 (32-bit block counter + 96-bit
 * nonce), matching how chachapoly.c drives the primitives.
 */
#include <string.h>
#include <crypto/cipher/chacha.h>
#include "internal.h"

struct aws_chacha {
	uint32_t key[8];
	uint32_t counter[4];	/* [0]=block counter, [1..3]=96-bit nonce */
	uint8_t  ks[CHACHA_BLOCKLEN];
	unsigned int ks_used;	/* consumed bytes of ks; == BLOCKLEN if empty */
};

_Static_assert(sizeof(struct aws_chacha) <= sizeof(struct chacha_ctx),
	       "aws ChaCha20 state does not fit in struct chacha_ctx");

static inline uint32_t
load_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

#if defined(__x86_64__)
extern unsigned int OPENSSL_ia32cap_P[4];

static int have_avx2(void)
{
#if defined(CONFIG_X86_HAS_AVX2)
	return 1;
#else
	/* leaf7 EBX bit 5 (AVX2) with leaf1 ECX bit 28 (AVX/OS-enabled YMM). */
	return (OPENSSL_ia32cap_P[2] & (1u << 5)) &&
	       (OPENSSL_ia32cap_P[1] & (1u << 28));
#endif
}

static int have_ssse3(void)
{
#if defined(CONFIG_X86_HAS_AVX)
	return 1;	/* AVX-capable parts all provide SSSE3 */
#else
	return OPENSSL_ia32cap_P[1] & (1u << 9);	/* leaf1 ECX bit 9 */
#endif
}

static void
chacha20_ctr32(uint8_t *out, const uint8_t *in, size_t len,
	       const uint32_t key[8], const uint32_t counter[4])
{
	if (len == 0)
		return;
	if (len > 128 && have_avx2())
		ChaCha20_ctr32_avx2(out, in, len, key, counter);
	else if (len > 128 && have_ssse3())
		ChaCha20_ctr32_ssse3_4x(out, in, len, key, counter);
	else
		ChaCha20_ctr32_nohw(out, in, len, key, counter);
}
#elif defined(__aarch64__)
extern unsigned int OPENSSL_armcap_P;

static void
chacha20_ctr32(uint8_t *out, const uint8_t *in, size_t len,
	       const uint32_t key[8], const uint32_t counter[4])
{
	if (len == 0)
		return;
	/* ARMV7_NEON == bit 0 of OPENSSL_armcap_P; the neon path wants >= 192B. */
	if (len >= 192 && (OPENSSL_armcap_P & 1u))
		ChaCha20_ctr32_neon(out, in, len, key, counter);
	else
		ChaCha20_ctr32_nohw(out, in, len, key, counter);
}
#else
#error "unsupported architecture for aws-lc ChaCha20 glue"
#endif

void
chacha_keysetup(struct chacha_ctx *x, const u8 *k, u32 kbits)
{
	struct aws_chacha *c = (struct aws_chacha *)x;
	unsigned int i;

	memset(c, 0, sizeof(*c));
	if (kbits == 128) {
		/* Duplicate the 128-bit key into both halves (RFC 7539 mandates
		 * 256-bit keys; this mirrors the common 128-bit fallback). */
		for (i = 0; i < 4; i++) {
			c->key[i] = load_le32(k + 4 * i);
			c->key[i + 4] = c->key[i];
		}
	} else {
		for (i = 0; i < 8; i++)
			c->key[i] = load_le32(k + 4 * i);
	}
	c->ks_used = CHACHA_BLOCKLEN;
}

void
chacha_ivsetup(struct chacha_ctx *x, const u8 *iv, const u8 *ctr)
{
	struct aws_chacha *c = (struct aws_chacha *)x;

	c->counter[0] = ctr ? load_le32(ctr) : 0;
	c->counter[1] = load_le32(iv + 0);
	c->counter[2] = load_le32(iv + 4);
	c->counter[3] = load_le32(iv + 8);
	c->ks_used = CHACHA_BLOCKLEN;
}

void
chacha_encrypt_bytes(struct chacha_ctx *x, const u8 *m, u8 *c_out, u32 bytes)
{
	struct aws_chacha *c = (struct aws_chacha *)x;
	size_t full;

	/* 1. Drain any keystream left over from a previous partial block. */
	while (c->ks_used < CHACHA_BLOCKLEN && bytes) {
		*c_out++ = *m++ ^ c->ks[c->ks_used++];
		bytes--;
	}

	/* 2. Bulk whole blocks with the fused assembly (picks the SIMD path). */
	full = (size_t)bytes & ~(size_t)(CHACHA_BLOCKLEN - 1);
	if (full) {
		chacha20_ctr32(c_out, m, full, c->key, c->counter);
		c->counter[0] += (uint32_t)(full / CHACHA_BLOCKLEN);
		c_out += full;
		m += full;
		bytes -= (u32)full;
	}

	/* 3. Trailing partial block: generate one keystream block, XOR, and keep
	 * the remainder buffered for a possible continuation. */
	if (bytes) {
		static const uint8_t zero[CHACHA_BLOCKLEN] = {0};
		unsigned int i;

		chacha20_ctr32(c->ks, zero, CHACHA_BLOCKLEN, c->key, c->counter);
		c->counter[0]++;
		for (i = 0; i < bytes; i++)
			c_out[i] = m[i] ^ c->ks[i];
		c->ks_used = bytes;
	}
}
