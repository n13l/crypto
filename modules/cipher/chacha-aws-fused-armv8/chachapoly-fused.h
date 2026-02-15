/*
 * Fused ChaCha20-Poly1305 over the aws-lc ARMv8 assembly.
 *
 * The two-pass construction in ../chacha/chachapoly.c runs the keystream over
 * the record and then the authenticator over it again, so every byte is
 * touched twice and the second pass is a serial multiply chain that cannot
 * overlap the first. chacha20_poly1305_{open,seal} interleave them: the NEON
 * units run the ChaCha rounds for the next block while the scalar units carry
 * the Poly1305 accumulator over the previous one, which is most of what is
 * left to win once both halves are vectorised on their own.
 *
 * The assembly is the aws-lc one, unmodified; only the calling convention is
 * described here. It is a one-shot interface — no init/update/final — and the
 * key is handed to it per call, which is why struct chachapoly_ctx carries the
 * key as well as the keyed chacha state.
 */
#ifndef CHACHAPOLY_FUSED_H
#define CHACHAPOLY_FUSED_H

#include <string.h>
#include <crypto/cipher/chacha.h>
#include <crypto/cipher/poly1305.h>

#define CHACHAPOLY_FUSED_NONCE_LEN 12

/*
 * What the assembly reads and writes. The input fields are overwritten by the
 * tag on return, which is what the union says; the layout and the sizes are
 * fixed by the assembly, so they are asserted rather than trusted.
 */
union chachapoly_fused_open_data {
	struct {
		u8  key[CHACHA_MAXKEYLEN];
		u32 counter;
		u8  nonce[CHACHAPOLY_FUSED_NONCE_LEN];
	} in;
	struct {
		u8 tag[POLY1305_TAGLEN];
	} out;
} __attribute__((aligned(16)));

union chachapoly_fused_seal_data {
	struct {
		u8  key[CHACHA_MAXKEYLEN];
		u32 counter;
		u8  nonce[CHACHAPOLY_FUSED_NONCE_LEN];
		const u8 *extra_ciphertext;
		size_t extra_ciphertext_len;
	} in;
	struct {
		u8 tag[POLY1305_TAGLEN];
	} out;
} __attribute__((aligned(16)));

_Static_assert(sizeof(union chachapoly_fused_open_data) == 48,
	       "fused open data does not match the assembly's layout");
_Static_assert(sizeof(union chachapoly_fused_seal_data) == 48 + 8 + 8,
	       "fused seal data does not match the assembly's layout");

extern void chacha20_poly1305_open(u8 *out_plaintext, const u8 *ciphertext,
				   size_t plaintext_len, const u8 *ad,
				   size_t ad_len,
				   union chachapoly_fused_open_data *data);

extern void chacha20_poly1305_seal(u8 *out_ciphertext, const u8 *plaintext,
				   size_t plaintext_len, const u8 *ad,
				   size_t ad_len,
				   union chachapoly_fused_seal_data *data);

/*
 * The assembly is RFC 7539 proper: a 256-bit key, a 96-bit nonce and the full
 * 16-byte tag. A caller outside that — the 128-bit key the generic code
 * duplicates into both halves, or a request for no authenticator at all — is
 * left to the two-pass path, which is also where a build without NEON goes.
 */
static inline int
chachapoly_fused_capable(const struct chachapoly_ctx *ctx, int tag_len)
{
#if defined(CONFIG_NEON)
	return ctx->key_bits == 256 && tag_len == POLY1305_TAGLEN;
#else
	/* ARMV7_NEON == bit 0; populated only under runtime accel. */
	extern unsigned int OPENSSL_armcap_P;

	return ctx->key_bits == 256 && tag_len == POLY1305_TAGLEN &&
	       (OPENSSL_armcap_P & 1u);
#endif
}

static inline void
chachapoly_fused_crypt(const struct chachapoly_ctx *ctx, const void *nonce,
		       const void *ad, int ad_len,
		       const void *input, int input_len,
		       void *output, u8 tag[POLY1305_TAGLEN], int encrypt)
{
	if (encrypt) {
		union chachapoly_fused_seal_data d;

		memset(&d, 0, sizeof(d));
		memcpy(d.in.key, ctx->key, CHACHA_MAXKEYLEN);
		d.in.counter = 0;
		memcpy(d.in.nonce, nonce, sizeof(d.in.nonce));

		chacha20_poly1305_seal(output, input, (size_t)input_len,
				       ad, (size_t)ad_len, &d);
		memcpy(tag, d.out.tag, POLY1305_TAGLEN);
	} else {
		union chachapoly_fused_open_data d;

		memset(&d, 0, sizeof(d));
		memcpy(d.in.key, ctx->key, CHACHA_MAXKEYLEN);
		d.in.counter = 0;
		memcpy(d.in.nonce, nonce, sizeof(d.in.nonce));

		chacha20_poly1305_open(output, input, (size_t)input_len,
				       ad, (size_t)ad_len, &d);
		memcpy(tag, d.out.tag, POLY1305_TAGLEN);
	}
}

#endif /* CHACHAPOLY_FUSED_H */
