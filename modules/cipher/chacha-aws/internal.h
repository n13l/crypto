/*
 * Prototypes for the aws-lc ChaCha20 assembly primitives used by the
 * accelerated ChaCha20-Poly1305 glue. Each variant XORs |in_len| bytes of the
 * ChaCha20 keystream (256-bit key) into |out|; |counter[0]| is the initial
 * 32-bit block counter and |counter[1..3]| the 96-bit nonce.
 */
#ifndef __OSS_CRYPTO_CIPHER_CHACHA_AWS_INTERNAL_H__
#define __OSS_CRYPTO_CIPHER_CHACHA_AWS_INTERNAL_H__

#include <hpc/compiler.h>
#include <stddef.h>
#include <stdint.h>

void ChaCha20_ctr32_nohw(uint8_t *out, const uint8_t *in, size_t in_len,
			 const uint32_t key[8], const uint32_t counter[4]);

#if defined(__x86_64__)
void ChaCha20_ctr32_ssse3(uint8_t *out, const uint8_t *in, size_t in_len,
			  const uint32_t key[8], const uint32_t counter[4]);
void ChaCha20_ctr32_ssse3_4x(uint8_t *out, const uint8_t *in, size_t in_len,
			     const uint32_t key[8], const uint32_t counter[4]);
void ChaCha20_ctr32_avx2(uint8_t *out, const uint8_t *in, size_t in_len,
			 const uint32_t key[8], const uint32_t counter[4]);
#elif defined(__aarch64__)
void ChaCha20_ctr32_neon(uint8_t *out, const uint8_t *in, size_t in_len,
			 const uint32_t key[8], const uint32_t counter[4]);
#endif

#endif
