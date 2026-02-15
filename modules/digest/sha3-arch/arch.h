/*
 * The SHA-3 sponge, written once for the backends whose assembly is the
 * permutation and nothing more.
 *
 * Keccak has no compression function to buffer around: absorbing is xor a rate
 * block into the state and permute, squeezing is read the first md_len bytes
 * back out. The assembly in sha3-aws-armv8, sha3-aws-x86_64, sha3-ossl-armv8
 * and sha3-ossl-x86_64 is that permutation - keccakf1600() - so the sponge
 * around it was the same C in all four.
 *
 * sha3-ossl-x86_64-avx2 is not one of them and does not include this file: the
 * AVX2 code absorbs whole blocks itself (OpenSSL's SHA3_absorb/SHA3_squeeze
 * take the buffer and the rate), so its glue is a different shape and stays in
 * its own built-in.h. A backend shares this file by having only a permutation
 * to offer, and the moment it offers more it stops sharing it.
 *
 * What a backend provides before the include:
 *
 *   struct sha3                the state, the rate and the partial block
 *   SHA3_*_DIGEST_SIZE         the four digest sizes
 *   keccakf1600(st)            one permutation of the 25-word state
 *
 * On the two builds this file exists for, see
 * <modules/digest/sha3-arch/decl.h>: a speed build takes the bodies below
 * into every caller, a size build compiles them once through arch.c.
 * Nothing here decides that - the guard around this include does, in the
 * backend's built-in.h, and it guards the permutation's own include with
 * it - and nothing here has to know which build it is in: CC_SZ_DECLARE
 * is the linkage either way.
 */
#ifndef __CRYPTO_DIGEST_SHA3_ARCH_H__
#define __CRYPTO_DIGEST_SHA3_ARCH_H__

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

CC_SZ_DECLARE(void arch_sha3_init(struct sha3 *sha3, unsigned int digest_sz))
{
	unsigned int i;
	for (i = 0; i < 25; i++)
		sha3->st[i] = 0;
	sha3->md_len = digest_sz;
	sha3->rsiz = 200 - 2 * digest_sz;
	sha3->rsizw = sha3->rsiz / 8;
	sha3->partial = 0;
	for (i = 0; i < sizeof(sha3->buf); i++)
		sha3->buf[i] = 0;
}

CC_SZ_DECLARE(void arch_sha3_224_init(struct sha3 *sha3))
{
	arch_sha3_init(sha3, SHA3_224_DIGEST_SIZE);
}

CC_SZ_DECLARE(void arch_sha3_256_init(struct sha3 *sha3))
{
	arch_sha3_init(sha3, SHA3_256_DIGEST_SIZE);
}

CC_SZ_DECLARE(void arch_sha3_384_init(struct sha3 *sha3))
{
	arch_sha3_init(sha3, SHA3_384_DIGEST_SIZE);
}

CC_SZ_DECLARE(void arch_sha3_512_init(struct sha3 *sha3))
{
	arch_sha3_init(sha3, SHA3_512_DIGEST_SIZE);
}

CC_SZ_DECLARE(int arch_sha3_update(struct sha3 *sha3, const u8 *data,
                                   unsigned int len))
{
	unsigned int i;

	if (sha3->partial) {
		unsigned int n = sha3->rsiz - sha3->partial;
		if (len < n) {
			for (i = 0; i < len; i++)
				sha3->buf[sha3->partial + i] = data[i];
			sha3->partial += len;
			return 0;
		}
		for (i = 0; i < n; i++)
			sha3->buf[sha3->partial + i] = data[i];
		for (i = 0; i < sha3->rsizw; i++)
			sha3->st[i] ^= ((uint64_t *)sha3->buf)[i];
		keccakf1600(sha3->st);
		data += n;
		len -= n;
		sha3->partial = 0;
	}

	while (len >= sha3->rsiz) {
		for (i = 0; i < sha3->rsizw; i++)
			sha3->st[i] ^= ((uint64_t *)data)[i];
		keccakf1600(sha3->st);
		data += sha3->rsiz;
		len -= sha3->rsiz;
	}

	for (i = 0; i < len; i++)
		sha3->buf[i] = data[i];
	sha3->partial = len;

	return 0;
}

CC_SZ_DECLARE(void arch_sha3_final(struct sha3 *sha3, u8 *out))
{
	unsigned int i, inlen = sha3->partial;

	sha3->buf[inlen++] = 0x06;
	for (i = inlen; i < sha3->rsiz; i++)
		sha3->buf[i] = 0;
	sha3->buf[sha3->rsiz - 1] |= 0x80;

	for (i = 0; i < sha3->rsizw; i++)
		sha3->st[i] ^= ((uint64_t *)sha3->buf)[i];

	keccakf1600(sha3->st);

	for (i = 0; i < sha3->rsizw; i++)
		sha3->st[i] = cpu_le64(sha3->st[i]);

	for (i = 0; i < sha3->md_len; i++)
		out[i] = ((u8 *)sha3->st)[i];
}

#endif
