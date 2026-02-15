#ifndef __CRYPTO_DIGEST_SHA3_H__
#define __CRYPTO_DIGEST_SHA3_H__

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>
#include <modules/built-in.h>

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)
#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)
#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)
#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

struct sha3 {
	u64             st[25];
	unsigned int    md_len;
	unsigned int    rsiz;
	unsigned int    rsizw;
	unsigned int    partial;
	u8              buf[SHA3_224_BLOCK_SIZE];
};

static inline void
arch_sha3_init(struct sha3 *sha3, unsigned int digest_sz)
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

static inline void
arch_sha3_224_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_224_DIGEST_SIZE);
}

static inline void
arch_sha3_256_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_256_DIGEST_SIZE);
}

static inline void
arch_sha3_384_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_384_DIGEST_SIZE);
}

static inline void
arch_sha3_512_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_512_DIGEST_SIZE);
}

#ifdef HAVE_DIGEST_SHA3_BUILT_IN 

static inline int
arch_sha3_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
	unsigned int done = 0;
	const u8 *src = data;

	if ((sha3->partial + len) > (sha3->rsiz - 1)) {
		if (sha3->partial) {
			unsigned int i;
			done = sha3->rsiz - sha3->partial;
			for (i = 0; i < done; i++)
				sha3->buf[sha3->partial + i] = data[i];
			src = sha3->buf;
		}

		do {
			unsigned int i;
			for (i = 0; i < sha3->rsizw; i++)
				sha3->st[i] ^= ((uint64_t *)src)[i];
			keccakf1600(sha3->st);
			done += sha3->rsiz;
			src = data + done;
		} while (done + (sha3->rsiz - 1) < len);

		sha3->partial = 0;
	}

	{
		unsigned int i, rem = len - done;
		for (i = 0; i < rem; i++)
			sha3->buf[sha3->partial + i] = src[i];
		sha3->partial += rem;
	}

	return 0;
}

static inline void
arch_sha3_final(struct sha3 *sha3, u8 *out)
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

#else

static inline int
arch_sha3_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
	return 0;
}

static inline void
arch_sha3_final(struct sha3 *sha3, u8 *out)
{
}

#endif

#endif
