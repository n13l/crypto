#ifndef __OSS_CRYPTO_SHA3_OSSL_X86_64_AVX2_BUILT_IN_H__
#define __OSS_CRYPTO_SHA3_OSSL_X86_64_AVX2_BUILT_IN_H__

#define __MODULES_DIGEST_SHA3_H__
#define __CRYPTO_ARCH_SHA3_H__

#ifndef HAVE_DIGEST_SHA3_BUILT_IN
#define HAVE_DIGEST_SHA3_BUILT_IN 1
#endif

#ifndef CONFIG_SILENT
#define DIGEST_SHA3_IMPL_DESC "OpenSSL, x86_64, AVX2"
#endif

#include "keccakf1600.c"

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

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
	if (sha3->partial) {
		unsigned int n = sha3->rsiz - sha3->partial;
		if (len < n) {
			for (unsigned int i = 0; i < len; i++)
				sha3->buf[sha3->partial + i] = data[i];
			sha3->partial += len;
			return 0;
		}
		for (unsigned int i = 0; i < n; i++)
			sha3->buf[sha3->partial + i] = data[i];
		SHA3_absorb((uint64_t (*)[5])sha3->st, sha3->buf, sha3->rsiz, sha3->rsiz);
		data += n;
		len -= n;
		sha3->partial = 0;
	}

	if (len >= sha3->rsiz) {
		unsigned int rem = SHA3_absorb((uint64_t (*)[5])sha3->st,
		                              data, len, sha3->rsiz);
		data += len - rem;
		len = rem;
	}

	if (len) {
		for (unsigned int i = 0; i < len; i++)
			sha3->buf[i] = data[i];
		sha3->partial = len;
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

	SHA3_absorb((uint64_t (*)[5])sha3->st, sha3->buf, sha3->rsiz, sha3->rsiz);

	SHA3_squeeze((uint64_t (*)[5])sha3->st, out, sha3->md_len, sha3->rsiz, 0);
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

#define arch_sha3_256_update   arch_sha3_update
#define arch_sha3_256_final    arch_sha3_final

#endif
