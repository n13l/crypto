#ifndef __MODULES_KECCAK_H__
#define __MODULES_KECCAK_H__

#include <hpc/compiler.h>
#include <inttypes.h>

#if defined(CONFIG_CRYPTO_SHA3_ASM)

#if defined(__aarch64__)
extern void KeccakF1600_hw(u64 st[25]);

static inline void
keccakf1600(u64 st[25])
{
	KeccakF1600_hw(st);
}
#elif defined(__x86_64__)
extern void sha3_keccak_f1600(u64 a[25], const u64 rc[24]);

static const u64 keccakf1600_rndc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static inline void
keccakf1600(u64 st[25])
{
	sha3_keccak_f1600(st, keccakf1600_rndc);
}
#else
#error "CONFIG_CRYPTO_SHA3_ASM: unsupported architecture"
#endif

#elif defined(CONFIG_CRYPTO_SHA3_OSSL)

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

#include <stddef.h>
#include <stdint.h>


#define NDEBUG
#define KeccakF1600 ossl_KeccakF1600_internal
#define SHA3_absorb ossl_SHA3_absorb_unused
#define SHA3_squeeze ossl_SHA3_squeeze_unused

static _unused size_t ossl_SHA3_absorb_unused(u64 A[5][5],
	const unsigned char *inp, size_t len, size_t r);
static _unused void ossl_SHA3_squeeze_unused(u64 A[5][5],
	unsigned char *out, size_t len, size_t r, int next);

#include "../vendor/openssl/crypto/sha/keccak1600.c"
#undef KeccakF1600
#undef SHA3_absorb
#undef SHA3_squeeze

static inline void
keccakf1600(u64 st[25])
{
	ossl_KeccakF1600_internal((u64 (*)[5])st);
}

#elif defined(CONFIG_CRYPTO_SHA3)

#define KECCAK_ROUNDS 24

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const u64 keccakf_rndc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
	1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
	27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
	10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

static inline void
keccakf1600(u64 st[25])
{
	int i, j, round;
	u64 t, bc[5];

	for (round = 0; round < KECCAK_ROUNDS; round++) {
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15]
				^ st[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		t = st[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) &
					     bc[(i + 2) % 5];
		}

		st[0] ^= keccakf_rndc[round];
	}
}

#undef ROTL64
#undef KECCAK_ROUNDS

#else

static inline void
keccakf1600(u64 st[25])
{
	(void)st;
}

#endif
#endif
