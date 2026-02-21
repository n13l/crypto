#ifndef __OSS_CRYPTO_SHA2_OSSL_ARMV8_BUILT_IN_H__
#define __OSS_CRYPTO_SHA2_OSSL_ARMV8_BUILT_IN_H__

#define __CRYPTO_ARCH_SHA2_H__
#define __MODULES_DIGEST_SHA2_H__

#ifndef HAVE_DIGEST_SHA2_BUILT_IN
#define HAVE_DIGEST_SHA2_BUILT_IN 1
#endif

#ifndef CONFIG_SILENT
#define DIGEST_SHA2_IMPL_DESC "OpenSSL, ARMv8"
#endif

#include "sha256_block.c"
#include "sha512_block.c"

#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>
#include <string.h>

#define SHA224_DIGEST_SIZE 28
#define SHA224_BLOCK_SIZE  64
#define SHA224_MAC_LEN     28

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64
#define SHA256_MAC_LEN     32

#define SHA384_DIGEST_SIZE 48
#define SHA384_BLOCK_SIZE  128
#define SHA384_MAC_LEN     48

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128

struct sha256 {
	u32          h[8];
	u32          Nl, Nh;
	u32          data[16];
	unsigned int num, md_len;
};

struct sha512 {
	u64          h[8];
	u64          Nl, Nh;
	union {
		u64 d[16];
		u8  p[128];
	} u;
	unsigned int num, md_len;
};

extern void sha256_block_data_order(void *ctx, const void *in, size_t num);
extern void sha512_block_data_order(void *ctx, const void *in, size_t num);

static inline void
arch_sha224_init(struct sha256 *c)
{
	c->h[0] = 0xc1059ed8;
	c->h[1] = 0x367cd507;
	c->h[2] = 0x3070dd17;
	c->h[3] = 0xf70e5939;
	c->h[4] = 0xffc00b31;
	c->h[5] = 0x68581511;
	c->h[6] = 0x64f98fa7;
	c->h[7] = 0xbefa4fa4;
	c->Nl = 0;
	c->Nh = 0;
	c->num = 0;
	c->md_len = SHA224_DIGEST_SIZE;
}

static inline void
arch_sha256_init(struct sha256 *c)
{
	c->h[0] = 0x6a09e667;
	c->h[1] = 0xbb67ae85;
	c->h[2] = 0x3c6ef372;
	c->h[3] = 0xa54ff53a;
	c->h[4] = 0x510e527f;
	c->h[5] = 0x9b05688c;
	c->h[6] = 0x1f83d9ab;
	c->h[7] = 0x5be0cd19;
	c->Nl = 0;
	c->Nh = 0;
	c->num = 0;
	c->md_len = SHA256_DIGEST_SIZE;
}

static inline void
arch_sha384_init(struct sha512 *c)
{
	c->h[0] = 0xcbbb9d5dc1059ed8ULL;
	c->h[1] = 0x629a292a367cd507ULL;
	c->h[2] = 0x9159015a3070dd17ULL;
	c->h[3] = 0x152fecd8f70e5939ULL;
	c->h[4] = 0x67332667ffc00b31ULL;
	c->h[5] = 0x8eb44a8768581511ULL;
	c->h[6] = 0xdb0c2e0d64f98fa7ULL;
	c->h[7] = 0x47b5481dbefa4fa4ULL;
	c->Nl = 0;
	c->Nh = 0;
	c->num = 0;
	c->md_len = SHA384_DIGEST_SIZE;
}

static inline void
arch_sha512_init(struct sha512 *c)
{
	c->h[0] = 0x6a09e667f3bcc908ULL;
	c->h[1] = 0xbb67ae8584caa73bULL;
	c->h[2] = 0x3c6ef372fe94f82bULL;
	c->h[3] = 0xa54ff53a5f1d36f1ULL;
	c->h[4] = 0x510e527fade682d1ULL;
	c->h[5] = 0x9b05688c2b3e6c1fULL;
	c->h[6] = 0x1f83d9abfb41bd6bULL;
	c->h[7] = 0x5be0cd19137e2179ULL;
	c->Nl = 0;
	c->Nh = 0;
	c->num = 0;
	c->md_len = SHA512_DIGEST_SIZE;
}

#ifdef HAVE_DIGEST_SHA2_BUILT_IN

static inline void
arch_sha256_update(struct sha256 *c, const u8 *data, unsigned int len)
{
	u8 *p = (u8 *)c->data;
	u32 l = (c->Nl + (((u32)len) << 3)) & 0xffffffffUL;

	if (l < c->Nl)
		c->Nh++;
	c->Nh += (u32)(len >> 29);
	c->Nl = l;

	if (c->num != 0) {
		unsigned int n = SHA256_BLOCK_SIZE - c->num;

		if (len < n) {
			memcpy(p + c->num, data, len);
			c->num += len;
			return;
		}

		memcpy(p + c->num, data, n);
		sha256_block_data_order(c, p, 1);
		c->num = 0;
		data += n;
		len -= n;
	}

	if (len >= SHA256_BLOCK_SIZE) {
		unsigned int n = len / SHA256_BLOCK_SIZE;
		sha256_block_data_order(c, data, n);
		n *= SHA256_BLOCK_SIZE;
		data += n;
		len -= n;
	}

	if (len != 0) {
		memcpy(p, data, len);
		c->num = len;
	}
}

static inline void
arch_sha256_final(struct sha256 *c, u8 *md)
{
	u8 *p = (u8 *)c->data;
	unsigned int n = c->num;

	p[n] = 0x80;
	n++;

	if (n > (SHA256_BLOCK_SIZE - 8)) {
		memset(p + n, 0, SHA256_BLOCK_SIZE - n);
		sha256_block_data_order(c, p, 1);
		n = 0;
	}

	memset(p + n, 0, SHA256_BLOCK_SIZE - 8 - n);

	p[SHA256_BLOCK_SIZE - 8] = (u8)(c->Nh >> 24);
	p[SHA256_BLOCK_SIZE - 7] = (u8)(c->Nh >> 16);
	p[SHA256_BLOCK_SIZE - 6] = (u8)(c->Nh >> 8);
	p[SHA256_BLOCK_SIZE - 5] = (u8)(c->Nh);
	p[SHA256_BLOCK_SIZE - 4] = (u8)(c->Nl >> 24);
	p[SHA256_BLOCK_SIZE - 3] = (u8)(c->Nl >> 16);
	p[SHA256_BLOCK_SIZE - 2] = (u8)(c->Nl >> 8);
	p[SHA256_BLOCK_SIZE - 1] = (u8)(c->Nl);

	sha256_block_data_order(c, p, 1);
	c->num = 0;

	for (unsigned int i = 0; i < c->md_len / 4; i++)
		put_u32_be(md + i * 4, c->h[i]);
}

static inline void
arch_sha512_update(struct sha512 *c, const u8 *data, unsigned int len)
{
	u8 *p = c->u.p;
	u64 l = c->Nl + (((u64)len) << 3);

	if (l < c->Nl)
		c->Nh++;
	c->Nh += (u64)(((u64)len) >> 61);
	c->Nl = l;

	if (c->num != 0) {
		unsigned int n = SHA512_BLOCK_SIZE - c->num;

		if (len < n) {
			memcpy(p + c->num, data, len);
			c->num += len;
			return;
		}

		memcpy(p + c->num, data, n);
		sha512_block_data_order(c, p, 1);
		c->num = 0;
		data += n;
		len -= n;
	}

	if (len >= SHA512_BLOCK_SIZE) {
		unsigned int n = len / SHA512_BLOCK_SIZE;
		sha512_block_data_order(c, data, n);
		n *= SHA512_BLOCK_SIZE;
		data += n;
		len -= n;
	}

	if (len != 0) {
		memcpy(p, data, len);
		c->num = len;
	}
}

static inline void
arch_sha512_final(struct sha512 *c, u8 *md)
{
	u8 *p = c->u.p;
	unsigned int n = c->num;

	p[n] = 0x80;
	n++;

	if (n > (SHA512_BLOCK_SIZE - 16)) {
		memset(p + n, 0, SHA512_BLOCK_SIZE - n);
		sha512_block_data_order(c, p, 1);
		n = 0;
	}

	memset(p + n, 0, SHA512_BLOCK_SIZE - 16 - n);

	p[SHA512_BLOCK_SIZE - 16] = (u8)(c->Nh >> 56);
	p[SHA512_BLOCK_SIZE - 15] = (u8)(c->Nh >> 48);
	p[SHA512_BLOCK_SIZE - 14] = (u8)(c->Nh >> 40);
	p[SHA512_BLOCK_SIZE - 13] = (u8)(c->Nh >> 32);
	p[SHA512_BLOCK_SIZE - 12] = (u8)(c->Nh >> 24);
	p[SHA512_BLOCK_SIZE - 11] = (u8)(c->Nh >> 16);
	p[SHA512_BLOCK_SIZE - 10] = (u8)(c->Nh >> 8);
	p[SHA512_BLOCK_SIZE -  9] = (u8)(c->Nh);
	p[SHA512_BLOCK_SIZE -  8] = (u8)(c->Nl >> 56);
	p[SHA512_BLOCK_SIZE -  7] = (u8)(c->Nl >> 48);
	p[SHA512_BLOCK_SIZE -  6] = (u8)(c->Nl >> 40);
	p[SHA512_BLOCK_SIZE -  5] = (u8)(c->Nl >> 32);
	p[SHA512_BLOCK_SIZE -  4] = (u8)(c->Nl >> 24);
	p[SHA512_BLOCK_SIZE -  3] = (u8)(c->Nl >> 16);
	p[SHA512_BLOCK_SIZE -  2] = (u8)(c->Nl >> 8);
	p[SHA512_BLOCK_SIZE -  1] = (u8)(c->Nl);

	sha512_block_data_order(c, p, 1);
	c->num = 0;

	for (unsigned int i = 0; i < c->md_len / 8; i++)
		put_u64_be(md + i * 8, c->h[i]);
}

#else

static inline void arch_sha256_update(struct sha256 *c, const u8 *d, unsigned int l) {}
static inline void arch_sha256_final(struct sha256 *c, u8 *md) {}
static inline void arch_sha512_update(struct sha512 *c, const u8 *d, unsigned int l) {}
static inline void arch_sha512_final(struct sha512 *c, u8 *md) {}

#endif

typedef struct {
	u32          h[8];
	unsigned int len;
	unsigned int tot_len;
	u8           block[SHA256_BLOCK_SIZE * 2];
} sha256_ctx;

typedef sha256_ctx sha224_ctx;

typedef struct {
	u64          h[8];
	unsigned int len;
	unsigned int tot_len;
	u8           block[SHA512_BLOCK_SIZE * 2];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;

#define arch_sha2_224_init     arch_sha224_init
#define arch_sha2_224_update   arch_sha256_update
#define arch_sha2_224_final    arch_sha256_final
#define arch_sha2_256_init     arch_sha256_init
#define arch_sha2_256_update   arch_sha256_update
#define arch_sha2_256_final    arch_sha256_final
#define arch_sha2_384_init     arch_sha384_init
#define arch_sha2_384_update   arch_sha512_update
#define arch_sha2_384_final    arch_sha512_final
#define arch_sha2_512_init     arch_sha512_init
#define arch_sha2_512_update   arch_sha512_update
#define arch_sha2_512_final    arch_sha512_final

#endif
