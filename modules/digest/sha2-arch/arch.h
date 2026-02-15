/*
 * The SHA-2 block glue, written once for every assembly backend.
 *
 * Two compression functions and the bookkeeping around them: the partial-block
 * buffer, the bit counter and the padding, for the 32-bit pair (SHA-224/256)
 * and the 64-bit pair (SHA-384/512). The assembly is the compression functions
 * and nothing else, so this was the same C in each of sha2-aws-armv8,
 * sha2-aws-x86_64 and its three instruction-set variants, and
 * sha2-ossl-armv8/x86_64: seven copies that differed in a pair of parentheses.
 *
 * What a backend provides before the include, all of it already in its
 * built-in.h for other reasons:
 *
 *   struct sha256, struct sha512     the two states, OpenSSL-shaped
 *   SHA{224,256,384,512}_DIGEST_SIZE, SHA{256,512}_BLOCK_SIZE
 *   sha256_block_data_order(c, p, n) n whole blocks from p into c's state
 *   sha512_block_data_order(c, p, n)
 *
 * The block functions are names, not signatures this file gets to choose: they
 * are OpenSSL's, both vendored implementations export them, and every backend
 * either declares the assembly symbol under them or wraps its dispatch in a
 * shim of that name taking (void *, const void *, size_t).
 *
 * A digest's identity within a pair is c->md_len, which the init sets and the
 * final truncates to: SHA-224 is SHA-256's compression function over different
 * constants, and SHA-384 is SHA-512's, which is why there are four inits and
 * two updates.
 *
 * On the two builds this file exists for, see
 * <modules/digest/sha2-arch/decl.h>: a speed build takes the bodies below
 * into every caller, a size build compiles them once through arch.c.
 * Nothing here decides that - the guard around this include does, in the
 * backend's built-in.h - and nothing here has to know which build it is
 * in: CC_SZ_DECLARE is the linkage either way.
 */
#ifndef __CRYPTO_DIGEST_SHA2_ARCH_H__
#define __CRYPTO_DIGEST_SHA2_ARCH_H__

#include <string.h>
#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

CC_SZ_DECLARE(void arch_sha224_init(struct sha256 *c))
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

CC_SZ_DECLARE(void arch_sha256_init(struct sha256 *c))
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

CC_SZ_DECLARE(void arch_sha384_init(struct sha512 *c))
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

CC_SZ_DECLARE(void arch_sha512_init(struct sha512 *c))
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

CC_SZ_DECLARE(void arch_sha256_update(struct sha256 *c, const u8 *data,
                                      unsigned int len))
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

CC_SZ_DECLARE(void arch_sha256_final(struct sha256 *c, u8 *md))
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

	/*
	 * Serialize all 8 state words into a full-size local buffer (always
	 * in-bounds: h[] has 8 entries) and copy out only md_len bytes. The
	 * caller's md is sized for the specific variant (28 for SHA-224, 32 for
	 * SHA-256); writing directly with a run-time md_len bound trips a false
	 * -Wstringop-overflow when this is inlined into a fixed-size buffer.
	 */
	{
		u8 out[SHA256_DIGEST_SIZE];

		for (unsigned int i = 0; i < 8; i++)
			put_u32_be(out + i * 4, c->h[i]);
		memcpy(md, out, c->md_len);
	}
}

CC_SZ_DECLARE(void arch_sha512_update(struct sha512 *c, const u8 *data,
                                      unsigned int len))
{
	u8 *p = c->u.p;
	u64 l = c->Nl + (((u64)len) << 3);

	if (l < c->Nl)
		c->Nh++;
	c->Nh += (u64)len >> 61;
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

CC_SZ_DECLARE(void arch_sha512_final(struct sha512 *c, u8 *md))
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

	/*
	 * The same buffer-then-copy as arch_sha256_final(), for the same reason:
	 * md_len is 48 for SHA-384 and 64 for SHA-512.
	 */
	{
		u8 out[SHA512_DIGEST_SIZE];

		for (unsigned int i = 0; i < 8; i++)
			put_u64_be(out + i * 8, c->h[i]);
		memcpy(md, out, c->md_len);
	}
}

#endif
