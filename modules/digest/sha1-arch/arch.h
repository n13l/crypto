/*
 * The SHA-1 block glue, written once for every assembly backend.
 *
 * FIPS 180-4 leaves a compression function and the bookkeeping around it: the
 * partial-block buffer, the 64-bit bit counter and the padding. The assembly is
 * the compression function and nothing else, so this - the bookkeeping - was
 * the same C in each of sha1-aws-armv8, sha1-aws-x86_64 and its three
 * instruction-set variants, and sha1-ossl-armv8/x86_64: seven copies of one
 * page that differed in whitespace. It is one page here, and each backend
 * includes it.
 *
 * What a backend provides before the include is its own half of the contract,
 * all of it already in its built-in.h for other reasons:
 *
 *   struct sha1                   the state, an OpenSSL-shaped SHA_CTX
 *   SHA1_BLOCK_SIZE               64
 *   sha1_block_data_order(c, p, n)   n whole blocks from p into c's state
 *
 * The block function is a name, not a signature this file gets to choose: it is
 * OpenSSL's, both vendored implementations export it, and every backend either
 * declares the assembly symbol under it or wraps its dispatch in a shim of that
 * name taking (void *, const void *, size_t).
 *
 * On the two builds this file exists for, see
 * <modules/digest/sha1-arch/decl.h>: a speed build takes the bodies below
 * into every caller, a size build compiles them once through arch.c.
 * Nothing here decides that - the guard around this include does, in the
 * backend's built-in.h - and nothing here has to know which build it is
 * in: CC_SZ_DECLARE is the linkage either way.
 */
#ifndef __CRYPTO_DIGEST_SHA1_ARCH_H__
#define __CRYPTO_DIGEST_SHA1_ARCH_H__

#include <string.h>
#include <hpc/compiler.h>
#include <hpc/mem/unaligned.h>

CC_SZ_DECLARE(void arch_sha1_160_init(struct sha1 *c))
{
	c->h0  = 0x67452301;
	c->h1  = 0xefcdab89;
	c->h2  = 0x98badcfe;
	c->h3  = 0x10325476;
	c->h4  = 0xc3d2e1f0;
	c->Nl  = 0;
	c->Nh  = 0;
	c->num = 0;
}

CC_SZ_DECLARE(void arch_sha1_160_update(struct sha1 *c, const u8 *data,
                                        unsigned int len))
{
	u8 *p = (u8 *)c->data;
	u32 l;

	l = c->Nl + (((u32)len) << 3);
	if (l < c->Nl)
		c->Nh++;
	c->Nh += (u32)(len >> 29);
	c->Nl = l;

	if (c->num > 0) {
		unsigned int n = SHA1_BLOCK_SIZE - c->num;
		if (len < n) {
			memcpy(p + c->num, data, len);
			c->num += len;
			return;
		}
		memcpy(p + c->num, data, n);
		sha1_block_data_order(c, p, 1);
		data += n;
		len  -= n;
		c->num = 0;
	}

	if (len >= SHA1_BLOCK_SIZE) {
		unsigned int n = len / SHA1_BLOCK_SIZE;
		sha1_block_data_order(c, data, n);
		n    *= SHA1_BLOCK_SIZE;
		data += n;
		len  -= n;
	}

	if (len > 0) {
		memcpy(p, data, len);
		c->num = len;
	}
}

CC_SZ_DECLARE(void arch_sha1_160_final(struct sha1 *c, u8 *out))
{
	u8 *p = (u8 *)c->data;
	unsigned int n = c->num;

	p[n++] = 0x80;

	if (n > 56) {
		memset(p + n, 0, SHA1_BLOCK_SIZE - n);
		sha1_block_data_order(c, p, 1);
		n = 0;
	}

	memset(p + n, 0, 56 - n);
	put_u32_be(p + 56, c->Nh);
	put_u32_be(p + 60, c->Nl);
	sha1_block_data_order(c, p, 1);

	put_u32_be(out,      c->h0);
	put_u32_be(out + 4,  c->h1);
	put_u32_be(out + 8,  c->h2);
	put_u32_be(out + 12, c->h3);
	put_u32_be(out + 16, c->h4);
}

#endif
