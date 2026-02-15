/*
 * RC4 stream cipher
 *
 * The MIT License (MIT)                     Copyright (c) 2026
 *                                                  Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Thirty lines, no tables and no rounds, which is most of why it was
 * everywhere and all of why it is prohibited (RFC 7465). It is here to read
 * captures of the *_WITH_RC4_128_* suites; the test vectors it is checked
 * against are RFC 6229's.
 */

#include <hpc/compiler.h>
#include <string.h>

#include <crypto/cipher.h>
#include <crypto/cipher/rc4.h>

void
rc4_init(struct rc4_ctx *ctx, const u8 *key, unsigned int key_len)
{
	unsigned int i, j = 0;

	for (i = 0; i < 256; i++)
		ctx->s[i] = (u8)i;

	if (!key_len)
		key_len = 1;	/* the loop below would divide by zero */

	for (i = 0; i < 256; i++) {
		u8 t;

		j = (j + ctx->s[i] + key[i % key_len]) & 0xff;
		t = ctx->s[i];
		ctx->s[i] = ctx->s[j];
		ctx->s[j] = t;
	}

	ctx->i = 0;
	ctx->j = 0;
}

void
rc4_crypt(struct rc4_ctx *ctx, u8 *buf, unsigned int len)
{
	unsigned int n;

	for (n = 0; n < len; n++) {
		u8 t;

		ctx->i = (u8)(ctx->i + 1);
		ctx->j = (u8)(ctx->j + ctx->s[ctx->i]);
		t = ctx->s[ctx->i];
		ctx->s[ctx->i] = ctx->s[ctx->j];
		ctx->s[ctx->j] = t;
		buf[n] ^= ctx->s[(u8)(ctx->s[ctx->i] + ctx->s[ctx->j])];
	}
}
