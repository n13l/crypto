/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2012-2018                          Daniel Kubec <niel@rtfm.cz>
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
 * Each AEAD algorithm will specify a range of possible lengths for the
 * per-record nonce, from N_MIN bytes to N_MAX bytes of input [RFC5116].
 *
 */

#include <sys/compiler.h>
#include <mem/unaligned.h>

static inline void
xor12(u8 b1[], const u8 b2[])
{
	for(unsigned i = 0; i < 12; i++)
		b1[i] ^= b2[i];
}

static inline void
aead_per_record_nonce(u64 seqno, const u8 *iv, u8 *output)
{
	u8 i[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	memcpy(output, iv, 12);
	put_u64_be(i + 4, seqno);
	xor12(output, i);
}
