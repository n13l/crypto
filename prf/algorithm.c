/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015                               Daniel Kubec <niel@rtfm.cz>
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
 */

#include <sys/compiler.h>
#include <bsd/array.h>
#include <crypto/prf.h>
#include <crypto/digest.h>

static void
none_prf_derive(struct prf_context *ctx,
                const u8 *seed0, unsigned int seed0_len,
                const u8 *seed1, unsigned int seed1_len,
                const u8 *seed2, unsigned int seed2_len,
                u8 *output, unsigned int output_len)
{
}

struct prf_algorithm none_prf_algorithm = {
	.name = "none_prf",
	.id = PRF_NONE,
	.derive = none_prf_derive
};

STATIC_1_BASED_ARRAY(struct prf_algorithm *, prfs, &none_prf_algorithm, 8);

void
crypto_prf_register(struct prf_algorithm *prf)
{
	prfs[prfs_verify(prf->id)] = prf;
}

struct prf_algorithm *
crypto_prf_by_id(unsigned int id)
{
	return prfs_at(id);
}

void crypto_init_prf_sha2(void);
void crypto_init_prf_algorithms(void)
{
	crypto_init_prf_sha2();
}
