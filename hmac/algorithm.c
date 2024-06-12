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
#include <sys/log.h>
#include <bsd/array.h>
#include <crypto/hmac.h>

static void
none_hmac(struct hmac_context *ctx, const u8 *key, unsigned int key_size,
          const u8 *msg, unsigned int msg_len, u8 *mac, unsigned int mac_size)
{
}

static void
none_vector(struct hmac_context *ctx, const u8 *key, unsigned int key_size,
            unsigned int num,
            const u8 **msg, unsigned int *msg_len, u8 *mac, unsigned int size)
{
}

struct hmac_algorithm none_algorithm = {
	.name = "none_hmac",
	.ctx_size = 0,
	.id = 0,
	.hmac = none_hmac,
	.vector = none_vector,
};

STATIC_1_BASED_ARRAY(struct hmac_algorithm *, hmacs, &none_algorithm, 8);

void
crypto_hmac_register(struct hmac_algorithm *hmac)
{
	hmacs[hmacs_verify(hmac->id)] = hmac;
}

struct hmac_algorithm *
crypto_hmac_by_id(unsigned int id)
{
	return hmacs_at(id);
}
