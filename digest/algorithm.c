/*
 * The MIT License (MIT)         Copyright (c) 2016 Daniel Kubec <niel@rtfm.cz>
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
#include <crypto/digest.h>

static void none_init(struct digest *d) { }
static void none_update(struct digest *d, const u8 *msg, unsigned int len) {}
static void none_digest(struct digest *digest, u8 *out) { }
static void none_hash(const u8 *key, unsigned int len, u8 *out) { }

static struct digest_algorithm none_alg = {
	.msg_size = 0,
	.blk_size = 0,
	.mac_size = 0,
	.ctx_size = 0,
	.name = "none",
	.id = 0,
	.init = none_init,
	.update = none_update,
	.digest = none_digest,
	.hash = none_hash,
};

STATIC_1_BASED_ARRAY(struct digest_algorithm *, digests, &none_alg, 8);

void
crypto_digest_register(struct digest_algorithm *digest)
{
	digests[digests_verify(digest->id)] = digest;
}

struct digest_algorithm *
crypto_digest_by_id(unsigned int id)
{
	return digests_at(id);
}

/* TODO: weak function calls */
void crypto_init_digest_sha1(void);
void crypto_init_digest_sha2(void);

void crypto_init_digest_algorithms(void)
{
	crypto_init_digest_sha1();
	crypto_init_digest_sha2();
}
