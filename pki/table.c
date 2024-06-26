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
 *
 */

#include <sys/compiler.h>
#include <sys/log.h>
#include <bsd/hash.h>
#include <bsd/hash/fn.h>
#include <bsd/hash/table.h>
#include <bsd/list.h>
#include <mem/page.h>

#include <crypto/pki.h>


DEFINE_HASHTABLE(ht_keypair, 12);

struct pki_node {
	struct page page;     /* memory page */
	struct qnode h;       /* hash tbl_session item */
	u32 hash;
	u32 slot;
	u32 created;
	u32 modified;         /* timestamp in seconds */
	u32 expires;
};

#define CRYPTO_PKI_KEY_SIZE_MAX 4096
#define CRYPTO_PKI_SIG_SIZE_MAX 512

struct pki *
pki_lookup(const u8 *sign, unsigned int len, int create)
{
	return NULL;
}


