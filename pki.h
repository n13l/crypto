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

#ifndef __CRYPTO_PKI_H__
#define __CRYPTO_PKI_H__

#include <sys/compiler.h>

#define PKI_KEY_SIZE_MAX 4096
#define PKI_SIG_SIZE_MAX 512

__BEGIN_DECLS

struct pki {
	u8 pub[PKI_KEY_SIZE_MAX];
	u8 sec[PKI_KEY_SIZE_MAX];
	u8 sig[PKI_SIG_SIZE_MAX];
	unsigned int sig_len, private_len, public_len;
};

/**
 * pki_lookup()
 *
 * O(1) time branchless memory access
 *
 * @sign:             signature
 * @len:              signature len
 * @create:           non zero creating next row in table
 */

struct pki *
pki_lookup(const u8 *sign, unsigned int len, int create);

/**
 * pki_add()
 *
 * O(1) time branchless memory access
 *
 * @pki:              contains keys and signature
 */

int
pki_add(struct pki *pki);

/**
 * pki_add()
 *
 * O(1) time branchless memory access
 *
 * @pki:              contains keys and signature
 */

int
pki_del(struct pki *pki);

__END_DECLS

#endif
