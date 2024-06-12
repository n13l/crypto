/*
 * The MIT License (MIT)
 *                               Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz> 
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

#ifndef __CRYPTO_P256_H__
#define __CRYPTO_P256_H__

#include <sys/compiler.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

#define P256_PUBLIC_KEY_SIZE 65
#define P256_SECRET_KEY_SIZE 32
#define P256_SHARED_KEY_SIZE 32

struct p256 {
	EVP_PKEY_CTX *ev_ctx;
	EVP_PKEY *ev_peer;
	EVP_PKEY *ev_private;
	EVP_PKEY_METHOD *pmeth;
	ENGINE *engine;
	EC_GROUP *grp;
	EC_POINT *ep_public;
	EC_POINT *ep_shared;
	EC_KEY *ec_peer;
	EC_KEY *ec_private;
	BN_CTX *bnc;
	BIGNUM *bn_public;
	BIGNUM *bn_secret;
};

void
p256_init(struct p256 *p256);

void
p256_fini(struct p256 *p256);

void
p256_reset(struct p256 *p256);

void
p256_key_public(struct p256 *p256, const u8 *private_key, u8 *public_key);

void
p256_key_exchange(struct p256 *p256, const u8 peer[P256_PUBLIC_KEY_SIZE], 
                  const u8 *secret, int bytes, u8 shared[P256_SHARED_KEY_SIZE]);

#endif
