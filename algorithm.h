/*
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz>
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

#ifndef __CRYPTO_ALGORITHM_H__
#define __CRYPTO_ALGORITHM_H__

#include <sys/compiler.h>
#include <bsd/array.h>

__BEGIN_DECLS

enum {
	ALGORITHM_NA = 0,
	ALGORITHM_DH,
	ALGORITHM_DHE,
	ALGORITHM_KRB,
	ALGORITHM_PSK,
	ALGORITHM_RSA,
	ALGORITHM_SRP,
	ALGORITHM_ECC,
	ALGORITHM_ECDH,
	ALGORITHM_ECDHE
};

enum key_exchange {
	KEY_EXCHANGE_NA = 0,
	KEY_EXCHANGE_RSA,
	KEY_EXCHANGE_DHE,
	KEY_EXCHANGE_ECC,
	KEY_EXCHANGE_PSK,
	KEY_EXCHANGE_KRB,
	KEY_EXCHANGE_SRP,
	KEY_EXCHANGE_DH,
	KEY_EXCHANGE_ECDH,
	KEY_EXCHANGE_ECDHE,
	KEY_EXCHANGE_ECJPAKE,
};

enum key_exchange_subtype {
	KEX_NA = 0,
	KEX_DH_ANON,
	KEX_DH_DSS,
	KEX_DH_RSA,
	KEX_DHE_DSS,
	KEX_DHE_PSK,
	KEX_DHE_RSA,
	KEX_ECDH_ANON,
	KEX_ECDH_RSA,
	KEX_ECDH_ECDSA,
	KEX_ECDHE_PSK,
	KEX_ECDHE_RSA,
	KEX_ECDHE_ECDSA,
	KEX_KRB5,
	KEX_PSK,
	KEX_RSA,
	KEX_RSA_PSK,
	KEX_SRP_SHA,
	KEX_SRP_SHA_DSS,
	KEX_SRP_SHA_RSA,
	KEX_ECJPAKE,
	KEX_ECC
};

enum authentication {
	AUTH_ANON = 0,
	AUTH_RSA,
	AUTH_ECC,
};

void
crypto_init_algorithms(void);

DECLARE_CONST_ARRAY(unsigned, kex_type_map);
DECLARE_CONST_ARRAY(unsigned, kex_mode_map);
DECLARE_CONST_ARRAY(const char *, kex_type_names);
DECLARE_CONST_ARRAY(const char *, auth_type_names);

__END_DECLS

#endif
