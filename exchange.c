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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <sys/compiler.h>
#include <bsd/array.h>
#include <crypto/algorithm.h>

DEFINE_CONST_1_BASED_ARRAY(unsigned, kex_type_map, KEY_EXCHANGE_NA,
	[KEX_NA]                     = KEY_EXCHANGE_NA,
	[KEX_DH_ANON]                = KEY_EXCHANGE_DH,
	[KEX_DH_DSS]                 = KEY_EXCHANGE_DH,
	[KEX_DH_RSA]                 = KEY_EXCHANGE_DH,
	[KEX_DHE_DSS]                = KEY_EXCHANGE_DHE,
	[KEX_DHE_PSK]                = KEY_EXCHANGE_DHE,
	[KEX_DHE_RSA]                = KEY_EXCHANGE_DHE,
	[KEX_ECDH_ANON]              = KEY_EXCHANGE_ECDH,
	[KEX_ECDH_RSA]               = KEY_EXCHANGE_ECDH,
	[KEX_ECDH_ECDSA]             = KEY_EXCHANGE_ECDH,
	[KEX_ECDHE_PSK]              = KEY_EXCHANGE_ECDHE,
	[KEX_ECDHE_RSA]              = KEY_EXCHANGE_ECDHE,
	[KEX_ECDHE_ECDSA]            = KEY_EXCHANGE_ECDHE,
	[KEX_KRB5]                   = KEY_EXCHANGE_KRB,
	[KEX_PSK]                    = KEY_EXCHANGE_PSK,
	[KEX_RSA]                    = KEY_EXCHANGE_RSA,
	[KEX_RSA_PSK]                = KEY_EXCHANGE_RSA,
	[KEX_SRP_SHA]                = KEY_EXCHANGE_SRP,
	[KEX_SRP_SHA_DSS]            = KEY_EXCHANGE_SRP,
	[KEX_SRP_SHA_RSA]            = KEY_EXCHANGE_SRP,
	[KEX_ECJPAKE]                = KEY_EXCHANGE_ECJPAKE,
	[KEX_ECC]                    = KEY_EXCHANGE_ECC
);

DEFINE_CONST_1_BASED_ARRAY(unsigned, kex_mode_map, KEY_EXCHANGE_NA,
	[KEX_NA]                     = KEY_EXCHANGE_NA,
	[KEX_DH_ANON]                = KEY_EXCHANGE_DHE,
	[KEX_DH_DSS]                 = KEY_EXCHANGE_DHE,
	[KEX_DH_RSA]                 = KEY_EXCHANGE_DHE,
	[KEX_DHE_DSS]                = KEY_EXCHANGE_DHE,
	[KEX_DHE_PSK]                = KEY_EXCHANGE_DHE,
	[KEX_DHE_RSA]                = KEY_EXCHANGE_DHE,
	[KEX_ECDH_ANON]              = KEY_EXCHANGE_ECC,
	[KEX_ECDH_RSA]               = KEY_EXCHANGE_ECC,
	[KEX_ECDH_ECDSA]             = KEY_EXCHANGE_ECC,
	[KEX_ECDHE_PSK]              = KEY_EXCHANGE_ECC,
	[KEX_ECDHE_RSA]              = KEY_EXCHANGE_ECC,
	[KEX_ECDHE_ECDSA]            = KEY_EXCHANGE_ECC,
	[KEX_KRB5]                   = KEY_EXCHANGE_KRB,
	[KEX_PSK]                    = KEY_EXCHANGE_PSK,
	[KEX_RSA]                    = KEY_EXCHANGE_RSA,
	[KEX_RSA_PSK]                = KEY_EXCHANGE_RSA,
	[KEX_SRP_SHA]                = KEY_EXCHANGE_SRP,
	[KEX_SRP_SHA_DSS]            = KEY_EXCHANGE_SRP,
	[KEX_SRP_SHA_RSA]            = KEY_EXCHANGE_SRP,
	[KEX_ECJPAKE]                = KEY_EXCHANGE_ECC,
	[KEX_ECC]                    = KEY_EXCHANGE_ECC
);

/* Key Exchange Methods. */
DEFINE_CONST_1_BASED_ARRAY(const char *, kex_names, "n/a",
	[KEX_DH_ANON]                = "dh-anon",
	[KEX_DH_DSS]                 = "dh-dss",
	[KEX_DH_RSA]                 = "dh-rsa",
	[KEX_DHE_DSS]                = "dhe-dss",
	[KEX_DHE_PSK]                = "dhe-psk",
	[KEX_DHE_RSA]                = "dhe-rsa",
	[KEX_ECDH_ANON]              = "ecdh-anon",
	[KEX_ECDH_RSA]               = "ecdh-rsa",
	[KEX_ECDH_ECDSA]             = "ecdh-ecdsa",
	[KEX_ECDHE_PSK]              = "ecdhe-psk",
	[KEX_ECDHE_RSA]              = "ecdhe-rsa",
	[KEX_ECDHE_ECDSA]            = "ecdhe-ecdsa",
	[KEX_KRB5]                   = "krb5",
	[KEX_PSK]                    = "psk",
	[KEX_RSA]                    = "rsa",
	[KEX_RSA_PSK]                = "rsa-psk",
	[KEX_SRP_SHA]                = "srp-sha",
	[KEX_SRP_SHA_DSS]            = "srp-sha_dss",
	[KEX_SRP_SHA_RSA]            = "srp-sha_rsa",
	[KEX_ECJPAKE]                = "ecjpake",
	[KEX_ECC]                    = "ecc"
);

DEFINE_CONST_1_BASED_ARRAY(const char *, kex_type_names, "n/a",
	[KEY_EXCHANGE_RSA]           = "rsa",
	[KEY_EXCHANGE_DHE]           = "dhe",
	[KEY_EXCHANGE_ECC]           = "ecc"
);

DEFINE_CONST_1_BASED_ARRAY(const char *, auth_type_names, "n/a",
	[AUTH_ANON]                  = "anon",
	[AUTH_RSA]                   = "rsa",
	[AUTH_ECC]                   = "ecc"
);
