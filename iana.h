/*
 * The MIT License (MIT)                                    IANA Considerations
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

#ifndef __CRYPTO_IANA_H__
#define __CRYPTO_IANA_H__

/* IANA Considerations */
enum iana_sha2_alg_assignments {
/* IANA has made the following IKE hash algorithm attribute assignments: */
   SHA2_256               = 4,
   SHA2_384               = 5,
   SHA2_512               = 6,
/*
 * For IKE Phase 2 negotiations, IANA has assigned the following
 * authentication algorithm identifiers:
 */
   HMAC_SHA2_256          = 5,
   HMAC_SHA2_384          = 6,
   HMAC_SHA2_512          = 7,
/*
 * For use of HMAC-SHA-256+ as a PRF in IKEv2, IANA has assigned the
 * following IKEv2 Pseudo-random function (type 2) transform
 * identifiers:
 */
   PRF_HMAC_SHA2_256      = 5,
   PRF_HMAC_SHA2_384      = 6,
   PRF_HMAC_SHA2_512      = 7,
/*
 * For the use of HMAC-SHA-256+ algorithms for data origin
 * authentication and integrity verification in IKEv2, ESP, or AH, IANA
 * has assigned the following IKEv2 integrity (type 3) transform
 * identifiers:
*/
   AUTH_HMAC_SHA2_256_128 = 12,
   AUTH_HMAC_SHA2_384_192 = 13,
   AUTH_HMAC_SHA2_512_256 = 14   
};

/*
 * Supported Groups (formerly named "EC Named Curve").
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 * #tls-parameters-8
 *
 * Supported Elliptic Curves Extension
 * Blake-Wilson, et al.     Expires April 20, 2006                [Page 13]

 * enum {
	sect163k1 (1), sect163r1 (2), sect163r2 (3),
	sect193r1 (4), sect193r2 (5), sect233k1 (6),
	sect233r1 (7), sect239k1 (8), sect283k1 (9),
	sect283r1 (10), sect409k1 (11), sect409r1 (12),
	sect571k1 (13), sect571r1 (14), secp160k1 (15),
	secp160r1 (16), secp160r2 (17), secp192k1 (18),
	secp192r1 (19), secp224k1 (20), secp224r1 (21),
	secp256k1 (22), secp256r1 (23), secp384r1 (24),
	secp521r1 (25),
	x25519i (29), x448 (30) [RFC8446][RFC8422]	
	reserved (0xFE00..0xFEFF),
	arbitrary_explicit_prime_curves(0xFF01),
	arbitrary_explicit_char2_curves(0xFF02),
	(0xFFFF)
 * } NamedCurve;
*/

/* 
 * Elliptic Curve Cryptography (ECC) Cipher Suites for (TLS) 1.2 and Earlier
 * https://tools.ietf.org/html/rfc8422
 */
enum iana_rfc8422_supported_groups {
	RFC8422_ECC_P192R1 = 19,
	RFC8422_ECC_P224R1 = 21,
	RFC8422_ECC_P256R1 = 23,
	RFC8422_ECC_P384R1 = 24,
	RFC8422_ECC_P521R1 = 25,
	RFC8422_ECC_X25519 = 29,
	RFC8422_ECC_X448   = 30,
};

enum iana_rfc8422_curve_types {
	RFC8422_CURVE_TYPE_NA = 0,
	RFC8422_EXPLICIT_PRIME = 1,
	RFC8422_EXPLICIT_CHAR2 = 2,
	RFC8422_NAMED_CURVE = 3,
};

#endif/*__CRYPTO_IANA_H__*/
