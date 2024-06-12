/*
 * The MIT License (MIT)    Internet X.509 Public Key Infrastructure [RFC-5280]
 *                               Copyright (c) 2018 Daniel Kubec <niel@rtfm.cz> 
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
 *
 * ASN.1
 * https://www.itu.int/ITU-T/formal-language/itu-t/x/x894/2018-cor1/\
 * PKIX1Explicit-2009.html
 */

#ifndef __CRYPTO_X509V3_FORMAT_H__
#define __CRYPTO_X509V3_FORMAT_H__

#include <sys/compiler.h>
#include <sys/log.h>
#include <crypto/tlv.h>
#include <crypto/ber.h>
#include <crypto/der.h>

/*
 * The X.509 v3 certificate basic syntax is as follows.  For signature
 * calculation, the data that is to be signed is encoded using the ASN.1
 * distinguished encoding rules (DER) [X.690].  ASN.1 DER encoding is a
 * tag, length, value encoding system for each element.
 *
 * Certificate  ::=  SEQUENCE  {
 * 	tbsCertificate       TBSCertificate,
 * 	signatureAlgorithm   AlgorithmIdentifier,
 * 	signatureValue       BIT STRING
 * }
 */

#define VISIT_X509_V3_CERTIFICATE(pdu, bytes, x509, block)

/*
 * TBSCertificate  ::=  SEQUENCE  {
 * 	version         [0]  EXPLICIT Version DEFAULT v1,
 * 	serialNumber         CertificateSerialNumber,
 * 	signature            AlgorithmIdentifier,
 * 	issuer               Name,
 * 	validity             Validity,
 * 	subject              Name,
 * 	subjectPublicKeyInfo SubjectPublicKeyInfo,
 * 	issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 * 	-- If present, version MUST be v2 or v3
 *
 * 	subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 * 	-- If present, version MUST be v2 or v3
 * 	extensions      [3]  EXPLICIT Extensions OPTIONAL
 * 	-- If present, version MUST be v3
 * }
 */

#define VISIT_X509_V3_TBSCERTIFICATE(pdu, bytes, x509, block)

#endif
