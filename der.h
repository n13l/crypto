/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017                               Daniel Kubec <niel@rtfm.cz>
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
 * X.690 is an ITU-T standard specifying several ASN.1 encoding formats:
 *
 * Basic Encoding Rules (BER)
 * Canonical Encoding Rules (CER)
 * Distinguished Encoding Rules (DER)
 *
 * DER (Distinguished Encoding Rules) is a restricted variant of BER for 
 * producing unequivocal transfer syntax for data structures described by ASN.1.
 *
 * Like CER, DER encodings are valid BER encodings. DER is the same thing as BER
 * with all but one sender's options removed.
 *
 * DER is a subset of BER providing for exactly one way to encode an ASN.1 
 * value. DER is intended for situations when a unique encoding is needed, such
 * as in cryptography, and ensures that a data structure that needs to be 
 * digitally signed produces a unique serialized representation. DER can be 
 * considered a canonical form of BER. For example, in BER a Boolean value of 
 * true can be encoded as any of 255 non-zero byte values, while in DER there is
 * one way to encode a boolean value of true.
 *
 * The most significant DER encoding constraints are:
 *
 * Length encoding must use the definite form
 * Additionally, the shortest possible length encoding must be used
 * Bitstring, octetstring, and restricted strings must use the primitive encoding
 * Elements of a Set are encoded in sorted order, based on their tag value
 * DER is widely used for digital certificates such as X.509.
 */

#ifndef __DER_FORMAT_H__
#define __DER_FORMAT_H__

#include <sys/compiler.h>
#include <crypto/tlv.h>
#include <crypto/ber.h>

#endif
