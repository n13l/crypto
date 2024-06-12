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
 * The format for Basic Encoding Rules specifies a self-describing and 
 * self-delimiting format for encoding ASN.1 data structures. Each data element
 * is encoded as a type identifier, a length description, the actual data
 * elements, and, where necessary, an end-of-content marker.
 *
 * These types of encodings are commonly called type–length–value (TLV) 
 * encodings. This format allows a receiver to decode the ASN.1 information from
 * an incomplete stream, without requiring any pre-knowledge of the size,
 * content, or semantic meaning of the data.
 */

#ifndef __BER_FORMAT_H__
#define __BER_FORMAT_H__

#include <sys/compiler.h>
#include <mem/unaligned.h>

#define BER_TYPE_EOC                0x0
#define BER_TYPE_BOOLEAN            0x1
#define BER_TYPE_INTEGER            0x2
#define BER_TYPE_BIT_STRING         0x3
#define BER_TYPE_OCTET_STRING       0x4
#define BER_TYPE_NULL               0x5
#define BER_TYPE_OBJECT_IDENTIFIER  0x6

#define BER_TYPE_UTF8STRING         0xc

#define BER_TYPE_SEQUENCE           0x10
#define BER_TYPE_SET                0x11

#define BER_TYPE_DATE               0x1f

/* The type is native to ASN.1. */
#define BER_CLASS_UNIVERSAL         0
/* The type is only valid for one specific application. */
#define BER_CLASS_APPLICATION       1 
/* Meaning of this type depends on the context (sequence, set or choice). */
#define BER_CLASS_CONTEXT_SPECIFIC  2
/* Defined in private specifications. */
#define BER_CLASS_PRIVATE           3

/* The contents octets directly encode the element value. */
#define BER_PRIMITIVE               0
/* The contents octets contain 0, 1, or more element encodings. */
#define BER_CONSTRUCTED             1

/* 
 * |----------------------------------------------------|
 * |         Octet 1             |   Octet 2 onwards    |
 * |-----------------------------|----------------------|
 * | 8 7 | 6 | 5 4 3 2 1         | 8    | 7 6 5 4 3 2 1 |
 * |----------------------------------------------------|
 * | Tag |P/C| Tag number (0–30) | more |   Tag number  |
 * |-----------------------------|----------------------|
 */

struct ber {
	unsigned class_id;
	unsigned type_id;
	unsigned tag_id;
	unsigned pc;
	unsigned len;

};

//#define BER_READ_TYPE(pdu, bytes, ber) 
//#define BER_READ_LENGTH(pdu, bytes, ber) 
//#define BER_READ_VALUE(pdu, bytes, ber) 

/* Run block on sequence */
#define VISIT_BER(pdu, bytes, ber, block)


/* Run block on fixed size string */
#define VISIT_BER_STR_U8(payload, avail, lv, block)

/* Run block on fixed size string in native order */
#define VISIT_BER_STR_U16(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_BER_STR_BE16(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_BER_STR_LE16(payload, avail, lv, block) \

/* Run block on fixed size string in native order */
#define VISIT_BER_STR_U32(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_BER_STR_BE32(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_BER_STR_LE32(payload, avail, lv, block) \

/* Run block on fixed size string in native order */
#define VISIT_BER_STR_U64(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_BER_STR_BE64(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_BER_STR_LE64(payload, avail, lv, block) \

/* Run block on fixed size buffer */
#define VISIT_BER_BUF_U8(payload, avail, lv, block)

/* Run block on fixed size buffer in native order */
#define VISIT_BER_BUF_U16(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_BER_BUF_BE16(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_BER_BUF_LE16(payload, avail, lv, block) \

/* Run block on fixed size buffer in native order */
#define VISIT_BER_BUF_U32(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_BER_BUF_BE32(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_BER_BUF_LE32(payload, avail, lv, block) \

/* Run block on fixed size buffer in native order */
#define VISIT_BER_BUF_U64(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_BER_BUF_BE64(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_BER_BUF_LE64(payload, avail, lv, block) \

#endif
