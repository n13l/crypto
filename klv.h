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
 */

/* KLV (Key-Length-Value) format */
/* TLV (Type-Length-Value) format */
/* LV (Length-Value) format */

#ifndef __KLV_FORMAT_H__
#define __KLV_FORMAT_H__

#include <sys/compiler.h>
#include <mem/unaligned.h>

/* Run block on fixed size string */
#define VISIT_KLV_STR_U8(payload, avail, lv, block)

/* Run block on fixed size string in native order */
#define VISIT_KLV_STR_U16(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_KLV_STR_BE16(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_KLV_STR_LE16(payload, avail, lv, block) \

/* Run block on fixed size string in native order */
#define VISIT_KLV_STR_U32(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_KLV_STR_BE32(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_KLV_STR_LE32(payload, avail, lv, block) \

/* Run block on fixed size string in native order */
#define VISIT_KLV_STR_U64(payload, avail, lv, block)

/* Run block on fixed size string in big endian order */
#define VISIT_KLV_STR_BE64(payload, avail, lv, block) \

/* Run block on fixed size string in little endian order */
#define VISIT_KLV_STR_LE64(payload, avail, lv, block) \

/* Run block on fixed size buffer */
#define VISIT_KLV_BUF_U8(payload, avail, lv, block)

/* Run block on fixed size buffer in native order */
#define VISIT_KLV_BUF_U16(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_KLV_BUF_BE16(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_KLV_BUF_LE16(payload, avail, lv, block) \

/* Run block on fixed size buffer in native order */
#define VISIT_KLV_BUF_U32(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_KLV_BUF_BE32(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_KLV_BUF_LE32(payload, avail, lv, block) \

/* Run block on fixed size buffer in native order */
#define VISIT_KLV_BUF_U64(payload, avail, lv, block)

/* Run block on fixed size buffer in big endian order */
#define VISIT_KLV_BUF_BE64(payload, avail, lv, block) \

/* Run block on fixed size buffer in little endian order */
#define VISIT_KLV_BUF_LE64(payload, avail, lv, block) \

#endif
