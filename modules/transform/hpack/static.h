/*
 * The MIT License (MIT)              HPACK static table (RFC 7541 Appendix A)
 *
 * Copyright (c) 2026                               Daniel Kubec <niel@rtfm.cz>
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

/*
 * GENERATED — do not edit. rfc7541.py in this directory reads RFC 7541
 * and writes this file.
 *
 * The sixty-one entries of Appendix A, as one blob of bytes and one array of
 * (offset, length) pairs into it. One object rather than sixty-one string
 * literals so that a lookup is two loads and no pointer chase, and so that the
 * whole table is one read-only page the decoder shares across every
 * connection it runs.
 *
 * Indices are the specification's, one-based: entry 0 does not exist, which
 * §2.3.3 says is what index zero on the wire means, so the array is padded to
 * keep hpack_static[i] the entry the wire named.
 */

#ifndef __CRYPTO_TRANSFORM_HPACK_STATIC_H__
#define __CRYPTO_TRANSFORM_HPACK_STATIC_H__

#include <hpc/compiler.h>

__BEGIN_DECLS

#define HPACK_STATIC_MAX	61

struct hpack_static_ent {
	u16	name_off;
	u16	name_len;
	u16	value_off;
	u16	value_len;
};

static const char hpack_static_blob[] =
	":authority:methodGET:methodPOST:path/:path/index.html:schemehttp:schemeh"
	"ttps:status200:status204:status206:status304:status400:status404:status5"
	"00accept-charsetaccept-encodinggzip, deflateaccept-languageaccept-ranges"
	"acceptaccess-control-allow-originageallowauthorizationcache-controlconte"
	"nt-dispositioncontent-encodingcontent-languagecontent-lengthcontent-loca"
	"tioncontent-rangecontent-typecookiedateetagexpectexpiresfromhostif-match"
	"if-modified-sinceif-none-matchif-rangeif-unmodified-sincelast-modifiedli"
	"nklocationmax-forwardsproxy-authenticateproxy-authorizationrangerefererr"
	"efreshretry-afterserverset-cookiestrict-transport-securitytransfer-encod"
	"inguser-agentvaryviawww-authenticate";

static const struct hpack_static_ent hpack_static[HPACK_STATIC_MAX + 1] = {
	/* index 0 is not an entry (RFC 7541 §2.3.3) */
	{ 0, 0, 0, 0 },
	{    0, 10,   10,  0 },	/*  1 :authority:  */
	{   10,  7,   17,  3 },	/*  2 :method: GET */
	{   20,  7,   27,  4 },	/*  3 :method: POST */
	{   31,  5,   36,  1 },	/*  4 :path: / */
	{   37,  5,   42, 11 },	/*  5 :path: /index.html */
	{   53,  7,   60,  4 },	/*  6 :scheme: http */
	{   64,  7,   71,  5 },	/*  7 :scheme: https */
	{   76,  7,   83,  3 },	/*  8 :status: 200 */
	{   86,  7,   93,  3 },	/*  9 :status: 204 */
	{   96,  7,  103,  3 },	/* 10 :status: 206 */
	{  106,  7,  113,  3 },	/* 11 :status: 304 */
	{  116,  7,  123,  3 },	/* 12 :status: 400 */
	{  126,  7,  133,  3 },	/* 13 :status: 404 */
	{  136,  7,  143,  3 },	/* 14 :status: 500 */
	{  146, 14,  160,  0 },	/* 15 accept-charset:  */
	{  160, 15,  175, 13 },	/* 16 accept-encoding: gzip, deflate */
	{  188, 15,  203,  0 },	/* 17 accept-language:  */
	{  203, 13,  216,  0 },	/* 18 accept-ranges:  */
	{  216,  6,  222,  0 },	/* 19 accept:  */
	{  222, 27,  249,  0 },	/* 20 access-control-allow-origin:  */
	{  249,  3,  252,  0 },	/* 21 age:  */
	{  252,  5,  257,  0 },	/* 22 allow:  */
	{  257, 13,  270,  0 },	/* 23 authorization:  */
	{  270, 13,  283,  0 },	/* 24 cache-control:  */
	{  283, 19,  302,  0 },	/* 25 content-disposition:  */
	{  302, 16,  318,  0 },	/* 26 content-encoding:  */
	{  318, 16,  334,  0 },	/* 27 content-language:  */
	{  334, 14,  348,  0 },	/* 28 content-length:  */
	{  348, 16,  364,  0 },	/* 29 content-location:  */
	{  364, 13,  377,  0 },	/* 30 content-range:  */
	{  377, 12,  389,  0 },	/* 31 content-type:  */
	{  389,  6,  395,  0 },	/* 32 cookie:  */
	{  395,  4,  399,  0 },	/* 33 date:  */
	{  399,  4,  403,  0 },	/* 34 etag:  */
	{  403,  6,  409,  0 },	/* 35 expect:  */
	{  409,  7,  416,  0 },	/* 36 expires:  */
	{  416,  4,  420,  0 },	/* 37 from:  */
	{  420,  4,  424,  0 },	/* 38 host:  */
	{  424,  8,  432,  0 },	/* 39 if-match:  */
	{  432, 17,  449,  0 },	/* 40 if-modified-since:  */
	{  449, 13,  462,  0 },	/* 41 if-none-match:  */
	{  462,  8,  470,  0 },	/* 42 if-range:  */
	{  470, 19,  489,  0 },	/* 43 if-unmodified-since:  */
	{  489, 13,  502,  0 },	/* 44 last-modified:  */
	{  502,  4,  506,  0 },	/* 45 link:  */
	{  506,  8,  514,  0 },	/* 46 location:  */
	{  514, 12,  526,  0 },	/* 47 max-forwards:  */
	{  526, 18,  544,  0 },	/* 48 proxy-authenticate:  */
	{  544, 19,  563,  0 },	/* 49 proxy-authorization:  */
	{  563,  5,  568,  0 },	/* 50 range:  */
	{  568,  7,  575,  0 },	/* 51 referer:  */
	{  575,  7,  582,  0 },	/* 52 refresh:  */
	{  582, 11,  593,  0 },	/* 53 retry-after:  */
	{  593,  6,  599,  0 },	/* 54 server:  */
	{  599, 10,  609,  0 },	/* 55 set-cookie:  */
	{  609, 25,  634,  0 },	/* 56 strict-transport-security:  */
	{  634, 17,  651,  0 },	/* 57 transfer-encoding:  */
	{  651, 10,  661,  0 },	/* 58 user-agent:  */
	{  661,  4,  665,  0 },	/* 59 vary:  */
	{  665,  3,  668,  0 },	/* 60 via:  */
	{  668, 16,  684,  0 },	/* 61 www-authenticate:  */
};

__END_DECLS

#endif/*__CRYPTO_TRANSFORM_HPACK_STATIC_H__*/
