/*
 * The MIT License (MIT)              QPACK static table (RFC 9204 Appendix A)
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
 * GENERATED — do not edit. rfc9204.py in this directory reads RFC 9204
 * and writes this file.
 *
 * The ninety-nine entries of Appendix A, as one blob of bytes and one array
 * of (offset, length) pairs into it — the same object hpack's static.h is,
 * for the same reasons: a lookup is two loads and no pointer chase, and the
 * whole table is one read-only page shared across every connection.
 *
 * Indices are the specification's, zero-based: unlike HPACK, QPACK numbers
 * its static table from 0 (§3.1) and has no unused first slot.
 */

#ifndef __CRYPTO_TRANSFORM_QPACK_STATIC_H__
#define __CRYPTO_TRANSFORM_QPACK_STATIC_H__

#include <hpc/compiler.h>

__BEGIN_DECLS

#define QPACK_STATIC_N	99

struct qpack_static_ent {
	u16	name_off;
	u16	name_len;
	u16	value_off;
	u16	value_len;
};

static const char qpack_static_blob[] =
	":authority:path/age0content-dispositioncontent-lengthcookiedateetagif-mod"
	"ified-sinceif-none-matchlast-modifiedlinklocationrefererset-cookie:method"
	"CONNECTDELETEGETHEADOPTIONSPOSTPUT:schemehttphttps:status103200304404503a"
	"ccept*/*application/dns-messageaccept-encodinggzip, deflate, braccept-ran"
	"gesbytesaccess-control-allow-headerscache-controlcontent-typeaccess-contr"
	"ol-allow-originmax-age=0max-age=2592000max-age=604800no-cacheno-storepubl"
	"ic, max-age=31536000content-encodingapplication/javascriptapplication/jso"
	"napplication/x-www-form-urlencodedimage/gifimage/jpegimage/pngtext/csstex"
	"t/html; charset=utf-8text/plaintext/plain;charset=utf-8bytes=0-strict-tra"
	"nsport-securitymax-age=31536000; includesubdomainsmax-age=31536000; inclu"
	"desubdomains; preloadvaryx-content-type-optionsnosniffx-xss-protection1; "
	"mode=block100204206302400403421425500accept-languageaccess-control-allow-"
	"credentialsFALSETRUEaccess-control-allow-methodsgetget, post, optionsacce"
	"ss-control-expose-headersaccess-control-request-headersaccess-control-req"
	"uest-methodalt-svcclearauthorizationcontent-security-policyscript-src 'no"
	"ne'; object-src 'none'; base-uri 'none'early-dataexpect-ctforwardedif-ran"
	"gepurposeprefetchservertiming-allow-originupgrade-insecure-requestsuser-a"
	"gentx-forwarded-forx-frame-optionsdenysameorigin";

static const struct qpack_static_ent qpack_static[QPACK_STATIC_N] = {
	{    0, 10,    0,  0 },	/*  0 :authority: */
	{   10,  5,   15,  1 },	/*  1 :path: / */
	{   16,  3,   19,  1 },	/*  2 age: 0 */
	{   20, 19,    0,  0 },	/*  3 content-disposition: */
	{   39, 14,   19,  1 },	/*  4 content-length: 0 */
	{   53,  6,    0,  0 },	/*  5 cookie: */
	{   59,  4,    0,  0 },	/*  6 date: */
	{   63,  4,    0,  0 },	/*  7 etag: */
	{   67, 17,    0,  0 },	/*  8 if-modified-since: */
	{   84, 13,    0,  0 },	/*  9 if-none-match: */
	{   97, 13,    0,  0 },	/* 10 last-modified: */
	{  110,  4,    0,  0 },	/* 11 link: */
	{  114,  8,    0,  0 },	/* 12 location: */
	{  122,  7,    0,  0 },	/* 13 referer: */
	{  129, 10,    0,  0 },	/* 14 set-cookie: */
	{  139,  7,  146,  7 },	/* 15 :method: CONNECT */
	{  139,  7,  153,  6 },	/* 16 :method: DELETE */
	{  139,  7,  159,  3 },	/* 17 :method: GET */
	{  139,  7,  162,  4 },	/* 18 :method: HEAD */
	{  139,  7,  166,  7 },	/* 19 :method: OPTIONS */
	{  139,  7,  173,  4 },	/* 20 :method: POST */
	{  139,  7,  177,  3 },	/* 21 :method: PUT */
	{  180,  7,  187,  4 },	/* 22 :scheme: http */
	{  180,  7,  191,  5 },	/* 23 :scheme: https */
	{  196,  7,  203,  3 },	/* 24 :status: 103 */
	{  196,  7,  206,  3 },	/* 25 :status: 200 */
	{  196,  7,  209,  3 },	/* 26 :status: 304 */
	{  196,  7,  212,  3 },	/* 27 :status: 404 */
	{  196,  7,  215,  3 },	/* 28 :status: 503 */
	{  218,  6,  224,  3 },	/* 29 accept: *|* */
	{  218,  6,  227, 23 },	/* 30 accept: application/dns-message */
	{  250, 15,  265, 17 },	/* 31 accept-encoding: gzip, deflate, br */
	{  282, 13,  295,  5 },	/* 32 accept-ranges: bytes */
	{  300, 28,  328, 13 },	/* 33 access-control-allow-headers: cache-control */
	{  300, 28,  341, 12 },	/* 34 access-control-allow-headers: content-type */
	{  353, 27,  224,  1 },	/* 35 access-control-allow-origin: * */
	{  328, 13,  380,  9 },	/* 36 cache-control: max-age=0 */
	{  328, 13,  389, 15 },	/* 37 cache-control: max-age=2592000 */
	{  328, 13,  404, 14 },	/* 38 cache-control: max-age=604800 */
	{  328, 13,  418,  8 },	/* 39 cache-control: no-cache */
	{  328, 13,  426,  8 },	/* 40 cache-control: no-store */
	{  328, 13,  434, 24 },	/* 41 cache-control: public, max-age=31536000 */
	{  458, 16,  280,  2 },	/* 42 content-encoding: br */
	{  458, 16,  265,  4 },	/* 43 content-encoding: gzip */
	{  341, 12,  227, 23 },	/* 44 content-type: application/dns-message */
	{  341, 12,  474, 22 },	/* 45 content-type: application/javascript */
	{  341, 12,  496, 16 },	/* 46 content-type: application/json */
	{  341, 12,  512, 33 },	/* 47 content-type: application/x-www-form-urlencoded */
	{  341, 12,  545,  9 },	/* 48 content-type: image/gif */
	{  341, 12,  554, 10 },	/* 49 content-type: image/jpeg */
	{  341, 12,  564,  9 },	/* 50 content-type: image/png */
	{  341, 12,  573,  8 },	/* 51 content-type: text/css */
	{  341, 12,  581, 24 },	/* 52 content-type: text/html; charset=utf-8 */
	{  341, 12,  605, 10 },	/* 53 content-type: text/plain */
	{  341, 12,  615, 24 },	/* 54 content-type: text/plain;charset=utf-8 */
	{  289,  5,  639,  8 },	/* 55 range: bytes=0- */
	{  647, 25,  442, 16 },	/* 56 strict-transport-security: max-age=31536000 */
	{  647, 25,  672, 35 },	/* 57 strict-transport-security: max-age=31536000; includesubdomains */
	{  647, 25,  707, 44 },	/* 58 strict-transport-security: max-age=31536000; includesubdomains; preload */
	{  751,  4,  250, 15 },	/* 59 vary: accept-encoding */
	{  751,  4,  374,  6 },	/* 60 vary: origin */
	{  755, 22,  777,  7 },	/* 61 x-content-type-options: nosniff */
	{  784, 16,  800, 13 },	/* 62 x-xss-protection: 1; mode=block */
	{  196,  7,  813,  3 },	/* 63 :status: 100 */
	{  196,  7,  816,  3 },	/* 64 :status: 204 */
	{  196,  7,  819,  3 },	/* 65 :status: 206 */
	{  196,  7,  822,  3 },	/* 66 :status: 302 */
	{  196,  7,  825,  3 },	/* 67 :status: 400 */
	{  196,  7,  828,  3 },	/* 68 :status: 403 */
	{  196,  7,  831,  3 },	/* 69 :status: 421 */
	{  196,  7,  834,  3 },	/* 70 :status: 425 */
	{  196,  7,  837,  3 },	/* 71 :status: 500 */
	{  840, 15,    0,  0 },	/* 72 accept-language: */
	{  855, 32,  887,  5 },	/* 73 access-control-allow-credentials: FALSE */
	{  855, 32,  892,  4 },	/* 74 access-control-allow-credentials: TRUE */
	{  300, 28,  224,  1 },	/* 75 access-control-allow-headers: * */
	{  896, 28,  924,  3 },	/* 76 access-control-allow-methods: get */
	{  896, 28,  927, 18 },	/* 77 access-control-allow-methods: get, post, options */
	{  896, 28,  770,  7 },	/* 78 access-control-allow-methods: options */
	{  945, 29,   39, 14 },	/* 79 access-control-expose-headers: content-length */
	{  974, 30,  341, 12 },	/* 80 access-control-request-headers: content-type */
	{ 1004, 29,  924,  3 },	/* 81 access-control-request-method: get */
	{ 1004, 29,  932,  4 },	/* 82 access-control-request-method: post */
	{ 1033,  7, 1040,  5 },	/* 83 alt-svc: clear */
	{ 1045, 13,    0,  0 },	/* 84 authorization: */
	{ 1058, 23, 1081, 53 },	/* 85 content-security-policy: script-src 'none'; object-src 'none'; base-uri 'none' */
	{ 1134, 10,  203,  1 },	/* 86 early-data: 1 */
	{ 1144,  9,    0,  0 },	/* 87 expect-ct: */
	{ 1153,  9,    0,  0 },	/* 88 forwarded: */
	{ 1162,  8,    0,  0 },	/* 89 if-range: */
	{  374,  6,    0,  0 },	/* 90 origin: */
	{ 1170,  7, 1177,  8 },	/* 91 purpose: prefetch */
	{ 1185,  6,    0,  0 },	/* 92 server: */
	{ 1191, 19,  224,  1 },	/* 93 timing-allow-origin: * */
	{ 1210, 25,  203,  1 },	/* 94 upgrade-insecure-requests: 1 */
	{ 1235, 10,    0,  0 },	/* 95 user-agent: */
	{ 1245, 15,    0,  0 },	/* 96 x-forwarded-for: */
	{ 1260, 15, 1275,  4 },	/* 97 x-frame-options: deny */
	{ 1260, 15, 1279, 10 },	/* 98 x-frame-options: sameorigin */
};

__END_DECLS

#endif/*__CRYPTO_TRANSFORM_QPACK_STATIC_H__*/
