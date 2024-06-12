/*
 * The MIT License (MIT)                                ABI SSL Runtime Support 
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
 * Pseudorandom functions are deterministic functions which return pseudorandom
 * output indistinguishable from random sequences.
 *
 * They are made based on pseudorandom generators but contrary to them, in 
 * addition to the internal state, they can accept any input data. The input 
 * may be arbitrary but the output must always look completely random.
 *
 * A pseudorandom function, which output is indistinguishable from random 
 * sequences, is called a secure one.
 */

#ifndef __ABI_OPENSSL_H__
#define __ABI_OPENSSL_H__

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static inline HMAC_CTX *HMAC_CTX_new(void)
{
	return malloc(4096);
}
static inline void HMAC_CTX_free(HMAC_CTX *ctx)
{
	free(ctx);
}                                                                               
#endif

typedef int (*ssl_fill_hello_random)
(const SSL *ssl, int server, unsigned char *field, size_t len, void *dgrd);

#define	SSL_CAP_SCA 0x1

//#define CALL_ABI(fn) plt_##fn.plt_##fn
#define CALL_SSL(fn) plt_SSL_##fn.plt_SSL_##fn
#define CALL_CTX(fn) plt_SSL_CTX_##fn.plt_SSL_CTX_##fn

int openssl_init(int server);
void openssl_init_ctxt(SSL_CTX *ctx);
void openssl_init_conn(SSL *ssl);
void openssl_set_caps(int cap);
void openssl_get_sess_id(SSL *ssl, char *buf, int size);
void openssl_info(const SSL *s, int where, int ret);
void openssl_version(char *str, int size);
int openssl_require(int a, int b, int c);
int openssl_lookup(void);

#endif/*__ABI_OPENSSL_PLATFORM_H__*/
