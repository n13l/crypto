/*
 * The MIT License (MIT)
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

#ifndef __CRYPTO_OPENSSL_AES_H__
#define __CRYPTO_OPENSSL_AES_H__

#include <sys/compiler.h>

#define AES128_BLOCK_SIZE 16
#define AES128_KEY_LENGTH 16

int
openssl_aes_ecb_decrypt(u8 *output, const u8 *secret, const u8 *block);

int
openssl_aes_gcm_decrypt(const u8 *sec, u16 slen, const u8 *key, u8 klen,
		const u8 *iv, u8 ilen, u8 *out);

int
openssl_aes_cbc_decrypt(const u8 *sec, u16 slen, const u8 *key, u8 klen,
		const u8 *iv, u8 ilen, u8 *out);

#endif/*__CRYPTO_AES_H__*/
