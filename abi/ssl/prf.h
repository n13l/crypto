/*
 * The MIT License (MIT)                         (PRF) A Pseudo-Random Function
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

#ifndef __OPENSSL_CRYPTO_PRF_H__
#define __OPENSSL_CRYPTO_PRF_H__

void
prf_sha1(const u8 *seed0, size_t seed0_len,
         const u8 *seed1, size_t seed1_len,
         const u8 *seed2, size_t seed2_len,
         u8 *output, size_t output_len);

void
prf_sha256(const u8 *seed0, size_t seed0_len,
           const u8 *seed1, size_t seed1_len,
           const u8 *seed2, size_t seed2_len,
           u8 *output, size_t output_len);

void
prf_sha384(const u8 *seed0, size_t seed0_len,
           const u8 *seed1, size_t seed1_len,
           const u8 *seed2, size_t seed2_len,
           u8 *output, size_t output_len);

void
prf_sha512(const u8 *seed0, size_t seed0_len,
           const u8 *seed1, size_t seed1_len,
           const u8 *seed2, size_t seed2_len,
           u8 *output, size_t output_len);

#endif/*__CRYPTO_PRF_H__*/
