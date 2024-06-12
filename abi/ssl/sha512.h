/*
 * SHA512 hash implementation and interface functions
 * Copyright (c) 2003-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SHA512_H
#define SHA512_H

#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define SHA512_SIZE  64

struct sha512 {
	SHA512_CTX ctx;
};

void
sha512_init(struct sha512 *sha512);

void
sha512_copy(struct sha512 *dst, struct sha512 *src);

void
sha512_update(struct sha512 *sha512, u8 *addr, size_t size);

void
sha512_final(struct sha512 *sha512, u8 *digest);

void
sha512(u8 *addr, size_t size, u8 *digest);

int
hmac_sha512_vector(const u8 *key, size_t klen, size_t num_elem, const u8 *addr[], 
                   const size_t *len, u8 *mac);
int
hmac_sha512(const u8 *key, size_t klen, const u8 *data, size_t dlen, u8 *mac);

void
sha512_prf(const u8 *key, size_t key_len, const char *label, const u8 *data, 
           size_t data_len, u8 *buf, size_t buf_len);

#endif /* SHA512_H */
