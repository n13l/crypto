/*
 * SHA384 hash implementation and interface functions
 * Copyright (c) 2003-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SHA384_H
#define SHA384_H

#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define SHA384_SIZE  48

struct sha384 {
	SHA512_CTX ctx;
};

void
openssl_sha384_init(struct sha384 *sha384);

void
openssl_sha384_copy(struct sha384 *dst, struct sha384 *src);

void
openssl_sha384_update(struct sha384 *sha384, u8 *addr, size_t size);

void
openssl_sha384_final(struct sha384 *sha384, u8 *digest);

void
openssl_sha384(u8 *addr, size_t size, u8 *digest);

int
hmac_sha384_vector(const u8 *key, size_t key_len, size_t num_elem,
                   const u8 *addr[], const size_t *len, u8 *mac);
int
hmac_sha384(const u8 *key, size_t key_len, const u8 *data,
            size_t data_len, u8 *mac);
void
sha384_prf(const u8 *key, size_t klen, const char *label,
           const u8 *data, size_t dlen, u8 *buf, size_t buf_len);

#endif /* SHA384_H */
