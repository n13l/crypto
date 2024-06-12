#ifndef SHA256_H
#define SHA256_H

#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define SHA256_SIZE  32
struct sha256 {
	SHA256_CTX ctx;
};

/*
void
sha256_init(struct sha256 *sha256);

void
sha256_copy(struct sha256 *dst, struct sha256 *src);

void
sha256_update(struct sha256 *sha256, u8 *addr, size_t size);

void
sha256_final(struct sha256 *sha256, u8 *digest);

void
sha256(u8 *addr, size_t size, u8 *digest);

void
sha256_vector(const u8 *key, size_t klen, u8 *addr, size_t size, u8 *digest);
*/
int
hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		       const u8 *addr[], const size_t *len, u8 *mac);
int
hmac_sha256(const u8 *key, size_t key_len, const u8 *data,
		size_t data_len, u8 *mac);

void
sha256_prf(const u8 *key, size_t key_len, const char *label,
           const u8 *data, size_t data_len, u8 *buf, size_t buf_len);

#endif /* SHA256_H */
