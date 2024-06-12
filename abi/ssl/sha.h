#ifndef SHA_H
#define SHA_H

#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define SHA_SIZE  20

struct sha {
	SHA_CTX ctx;
};

void
sha_init(struct sha *sha);

void
sha_copy(struct sha *dst, struct sha *src);

void
sha_update(struct sha *sha, u8 *addr, size_t size);

void
sha_final(struct sha *sha, u8 *digest);

void
sha(u8 *addr, size_t size, u8 *digest);

void
sha_vector(const u8 *key, size_t klen, u8 *addr, size_t size, u8 *digest);

int
hmac_sha_vector(const u8 *key, size_t key_len, size_t num_elem,
		       const u8 *addr[], const size_t *len, u8 *mac);
int
hmac_sha(const u8 *key, size_t key_len, const u8 *data,
		size_t data_len, u8 *mac);
void
sha_prf(const u8 *key, size_t key_len, const char *label,
           const u8 *data, size_t data_len, u8 *buf, size_t buf_len);

#endif /* SHA_H */
