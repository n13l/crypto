
#include <sys/compiler.h>
#include <string.h>
#include "sha256.h"
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <crypto/abi/ssl.h>

static void
sha256_init(struct sha256 *sha256)
{
	SHA256_Init(&sha256->ctx);
}

static void
sha256_copy(struct sha256 *dst, struct sha256 *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static void
sha256_update(struct sha256 *sha256, u8 *addr, size_t size)
{
	SHA256_Update(&sha256->ctx, addr, size);
}

static void
sha256_final(struct sha256 *sha256, u8 *digest)
{
	SHA256_Final(digest, &sha256->ctx);
}

static void
sha256(u8 *addr, size_t size, u8 *digest)
{
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, addr, size);
	SHA256_Final(digest, &sha256);
}

static void
sha256_vector(const u8 *key, size_t klen, u8 *addr, size_t size, u8 *digest)
{
	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	SHA256_Transform(&sha256, key);
	SHA256_Update(&sha256, addr, size);
	SHA256_Final(digest, &sha256);
}

int
hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
                   const u8 *addr[], const size_t *len, u8 *mac)
{
	size_t i;
	unsigned int mdlen;
	int res;

	HMAC_CTX *ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL);
	for (i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	mdlen = SHA256_SIZE;
	res = HMAC_Final(ctx, mac, &mdlen);
	HMAC_CTX_free(ctx);
	return res == 1 ? 0 : -1;
}

int
hmac_sha256(const u8 *key, size_t klen, const u8 *data, size_t dlen, u8 *mac)
{
	return hmac_sha256_vector(key, klen, 1, &data, &dlen, mac);
}
