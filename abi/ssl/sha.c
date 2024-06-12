
#include <sys/compiler.h>
#include <string.h>
#include "sha.h"
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <crypto/abi/ssl.h>

void
sha_init(struct sha *sha)
{
	SHA1_Init(&sha->ctx);
}

void
sha_copy(struct sha *dst, struct sha *src)
{
	memcpy(dst, src, sizeof(*dst));
}

void
sha_update(struct sha *sha, u8 *addr, size_t size)
{
	SHA1_Update(&sha->ctx, addr, size);
}

void
sha_final(struct sha *sha, u8 *digest)
{
	SHA1_Final(digest, &sha->ctx);
}

void
sha(u8 *addr, size_t size, u8 *digest)
{
	SHA_CTX sha;
	SHA1_Init(&sha);
	SHA1_Update(&sha, addr, size);
	SHA1_Final(digest, &sha);
}

void
sha_vector(const u8 *key, size_t klen, u8 *addr, size_t size, u8 *digest)
{
	SHA_CTX sha;
	SHA1_Init(&sha);

	SHA1_Transform(&sha, key);
	SHA1_Update(&sha, addr, size);
	SHA1_Final(digest, &sha);
}

int
hmac_sha_vector(const u8 *key, size_t key_len, size_t num_elem,
                   const u8 *addr[], const size_t *len, u8 *mac)
{
	size_t i;
	unsigned int mdlen;
	int res;

	HMAC_CTX *ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key, key_len, EVP_sha1(), NULL);
	for (i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	mdlen = SHA_SIZE;
	res = HMAC_Final(ctx, mac, &mdlen);
	HMAC_CTX_free(ctx);
	return res == 1 ? 0 : -1;
}

int
hmac_sha(const u8 *key, size_t klen, const u8 *data, size_t dlen, u8 *mac)
{
	return hmac_sha_vector(key, klen, 1, &data, &dlen, mac);
}
