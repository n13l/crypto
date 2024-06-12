#include <sys/compiler.h>
#include <string.h>
#include "sha384.h"
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <crypto/abi/ssl.h>

void
openssl_sha384_init(struct sha384 *sha384)
{
	SHA384_Init(&sha384->ctx);
}

void
openssl_sha384_copy(struct sha384 *dst, struct sha384 *src)
{
	memcpy(dst, src, sizeof(*dst));
}

void
openssl_sha384_update(struct sha384 *sha384, u8 *addr, size_t size)
{
	SHA384_Update(&sha384->ctx, addr, size);
}

void
openssl_sha384_final(struct sha384 *sha384, u8 *digest)
{
	SHA384_Final(digest, &sha384->ctx);
}

void
openssl_sha384(u8 *addr, size_t size, u8 *digest)
{
	SHA512_CTX sha384;
	SHA384_Init(&sha384);
	SHA384_Update(&sha384, addr, size);
	SHA384_Final(digest, &sha384);
}

int
hmac_sha384_vector(const u8 *key, size_t key_len, size_t num_elem,
                   const u8 *addr[], const size_t *len, u8 *mac)
{
	size_t i;
	unsigned int mdlen;
	int res;

	HMAC_CTX *ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key, key_len, EVP_sha384(), NULL);
	for (i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	mdlen = SHA384_SIZE;
	res = HMAC_Final(ctx, mac, &mdlen);
	HMAC_CTX_free(ctx);
	return res == 1 ? 0 : -1;
}

int
hmac_sha384(const u8 *key, size_t klen, const u8 *data, size_t dlen, u8 *mac)
{
	return hmac_sha384_vector(key, klen, 1, &data, &dlen, mac);
}
