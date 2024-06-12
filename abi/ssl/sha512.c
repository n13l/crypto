#include <sys/compiler.h>
#include <string.h>
#include "sha512.h"
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <crypto/abi/ssl.h>

void
sha512_init(struct sha512 *sha512)
{
	SHA512_Init(&sha512->ctx);
}

void
sha512_copy(struct sha512 *dst, struct sha512 *src)
{
	memcpy(dst, src, sizeof(*dst));
}

void
sha512_update(struct sha512 *sha512, u8 *addr, size_t size)
{
	SHA512_Update(&sha512->ctx, addr, size);
}

void
sha512_final(struct sha512 *sha512, u8 *digest)
{
	SHA512_Final(digest, &sha512->ctx);
}


void
sha512(u8 *addr, size_t size, u8 *digest)
{
	SHA512_CTX sha512;
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, addr, size);
	SHA512_Final(digest, &sha512);
}

int
hmac_sha512_vector(const u8 *key, size_t key_len, size_t num_elem,
                   const u8 *addr[], const size_t *len, u8 *mac)
{
	size_t i;
	unsigned int mdlen;
	int res;

	HMAC_CTX *ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key, key_len, EVP_sha512(), NULL);
	for (i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	mdlen = SHA512_SIZE;
	res = HMAC_Final(ctx, mac, &mdlen);
	HMAC_CTX_free(ctx);
	return res == 1 ? 0 : -1;
}


int
hmac_sha512(const u8 *key, size_t klen, const u8 *data, size_t dlen, u8 *mac)
{
	return hmac_sha512_vector(key, klen, 1, &data, &dlen, mac);
}
