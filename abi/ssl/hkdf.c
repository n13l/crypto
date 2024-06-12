#include <sys/compiler.h>
#include <stdlib.h>
#include <bsd/bb.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <crypto/openssl/sha.h>
#include <crypto/openssl/sha256.h>
#include <crypto/openssl/sha384.h>
#include <crypto/openssl/sha512.h>
#include <crypto/openssl/hkdf.h>

#define CHECK_ERR(fn) \
	if ((fn) <= 0) { err = 1; goto error; }

int
hkdf_extract_sha(const u8 *salt, size_t salt_len,
                    const u8 *ikm, size_t ikm_len, u8 *sec)
{
	size_t err = 0, outlen = SHA_SIZE;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, 0);
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_CTX_hkdf_mode(c, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY));
	CHECK_ERR(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha1()));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_salt(c, salt, salt_len));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_key(c, ikm, ikm_len));
	CHECK_ERR(EVP_PKEY_derive(c, sec, &outlen));
	EVP_PKEY_CTX_free(c);
error:
	return err;
}

int
hkdf_expand_sha(const u8 *key, size_t key_len,
                const u8 *info, size_t info_len,
                u8 *sec, size_t len)
{
	size_t err = 0, outlen = SHA_SIZE;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, 0);
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_CTX_hkdf_mode(c, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));
	CHECK_ERR(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha1()));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_key(c, key, key_len));
	CHECK_ERR(EVP_PKEY_CTX_add1_hkdf_info(c, info, info_len));
	CHECK_ERR(EVP_PKEY_derive(c, sec, &len));
	EVP_PKEY_CTX_free(c);
error:
	return err;
}
	
int
hkdf_extract_sha256(const u8 *salt, size_t salt_len,
                    const u8 *ikm, size_t ikm_len, u8 *sec)
{
	size_t err = 0, outlen = SHA256_SIZE;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, 0);
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_CTX_hkdf_mode(c, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY));
	CHECK_ERR(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_salt(c, salt, salt_len));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_key(c, ikm, ikm_len));
	CHECK_ERR(EVP_PKEY_derive(c, sec, &outlen));
	EVP_PKEY_CTX_free(c);
error:
	return err;
}

int
hkdf_expand_sha256(const u8 *key, size_t key_len,
		   const u8 *info, size_t info_len,
		   u8 *sec, size_t len)
{

	size_t err = 0, outlen = SHA256_SIZE;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, 0);
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_CTX_hkdf_mode(c, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));
	CHECK_ERR(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_key(c, key, key_len));
	CHECK_ERR(EVP_PKEY_CTX_add1_hkdf_info(c, info, info_len));
	CHECK_ERR(EVP_PKEY_derive(c, sec, &len));
	EVP_PKEY_CTX_free(c);
error:
	return err;
}
	
int
hkdf_extract_sha384(const u8 *salt, size_t salt_len,
                    const u8 *ikm, size_t ikm_len, u8 *sec)
{
	size_t err = 0, outlen = SHA384_SIZE;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, 0);
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_CTX_hkdf_mode(c, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY));
	CHECK_ERR(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha384()));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_salt(c, salt, salt_len));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_key(c, ikm, ikm_len));
	CHECK_ERR(EVP_PKEY_derive(c, sec, &outlen));
	EVP_PKEY_CTX_free(c);
error:
	return err;
}

int
hkdf_expand_sha384(const u8 *key, size_t key_len,
		   const u8 *info, size_t info_len, u8 *sec, size_t len)
{

	size_t err = 0, outlen = SHA384_SIZE;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, 0);
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_CTX_hkdf_mode(c, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));
	CHECK_ERR(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha384()));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_key(c, key, key_len));
	CHECK_ERR(EVP_PKEY_CTX_add1_hkdf_info(c, info, info_len));
	CHECK_ERR(EVP_PKEY_derive(c, sec, &len));
	EVP_PKEY_CTX_free(c);
error:
	return err;
}

int
hkdf_extract_sha512(const u8 *salt, size_t salt_len,
                    const u8 *ikm, size_t ikm_len, u8 *sec)
{
	size_t err = 0, outlen = SHA512_SIZE;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, 0);
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_CTX_hkdf_mode(c, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY));
	CHECK_ERR(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha512()));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_salt(c, salt, salt_len));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_key(c, ikm, ikm_len));
	CHECK_ERR(EVP_PKEY_derive(c, sec, &outlen));
	EVP_PKEY_CTX_free(c);
error:
	return err;
}

int
hkdf_expand_sha512(const u8 *key, size_t key_len,
		   const u8 *info, size_t info_len, u8 *sec, size_t len)
{

	size_t err = 0, outlen = SHA512_SIZE;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, 0);
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_derive_init(c));
	CHECK_ERR(EVP_PKEY_CTX_hkdf_mode(c, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));
	CHECK_ERR(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha512()));
	CHECK_ERR(EVP_PKEY_CTX_set1_hkdf_key(c, key, key_len));
	CHECK_ERR(EVP_PKEY_CTX_add1_hkdf_info(c, info, info_len));
	CHECK_ERR(EVP_PKEY_derive(c, sec, &len));
	EVP_PKEY_CTX_free(c);
error:
	return err;
}
