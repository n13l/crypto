#include <sys/compiler.h>
#include <sys/log.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>

int
openssl_aes_ecb_decrypt(u8 *output, const u8 *secret, const u8 *block)
{
	AES_KEY aes;
	if (AES_set_decrypt_key(secret, 16 * 8, &aes) < 0)
		return -1;
	AES_ecb_encrypt(block, output, &aes, AES_DECRYPT);
	AES_ecb_encrypt(block + 16, output + 16, &aes, AES_DECRYPT);
	return 0;
}

/*
 * AES Galois Counter Mode (GCM) Cipher Suites for TLS
 * https://tools.ietf.org/rfc/rfc5288.txt
 *
 * An Interface and Algorithms for Authenticated Encryption
 * https://tools.ietf.org/html/rfc5116
 *
 */

int
openssl_aes_gcm_decrypt(const u8 *secret, u16 secret_len, const u8 *key, u8 key_len, 
                const u8 *iv, u8 iv_len, u8 *out)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = key_len == 16 ? EVP_aes_128_gcm():
	                           key_len == 32 ? EVP_aes_256_gcm(): 0;
	int ret, len = 0, output_len = 0;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		return -1;
	if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
		goto error;
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		goto error;
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		goto error;
	if(!EVP_DecryptUpdate(ctx, out, &len, secret, secret_len))
		goto error;
	output_len = len - 16; //(key_len == 16 ? 16: 16);
	EVP_DecryptFinal_ex(ctx, out, &len);
	EVP_CIPHER_CTX_free(ctx);

	return output_len;
error:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return 0;
}
	
int
openssl_aes_ccm_decrypt(const u8 *secret, u16 secret_len, const u8 *key, u8 key_len, 
                const u8 *iv,u8 iv_len, u8 *out)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = key_len == 16 ? EVP_aes_128_ccm():
	                           key_len == 32 ? EVP_aes_256_ccm(): 0;
	int ret, len = 0, output_len = 0;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		return -1;
	if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
		goto error;
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL))
		goto error;
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		goto error;
	if(!EVP_DecryptUpdate(ctx, out, &len, secret, secret_len))
		goto error;
	output_len = len;
	ret = EVP_DecryptFinal_ex(ctx, out + len, &len);
	EVP_CIPHER_CTX_free(ctx);

	return output_len;
error:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return 0;
}
	
int
openssl_aes_cbc_decrypt(const u8 *secret, u16 secret_len, const u8 *key, u8 key_len, 
                const u8 *iv, u8 iv_len, u8 *out)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = key_len == 16 ? EVP_aes_128_cbc():
	                           key_len == 32 ? EVP_aes_256_cbc(): 0;
	int ret, len = 0, output_len = 0;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		return -1;
	if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
		goto error;
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		goto error;
	if(!EVP_DecryptUpdate(ctx, out, &len, secret, secret_len))
		goto error;
	output_len = len;
	EVP_CIPHER_CTX_free(ctx);

	return output_len;
error:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return 0;
}
