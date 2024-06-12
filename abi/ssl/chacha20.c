#include <sys/compiler.h>
#include <sys/log.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "chacha20.h"

/*
 * https://cr.yp.to/chacha.html
 *
 * D. J. Bernstein 
 * Hash functions and ciphers
 * The ChaCha family of stream ciphers
 */

//#if OPENSSL_VERSION_NUMBER >= 0x10101010L
#if 1
int
openssl_chacha20_poly1305_decrypt(const u8 *secret, u16 secret_len,
                          const u8 *key, u8 key_len,
                          const u8 *iv, u8 iv_len, u8 *output)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = EVP_chacha20_poly1305();
	int ret, len = 0, output_len = 0;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		return -1;
	if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
		goto error;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL))
		goto error;
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		goto error;
	if(!EVP_DecryptUpdate(ctx, output, &len, secret, secret_len))
		goto error;
	output_len = len - 16;
	EVP_CIPHER_CTX_free(ctx);

	return output_len < 0 ? 0: output_len;
error:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return 0;
}

#else
int
openssl_chacha20_poly1305_decrypt(const u8 *secret, u16 secret_len,
                          const u8 *key, u8 key_len,
                          const u8 *iv, u8 iv_len, u8 *output)
{
	error("chacha20 not supported");
	return -1;
}

#endif
struct chacha20_vector {
	const u8 *key;
	u32 key_size;
	const u8 *input;
	u32 input_size;
	const u8 *nonce;
	u32 nonce_size;
	const u8 *ad;
	u32 ad_size;
	u8 *output;
	u32 output_size;
	const u8 *tag;
	u32 tag_size;
};
	
void
chacha20_test_vector(void)
{
}


/*
 * # test vector courtesy https://tools.ietf.org/html/rfc7539
 * vector = {
 * key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
 * input: "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
 * nonce: "070000004041424344454647",
 * ad: "50515253c0c1c2c3c4c5c6c7",
 * output: "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
 * tag: "1ae10b594f09e26a7e902ecbd0600691"
 * }
 */
