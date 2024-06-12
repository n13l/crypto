/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Grigori Goronzy <goronzy@kinoho.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/compiler.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define CHACHAPOLY_OK           0
#define CHACHAPOLY_INVALID_MAC  -1

struct chachapoly_ctx {
    struct chacha_ctx cha_ctx;
};

/**
 * Initialize ChaCha20-Poly1305 AEAD.
 * For RFC 7539 conformant AEAD, 256 bit keys must be used.
 *
 * \param ctx context data
 * \param key 16 or 32 bytes of key material
 * \param key_len key length, 256 or 512 bits
 * \return success if 0
 */
int chachapoly_init(struct chachapoly_ctx *ctx, const void *key, int key_len);

/**
 * Encrypt or decrypt with ChaCha20-Poly1305. The AEAD construction conforms
 * to RFC 7539.
 *
 * \param ctx context data
 * \param nonce nonce (12 bytes)
 * \param ad associated data
 * \param ad_len associated data length in bytes
 * \param input plaintext/ciphertext input
 * \param input_len input length in bytes;
 * \param output plaintext/ciphertext output
 * \param tag tag output
 * \param tag_len tag length in bytes (0-16);
          if 0, authentification is skipped
 * \param encrypt decrypt if 0, else encrypt
 * \return CHACHAPOLY_OK if no error, CHACHAPOLY_INVALID_MAC if auth
 *         failed when decrypting
 */
int chachapoly_crypt(struct chachapoly_ctx *ctx, const void *nonce,
        const void *ad, int ad_len, void *input, int input_len,
        void *output, void *tag, int tag_len, int encrypt);

/**
 * Encrypt or decrypt with Chacha20-Poly1305 for short messages.
 * The AEAD construction is different from chachapoly_crypt, but more
 * efficient for small messages. Up to 32 bytes can be encrypted. The size
 * of associated data is not restricted. The interface is similar to
 * chachapoly_crypt.
 */
int chachapoly_crypt_short(struct chachapoly_ctx *ctx, const void *nonce,
        const void *ad, int ad_len, void *input, int input_len,
        void *output, void *tag, int tag_len, int encrypt);


/**
 * Constant-time memory compare. This should help to protect against
 * side-channel attacks.
 *
 * \param av input 1
 * \param bv input 2
 * \param n bytes to compare
 * \return 0 if inputs are equal
 */
static int memcmp_eq(const void *av, const void *bv, int n)
{
    const u8 *a = (const u8*) av;
    const u8 *b = (const u8*) bv;
    u8 res = 0;
    int i;

    for (i = 0; i < n; i++) {
        res |= *a ^ *b;
        a++;
        b++;
    }

    return res;
}

/**
 * Poly1305 tag generation. This concatenates a string according to the rules
 * outlined in RFC 7539 and calculates the tag.
 *
 * \param poly_key 32 byte secret one-time key for poly1305
 * \param ad associated data
 * \param ad_len associated data length in bytes
 * \param ct ciphertext
 * \param ct_len ciphertext length in bytes
 * \param tag pointer to 16 bytes for tag storage
 */
static void poly1305_get_tag(u8 *poly_key, const void *ad,
        int ad_len, const void *ct, int ct_len, u8 *tag)
{
    struct poly1305_context poly;
    unsigned left_over;
    u64 len;
    u8 pad[16];

    poly1305_init(&poly, poly_key);
    memset(&pad, 0, sizeof(pad)); 

    /* associated data and padding */
    poly1305_update(&poly, ad, ad_len);
    left_over = ad_len % 16;
    if (left_over)
        poly1305_update(&poly, pad, 16 - left_over);

    /* payload and padding */
    poly1305_update(&poly, ct, ct_len);
    left_over = ct_len % 16;
    if (left_over)
        poly1305_update(&poly, pad, 16 - left_over);
    
    /* lengths */
    len = ad_len;
    poly1305_update(&poly, (u8 *)&len, 8);
    len = ct_len;
    poly1305_update(&poly, (u8 *)&len, 8);

    poly1305_finish(&poly, tag);
}

int chachapoly_init(struct chachapoly_ctx *ctx, const void *key, int key_len)
{
    assert (key_len == 128 || key_len == 256);

    memset(ctx, 0, sizeof(*ctx));
    chacha_keysetup(&ctx->cha_ctx, key, key_len);
    return CHACHAPOLY_OK;
}

int chachapoly_crypt(struct chachapoly_ctx *ctx, const void *nonce,
        const void *ad, int ad_len, void *input, int input_len,
        void *output, void *tag, int tag_len, int encrypt)
{
    u8 poly_key[CHACHA_BLOCKLEN];
    u8 calc_tag[POLY1305_TAGLEN];
    const u8 one[4] = { 1, 0, 0, 0 };

    /* initialize keystream and generate poly1305 key */
    memset(poly_key, 0, sizeof(poly_key));
    chacha_ivsetup(&ctx->cha_ctx, nonce, NULL);
    chacha_encrypt_bytes(&ctx->cha_ctx, poly_key, poly_key, sizeof(poly_key));

    /* check tag if decrypting */
    if (encrypt == 0 && tag_len) {
        poly1305_get_tag(poly_key, ad, ad_len, input, input_len, calc_tag);
        if (memcmp_eq(calc_tag, tag, tag_len) != 0) {
            return CHACHAPOLY_INVALID_MAC;
        }
    }

    /* crypt data */
    chacha_ivsetup(&ctx->cha_ctx, nonce, one);
    chacha_encrypt_bytes(&ctx->cha_ctx, (u8 *)input,
                         (u8 *)output, input_len);

    /* add tag if encrypting */
    if (encrypt && tag_len) {
        poly1305_get_tag(poly_key, ad, ad_len, output, input_len, calc_tag);
        memcpy(tag, calc_tag, tag_len);
    }

    return CHACHAPOLY_OK;
}

int chachapoly_crypt_short(struct chachapoly_ctx *ctx, const void *nonce,
        const void *ad, int ad_len, void *input, int input_len,
        void *output, void *tag, int tag_len, int encrypt)
{
    u8 keystream[CHACHA_BLOCKLEN];
    u8 calc_tag[POLY1305_TAGLEN];
    int i;

    assert(input_len <= 32);

    /* initialize keystream and generate poly1305 key */
    memset(keystream, 0, sizeof(keystream));
    chacha_ivsetup(&ctx->cha_ctx, nonce, NULL);
    chacha_encrypt_bytes(&ctx->cha_ctx, keystream, keystream,
            sizeof(keystream));

    /* check tag if decrypting */
    if (encrypt == 0 && tag_len) {
        poly1305_get_tag(keystream, ad, ad_len, input, input_len, calc_tag);
        if (memcmp_eq(calc_tag, tag, tag_len) != 0) {
            return CHACHAPOLY_INVALID_MAC;
        }
    }

    /* crypt data */
    for (i = 0; i < input_len; i++) {
        ((u8 *)output)[i] =
            ((u8 *)input)[i] ^ keystream[32 + i];
    }

    /* add tag if encrypting */
    if (encrypt && tag_len) {
        poly1305_get_tag(keystream, ad, ad_len, output, input_len, calc_tag);
        memcpy(tag, calc_tag, tag_len);
    }

    return CHACHAPOLY_OK;
}

#ifdef TEST_VECTORS

/* AEAD test vector from RFC 7539 */
int chachapoly_test_rfc7539(void)
{
    u8 tag[16];
    u8 ct[114];
    int i, ret;
    struct chachapoly_ctx ctx;

    u8 key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    u8 ad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };
    u8 pt[114];
    memcpy(pt, "Ladies and Gentlemen of the class of '99: If I could offer you "
               "only one tip for the future, sunscreen would be it.", 114);
    u8 nonce[12] = {
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };
    u8 tag_verify[16] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    u8 ct_verify[114] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };

    chachapoly_init(&ctx, key, 256);
    chachapoly_crypt(&ctx, nonce, ad, 12, pt, 114, ct, tag, 16, 1);

    for (i = 0; i < 114; i++) {
        if (ct[i] != ct_verify[i]) {
            return -2;
        }
    }

    for (i = 0; i < 16; i++) {
        if (tag[i] != tag_verify[i]) {
            return -3;
        }
    }

    ret = chachapoly_crypt(&ctx, nonce, ad, 12, ct, 114, pt, tag, 16, 0);

    return ret;
}

/* AEAD auth-only case */
int chachapoly_test_auth_only(void)
{
    u8 tag[16];
    int i, ret;
    struct chachapoly_ctx ctx;

    u8 key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    u8 pt[114];
    memcpy(pt, "Ladies and Gentlemen of the class of '99: If I could offer you "
               "only one tip for the future, sunscreen would be it.", 114);
    u8 nonce[12] = {
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };
    u8 tag_verify[16] = {
        0x03, 0xDC, 0xD0, 0x84, 0x04, 0x67, 0x80, 0xE6, 0x39, 0x50, 0x67, 0x0D, 0x3B, 0xBC, 0xC8, 0x95
    };

    chachapoly_init(&ctx, key, 256);
    chachapoly_crypt(&ctx, nonce, pt, 114, NULL, 0, NULL, tag, 16, 1);

    for (i = 0; i < 16; i++) {
        if (tag[i] != tag_verify[i]) {
            return -3;
        }
    }

    ret = chachapoly_crypt(&ctx, nonce, pt, 114, NULL, 0, NULL, tag, 16, 0);

    return ret;
}

int main(int argc, char **argv)
{
    int res = chachapoly_test_rfc7539();
    printf("%s = %d\n", "rfc7539", res);
    res = chachapoly_test_auth_only();
    printf("%s = %d\n", "auth_only", res);
}

#endif
