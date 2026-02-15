#ifndef __CRYPTO_CIPHER_RC4_H__
#define __CRYPTO_CIPHER_RC4_H__

#include <hpc/compiler.h>

/*
 * RC4, for the *_WITH_RC4_128_{SHA,MD5} suites of TLS 1.0/1.1 (and of TLS 1.2,
 * where RFC 7465 prohibited them). Prohibited is not the same as unused: a
 * capture of that era carries them, so the decoder opens them and counts the
 * channel as insecure (net.tls.sec_insecure_ciphersuite) rather than declining
 * to read it.
 *
 * The state is the whole cipher: a keystream position that is never reset,
 * which is why a channel using RC4 keeps one of these per direction for its
 * whole life rather than per record. A gap in a capture is therefore
 * unrecoverable for RC4 in a way it is not for a CBC or AEAD suite, whose
 * every record re-keys or re-IVs.
 */

#define RC4_KEYLEN_MAX 256

struct rc4_ctx {
	u8 s[256];
	u8 i, j;
};

void
rc4_init(struct rc4_ctx *ctx, const u8 *key, unsigned int key_len);

/* RC4 is its own inverse: one call, in place, and the state advances. */
void
rc4_crypt(struct rc4_ctx *ctx, u8 *buf, unsigned int len);

#endif
