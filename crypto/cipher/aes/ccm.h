/*
 * AES-CCM (Counter with CBC-MAC), NIST SP 800-38C and RFC 3610, in the shape
 * TLS asks for it: a 12-byte nonce, associated data, and a tag of 16 or 8
 * bytes appended to the ciphertext (RFC 6655 for TLS 1.2, RFC 8446 §8.3 for
 * the TLS 1.3 code points).
 *
 * The contract matches <crypto/cipher/aes/gcm.h> so the record layer can hold
 * both modes the same way, with one difference the mode forces: the tag length
 * is a parameter rather than a constant, because CCM_8 is the same
 * construction with the tag truncated to 8 and it is a separate ciphersuite
 * rather than a separate mode.
 *
 * A note on what a failed decrypt leaves behind. CCM authenticates the
 * *plaintext*, not the ciphertext, so unlike GCM the tag cannot be checked
 * before decrypting - the counter pass has to run first for there to be
 * anything to MAC. On CCM_AUTH_FAILURE |output| therefore holds bytes that
 * were never authenticated, and the caller has to discard them rather than
 * read them. This is inherent to CCM and is why RFC 3610 §2.2 says the
 * plaintext must not be revealed until the tag has been verified.
 */
#ifndef AES_CCM_HEADER
#define AES_CCM_HEADER

#include <hpc/compiler.h>
#include <stdint.h>
#include <stddef.h>

#define CCM_AUTH_FAILURE    0x55555556  /* authentication failure */

#define AES_CCM_NONCE_LEN   12  /* what TLS uses; fixes L to 3 */
#define AES_CCM_TAG_LEN     16
#define AES_CCM_8_TAG_LEN   8

/*
 * Encrypt |input_length| bytes and append |tag_len| bytes of tag, so |output|
 * needs |input_length| + |tag_len| bytes. |aad| may be NULL when |aad_len| is
 * 0. Returns 0, or CCM_AUTH_FAILURE for a parameter this implementation does
 * not accept (a nonce that is not 12 bytes, a tag length that is not 16 or 8,
 * a key that is not 128 or 256 bits).
 */
int
aes_ccm_encrypt_aad(u8 *output, const u8 *input, int input_length,
		    const u8 *aad, size_t aad_len,
		    const u8 *key, size_t key_len,
		    const u8 *iv, size_t iv_len, size_t tag_len);

/*
 * The reverse: |input_length| counts the trailing tag, and |output| receives
 * |input_length| - |tag_len| bytes. Returns 0 when the tag verifies, and
 * CCM_AUTH_FAILURE when it does not or the parameters are refused - see the
 * note above about what |output| holds in that case.
 */
int
aes_ccm_decrypt_aad(u8 *output, const u8 *input, int input_length,
		    const u8 *aad, size_t aad_len,
		    const u8 *key, size_t key_len,
		    const u8 *iv, size_t iv_len, size_t tag_len);

#endif /* AES_CCM_HEADER */
