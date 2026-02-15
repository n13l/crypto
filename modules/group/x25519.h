/*
 * Shared X25519 (RFC 7748) registration glue. Each X25519 backend defines its
 * keygen/derive functions plus the descriptive macros below, then includes
 * this header to materialise the group_algorithm entry and its __init__
 * registrar. Only one backend is ever compiled (Kconfig choice), so the
 * static definitions never collide.
 *
 * Before including, a backend must define:
 *   X25519_KEYGEN   fn_group_keygen for group x25519
 *   X25519_DERIVE   fn_group_derive for group x25519
 *   X25519_DESC     human-readable implementation description
 *   X25519_INIT_FN  name of the generated constructor
 */

#ifndef __CRYPTO_GROUP_X25519_H__
#define __CRYPTO_GROUP_X25519_H__

#include <crypto/ecc.h>

#if !defined(X25519_KEYGEN) || !defined(X25519_DERIVE) || \
    !defined(X25519_DESC) || !defined(X25519_INIT_FN)
#error "X25519 backend must define X25519_KEYGEN/DERIVE/DESC/INIT_FN"
#endif

#ifndef X25519_KEY_LEN
#define X25519_KEY_LEN 32
#endif

static struct group_algorithm x25519_algorithm = {
	.id                = GROUP_X25519,
	.category          = GROUP_CAT_ECDHE,
	.private_key_size  = X25519_KEY_LEN,
	.public_key_size   = X25519_KEY_LEN,
	.shared_secret_size = X25519_KEY_LEN,
	.tls12             = 1,
	.tls13             = 1,
	.name              = "x25519",
	.desc              = X25519_DESC,
	.keygen            = X25519_KEYGEN,
	.derive            = X25519_DERIVE,
};

static void __init__ X25519_INIT_FN(void)
{
	crypto_group_register(&x25519_algorithm);
}

#endif
