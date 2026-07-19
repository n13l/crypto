/*
 * Group identification (metadata) backend.
 *
 * Registers every negotiable group that does not (yet) have a dedicated
 * compute module, so the passive dissector can name each group and size its
 * key_share from the supported_groups / key_share extensions. keygen/derive
 * are left NULL: this module carries no curve/KEM arithmetic and no OpenSSL
 * dependency.
 *
 * To add real key-exchange for one of these groups, create a per-group module
 * following modules/group/x25519 (generic C) + x25519-aws-* (s2n-bignum
 * assembly) and drop its id from the table below — the registry lets the
 * dedicated entry replace this one.
 *
 * x25519, secp256r1 and secp384r1 are intentionally absent: they are owned by
 * their dedicated compute backends.
 */

#define __CRYPTO_GROUP_MODULE__
#include <crypto/ecc.h>

#define G(gid, cat, pr, pb, s, v12, v13, nm, ds) \
	{ .id = (gid), .category = (cat), \
	  .private_key_size = (pr), .public_key_size = (pb), \
	  .shared_secret_size = (s), .tls12 = (v12), .tls13 = (v13), \
	  .name = (nm), .desc = (ds) }

static struct group_algorithm meta_groups[] = {
	/* Elliptic-curve ECDHE (RFC 8422 / RFC 8446) */
	G(GROUP_SECP521R1, GROUP_CAT_ECDHE, 66, 133,  66, 1, 1,
	  "secp521r1", "NIST P-521 ECDHE (identification)"),
	G(GROUP_X448,      GROUP_CAT_ECDHE, 56,  56,  56, 1, 1,
	  "x448", "Curve448 ECDHE (identification)"),

	/* Finite-field DHE (RFC 7919) */
	G(GROUP_FFDHE2048, GROUP_CAT_FFDHE, 256, 256, 256, 1, 1,
	  "ffdhe2048", "Finite-field DHE 2048-bit (identification)"),
	G(GROUP_FFDHE3072, GROUP_CAT_FFDHE, 384, 384, 384, 1, 1,
	  "ffdhe3072", "Finite-field DHE 3072-bit (identification)"),
	G(GROUP_FFDHE4096, GROUP_CAT_FFDHE, 512, 512, 512, 1, 1,
	  "ffdhe4096", "Finite-field DHE 4096-bit (identification)"),

	/* Post-quantum hybrids (RFC 9370 / drafts), TLS 1.3 only */
	G(GROUP_X25519MLKEM768,       GROUP_CAT_HYBRID, 0, 1216, 64, 0, 1,
	  "x25519mlkem768", "X25519 + ML-KEM-768 hybrid (identification)"),
	G(GROUP_SECP256R1MLKEM768,    GROUP_CAT_HYBRID, 0, 1249, 64, 0, 1,
	  "secp256r1mlkem768", "NIST P-256 + ML-KEM-768 hybrid (identification)"),
	G(GROUP_SECP384R1MLKEM1024,   GROUP_CAT_HYBRID, 0, 1665, 80, 0, 1,
	  "secp384r1mlkem1024", "NIST P-384 + ML-KEM-1024 hybrid (identification)"),
	G(GROUP_X25519KYBER768D00,    GROUP_CAT_HYBRID, 0, 1216, 64, 0, 1,
	  "x25519kyber768draft00", "X25519 + Kyber-768 (draft00) hybrid (identification)"),
	G(GROUP_SECP256R1KYBER768D00, GROUP_CAT_HYBRID, 0, 1249, 64, 0, 1,
	  "secp256r1kyber768draft00", "NIST P-256 + Kyber-768 (draft00) hybrid (identification)"),
};

static void __init__ group_meta_init(void)
{
	unsigned int i;

	for (i = 0; i < array_size(meta_groups); i++)
		crypto_group_register(&meta_groups[i]);
}
