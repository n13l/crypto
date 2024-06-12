#include <sys/compiler.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "p384.h"

void
p384_init(struct p384 *p384)
{
	p384->bnc = BN_CTX_new();
	p384->grp = EC_GROUP_new_by_curve_name(NID_secp384r1);

	p384->ev_peer = EVP_PKEY_new();
	p384->ev_private = EVP_PKEY_new();
	p384->ec_peer = EC_KEY_new_by_curve_name(NID_secp384r1);
	p384->ec_private = EC_KEY_new_by_curve_name(NID_secp384r1);

	EVP_PKEY_set1_EC_KEY(p384->ev_peer, p384->ec_peer);
	EVP_PKEY_set1_EC_KEY(p384->ev_private, p384->ec_private);

	p384->ev_ctx = EVP_PKEY_CTX_new(p384->ev_private, NULL);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p384->ev_ctx, NID_secp384r1);
}

void
p384_reset(struct p384 *p384)
{
	BN_CTX_start(p384->bnc);
}

void
p384_fini(struct p384 *p384)
{
	EVP_PKEY_free(p384->ev_peer);
	EVP_PKEY_free(p384->ev_private);

	EC_KEY_free(p384->ec_peer);
	EC_KEY_free(p384->ec_private);

	EC_GROUP_free(p384->grp);
	BN_CTX_free(p384->bnc);

	EVP_PKEY_CTX_free(p384->ev_ctx);
}

void
p384_key_public(struct p384 *c, const u8 secret[P384_SECRET_KEY_SIZE],
                u8 public_key[P384_PUBLIC_KEY_SIZE])
{
	BN_bin2bn(secret, P384_SECRET_KEY_SIZE, c->bn_secret);
	/* compute pub key from priv key and group */
	EC_POINT_mul(c->grp, c->ep_public, c->bn_secret, NULL, NULL, NULL);
	/* convert pub_key from elliptic curve coordinate to array of bytes */
	EC_POINT_point2oct(c->grp, c->ep_public, POINT_CONVERSION_UNCOMPRESSED, 
	                   public_key, P384_PUBLIC_KEY_SIZE, NULL);
}

static inline void
derive_private_key(struct p384 *p384, EC_KEY *key, const u8 *secret, int bytes)
{
	BIGNUM *s = BN_CTX_get(p384->bnc);
	BN_bin2bn(secret, bytes, s);

	EC_POINT *p = EC_POINT_new(p384->grp);
	EC_POINT_mul(p384->grp, p, s, NULL, NULL, NULL);
	EC_POINT_point2oct(p384->grp, p, POINT_CONVERSION_UNCOMPRESSED, 
	                   (u8 *)secret, bytes, NULL);

	/* validate coordinates */
	BIGNUM *x = BN_CTX_get(p384->bnc);
	BIGNUM *y = BN_CTX_get(p384->bnc);
	EC_POINT_get_affine_coordinates(p384->grp, p, x, y, p384->bnc);

	EC_KEY_set_public_key(key, p);
	EC_KEY_set_private_key(key, s);
	EC_POINT_free(p);
}

void
p384_key_exchange(struct p384 *p384, const u8 peer[P384_PUBLIC_KEY_SIZE], 
                  const u8 *secret, int bytes, u8 shared[P384_SHARED_KEY_SIZE])
{
	BIGNUM *bn_peer = BN_CTX_get(p384->bnc);
	BN_bin2bn(peer, P384_PUBLIC_KEY_SIZE, bn_peer);

	EC_POINT *p = EC_POINT_new(p384->grp);
	EC_POINT_bn2point(p384->grp, bn_peer, p, p384->bnc);
	EC_KEY_set_public_key(p384->ec_peer, p);
	EC_KEY_set_private_key(p384->ec_peer, bn_peer);

	/* derive private key */
	derive_private_key(p384, p384->ec_private, secret, bytes);

	size_t len = P384_SHARED_KEY_SIZE;
	EVP_PKEY_derive_init(p384->ev_ctx);
	EVP_PKEY_derive_set_peer(p384->ev_ctx, p384->ev_peer);
	EVP_PKEY_derive(p384->ev_ctx, shared, &len);

	EC_POINT_free(p);
}
