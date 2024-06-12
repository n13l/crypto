#include <sys/compiler.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "p256.h"

void
p256_init(struct p256 *p256)
{
	p256->bnc = BN_CTX_new();
	p256->grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

	p256->ev_peer = EVP_PKEY_new();
	p256->ev_private = EVP_PKEY_new();
	p256->ec_peer = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	p256->ec_private = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	EVP_PKEY_set1_EC_KEY(p256->ev_peer, p256->ec_peer);
	EVP_PKEY_set1_EC_KEY(p256->ev_private, p256->ec_private);

	p256->ev_ctx = EVP_PKEY_CTX_new(p256->ev_private, NULL);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p256->ev_ctx, NID_X9_62_prime256v1);
}

void
p256_reset(struct p256 *p256)
{
	BN_CTX_start(p256->bnc);
}

void
p256_fini(struct p256 *p256)
{
	EVP_PKEY_free(p256->ev_peer);
	EVP_PKEY_free(p256->ev_private);

	EC_KEY_free(p256->ec_peer);
	EC_KEY_free(p256->ec_private);

	EC_GROUP_free(p256->grp);
	BN_CTX_free(p256->bnc);

	EVP_PKEY_CTX_free(p256->ev_ctx);
}

void
p256_key_public(struct p256 *c, const u8 secret[P256_SECRET_KEY_SIZE],
                u8 public_key[P256_PUBLIC_KEY_SIZE])
{
	BN_bin2bn(secret, P256_SECRET_KEY_SIZE, c->bn_secret);
	/* compute pub key from priv key and group */
	EC_POINT_mul(c->grp, c->ep_public, c->bn_secret, NULL, NULL, NULL);
	/* convert pub_key from elliptic curve coordinate to array of bytes */
	EC_POINT_point2oct(c->grp, c->ep_public, POINT_CONVERSION_UNCOMPRESSED, 
	                   public_key, P256_PUBLIC_KEY_SIZE, NULL);
}

static inline void
derive_private_key(struct p256 *p256, EC_KEY *key, const u8 *secret, int bytes)
{
	BIGNUM *s = BN_CTX_get(p256->bnc);
	BN_bin2bn(secret, bytes, s);

	EC_POINT *p = EC_POINT_new(p256->grp);
	EC_POINT_mul(p256->grp, p, s, NULL, NULL, NULL);
	EC_POINT_point2oct(p256->grp, p, POINT_CONVERSION_UNCOMPRESSED, 
	                   (u8 *)secret, bytes, NULL);

	/* validate coordinates */
	BIGNUM *x = BN_CTX_get(p256->bnc);
	BIGNUM *y = BN_CTX_get(p256->bnc);
	EC_POINT_get_affine_coordinates(p256->grp, p, x, y, p256->bnc);

	EC_KEY_set_public_key(key, p);
	EC_KEY_set_private_key(key, s);
	EC_POINT_free(p);
}

void
p256_key_exchange(struct p256 *p256, const u8 peer[P256_PUBLIC_KEY_SIZE], 
                  const u8 *secret, int bytes, u8 shared[P256_SHARED_KEY_SIZE])
{
	BIGNUM *bn_peer = BN_CTX_get(p256->bnc);
	BN_bin2bn(peer, P256_PUBLIC_KEY_SIZE, bn_peer);

	EC_POINT *p = EC_POINT_new(p256->grp);
	EC_POINT_bn2point(p256->grp, bn_peer, p, p256->bnc);
	EC_KEY_set_public_key(p256->ec_peer, p);
	EC_KEY_set_private_key(p256->ec_peer, bn_peer);

	/* derive private key */
	derive_private_key(p256, p256->ec_private, secret, bytes);

	size_t len = P256_SHARED_KEY_SIZE;
	EVP_PKEY_derive_init(p256->ev_ctx);
	EVP_PKEY_derive_set_peer(p256->ev_ctx, p256->ev_peer);
	EVP_PKEY_derive(p256->ev_ctx, shared, &len);

	EC_POINT_free(p);
}
