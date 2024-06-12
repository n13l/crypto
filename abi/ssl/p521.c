#include <sys/compiler.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "p521.h"

void
p521_init(struct p521 *p521)
{
	p521->bnc = BN_CTX_new();
	p521->grp = EC_GROUP_new_by_curve_name(NID_secp521r1);

	p521->ev_peer = EVP_PKEY_new();
	p521->ev_private = EVP_PKEY_new();
	p521->ec_peer = EC_KEY_new_by_curve_name(NID_secp521r1);
	p521->ec_private = EC_KEY_new_by_curve_name(NID_secp521r1);

	EVP_PKEY_set1_EC_KEY(p521->ev_peer, p521->ec_peer);
	EVP_PKEY_set1_EC_KEY(p521->ev_private, p521->ec_private);

	p521->ev_ctx = EVP_PKEY_CTX_new(p521->ev_private, NULL);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p521->ev_ctx, NID_secp521r1);
}

void
p521_reset(struct p521 *p521)
{
	BN_CTX_start(p521->bnc);
}

void
p521_fini(struct p521 *p521)
{
	EVP_PKEY_free(p521->ev_peer);
	EVP_PKEY_free(p521->ev_private);

	EC_KEY_free(p521->ec_peer);
	EC_KEY_free(p521->ec_private);

	EC_GROUP_free(p521->grp);
	BN_CTX_free(p521->bnc);

	EVP_PKEY_CTX_free(p521->ev_ctx);
}

void
p521_key_public(struct p521 *c, const u8 secret[p521_SECRET_KEY_SIZE],
                u8 public_key[p521_PUBLIC_KEY_SIZE])
{
	BN_bin2bn(secret, p521_SECRET_KEY_SIZE, c->bn_secret);
	/* compute pub key from priv key and group */
	EC_POINT_mul(c->grp, c->ep_public, c->bn_secret, NULL, NULL, NULL);
	/* convert pub_key from elliptic curve coordinate to array of bytes */
	EC_POINT_point2oct(c->grp, c->ep_public, POINT_CONVERSION_UNCOMPRESSED, 
	                   public_key, p521_PUBLIC_KEY_SIZE, NULL);
}

static inline void
derive_private_key(struct p521 *p521, EC_KEY *key, const u8 *secret, int bytes)
{
	BIGNUM *s = BN_CTX_get(p521->bnc);
	BN_bin2bn(secret, bytes, s);

	EC_POINT *p = EC_POINT_new(p521->grp);
	EC_POINT_mul(p521->grp, p, s, NULL, NULL, NULL);
	EC_POINT_point2oct(p521->grp, p, POINT_CONVERSION_UNCOMPRESSED, 
	                   (u8 *)secret, bytes, NULL);

	/* validate coordinates */
	BIGNUM *x = BN_CTX_get(p521->bnc);
	BIGNUM *y = BN_CTX_get(p521->bnc);
	EC_POINT_get_affine_coordinates(p521->grp, p, x, y, p521->bnc);

	EC_KEY_set_public_key(key, p);
	EC_KEY_set_private_key(key, s);
	EC_POINT_free(p);
}

void
p521_key_exchange(struct p521 *p521, const u8 peer[p521_PUBLIC_KEY_SIZE], 
                  const u8 *secret, int bytes, u8 shared[p521_SHARED_KEY_SIZE])
{
	BIGNUM *bn_peer = BN_CTX_get(p521->bnc);
	BN_bin2bn(peer, p521_PUBLIC_KEY_SIZE, bn_peer);

	EC_POINT *p = EC_POINT_new(p521->grp);
	EC_POINT_bn2point(p521->grp, bn_peer, p, p521->bnc);
	EC_KEY_set_public_key(p521->ec_peer, p);
	EC_KEY_set_private_key(p521->ec_peer, bn_peer);

	/* derive private key */
	derive_private_key(p521, p521->ec_private, secret, bytes);

	size_t len = p521_SHARED_KEY_SIZE;
	EVP_PKEY_derive_init(p521->ev_ctx);
	EVP_PKEY_derive_set_peer(p521->ev_ctx, p521->ev_peer);
	EVP_PKEY_derive(p521->ev_ctx, shared, &len);

	EC_POINT_free(p);
}
