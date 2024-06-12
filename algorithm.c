#include <sys/compiler.h>
#include <crypto/digest.h>
#include <crypto/cipher.h>
#include <crypto/hmac.h>
#include <crypto/prf.h>
#include <crypto/ecc.h>

/* FIXME: weak eval. */
void crypto_init_digest_algorithms(void);
void crypto_init_hmac_algorithms(void);
void crypto_init_prf_algorithms(void);
void crypto_cipher_init(void);
void crypto_init_ecc_groups(void);

void
crypto_init_algorithms(void)
{
	crypto_init_digest_algorithms();
	//crypto_init_hmac_algorithms();
	crypto_init_prf_algorithms();
	crypto_init_ecc_groups();
	crypto_cipher_init();
}
