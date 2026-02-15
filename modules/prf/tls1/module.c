#define __CRYPTO_PRF_MODULE__
#include <crypto/prf.h>
#include <modules/digest/module.h>

/*
 * Two digests through the one module_digest seam: the PRF keys an MD5 and a
 * SHA-1 expansion from the same secret, so both names are redirected before
 * the bodies are read and both are undone after.
 */
#define md5 module_digest
#define arch_md5_init(_ctx) module_digest_init((_ctx), ALGORITHM_MD5)
#define arch_md5_update module_digest_update
#define arch_md5_final module_digest_final
#define sha1 module_digest
#define arch_sha1_160_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA1_160)
#define arch_sha1_160_update module_digest_update
#define arch_sha1_160_final module_digest_final
#define PRF_TLS1_SCOPE static
#include "tls1.c"
#undef arch_sha1_160_final
#undef arch_sha1_160_update
#undef arch_sha1_160_init
#undef sha1
#undef arch_md5_final
#undef arch_md5_update
#undef arch_md5_init
#undef md5

static struct prf_algorithm prf_tls1_algorithm = {
	.msg_size = SHA1_DIGEST_SIZE,
	.ctx_size = SHA1_DIGEST_SIZE,
	.name = "prf-tls1",
	.desc = "PRF-TLS-1.0/1.1 (P_MD5 XOR P_SHA1)",
	.id = PRF_TLS1,
	.derive = prf_tls1,
};

static void __init__ prf_tls1_init(void)
{
	crypto_prf_register(&prf_tls1_algorithm);
}
