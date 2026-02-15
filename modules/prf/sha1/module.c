#define __CRYPTO_PRF_MODULE__
#include <crypto/prf.h>
#include <modules/digest/module.h>

#define sha1 module_digest
#define arch_sha1_160_init(_ctx) \
	module_digest_init((_ctx), ALGORITHM_SHA1_160)
#define arch_sha1_160_update module_digest_update
#define arch_sha1_160_final module_digest_final
#define PRF_SHA1_SCOPE static
#include "sha1.c"
#undef arch_sha1_160_final
#undef arch_sha1_160_update
#undef arch_sha1_160_init
#undef sha1

static struct prf_algorithm prf_sha1_algorithm = {
	.msg_size = SHA1_DIGEST_SIZE,
	.ctx_size = SHA1_DIGEST_SIZE,
	.name = "prf-sha1",
	.desc = "PRF-SHA1-160",
	.id = PRF_SHA1,
	.derive = prf_sha1,
};

static void __init__ prf_sha1_init(void)
{
	crypto_prf_register(&prf_sha1_algorithm);
}
