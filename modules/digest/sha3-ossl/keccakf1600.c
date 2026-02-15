#include <hpc/compiler.h>
#include <inttypes.h>

#include "internal/nelem.h"
#include "openssl/e_os2.h"
#define NDEBUG
#define KeccakF1600 ossl_KeccakF1600_internal
#define SHA3_absorb ossl_SHA3_absorb_unused
#define SHA3_squeeze ossl_SHA3_squeeze_unused
#include "../../../../vendor/openssl/crypto/sha/keccak1600.c"
#undef KeccakF1600
#undef SHA3_absorb
#undef SHA3_squeeze

static void _unused
keccakf1600(uint64_t st[25])
{
	ossl_KeccakF1600_internal((uint64_t (*)[5])st);
}
