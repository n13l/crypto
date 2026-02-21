#include <hpc/compiler.h>
#include <inttypes.h>

extern size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp,
                          size_t len, size_t r);
extern void SHA3_squeeze(uint64_t A[5][5], unsigned char *out,
                         size_t len, size_t r, int next);

static void _unused
keccakf1600(uint64_t st[25])
{
	(void)st;
}
