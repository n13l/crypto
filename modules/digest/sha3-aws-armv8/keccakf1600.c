#include <hpc/compiler.h>
#include <inttypes.h>

extern void KeccakF1600_hw(uint64_t st[25]);

static inline void
keccakf1600(uint64_t st[25])
{
	KeccakF1600_hw(st);
}
