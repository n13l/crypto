#include <hpc/compiler.h>
#include <inttypes.h>

typedef unsigned int SHA_LONG;

#define SHA_LBLOCK 16
#define SHA_CBLOCK (SHA_LBLOCK * 4)

typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

extern void sha1_block_data_order_avx2(SHA_CTX *c, const void *p, size_t num);

static inline void
sha1_block_data_order(void *c, const void *p, size_t num)
{
	sha1_block_data_order_avx2(c, p, num);
}
