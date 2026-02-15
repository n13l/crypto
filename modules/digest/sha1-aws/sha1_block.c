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

extern void sha1_block_data_order_nohw(SHA_CTX *c, const void *p, size_t num);
extern void sha1_block_data_order_hw(SHA_CTX *c, const void *p, size_t num);

void
sha1_block_data_order(SHA_CTX *c, const void *p, size_t num)
{
	sha1_block_data_order_hw(c, p, num);
}
