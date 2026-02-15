#include <hpc/compiler.h>

#define SHA_LBLOCK 16
#define SHA_CBLOCK (SHA_LBLOCK * 4)

typedef struct SHAstate_st {
    u32 h0, h1, h2, h3, h4;
    u32 Nl, Nh;
    u32 data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

extern void sha1_block_data_order(SHA_CTX *c, const void *p, size_t num);
