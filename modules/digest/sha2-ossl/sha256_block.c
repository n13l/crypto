#include <hpc/compiler.h>
#include <inttypes.h>

typedef unsigned int SHA_LONG;

#define SHA_LBLOCK 16

typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

extern void sha256_block_data_order(SHA256_CTX *ctx, const void *in, size_t num);
