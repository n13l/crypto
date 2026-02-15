#include <hpc/compiler.h>
#include <inttypes.h>

typedef unsigned long long SHA_LONG64;

#define SHA_LBLOCK 16
#define SHA512_CBLOCK (SHA_LBLOCK * 8)

typedef struct SHA512state_st {
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

extern void sha512_block_data_order(SHA512_CTX *ctx, const void *in, size_t num);
