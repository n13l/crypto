#include <hpc/compiler.h>

#define SHA_LBLOCK 16
#define SHA512_CBLOCK (SHA_LBLOCK * 8)

typedef struct {
    u64 h[8];
    u64 Nl, Nh;
    union {
        u64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

extern void sha512_block_data_order_nohw(SHA512_CTX *ctx, const void *in, size_t num);
extern void sha512_block_data_order_hw(SHA512_CTX *ctx, const void *in, size_t num);

static inline void
sha512_block_data_order(SHA512_CTX *ctx, const void *in, size_t num)
{
	sha512_block_data_order_hw(ctx, in, num);
}
