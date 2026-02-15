#include <hpc/compiler.h>

#define SHA_LBLOCK 16

typedef struct {
    u32 h[8];
    u32 Nl, Nh;
    u32 data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

extern void sha256_block_data_order_nohw(SHA256_CTX *ctx, const void *in, size_t num);
extern void sha256_block_data_order_hw(SHA256_CTX *ctx, const void *in, size_t num);

static inline void
sha256_block_data_order(SHA256_CTX *ctx, const void *in, size_t num)
{
	sha256_block_data_order_hw(ctx, in, num);
}
