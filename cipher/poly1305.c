/*
 * poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64
 * bit addition public domain.
*/

#include <sys/compiler.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define POLY1305_KEYLEN     32
#define POLY1305_TAGLEN     16
#define POLY1305_BLOCK_SIZE 16

/* use memcpy() to copy blocks of memory (typically faster) */
#define USE_MEMCPY          1
/* use unaligned little-endian load/store (can be faster) */
#define USE_UNALIGNED       0

struct poly1305_context {
    u32 r[5];
    u32 h[5];
    u32 pad[4];
    size_t leftover;
    u8 buffer[POLY1305_BLOCK_SIZE];
    u8 final;
};

void poly1305_init(struct poly1305_context *ctx, const u8 key[32]);
void poly1305_update(struct poly1305_context *ctx, const u8 *m, size_t bytes);
void poly1305_finish(struct poly1305_context *ctx, u8 mac[16]);
void poly1305_auth(u8 mac[16], const u8 *m, size_t bytes, const u8 key[32]);


#if (USE_UNALIGNED == 1)
#define U8TO32(p) \
    (*((u32 *)(p)))
#define U32TO8(p, v) \
    do { \
      *((u32 *)(p)) = v; \
    } while (0)
#else
/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static u32
U8TO32(const u8 *p)
{
    return
        (((u32)(p[0] & 0xff)      ) |
         ((u32)(p[1] & 0xff) <<  8) |
         ((u32)(p[2] & 0xff) << 16) |
         ((u32)(p[3] & 0xff) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void
U32TO8(u8 *p, u32 v)
{
    p[0] = (v      ) & 0xff;
    p[1] = (v >>  8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}
#endif

void
poly1305_init(struct poly1305_context *st, const u8 key[32])
{
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = (U8TO32(&key[ 0])     ) & 0x3ffffff;
    st->r[1] = (U8TO32(&key[ 3]) >> 2) & 0x3ffff03;
    st->r[2] = (U8TO32(&key[ 6]) >> 4) & 0x3ffc0ff;
    st->r[3] = (U8TO32(&key[ 9]) >> 6) & 0x3f03fff;
    st->r[4] = (U8TO32(&key[12]) >> 8) & 0x00fffff;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* save pad for later */
    st->pad[0] = U8TO32(&key[16]);
    st->pad[1] = U8TO32(&key[20]);
    st->pad[2] = U8TO32(&key[24]);
    st->pad[3] = U8TO32(&key[28]);

    st->leftover = 0;
    st->final = 0;
}

static void
poly1305_blocks(struct poly1305_context *st, const u8 *m, size_t bytes)
{
    const u32 hibit = (st->final) ? 0 : (1 << 24); /* 1 << 128 */
    u32 r0,r1,r2,r3,r4;
    u32 s1,s2,s3,s4;
    u32 h0,h1,h2,h3,h4;
    u64 d0,d1,d2,d3,d4;
    u32 c;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];
    r3 = st->r[3];
    r4 = st->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    while (bytes >= POLY1305_BLOCK_SIZE) {
        /* h += m[i] */
        h0 += (U8TO32(m+ 0)     ) & 0x3ffffff;
        h1 += (U8TO32(m+ 3) >> 2) & 0x3ffffff;
        h2 += (U8TO32(m+ 6) >> 4) & 0x3ffffff;
        h3 += (U8TO32(m+ 9) >> 6) & 0x3ffffff;
        h4 += (U8TO32(m+12) >> 8) | hibit;

        /* h *= r */
        d0 = ((u64)h0 * r0) + ((u64)h1 * s4) + ((u64)h2 * s3) + ((u64)h3 * s2) + ((u64)h4 * s1);
        d1 = ((u64)h0 * r1) + ((u64)h1 * r0) + ((u64)h2 * s4) + ((u64)h3 * s3) + ((u64)h4 * s2);
        d2 = ((u64)h0 * r2) + ((u64)h1 * r1) + ((u64)h2 * r0) + ((u64)h3 * s4) + ((u64)h4 * s3);
        d3 = ((u64)h0 * r3) + ((u64)h1 * r2) + ((u64)h2 * r1) + ((u64)h3 * r0) + ((u64)h4 * s4);
        d4 = ((u64)h0 * r4) + ((u64)h1 * r3) + ((u64)h2 * r2) + ((u64)h3 * r1) + ((u64)h4 * r0);

        /* (partial) h %= p */
                      c = (u32)(d0 >> 26); h0 = (u32)d0 & 0x3ffffff;
        d1 += c;      c = (u32)(d1 >> 26); h1 = (u32)d1 & 0x3ffffff;
        d2 += c;      c = (u32)(d2 >> 26); h2 = (u32)d2 & 0x3ffffff;
        d3 += c;      c = (u32)(d3 >> 26); h3 = (u32)d3 & 0x3ffffff;
        d4 += c;      c = (u32)(d4 >> 26); h4 = (u32)d4 & 0x3ffffff;
        h0 += c * 5;  c =           (h0 >> 26); h0 =           h0 & 0x3ffffff;
        h1 += c;

        m += POLY1305_BLOCK_SIZE;
        bytes -= POLY1305_BLOCK_SIZE;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

void
poly1305_finish(struct poly1305_context *st, u8 mac[16])
{
    u32 h0,h1,h2,h3,h4,c;
    u32 g0,g1,g2,g3,g4;
    u64 f;
    u32 mask;

    /* process the remaining block */
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < POLY1305_BLOCK_SIZE; i++)
            st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, POLY1305_BLOCK_SIZE);
    }

    /* fully carry h */
    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

                 c = h1 >> 26; h1 = h1 & 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
    h1 +=     c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1 << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> ((sizeof(u32) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f = (u64)h0 + st->pad[0]            ; h0 = (u32)f;
    f = (u64)h1 + st->pad[1] + (f >> 32); h1 = (u32)f;
    f = (u64)h2 + st->pad[2] + (f >> 32); h2 = (u32)f;
    f = (u64)h3 + st->pad[3] + (f >> 32); h3 = (u32)f;

    U32TO8(mac +  0, h0);
    U32TO8(mac +  4, h1);
    U32TO8(mac +  8, h2);
    U32TO8(mac + 12, h3);

    /* zero out the state */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;
    st->r[0] = 0;
    st->r[1] = 0;
    st->r[2] = 0;
    st->r[3] = 0;
    st->r[4] = 0;
    st->pad[0] = 0;
    st->pad[1] = 0;
    st->pad[2] = 0;
    st->pad[3] = 0;
}


void
poly1305_update(struct poly1305_context *st, const u8 *m, size_t bytes)
{
    size_t i;

    /* handle leftover */
    if (st->leftover) {
        size_t want = (POLY1305_BLOCK_SIZE - st->leftover);
        if (want > bytes)
            want = bytes;
        for (i = 0; i < want; i++)
            st->buffer[st->leftover + i] = m[i];
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < POLY1305_BLOCK_SIZE)
            return;
        poly1305_blocks(st, st->buffer, POLY1305_BLOCK_SIZE);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= POLY1305_BLOCK_SIZE) {
        size_t want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));
        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
#if (USE_MEMCPY == 1)
        memcpy(st->buffer + st->leftover, m, bytes);
#else
        for (i = 0; i < bytes; i++)
            st->buffer[st->leftover + i] = m[i];
#endif
        st->leftover += bytes;
    }
}

void
poly1305_auth(u8 mac[16], const u8 *m, size_t bytes, const u8 key[32])
{
    struct poly1305_context ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, m, bytes);
    poly1305_finish(&ctx, mac);
}
