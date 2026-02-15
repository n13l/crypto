/*
poly1305 implementation using 64 bit * 64 bit = 128 bit multiplication
and 128 bit addition
public domain
*/

typedef unsigned __int128 poly1305_uint128_t;

/* interpret eight 8 bit unsigned integers as a 64 bit unsigned integer in little endian */
#if (USE_UNALIGNED == 1)
#define U8TO64(p) \
    (*((u64 *)(p)))
#define U64TO8(p, v) \
    do { \
      *((u64 *)(p)) = v; \
    } while (0)
#else
static u64
U8TO64(const u8 *p)
{
    return
        (((u64)(p[0] & 0xff)      ) |
         ((u64)(p[1] & 0xff) <<  8) |
         ((u64)(p[2] & 0xff) << 16) |
         ((u64)(p[3] & 0xff) << 24) |
         ((u64)(p[4] & 0xff) << 32) |
         ((u64)(p[5] & 0xff) << 40) |
         ((u64)(p[6] & 0xff) << 48) |
         ((u64)(p[7] & 0xff) << 56));
}

/* store a 64 bit unsigned integer as eight 8 bit unsigned integers in little endian */
static void
U64TO8(u8 *p, u64 v)
{
    p[0] = (v      ) & 0xff;
    p[1] = (v >>  8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
    p[4] = (v >> 32) & 0xff;
    p[5] = (v >> 40) & 0xff;
    p[6] = (v >> 48) & 0xff;
    p[7] = (v >> 56) & 0xff;
}
#endif

void
poly1305_init(struct poly1305_context *st, const u8 key[32])
{
    u64 t0,t1;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    t0 = U8TO64(&key[0]);
    t1 = U8TO64(&key[8]);

    st->r[0] = ( t0                    ) & 0xffc0fffffff;
    st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
    st->r[2] = ((t1 >> 24)             ) & 0x00ffffffc0f;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;

    /* save pad for later */
    st->pad[0] = U8TO64(&key[16]);
    st->pad[1] = U8TO64(&key[24]);

    st->leftover = 0;
    st->final = 0;
}

static void
poly1305_blocks(struct poly1305_context *st, const u8 *m, size_t bytes)
{
    const u64 hibit = (st->final) ? 0 : ((u64)1 << 40); /* 1 << 128 */
    u64 r0,r1,r2;
    u64 s1,s2;
    u64 h0,h1,h2;
    u64 c;
    poly1305_uint128_t d0,d1,d2,d;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];

    s1 = r1 * (5 << 2);
    s2 = r2 * (5 << 2);

    while (bytes >= POLY1305_BLOCK_SIZE) {
        u64 t0,t1;

        /* h += m[i] */
        t0 = U8TO64(m + 0);
        t1 = U8TO64(m + 8);

        h0 += (( t0                    ) & 0xfffffffffff);
        h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
        h2 += (((t1 >> 24)             ) & 0x3ffffffffff) | hibit;

        /* h *= r */
        d0 = ((poly1305_uint128_t)h0 * r0);
        d  = ((poly1305_uint128_t)h1 * s2); d0 += d;
        d  = ((poly1305_uint128_t)h2 * s1); d0 += d;
        d1 = ((poly1305_uint128_t)h0 * r1);
        d  = ((poly1305_uint128_t)h1 * r0); d1 += d;
        d  = ((poly1305_uint128_t)h2 * s2); d1 += d;
        d2 = ((poly1305_uint128_t)h0 * r2);
        d  = ((poly1305_uint128_t)h1 * r1); d2 += d;
        d  = ((poly1305_uint128_t)h2 * r0); d2 += d;

        /* (partial) h %= p */
                      c = (u64)(d0 >> 44); h0 = (u64)d0 & 0xfffffffffff;
        d1 += c;      c = (u64)(d1 >> 44); h1 = (u64)d1 & 0xfffffffffff;
        d2 += c;      c = (u64)(d2 >> 42); h2 = (u64)d2 & 0x3ffffffffff;
        h0  += c * 5; c =       (h0 >> 44); h0 =      h0 & 0xfffffffffff;
        h1  += c;

        m += POLY1305_BLOCK_SIZE;
        bytes -= POLY1305_BLOCK_SIZE;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
}

void
poly1305_finish(struct poly1305_context *st, u8 mac[16])
{
    u64 h0,h1,h2,c;
    u64 g0,g1,g2;
    u64 t0,t1;

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

                 c = (h1 >> 44); h1 &= 0xfffffffffff;
    h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
    h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
    h1 += c;     c = (h1 >> 44); h1 &= 0xfffffffffff;
    h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
    h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
    h1 += c;

    /* compute h + -p */
    g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
    g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
    g2 = h2 + c - ((u64)1 << 42);

    /* select h if h < p, or h + -p if h >= p */
    c = (g2 >> ((sizeof(u64) * 8) - 1)) - 1;
    g0 &= c;
    g1 &= c;
    g2 &= c;
    c = ~c;
    h0 = (h0 & c) | g0;
    h1 = (h1 & c) | g1;
    h2 = (h2 & c) | g2;

    /* h = (h + pad) */
    t0 = st->pad[0];
    t1 = st->pad[1];

    h0 += (( t0                    ) & 0xfffffffffff)    ; c = (h0 >> 44); h0 &= 0xfffffffffff;
    h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h1 >> 44); h1 &= 0xfffffffffff;
    h2 += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                 h2 &= 0x3ffffffffff;

    /* mac = h % (2^128) */
    h0 = ((h0      ) | (h1 << 44));
    h1 = ((h1 >> 20) | (h2 << 24));

    U64TO8(mac + 0, h0);
    U64TO8(mac + 8, h1);

    /* zero out the state */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->r[0] = 0;
    st->r[1] = 0;
    st->r[2] = 0;
    st->pad[0] = 0;
    st->pad[1] = 0;
}
