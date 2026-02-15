/*
poly1305 implementation
public domain

The accumulator arithmetic — poly1305_init, poly1305_blocks and
poly1305_finish — is the part that differs between the two limb widths and
lives in the donna header selected below; the buffering above it is the same
either way and stays here.
*/

#include <crypto/cipher/poly1305.h>

#if POLY1305_DONNA_64
#include "poly1305-donna-64.h"
#else
#include "poly1305-donna-32.h"
#endif

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
