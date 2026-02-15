#ifndef POLY1305_H
#define POLY1305_H

#include <hpc/compiler.h>
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

#endif /* POLY1305_H */
