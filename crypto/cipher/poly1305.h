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

/*
 * Limb width of the poly1305-donna accumulator.
 *
 * The 64-bit form carries r and h in three 44/44/42-bit limbs and multiplies
 * into a 128-bit product; the 32-bit form uses five 26-bit limbs and 32x32->64
 * multiplies. The first is roughly twice the throughput on any target whose
 * compiler offers __int128 — which is every 64-bit target we build for — and
 * the second is what the rest are left with.
 *
 * The choice is a property of the compiler rather than of a Kconfig symbol on
 * purpose: struct poly1305_context is a stack object in callers outside this
 * package (net/tls opens records with one), so every translation unit that
 * sees this header has to agree on its layout, and only a predefined macro is
 * guaranteed to be visible to all of them.
 */
#if defined(__SIZEOF_INT128__)
#define POLY1305_DONNA_64   1
#else
#define POLY1305_DONNA_64   0
#endif

struct poly1305_context {
#if POLY1305_DONNA_64
    u64 r[3];
    u64 h[3];
    u64 pad[2];
#else
    u32 r[5];
    u32 h[5];
    u32 pad[4];
#endif
    size_t leftover;
    u8 buffer[POLY1305_BLOCK_SIZE];
    u8 final;
};

void poly1305_init(struct poly1305_context *ctx, const u8 key[32]);
void poly1305_update(struct poly1305_context *ctx, const u8 *m, size_t bytes);
void poly1305_finish(struct poly1305_context *ctx, u8 mac[16]);
void poly1305_auth(u8 mac[16], const u8 *m, size_t bytes, const u8 key[32]);

#endif /* POLY1305_H */
