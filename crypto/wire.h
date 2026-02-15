/*
 * The MIT License (MIT)                     A cursor over a run of wire bytes,
 *                                           and where the bounds tests are paid
 * Copyright (c) 2026                               Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __CRYPTO_WIRE_H__
#define __CRYPTO_WIRE_H__

#include <hpc/compiler.h>
#include <mem/unaligned.h>

__BEGIN_DECLS

/*
 * Reading a wire format is two different jobs, and the trouble starts when one
 * set of accessors tries to be both.
 *
 * So the two jobs are separate here, and which one a name does is in the name:
 *
 *   wire_has(), wire_left(), wire_done()   ask, and answer
 *   wire_*_unchecked()                     load or move, and do not ask
 *   everything else                        ask and then load, failing as one
 *
 * The unchecked half is not the dangerous half - it is the half whose bound has
 * already been proven, by a wire_has() covering the whole run or by the
 * wire_split*() that produced the cursor. What makes it safe is that the proof
 * is visible a few lines up instead of being spread across the field loads.
 *
 *   if (!wire_has(&w, 2 + 32 + 1))            <- one test, three fields
 *           return -1;
 *   version = wire_get_u16_unchecked(&w);
 *   random  = wire_consume_unchecked(&w, 32);
 *   idlen   = wire_get_u8_unchecked(&w);
 *
 * The other idiom is the one a length-prefixed format is made of. wire_split()
 * and its wire_split_u8()/_u16()/_u24() forms cut a child cursor out of the
 * parent and step the parent over it in one move, so a body is bounded by its
 * own length and the walk past it does not depend on how much of it was read.
 * An element that lies about its size, or one the caller does not parse to the
 * end, takes only itself down:
 *
 *   if (!wire_split_u16(&w, &vec))            <- @w is already past the vector
 *           return -1;
 *   for (p = vec.p; p != vec.e; p += 2)
 *           seen |= classify(get_u16_be(p));  <- no test in the loop
 *
 * Loads go through mem/unaligned.h, so nothing here assumes an aligned pointer
 * and nothing here reads more bytes than the field has. Everything is a static
 * inline over three pointers: there is no state beyond the run itself and no
 * allocation anywhere.
 *
 */
struct wire {
	const u8 *b;	/* where this run began: what wire_seek() is against */
	const u8 *p;	/* the next byte                                    */
	const u8 *e;	/* one past the last byte of the run                */
};

static inline void
wire_init(struct wire *c, const u8 *pdu, unsigned int bytes)
{
	c->b = c->p = pdu;
	c->e = pdu + bytes;
}

/* how much is left ahead of the cursor */
static inline unsigned int
wire_left(const struct wire *c)
{
	return (unsigned int)(c->e - c->p);
}

/* how far in the cursor has got */
static inline unsigned int
wire_off(const struct wire *c)
{
	return (unsigned int)(c->p - c->b);
}

/* is there room for @n more bytes: the one test a run of unchecked loads
 * stands on */
static inline int
wire_has(const struct wire *c, unsigned int n)
{
	return n <= (unsigned int)(c->e - c->p);
}

static inline int
wire_done(const struct wire *c)
{
	return c->p == c->e;
}

static inline u8
wire_peek_u8_unchecked(const struct wire *c)
{
	return c->p[0];
}

static inline u16
wire_peek_u16_unchecked(const struct wire *c)
{
	return (u16)get_u16_be(c->p);
}

static inline u32
wire_peek_u24_unchecked(const struct wire *c)
{
	return ((u32)c->p[0] << 16) | ((u32)c->p[1] << 8) | c->p[2];
}

static inline u32
wire_peek_u32_unchecked(const struct wire *c)
{
	return get_u32_be(c->p);
}

static inline void
wire_advance_unchecked(struct wire *c, unsigned int n)
{
	c->p += n;
}

static inline u8
wire_get_u8_unchecked(struct wire *c)
{
	u8 v = wire_peek_u8_unchecked(c);

	c->p += 1;
	return v;
}

static inline u16
wire_get_u16_unchecked(struct wire *c)
{
	u16 v = wire_peek_u16_unchecked(c);

	c->p += 2;
	return v;
}

static inline u32
wire_get_u24_unchecked(struct wire *c)
{
	u32 v = wire_peek_u24_unchecked(c);

	c->p += 3;
	return v;
}

static inline u32
wire_get_u32_unchecked(struct wire *c)
{
	u32 v = wire_peek_u32_unchecked(c);

	c->p += 4;
	return v;
}

/* the next @n bytes, and the cursor past them */
static inline const u8 *
wire_consume_unchecked(struct wire *c, unsigned int n)
{
	const u8 *p = c->p;

	c->p += n;
	return p;
}

static inline int
wire_advance(struct wire *c, unsigned int n)
{
	if (!wire_has(c, n))
		return 0;
	c->p += n;
	return 1;
}

/* back to @off bytes from the start of the run */
static inline int
wire_seek(struct wire *c, unsigned int off)
{
	if (off > (unsigned int)(c->e - c->b))
		return 0;
	c->p = c->b + off;
	return 1;
}

static inline const u8 *
wire_consume(struct wire *c, unsigned int n)
{
	if (!wire_has(c, n))
		return NULL;
	return wire_consume_unchecked(c, n);
}

static inline int
wire_get_u8(struct wire *c, u8 *v)
{
	if (!wire_has(c, 1))
		return 0;
	*v = wire_get_u8_unchecked(c);
	return 1;
}

static inline int
wire_get_u16(struct wire *c, u16 *v)
{
	if (!wire_has(c, 2))
		return 0;
	*v = wire_get_u16_unchecked(c);
	return 1;
}

static inline int
wire_get_u24(struct wire *c, u32 *v)
{
	if (!wire_has(c, 3))
		return 0;
	*v = wire_get_u24_unchecked(c);
	return 1;
}

/*
 * Cut @n bytes off the front of @c into @out and step @c over them. @out is a
 * cursor of its own, so what reads it cannot reach past the body whatever it
 * does with it, and @c is already at the next element whether or not @out was
 * read to the end.
 */
static inline int
wire_split(struct wire *c, unsigned int n, struct wire *out)
{
	if (!wire_has(c, n))
		return 0;
	wire_init(out, c->p, n);
	c->p += n;
	return 1;
}

static inline int
wire_split_unchecked(struct wire *c, unsigned int n, struct wire *out)
{
	wire_init(out, c->p, n);
	c->p += n;
	return 1;
}

/* a one-byte length and the body it counts */
static inline int
wire_split_u8(struct wire *c, struct wire *out)
{
	unsigned int n;

	if (!wire_has(c, 1))
		return 0;
	n = wire_peek_u8_unchecked(c);
	if ((unsigned int)(c->e - c->p) - 1u < n)
		return 0;
	c->p += 1;
	return wire_split_unchecked(c, n, out);
}

/* a two-byte length and the body it counts: most of TLS */
static inline int
wire_split_u16(struct wire *c, struct wire *out)
{
	unsigned int n;

	if (!wire_has(c, 2))
		return 0;
	n = wire_peek_u16_unchecked(c);
	if ((unsigned int)(c->e - c->p) - 2u < n)
		return 0;
	c->p += 2;
	return wire_split_unchecked(c, n, out);
}

/* a three-byte length and the body it counts: handshake messages */
static inline int
wire_split_u24(struct wire *c, struct wire *out)
{
	unsigned int n;

	if (!wire_has(c, 3))
		return 0;
	n = wire_peek_u24_unchecked(c);
	if ((unsigned int)(c->e - c->p) - 3u < n)
		return 0;
	c->p += 3;
	return wire_split_unchecked(c, n, out);
}

__END_DECLS

#endif
