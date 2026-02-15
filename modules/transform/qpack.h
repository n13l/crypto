/*
 * The MIT License (MIT)                    QPACK field compression (RFC 9204)
 *
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

#ifndef __CRYPTO_TRANSFORM_QPACK_H__
#define __CRYPTO_TRANSFORM_QPACK_H__

#include <hpc/compiler.h>

__BEGIN_DECLS

#ifndef QPACK_FIELD_MAX
#ifdef CONFIG_CRYPTO_TRANSFORM_QPACK_FIELD_MAX
#define QPACK_FIELD_MAX	((unsigned int)CONFIG_CRYPTO_TRANSFORM_QPACK_FIELD_MAX)
#else
#define QPACK_FIELD_MAX		8192u
#endif
#endif

#define QPACK_NAME_MAX		QPACK_FIELD_MAX
#define QPACK_VALUE_MAX		QPACK_FIELD_MAX

#define QPACK_OK		0
#define QPACK_E_TRUNCATED	(-1)
#define QPACK_E_INTEGER		(-2)
#define QPACK_E_HUFFMAN		(-3)
#define QPACK_E_INDEX		(-4)
#define QPACK_E_EVICTED		(-5)
#define QPACK_E_CAPACITY	(-6)
#define QPACK_E_ENTRY		(-7)
#define QPACK_E_SPACE		(-8)
#define QPACK_E_CALLBACK	(-9)
#define QPACK_E_BLOCKED		(-10)
#define QPACK_E_PREFIX		(-11)

#define QPACK_F_INDEXED		0x01	/* whole field from a table          */
#define QPACK_F_STATIC		0x02	/* ...the static one (T bit)         */
#define QPACK_F_POST_BASE	0x04	/* §4.5.3/§4.5.5: indexed past Base  */
#define QPACK_F_NEVER_INDEXED	0x08	/* the N bit (§7.1 obligations)      */
#define QPACK_F_HUFFMAN_NAME	0x10	/* §4.1.2: the name arrived coded    */
#define QPACK_F_HUFFMAN_VALUE	0x20	/* §4.1.2: the value did             */
#define QPACK_F_UNRESOLVED	0x40	/* a coordinate this partial table
					 * cannot spell (qpack_partial())    */
#define QPACK_F_NAME_INDEX	0x80

#define QPACK_EMIT_HUFFMAN	0x01
#define QPACK_EMIT_STATIC	0x02
#define QPACK_EMIT_UNRESOLVED	0x04

struct qpack_field {
	const u8	*name;
	unsigned int	name_len;
	const u8	*value;
	unsigned int	value_len;
	u64		index;
	unsigned int	flags;
};

typedef int (*qpack_fn)(void *ctx, const struct qpack_field *f);

struct qpack_ent {
	u32	off;
	u16	name_len;
	u16	value_len;
};

#define QPACK_MEM(_cap) \
	((size_t)(_cap) + ((size_t)(_cap) / 32 + 1) * sizeof(struct qpack_ent))

struct qpack {
	u8		*buf;
	struct qpack_ent *ent;
	u32		nent;
	u32		size;
	u32		head, tail;
	u32		first;
	u32		count;
	u32		cap;
	u32		limit;
	u32		used;
	u32		max_ents;
	u32		broken;
	u32		partial;
	u32		recovered;
	u64		inserted;
	u64		evicted;
	u64		join;	
	u64		missed;
	u64		known;
	u64		acked;
	u64		cancelled;
};

struct qpack_scratch {
	u8	name[QPACK_NAME_MAX];
	u8	value[QPACK_VALUE_MAX];
	u8	ins[QPACK_NAME_MAX + QPACK_VALUE_MAX];
};

int qpack_init(struct qpack *q, void *mem, unsigned int cap,
               unsigned int max_capacity);

void qpack_reset(struct qpack *q);

void qpack_partial(struct qpack *q);

static inline int
qpack_is_partial(const struct qpack *q)
{
	return (int)q->partial;
}

static inline int
qpack_recovered(const struct qpack *q)
{
	return (int)q->recovered;
}

static inline unsigned long long
qpack_missed(const struct qpack *q)
{
	return (unsigned long long)q->missed;
}

int qpack_ins(struct qpack *q, struct qpack_scratch *s, const u8 *p,
              unsigned int len, unsigned int *taken);

int qpack_ack(struct qpack *q, const u8 *p, unsigned int len,
              unsigned int *taken);

int qpack_decode(struct qpack *q, struct qpack_scratch *s, const u8 *block,
                 unsigned int len, qpack_fn fn, void *ctx);

int qpack_section_ric(const struct qpack *q, const u8 *block,
                      unsigned int len, u64 *ric);

int qpack_entry(const struct qpack *q, unsigned int i, struct qpack_field *f);

int qpack_section_prefix(const struct qpack *q, const u8 *block,
                         unsigned int len, u64 *ric, u64 *base,
                         unsigned int *plen);

int qpack_emit_prefix(u8 *dst, unsigned int size, u64 ric, u64 base);
int qpack_emit(u8 *dst, unsigned int size, const struct qpack_field *f,
               u64 base, unsigned int opts);

#define QPACK_WIRE_MAX(_cap) \
	(96u + ((unsigned int)(_cap) / 32 + 1) * 4u + (unsigned int)(_cap))

int qpack_snapshot(const struct qpack *q, void *buf, unsigned int size,
                   unsigned int *len);
int qpack_recovery(struct qpack *q, void *mem, unsigned int size,
                   const void *buf, unsigned int len);
int qpack_wire_size(const void *buf, unsigned int len);

static inline int
qpack_broken(const struct qpack *q)
{
	return (int)q->broken;
}

static inline unsigned int
qpack_used(const struct qpack *q)
{
	return q->used;
}

static inline unsigned int
qpack_capacity(const struct qpack *q)
{
	return q->cap;
}

static inline unsigned int
qpack_entries(const struct qpack *q)
{
	return q->count;
}

static inline unsigned long long
qpack_inserted(const struct qpack *q)
{
	return (unsigned long long)q->inserted;
}

__END_DECLS

#endif/*__CRYPTO_TRANSFORM_QPACK_H__*/
