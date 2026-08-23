
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

#define QPACK_F_INDEXED		0x01
#define QPACK_F_STATIC		0x02
#define QPACK_F_POST_BASE	0x04
#define QPACK_F_NEVER_INDEXED	0x08
#define QPACK_F_HUFFMAN_NAME	0x10
#define QPACK_F_HUFFMAN_VALUE	0x20
#define QPACK_F_UNRESOLVED	0x40
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

typedef void *(*qpack_mem_fn)(void *arg, void *mem, size_t old, size_t len);

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
	qpack_mem_fn	grow;
	void		*grow_arg;
};

struct qpack_scratch {
	u8	name[QPACK_NAME_MAX];
	u8	value[QPACK_VALUE_MAX];
	u8	ins[QPACK_NAME_MAX + QPACK_VALUE_MAX];
};

int qpack_init(struct qpack *q, void *mem, unsigned int cap,
               unsigned int max_capacity);

void qpack_reset(struct qpack *q);

void qpack_limit(struct qpack *q, unsigned int limit);

void qpack_growable(struct qpack *q, qpack_mem_fn fn, void *arg);

int qpack_grow(struct qpack *q, void *mem, unsigned int cap);

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

#endif
