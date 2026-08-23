
#ifndef __CRYPTO_TRANSFORM_HPACK_H__
#define __CRYPTO_TRANSFORM_HPACK_H__

#include <hpc/compiler.h>

__BEGIN_DECLS

#ifndef HPACK_FIELD_MAX
#ifdef CONFIG_CRYPTO_TRANSFORM_HPACK_FIELD_MAX
#define HPACK_FIELD_MAX		((unsigned int)CONFIG_CRYPTO_TRANSFORM_HPACK_FIELD_MAX)
#else
#define HPACK_FIELD_MAX		8192u
#endif
#endif

#define HPACK_NAME_MAX		HPACK_FIELD_MAX
#define HPACK_VALUE_MAX		HPACK_FIELD_MAX

#define HPACK_OK		0
#define HPACK_E_TRUNCATED	(-1)
#define HPACK_E_INTEGER		(-2)
#define HPACK_E_HUFFMAN		(-3)
#define HPACK_E_INDEX		(-4)
#define HPACK_E_TABLE_SIZE	(-5)
#define HPACK_E_SPACE		(-6)
#define HPACK_E_CALLBACK	(-7)

#define HPACK_F_INDEXED		0x01
#define HPACK_F_INCREMENTAL	0x02
#define HPACK_F_NEVER_INDEXED	0x04
#define HPACK_F_STATIC		0x08
#define HPACK_F_HUFFMAN_NAME	0x10
#define HPACK_F_HUFFMAN_VALUE	0x20
#define HPACK_F_UNRESOLVED	0x40

#define HPACK_EMIT_HUFFMAN	0x01
#define HPACK_EMIT_STATIC	0x02
#define HPACK_EMIT_UNRESOLVED	0x04
#define HPACK_EMIT_INDEXING	0x08

struct hpack_field {
	const u8	*name;
	unsigned int	name_len;
	const u8	*value;
	unsigned int	value_len;
	unsigned int	index;
	unsigned int	flags;
};

typedef int (*hpack_fn)(void *ctx, const struct hpack_field *f);

typedef void *(*hpack_mem_fn)(void *arg, void *mem, size_t old, size_t len);

struct hpack_ent {
	u32	off;
	u16	name_len;
	u16	value_len;
};

#define HPACK_MEM(_cap) \
	((size_t)(_cap) + ((size_t)(_cap) / 32 + 1) * sizeof(struct hpack_ent))

struct hpack {
	u8		*buf;
	struct hpack_ent *ent;
	u32		nent;
	u32		size;
	u32		head, tail;
	u32		first;
	u32		count;
	u32		cap;
	u32		limit;
	u32		used;
	u32		broken;
	u32		partial;
	u32		recovered;
	u64		inserted;
	u64		evicted;
	hpack_mem_fn	grow;
	void		*grow_arg;
};

struct hpack_scratch {
	u8	name[HPACK_NAME_MAX];
	u8	value[HPACK_VALUE_MAX];
	u8	ins[HPACK_NAME_MAX + HPACK_VALUE_MAX];
};

int hpack_init(struct hpack *h, void *mem, unsigned int cap);
void hpack_reset(struct hpack *h);

void hpack_growable(struct hpack *h, hpack_mem_fn fn, void *arg);

int hpack_grow(struct hpack *h, void *mem, unsigned int cap);
void hpack_partial(struct hpack *h);

static inline int
hpack_is_partial(const struct hpack *h)
{
	return (int)h->partial;
}

static inline int
hpack_recovered(const struct hpack *h)
{
	return (int)h->recovered;
}

int hpack_entry(const struct hpack *h, unsigned int i, struct hpack_field *f);
void hpack_limit(struct hpack *h, unsigned int limit);
int hpack_decode(struct hpack *h, struct hpack_scratch *s, const u8 *block,
                 unsigned int len, hpack_fn fn, void *ctx);

#define HPACK_WIRE_MAX(_cap) \
	(64u + ((unsigned int)(_cap) / 32 + 1) * 4u + (unsigned int)(_cap))

int hpack_snapshot(const struct hpack *h, void *buf, unsigned int size,
                   unsigned int *len);
int hpack_recovery(struct hpack *h, void *mem, unsigned int size,
                   const void *buf, unsigned int len);
int hpack_wire_size(const void *buf, unsigned int len);

int hpack_emit(u8 *dst, unsigned int size, const struct hpack_field *f,
               unsigned int opts);

static inline int
hpack_broken(const struct hpack *h)
{
	return (int)h->broken;
}

static inline unsigned int
hpack_used(const struct hpack *h)
{
	return h->used;
}

static inline unsigned int
hpack_capacity(const struct hpack *h)
{
	return h->cap;
}

static inline unsigned int
hpack_entries(const struct hpack *h)
{
	return h->count;
}

__END_DECLS

#endif
