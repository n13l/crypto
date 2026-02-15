

#include <string.h>

#include <hpc/compiler.h>
#include <modules/transform/qpack.h>
#include <modules/transform/hpack/huffman.h>
#include <modules/transform/qpack/static.h>

#define QPACK_INT_MAX		((u64)1 << 62)

struct qpack_in {
	const u8	*p;
	const u8	*end;
};

static inline unsigned int
qpack_left(const struct qpack_in *in)
{
	return (unsigned int)(in->end - in->p);
}

static int
qpack_int(struct qpack_in *in, unsigned int prefix, u64 *out)
{
	u64 mask = ((u64)1 << prefix) - 1;
	unsigned int shift = 0;
	u64 v;

	if (in->p >= in->end)
		return QPACK_E_TRUNCATED;

	v = *in->p++ & mask;
	if (v < mask) {
		*out = v;
		return QPACK_OK;
	}
	for (;;) {
		u8 b;

		if (in->p >= in->end)
			return QPACK_E_TRUNCATED;
		if (shift > 56)
			return QPACK_E_INTEGER;
		b = *in->p++;
		v += (u64)(b & 0x7f) << shift;
		if (v > QPACK_INT_MAX)
			return QPACK_E_INTEGER;
		if (!(b & 0x80))
			break;
		shift += 7;
	}
	*out = v;
	return QPACK_OK;
}

static int
qpack_string(struct qpack_in *in, unsigned int prefix, u8 *dst,
             unsigned int dst_max, const u8 **out, unsigned int *out_len,
             int *huffman)
{
	unsigned int state = 0, n = 0, i;
	int rc, coded, accept = 1;
	const u8 *src;
	u64 len;

	if (in->p >= in->end)
		return QPACK_E_TRUNCATED;
	coded = (*in->p & (1u << prefix)) != 0;
	if ((rc = qpack_int(in, prefix, &len)) != QPACK_OK)
		return rc;
	if (!coded && len > dst_max)
		return QPACK_E_SPACE;
	if (len > qpack_left(in))
		return QPACK_E_TRUNCATED;

	src = in->p;
	in->p += len;
	*huffman = coded;

	if (!coded) {
		*out = src;
		*out_len = (unsigned int)len;
		return QPACK_OK;
	}

	for (i = 0; i < (unsigned int)len; i++) {
		unsigned int nib;

		for (nib = 0; nib < 2; nib++) {
			const struct hpack_huff_ent *e =
				&hpack_huff[state][nib == 0 ? (src[i] >> 4)
				                            : (src[i] & 0x0f)];

			if (e->flags & HPACK_HUFF_FAIL)
				return QPACK_E_HUFFMAN;
			if (e->flags & HPACK_HUFF_SYM) {
				if (n >= dst_max)
					return QPACK_E_SPACE;
				dst[n++] = e->sym;
			}
			state = e->next;
			accept = (e->flags & HPACK_HUFF_ACCEPT) != 0;
		}
	}
	if (!accept)
		return QPACK_E_HUFFMAN;

	*out = dst;
	*out_len = n;
	return QPACK_OK;
}


static inline unsigned int
qpack_ent_size(unsigned int name_len, unsigned int value_len)
{
	return name_len + value_len + 32;
}

static inline const struct qpack_ent *
qpack_at(const struct qpack *q, u64 abs)
{
	u64 i = q->inserted - 1 - abs;

	return &q->ent[(q->first + (unsigned int)i) % q->nent];
}

static void
qpack_evict(struct qpack *q, unsigned int want)
{
	while (q->count && q->used > want) {
		const struct qpack_ent *e = qpack_at(q, q->evicted);

		q->used -= qpack_ent_size(e->name_len, e->value_len);
		q->tail = e->off + e->name_len + e->value_len;
		q->count--;
		q->evicted++;
	}
	if (!q->count) {
		q->head = q->tail = 0;
		q->used = 0;
	}
}

static int qpack_grow_by(struct qpack *q, unsigned int live, unsigned int need);

static int
qpack_insert(struct qpack *q, const u8 *name, unsigned int name_len,
             const u8 *value, unsigned int value_len)
{
	unsigned int need = name_len + value_len;
	unsigned int size = qpack_ent_size(name_len, value_len);
	struct qpack_ent *e;

	if (size > q->cap)
		return QPACK_E_ENTRY;
	qpack_evict(q, q->cap - size);

	if (q->head + need > q->size || q->count + 1 > q->nent) {
		unsigned int live = q->head - q->tail, i;

		if (live + need > q->size || q->count + 1 > q->nent) {
			int rc = qpack_grow_by(q, live, need);

			if (rc != QPACK_OK)
				return rc;
		} else if (live) {
			memmove(q->buf, q->buf + q->tail, live);
		}
		if (q->tail) {
			for (i = 0; i < q->count; i++)
				q->ent[(q->first + i) % q->nent].off -= q->tail;
			q->tail = 0;
			q->head = live;
		}
	}

	q->first = (q->first + q->nent - 1) % q->nent;
	e = &q->ent[q->first];
	e->off = q->head;
	e->name_len = (u16)name_len;
	e->value_len = (u16)value_len;
	memcpy(q->buf + q->head, name, name_len);
	memcpy(q->buf + q->head + name_len, value, value_len);
	q->head += need;
	q->count++;
	q->used += size;
	q->inserted++;
	return QPACK_OK;
}

static int
qpack_lookup(const struct qpack *q, int stat, u64 abs, struct qpack_field *f)
{
	if (stat) {
		const struct qpack_static_ent *s;

		if (abs >= QPACK_STATIC_N)
			return QPACK_E_INDEX;
		s = &qpack_static[abs];
		f->name      = (const u8 *)qpack_static_blob + s->name_off;
		f->name_len  = s->name_len;
		f->value     = (const u8 *)qpack_static_blob + s->value_off;
		f->value_len = s->value_len;
		f->flags    |= QPACK_F_STATIC;
		f->index     = abs;
		return QPACK_OK;
	}
	if (abs >= q->inserted)
		return QPACK_E_INDEX;
	if (abs < q->evicted)
		return QPACK_E_EVICTED;
	{
		const struct qpack_ent *e = qpack_at(q, abs);

		f->name      = q->buf + e->off;
		f->name_len  = e->name_len;
		f->value     = q->buf + e->off + e->name_len;
		f->value_len = e->value_len;
		f->index     = abs;
	}
	return QPACK_OK;
}


int
qpack_init(struct qpack *q, void *mem, unsigned int cap,
           unsigned int max_capacity)
{
	unsigned int nent = cap / 32 + 1;

	if (!mem)
		return -1;
	if (max_capacity < cap)
		max_capacity = cap;

	memset(q, 0, sizeof(*q));
	q->ent  = (struct qpack_ent *)mem;
	q->nent = nent;
	q->buf  = (u8 *)mem + (size_t)nent * sizeof(struct qpack_ent);
	q->size = cap;
	q->limit = cap;
	q->cap = 0;
	q->max_ents = max_capacity / 32;
	return 0;
}

void
qpack_reset(struct qpack *q)
{
	q->head = q->tail = q->first = q->count = q->used = 0;
	q->cap = 0;
	q->broken = 0;
	q->partial = q->recovered = 0;
	q->inserted = q->evicted = q->join = q->missed = 0;
	q->known = q->acked = q->cancelled = 0;
}

void
qpack_limit(struct qpack *q, unsigned int limit)
{
	if (limit > q->size && !q->grow)
		limit = q->size;
	q->limit = limit;
	if (q->cap > limit) {
		q->cap = limit;
		qpack_evict(q, q->cap);
	}
}

void
qpack_growable(struct qpack *q, qpack_mem_fn fn, void *arg)
{
	q->grow = fn;
	q->grow_arg = arg;
}

static void
qpack_reverse(struct qpack_ent *e, unsigned int lo, unsigned int hi)
{
	while (lo + 1 < hi) {
		struct qpack_ent t = e[lo];

		e[lo++] = e[--hi];
		e[hi] = t;
	}
}

int
qpack_grow(struct qpack *q, void *mem, unsigned int cap)
{
	unsigned int onent = q->nent, nent = cap / 32 + 1, live, i;
	struct qpack_ent *ent = (struct qpack_ent *)mem;
	u8 *obuf = (u8 *)mem + (size_t)onent * sizeof(*ent);
	u8 *buf = (u8 *)mem + (size_t)nent * sizeof(*ent);

	if (!mem || cap < q->size)
		return -1;

	live = q->head - q->tail;
	if (live)
		memmove(buf, obuf + q->tail, live);
	qpack_reverse(ent, 0, q->first);
	qpack_reverse(ent, q->first, onent);
	qpack_reverse(ent, 0, onent);
	for (i = 0; i < q->count; i++)
		ent[i].off -= q->tail;

	q->ent = ent;
	q->nent = nent;
	q->buf = buf;
	q->first = 0;
	q->tail = 0;
	q->head = live;
	q->size = cap;
	return 0;
}

static int
qpack_grow_by(struct qpack *q, unsigned int live, unsigned int need)
{
	unsigned int want = q->size ? q->size : 32;
	void *mem;

	if (!q->grow)
		return QPACK_E_SPACE;
	while (want < live + need || want < 32u * (q->count + 1))
		want *= 2;
	if (want > q->cap)
		want = q->cap;
	mem = q->grow(q->grow_arg, q->ent, QPACK_MEM(q->size), QPACK_MEM(want));
	if (!mem || qpack_grow(q, mem, want))
		return QPACK_E_SPACE;
	return QPACK_OK;
}

void
qpack_partial(struct qpack *q)
{
	q->join = q->inserted;
	q->partial = 1;
}

static inline int
qpack_turned(const struct qpack *q)
{
	return q->evicted > q->join;
}

static const u8 qpack_no_bytes[1] = "";

static void
qpack_unresolved(struct qpack_field *f, u64 abs)
{
	f->name = qpack_no_bytes;
	f->name_len = 0;
	f->value = qpack_no_bytes;
	f->value_len = 0;
	f->index = abs;
	f->flags |= QPACK_F_UNRESOLVED;
}

static int
qpack_resolve(const struct qpack *q, int stat, u64 abs, struct qpack_field *f,
              unsigned int *astray)
{
	if (!stat && q->partial) {
		if (abs < q->evicted || abs >= q->inserted)
			(*astray)++;
		qpack_unresolved(f, abs);
		return QPACK_OK;
	}
	return qpack_lookup(q, stat, abs, f);
}

int
qpack_entry(const struct qpack *q, unsigned int i, struct qpack_field *f)
{
	if (i >= q->count)
		return -1;
	memset(f, 0, sizeof(*f));
	return qpack_lookup(q, 0, q->inserted - 1 - i, f);
}

static int
qpack_ins_one(struct qpack *q, struct qpack_scratch *s, struct qpack_in *in)
{
	struct qpack_field f;
	unsigned int nlen, vlen;
	const u8 *name, *value;
	int rc, coded;
	u64 v;
	u8 b = *in->p;

	if (b & 0x80) {
		int stat = (b & 0x40) != 0;

		memset(&f, 0, sizeof(f));
		if ((rc = qpack_int(in, 6, &v)) != QPACK_OK)
			return rc;
		if (!stat) {
			if (v >= q->inserted)
				return QPACK_E_INDEX;
			v = q->inserted - 1 - v;
		}
		if ((rc = qpack_lookup(q, stat, v, &f)) != QPACK_OK)
			return rc;
		rc = qpack_string(in, 7, s->value, QPACK_VALUE_MAX,
		                  &value, &vlen, &coded);
		if (rc != QPACK_OK)
			return rc;
		memcpy(s->ins, f.name, f.name_len);
		memcpy(s->ins + f.name_len, value, vlen);
		return qpack_insert(q, s->ins, f.name_len,
		                    s->ins + f.name_len, vlen);
	}
	if (b & 0x40) {
		rc = qpack_string(in, 5, s->name, QPACK_NAME_MAX,
		                  &name, &nlen, &coded);
		if (rc != QPACK_OK)
			return rc;
		rc = qpack_string(in, 7, s->value, QPACK_VALUE_MAX,
		                  &value, &vlen, &coded);
		if (rc != QPACK_OK)
			return rc;
		return qpack_insert(q, name, nlen, value, vlen);
	}
	if (b & 0x20) {
		if ((rc = qpack_int(in, 5, &v)) != QPACK_OK)
			return rc;
		if (v > q->limit)
			return QPACK_E_CAPACITY;
		q->cap = (u32)v;
		qpack_evict(q, q->cap);
		return QPACK_OK;
	}
	memset(&f, 0, sizeof(f));
	if ((rc = qpack_int(in, 5, &v)) != QPACK_OK)
		return rc;
	if (v >= q->inserted)
		return QPACK_E_INDEX;
	v = q->inserted - 1 - v;
	if ((rc = qpack_lookup(q, 0, v, &f)) != QPACK_OK)
		return rc;
	memcpy(s->ins, f.name, f.name_len);
	memcpy(s->ins + f.name_len, f.value, f.value_len);
	return qpack_insert(q, s->ins, f.name_len,
	                    s->ins + f.name_len, f.value_len);
}

int
qpack_ins(struct qpack *q, struct qpack_scratch *s, const u8 *p,
          unsigned int len, unsigned int *taken)
{
	struct qpack_in in = { .p = p, .end = p + len };

	*taken = 0;
	if (q->broken)
		return QPACK_OK;

	while (in.p < in.end) {
		const u8 *start = in.p;
		int rc = qpack_ins_one(q, s, &in);

		if (rc == QPACK_E_TRUNCATED) {
			in.p = start;
			break;
		}
		if (rc != QPACK_OK) {
			q->broken = 1;
			*taken = (unsigned int)(in.p - p);
			return rc;
		}
	}
	*taken = (unsigned int)(in.p - p);
	return QPACK_OK;
}

static void
qpack_rebase(struct qpack *q, u64 d)
{
	q->inserted += d;
	q->evicted  += d;
	q->join     += d;
	q->missed   += d;
}

int
qpack_ack(struct qpack *q, const u8 *p, unsigned int len, unsigned int *taken)
{
	struct qpack_in in = { .p = p, .end = p + len };

	*taken = 0;
	while (in.p < in.end) {
		const u8 *start = in.p;
		u8 b = *in.p;
		int rc;
		u64 v;

		if (b & 0x80) {
			rc = qpack_int(&in, 7, &v);
			if (rc == QPACK_OK)
				q->acked++;
		} else if (b & 0x40) {
			rc = qpack_int(&in, 6, &v);
			if (rc == QPACK_OK)
				q->cancelled++;
		} else {
			rc = qpack_int(&in, 6, &v);
			if (rc == QPACK_OK)
				q->known += v;
		}
		if (rc == QPACK_E_TRUNCATED) {
			in.p = start;
			break;
		}
		if (rc != QPACK_OK) {
			*taken = (unsigned int)(in.p - p);
			return rc;
		}
	}
	if (q->partial && q->known > q->inserted)
		qpack_rebase(q, q->known - q->inserted);
	*taken = (unsigned int)(in.p - p);
	return QPACK_OK;
}

static int
qpack_ric(const struct qpack *q, u64 enc, u64 *out)
{
	u64 fullrange, maxvalue, maxwrap, ric;

	if (!enc) {
		*out = 0;
		return QPACK_OK;
	}
	if (!q->max_ents)
		return QPACK_E_PREFIX;
	fullrange = 2 * (u64)q->max_ents;
	if (enc > fullrange)
		return QPACK_E_PREFIX;
	maxvalue = q->inserted + q->max_ents;
	maxwrap = (maxvalue / fullrange) * fullrange;
	ric = maxwrap + enc - 1;
	if (ric > maxvalue) {
		if (ric <= fullrange)
			return QPACK_E_PREFIX;
		ric -= fullrange;
	}
	if (!ric)
		return QPACK_E_PREFIX;
	*out = ric;
	return QPACK_OK;
}

static int
qpack_prefix(const struct qpack *q, struct qpack_in *in, u64 *ric, u64 *base)
{
	u64 enc, delta;
	int rc, sign;

	if ((rc = qpack_int(in, 8, &enc)) != QPACK_OK)
		return rc;
	if ((rc = qpack_ric(q, enc, ric)) != QPACK_OK)
		return rc;

	if (in->p >= in->end)
		return QPACK_E_TRUNCATED;
	sign = (*in->p & 0x80) != 0;
	if ((rc = qpack_int(in, 7, &delta)) != QPACK_OK)
		return rc;
	if (!sign) {
		*base = *ric + delta;
	} else {
		if (delta >= *ric)
			return QPACK_E_PREFIX;
		*base = *ric - delta - 1;
	}
	return QPACK_OK;
}

int
qpack_section_prefix(const struct qpack *q, const u8 *block, unsigned int len,
                     u64 *ric, u64 *base, unsigned int *plen)
{
	struct qpack_in in = { .p = block, .end = block + len };
	u64 r = 0, b = 0;
	int rc;

	if ((rc = qpack_prefix(q, &in, &r, &b)) != QPACK_OK)
		return rc;
	if (ric)
		*ric = r;
	if (base)
		*base = b;
	if (plen)
		*plen = (unsigned int)(in.p - block);
	return QPACK_OK;
}


static int
qpack_emit_int(u8 *dst, unsigned int size, u8 pattern, unsigned int prefix,
               u64 value)
{
	u64 mask = ((u64)1 << prefix) - 1;
	unsigned int n = 0;

	if (!size)
		return -1;
	if (value < mask) {
		dst[n++] = (u8)(pattern | value);
		return (int)n;
	}
	dst[n++] = (u8)(pattern | mask);
	value -= mask;
	while (value >= 128) {
		if (n >= size)
			return -1;
		dst[n++] = (u8)(0x80 | (value & 0x7f));
		value >>= 7;
	}
	if (n >= size)
		return -1;
	dst[n++] = (u8)value;
	return (int)n;
}

static unsigned int
qpack_huff_bytes(const u8 *s, unsigned int len)
{
	unsigned int i, bits = 0;

	for (i = 0; i < len; i++)
		bits += hpack_huff_sym[s[i]].len;
	return (bits + 7) / 8;
}

static void
qpack_huff_write(u8 *dst, const u8 *s, unsigned int len)
{
	u64 acc = 0;
	unsigned int nbits = 0, i;

	for (i = 0; i < len; i++) {
		const struct hpack_huff_sym *c = &hpack_huff_sym[s[i]];

		acc = (acc << c->len) | c->code;
		nbits += c->len;
		while (nbits >= 8) {
			nbits -= 8;
			*dst++ = (u8)(acc >> nbits);
		}
	}
	if (nbits)
		*dst = (u8)((acc << (8 - nbits)) | ((1u << (8 - nbits)) - 1));
}

static int
qpack_emit_str(u8 *dst, unsigned int size, const u8 *str, unsigned int len,
               u8 pattern, u8 hbit, unsigned int prefix, unsigned int opts)
{
	unsigned int out = len, coded = 0;
	int n;

	if (opts & QPACK_EMIT_HUFFMAN) {
		unsigned int bytes = qpack_huff_bytes(str, len);

		if (bytes < len) {
			coded = bytes;
			out = bytes;
		}
	}
	n = qpack_emit_int(dst, size, (u8)(pattern | (coded ? hbit : 0)),
	                   prefix, out);
	if (n < 0 || out > size - (unsigned int)n)
		return -1;
	if (coded)
		qpack_huff_write(dst + n, str, len);
	else
		memcpy(dst + n, str, len);
	return n + (int)out;
}

static unsigned int
qpack_static_find(const struct qpack_field *f, unsigned int *name_idx)
{
	unsigned int i;

	*name_idx = 0;
	for (i = 0; i < QPACK_STATIC_N; i++) {
		const struct qpack_static_ent *e = &qpack_static[i];

		if (e->name_len != f->name_len ||
		    memcmp(qpack_static_blob + e->name_off, f->name,
		           f->name_len))
			continue;
		if (!*name_idx)
			*name_idx = i + 1;
		if (e->value_len == f->value_len &&
		    !memcmp(qpack_static_blob + e->value_off, f->value,
		            f->value_len))
			return i + 1;
	}
	return 0;
}

int
qpack_emit_prefix(u8 *dst, unsigned int size, u64 ric, u64 base)
{
	int n, m;

	n = qpack_emit_int(dst, size, 0x00, 8, ric);
	if (n < 0)
		return -1;
	if (base >= ric)
		m = qpack_emit_int(dst + n, size - (unsigned int)n, 0x00, 7,
		                   base - ric);
	else
		m = qpack_emit_int(dst + n, size - (unsigned int)n, 0x80, 7,
		                   ric - base - 1);
	if (m < 0)
		return -1;
	return n + m;
}

int
qpack_emit(u8 *dst, unsigned int size, const struct qpack_field *f, u64 base,
           unsigned int opts)
{
	unsigned int name_idx = 0;
	int n, m;

	if (f->flags & QPACK_F_UNRESOLVED) {
		u8 never = (f->flags & QPACK_F_NEVER_INDEXED) ? 1 : 0;
		u64 rel;

		if (!(opts & QPACK_EMIT_UNRESOLVED))
			return -1;
		if (f->flags & QPACK_F_POST_BASE) {
			if (f->index < base)
				return -1;
			rel = f->index - base;
			if (f->flags & QPACK_F_INDEXED)
				return qpack_emit_int(dst, size, 0x10, 4, rel);
			n = qpack_emit_int(dst, size,
			                   (u8)(0x00 | (never ? 0x08 : 0)), 3,
			                   rel);
		} else {
			if (!base || f->index > base - 1)
				return -1;
			rel = base - 1 - f->index;
			if (f->flags & QPACK_F_INDEXED)
				return qpack_emit_int(dst, size, 0x80, 6, rel);
			n = qpack_emit_int(dst, size,
			                   (u8)(0x40 | (never ? 0x20 : 0)), 4,
			                   rel);
		}
		if (n < 0)
			return -1;
		m = qpack_emit_str(dst + n, size - (unsigned int)n, f->value,
		                   f->value_len, 0x00, 0x80, 7, opts);
		if (m < 0)
			return -1;
		return n + m;
	}

	if (opts & QPACK_EMIT_STATIC) {
		unsigned int idx = qpack_static_find(f, &name_idx);

		if (idx && !(f->flags & QPACK_F_NEVER_INDEXED))
			return qpack_emit_int(dst, size, 0xc0, 6, idx - 1);
	}

	if (name_idx) {
		n = qpack_emit_int(dst, size,
		                   (u8)(0x40 | 0x10 |
		                        ((f->flags & QPACK_F_NEVER_INDEXED)
		                             ? 0x20 : 0)),
		                   4, name_idx - 1);
		if (n < 0)
			return -1;
	} else {
		n = qpack_emit_str(dst, size, f->name, f->name_len,
		                   (u8)(0x20 |
		                        ((f->flags & QPACK_F_NEVER_INDEXED)
		                             ? 0x10 : 0)),
		                   0x08, 3, opts);
		if (n < 0)
			return -1;
	}
	m = qpack_emit_str(dst + n, size - (unsigned int)n, f->value,
	                   f->value_len, 0x00, 0x80, 7, opts);
	if (m < 0)
		return -1;
	return n + m;
}

int
qpack_section_ric(const struct qpack *q, const u8 *block, unsigned int len,
                  u64 *ric)
{
	struct qpack_in in = { .p = block, .end = block + len };
	u64 enc;
	int rc;

	if ((rc = qpack_int(&in, 8, &enc)) != QPACK_OK)
		return rc;
	return qpack_ric(q, enc, ric);
}

int
qpack_decode(struct qpack *q, struct qpack_scratch *s, const u8 *block,
             unsigned int len, qpack_fn fn, void *ctx)
{
	struct qpack_in in = { .p = block, .end = block + len };
	unsigned int astray = 0;
	u64 ric, base;
	int rc;

	if ((rc = qpack_prefix(q, &in, &ric, &base)) != QPACK_OK)
		return rc;
	if (ric > q->inserted && !q->partial)
		return QPACK_E_BLOCKED;
	if (ric && q->broken)
		return QPACK_E_INDEX;

	while (in.p < in.end) {
		struct qpack_field f;
		int coded;
		u64 v;
		u8 b = *in.p;

		memset(&f, 0, sizeof(f));

		if (b & 0x80) {
			int stat = (b & 0x40) != 0;

			f.flags = QPACK_F_INDEXED;
			if ((rc = qpack_int(&in, 6, &v)) != QPACK_OK)
				return rc;
			if (!stat) {
				if (v >= base)
					return QPACK_E_INDEX;
				v = base - 1 - v;
			}
			if ((rc = qpack_resolve(q, stat, v, &f,
			                        &astray)) != QPACK_OK)
				return rc;
		} else if (b & 0x40) {
			int stat = (b & 0x10) != 0;

			f.flags = QPACK_F_NAME_INDEX |
			          ((b & 0x20) ? QPACK_F_NEVER_INDEXED : 0);
			if ((rc = qpack_int(&in, 4, &v)) != QPACK_OK)
				return rc;
			if (!stat) {
				if (v >= base)
					return QPACK_E_INDEX;
				v = base - 1 - v;
			}
			if ((rc = qpack_resolve(q, stat, v, &f,
			                        &astray)) != QPACK_OK)
				return rc;
			rc = qpack_string(&in, 7, s->value, QPACK_VALUE_MAX,
			                  &f.value, &f.value_len, &coded);
			if (rc != QPACK_OK)
				return rc;
			if (coded)
				f.flags |= QPACK_F_HUFFMAN_VALUE;
		} else if (b & 0x20) {
			f.flags = (b & 0x10) ? QPACK_F_NEVER_INDEXED : 0;
			rc = qpack_string(&in, 3, s->name, QPACK_NAME_MAX,
			                  &f.name, &f.name_len, &coded);
			if (rc != QPACK_OK)
				return rc;
			if (coded)
				f.flags |= QPACK_F_HUFFMAN_NAME;
			rc = qpack_string(&in, 7, s->value, QPACK_VALUE_MAX,
			                  &f.value, &f.value_len, &coded);
			if (rc != QPACK_OK)
				return rc;
			if (coded)
				f.flags |= QPACK_F_HUFFMAN_VALUE;
		} else if (b & 0x10) {
			f.flags = QPACK_F_INDEXED | QPACK_F_POST_BASE;
			if ((rc = qpack_int(&in, 4, &v)) != QPACK_OK)
				return rc;
			v += base;
			if (v >= ric)
				return QPACK_E_INDEX;
			if ((rc = qpack_resolve(q, 0, v, &f,
			                        &astray)) != QPACK_OK)
				return rc;
		} else {
			f.flags = QPACK_F_NAME_INDEX | QPACK_F_POST_BASE |
			          ((b & 0x08) ? QPACK_F_NEVER_INDEXED : 0);
			if ((rc = qpack_int(&in, 3, &v)) != QPACK_OK)
				return rc;
			v += base;
			if (v >= ric)
				return QPACK_E_INDEX;
			if ((rc = qpack_resolve(q, 0, v, &f,
			                        &astray)) != QPACK_OK)
				return rc;
			rc = qpack_string(&in, 7, s->value, QPACK_VALUE_MAX,
			                  &f.value, &f.value_len, &coded);
			if (rc != QPACK_OK)
				return rc;
			if (coded)
				f.flags |= QPACK_F_HUFFMAN_VALUE;
		}

		if (fn && fn(ctx, &f))
			return QPACK_E_CALLBACK;
	}
	if (q->partial && ric && !astray && qpack_turned(q) &&
	    ric == q->inserted) {
		q->partial = 0;
		q->recovered = 1;
	}
	return QPACK_OK;
}

#define QPACK_WIRE_MAGIC	0x6b637071u
#define QPACK_WIRE_VERSION	2

struct qpack_wire {
	u32	magic;
	u32	version;
	u32	len;
	u32	size;
	u32	cap;
	u32	limit;
	u32	max_ents;
	u32	used;
	u32	count;
	u32	broken;
	u32	partial;
	u32	recovered;
	u64	inserted;
	u64	evicted;
	u64	join;
	u64	missed;
	u64	known;
	u64	acked;
	u64	cancelled;
};

struct qpack_wire_ent {
	u16	name_len;
	u16	value_len;
};

int
qpack_snapshot(const struct qpack *q, void *buf, unsigned int size,
               unsigned int *len)
{
	struct qpack_wire w;
	u8 *p = buf;
	unsigned int i;

	*len = 0;

	memset(&w, 0, sizeof(w));
	w.magic = QPACK_WIRE_MAGIC;
	w.version = QPACK_WIRE_VERSION;
	w.size = q->size;
	w.cap = q->cap;
	w.limit = q->limit;
	w.max_ents = q->max_ents;
	w.used = q->used;
	w.count = q->count;
	w.broken = q->broken;
	w.partial = q->partial;
	w.recovered = q->recovered;
	w.inserted = q->inserted;
	w.evicted = q->evicted;
	w.join = q->join;
	w.missed = q->missed;
	w.known = q->known;
	w.acked = q->acked;
	w.cancelled = q->cancelled;
	w.len = (u32)sizeof(w) + w.count * (u32)sizeof(struct qpack_wire_ent) +
	        (w.used - w.count * 32);

	if (w.len > size)
		return 0;

	memcpy(p, &w, sizeof(w));
	p += sizeof(w);
	for (i = q->count; i-- > 0; ) {
		const struct qpack_ent *e = qpack_at(q, q->inserted - 1 - i);
		struct qpack_wire_ent we = {
			.name_len = e->name_len,
			.value_len = e->value_len,
		};

		memcpy(p, &we, sizeof(we));
		p += sizeof(we);
	}
	for (i = q->count; i-- > 0; ) {
		const struct qpack_ent *e = qpack_at(q, q->inserted - 1 - i);

		memcpy(p, q->buf + e->off,
		       (unsigned int)e->name_len + e->value_len);
		p += (unsigned int)e->name_len + e->value_len;
	}

	*len = w.len;
	return 1;
}

int
qpack_wire_size(const void *buf, unsigned int len)
{
	struct qpack_wire w;

	if (len < sizeof(w))
		return -1;
	memcpy(&w, buf, sizeof(w));
	if (w.magic != QPACK_WIRE_MAGIC || w.version != QPACK_WIRE_VERSION)
		return -1;
	return (int)w.size;
}

int
qpack_recovery(struct qpack *q, void *mem, unsigned int size, const void *buf,
               unsigned int len)
{
	const u8 *ents, *bytes;
	struct qpack_wire w;
	unsigned int i, left;

	if (qpack_init(q, mem, size, size))
		return -1;

	if (len < sizeof(w))
		return -1;
	memcpy(&w, buf, sizeof(w));

	if (w.magic != QPACK_WIRE_MAGIC || w.version != QPACK_WIRE_VERSION ||
	    w.len > len || w.size > size ||
	    w.cap > w.size || w.cap > w.limit ||
	    w.used > w.cap || w.count > w.used / 32 ||
	    w.evicted > w.inserted ||
	    w.inserted - w.evicted != (u64)w.count ||
	    w.join > w.inserted || w.missed > w.join ||
	    (w.partial && w.recovered) ||
	    w.len != (u32)sizeof(w) +
	             w.count * (u32)sizeof(struct qpack_wire_ent) +
	             (w.used - w.count * 32))
		return -1;

	q->limit = w.limit;
	q->max_ents = w.max_ents;
	q->cap = w.cap;

	ents = (const u8 *)buf + sizeof(w);
	bytes = ents + w.count * sizeof(struct qpack_wire_ent);
	left = w.used - w.count * 32;

	for (i = 0; i < w.count; i++) {
		struct qpack_wire_ent we;
		unsigned int n;

		memcpy(&we, ents + i * sizeof(we), sizeof(we));
		n = (unsigned int)we.name_len + we.value_len;
		if (n > left ||
		    qpack_insert(q, bytes, we.name_len, bytes + we.name_len,
		                 we.value_len) != QPACK_OK) {
			qpack_reset(q);
			return -1;
		}
		bytes += n;
		left -= n;
	}

	if (left || q->count != w.count || q->used != w.used || q->evicted) {
		qpack_reset(q);
		return -1;
	}

	q->inserted = w.inserted;
	q->evicted = w.evicted;
	q->join = w.join;
	q->missed = w.missed;
	q->broken = w.broken;
	q->partial = w.partial;
	q->recovered = w.recovered;
	q->known = w.known;
	q->acked = w.acked;
	q->cancelled = w.cancelled;
	return 0;
}
