/*
 * The MIT License (MIT)                     HPACK header compression (RFC 7541)
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

#include <string.h>
#include <hpc/compiler.h>
#include <modules/transform/hpack.h>
#include "huffman.h"
#include "static.h"

#define HPACK_INT_MAX		(1u << 30)

struct hpack_in {
	const u8	*p;
	const u8	*end;
};

static inline unsigned int
hpack_left(const struct hpack_in *in)
{
	return (unsigned int)(in->end - in->p);
}

static int
hpack_int(struct hpack_in *in, unsigned int prefix, unsigned int *out)
{
	unsigned int mask = (1u << prefix) - 1;
	unsigned int shift = 0;
	u64 v;

	if (in->p >= in->end)
		return HPACK_E_TRUNCATED;

	v = *in->p++ & mask;
	if (v < mask) {
		*out = (unsigned int)v;
		return HPACK_OK;
	}
	for (;;) {
		u8 b;

		if (in->p >= in->end)
			return HPACK_E_TRUNCATED;
		if (shift > 28)
			return HPACK_E_INTEGER;
		b = *in->p++;
		v += (u64)(b & 0x7f) << shift;
		if (v > HPACK_INT_MAX)
			return HPACK_E_INTEGER;
		if (!(b & 0x80))
			break;
		shift += 7;
	}
	*out = (unsigned int)v;
	return HPACK_OK;
}

static int
hpack_string(struct hpack_in *in, u8 *dst, unsigned int dst_max,
             const u8 **out, unsigned int *out_len, int *huffman)
{
	unsigned int len, state = 0, n = 0, i;
	int rc, coded, accept = 1;
	const u8 *src;

	if (in->p >= in->end)
		return HPACK_E_TRUNCATED;
	coded = (*in->p & 0x80) != 0;
	if ((rc = hpack_int(in, 7, &len)) != HPACK_OK)
		return rc;
	if (len > hpack_left(in))
		return HPACK_E_TRUNCATED;

	src = in->p;
	in->p += len;
	*huffman = coded;

	if (!coded) {
		if (len > dst_max)
			return HPACK_E_SPACE;
		*out = src;
		*out_len = len;
		return HPACK_OK;
	}

	for (i = 0; i < len; i++) {
		unsigned int nib;

		for (nib = 0; nib < 2; nib++) {
			const struct hpack_huff_ent *e =
				&hpack_huff[state][nib == 0 ? (src[i] >> 4)
				                            : (src[i] & 0x0f)];

			if (e->flags & HPACK_HUFF_FAIL)
				return HPACK_E_HUFFMAN;
			if (e->flags & HPACK_HUFF_SYM) {
				if (n >= dst_max)
					return HPACK_E_SPACE;
				dst[n++] = e->sym;
			}
			state = e->next;
			accept = (e->flags & HPACK_HUFF_ACCEPT) != 0;
		}
	}
	if (!accept)
		return HPACK_E_HUFFMAN;

	*out = dst;
	*out_len = n;
	return HPACK_OK;
}

static inline unsigned int
hpack_ent_size(unsigned int name_len, unsigned int value_len)
{
	return name_len + value_len + 32;
}

static inline const struct hpack_ent *
hpack_at(const struct hpack *h, unsigned int i)
{
	return &h->ent[(h->first + i) % h->nent];
}

static void
hpack_evict(struct hpack *h, unsigned int want)
{
	while (h->count && h->used > want) {
		const struct hpack_ent *e = hpack_at(h, h->count - 1);

		h->used -= hpack_ent_size(e->name_len, e->value_len);
		h->tail = e->off + e->name_len + e->value_len;
		h->count--;
		h->evicted++;
	}
	if (!h->count) {
		/* an empty table is the one chance to start the arena over,
		 * which is what keeps the compaction below rare */
		h->head = h->tail = 0;
		h->used = 0;
	}
}

static void
hpack_turnover(struct hpack *h)
{
	if (!h->partial)
		return;
	h->partial = 0;
	h->recovered = 1;
}

static void
hpack_insert(struct hpack *h, const u8 *name, unsigned int name_len,
             const u8 *value, unsigned int value_len)
{
	unsigned int need = name_len + value_len;
	unsigned int size = hpack_ent_size(name_len, value_len);
	u64 ev = h->evicted;
	struct hpack_ent *e;

	if (size > h->cap) {
		hpack_evict(h, 0);
		hpack_turnover(h);
		return;
	}
	hpack_evict(h, h->cap - size);
	if (h->evicted != ev)
		hpack_turnover(h);

	if (h->head + need > h->size) {
		unsigned int live = h->head - h->tail, i;

		if (live)
			memmove(h->buf, h->buf + h->tail, live);
		for (i = 0; i < h->count; i++)
			h->ent[(h->first + i) % h->nent].off -= h->tail;
		h->tail = 0;
		h->head = live;
	}

	h->first = (h->first + h->nent - 1) % h->nent;
	e = &h->ent[h->first];
	e->off = h->head;
	e->name_len = (u16)name_len;
	e->value_len = (u16)value_len;
	memcpy(h->buf + h->head, name, name_len);
	memcpy(h->buf + h->head + name_len, value, value_len);
	h->head += need;
	h->count++;
	h->used += size;
	h->inserted++;
}

static int
hpack_lookup(const struct hpack *h, unsigned int idx, struct hpack_field *f)
{
	if (!idx)
		return HPACK_E_INDEX;
	if (idx <= HPACK_STATIC_MAX) {
		const struct hpack_static_ent *s = &hpack_static[idx];

		f->name      = (const u8 *)hpack_static_blob + s->name_off;
		f->name_len  = s->name_len;
		f->value     = (const u8 *)hpack_static_blob + s->value_off;
		f->value_len = s->value_len;
		f->flags    |= HPACK_F_STATIC;
		f->index     = idx;
		return HPACK_OK;
	}
	idx -= HPACK_STATIC_MAX + 1;
	if (idx >= h->count)
		return HPACK_E_INDEX;
	{
		const struct hpack_ent *e = hpack_at(h, idx);

		f->name      = h->buf + e->off;
		f->name_len  = e->name_len;
		f->value     = h->buf + e->off + e->name_len;
		f->value_len = e->value_len;
		f->index     = idx + HPACK_STATIC_MAX + 1;
	}
	return HPACK_OK;
}

int
hpack_init(struct hpack *h, void *mem, unsigned int cap)
{
	unsigned int nent = cap / 32 + 1;

	if (!mem || cap < 32)
		return -1;

	memset(h, 0, sizeof(*h));
	h->ent  = (struct hpack_ent *)mem;
	h->nent = nent;
	h->buf  = (u8 *)mem + (size_t)nent * sizeof(struct hpack_ent);
	h->size = cap;
	h->cap = h->limit = cap;
	return 0;
}

void
hpack_reset(struct hpack *h)
{
	h->head = h->tail = h->first = h->count = h->used = 0;
	h->broken = 0;
	h->partial = 0;
	h->recovered = 0;
	h->cap = h->limit;
	h->inserted = h->evicted = 0;
}

int
hpack_entry(const struct hpack *h, unsigned int i, struct hpack_field *f)
{
	const struct hpack_ent *e;

	if (i >= h->count)
		return -1;
	e = hpack_at(h, i);
	memset(f, 0, sizeof(*f));
	f->name = h->buf + e->off;
	f->name_len = e->name_len;
	f->value = h->buf + e->off + e->name_len;
	f->value_len = e->value_len;
	f->index = HPACK_STATIC_MAX + 1 + i;
	return 0;
}

void
hpack_partial(struct hpack *h)
{
	h->partial = 1;
}

static inline int
hpack_prejoin(const struct hpack *h, unsigned int idx)
{
	return h->partial && idx > HPACK_STATIC_MAX + h->count;
}

static const u8 hpack_no_bytes[1] = "";

static void
hpack_unresolved(struct hpack_field *f, unsigned int idx)
{
	f->name = hpack_no_bytes;
	f->name_len = 0;
	f->value = hpack_no_bytes;
	f->value_len = 0;
	f->index = idx;
	f->flags |= HPACK_F_UNRESOLVED;
}

void
hpack_limit(struct hpack *h, unsigned int limit)
{
	if (limit > h->size)
		limit = h->size;
	h->limit = limit;
	if (h->cap > limit) {
		h->cap = limit;
		hpack_evict(h, h->cap);
	}
}

static int
hpack_literal(struct hpack *h, struct hpack_scratch *s, struct hpack_in *in,
              unsigned int prefix, unsigned int flags, struct hpack_field *f)
{
	unsigned int idx;
	int rc, coded;

	f->flags = flags;
	f->index = 0;

	if ((rc = hpack_int(in, prefix, &idx)) != HPACK_OK)
		return rc;

	if (idx) {
		if ((rc = hpack_lookup(h, idx, f)) != HPACK_OK) {
			if (!hpack_prejoin(h, idx) ||
			    (flags & HPACK_F_INCREMENTAL))
				return rc;
			hpack_unresolved(f, idx);
		}
		f->value = NULL;
		f->value_len = 0;
	} else {
		rc = hpack_string(in, s->name, HPACK_NAME_MAX, &f->name,
		                  &f->name_len, &coded);
		if (rc != HPACK_OK)
			return rc;
		if (coded)
			f->flags |= HPACK_F_HUFFMAN_NAME;
	}

	rc = hpack_string(in, s->value, HPACK_VALUE_MAX, &f->value,
	                  &f->value_len, &coded);
	if (rc != HPACK_OK)
		return rc;
	if (coded)
		f->flags |= HPACK_F_HUFFMAN_VALUE;

	if (flags & HPACK_F_INCREMENTAL) {
		unsigned int n = f->name_len, v = f->value_len;

		memcpy(s->ins, f->name, n);
		memcpy(s->ins + n, f->value, v);
		hpack_insert(h, s->ins, n, s->ins + n, v);
		if (h->count) {
			const struct hpack_ent *e = hpack_at(h, 0);

			f->name      = h->buf + e->off;
			f->value     = h->buf + e->off + e->name_len;
			f->name_len  = e->name_len;
			f->value_len = e->value_len;
		} else {
			f->name  = s->ins;
			f->value = s->ins + n;
		}
	}
	return HPACK_OK;
}

#define HPACK_WIRE_MAGIC	0x6b637068u	/* "hpck" */
#define HPACK_WIRE_VERSION	1

struct hpack_wire {
	u32	magic;
	u32	version;
	u32	len;
	u32	size;
	u32	cap;
	u32	limit;
	u32	used;
	u32	count;
	u32	broken;
	u32	partial;
	u32	recovered;
	u32	pad;
	u64	inserted;
	u64	evicted;
};

struct hpack_wire_ent {
	u16	name_len;
	u16	value_len;
};

int
hpack_snapshot(const struct hpack *h, void *buf, unsigned int size,
               unsigned int *len)
{
	struct hpack_wire w;
	u8 *p = buf;
	unsigned int i;

	*len = 0;

	memset(&w, 0, sizeof(w));
	w.magic = HPACK_WIRE_MAGIC;
	w.version = HPACK_WIRE_VERSION;
	w.size = h->size;
	w.cap = h->cap;
	w.limit = h->limit;
	w.used = h->used;
	w.count = h->count;
	w.broken = h->broken;
	w.partial = h->partial;
	w.recovered = h->recovered;
	w.inserted = h->inserted;
	w.evicted = h->evicted;
	w.len = (u32)sizeof(w) + w.count * (u32)sizeof(struct hpack_wire_ent) +
	        (w.used - w.count * 32);

	if (w.len > size)
		return 0;

	memcpy(p, &w, sizeof(w));
	p += sizeof(w);
	for (i = h->count; i-- > 0; ) {
		const struct hpack_ent *e = hpack_at(h, i);
		struct hpack_wire_ent we = {
			.name_len = e->name_len,
			.value_len = e->value_len,
		};

		memcpy(p, &we, sizeof(we));
		p += sizeof(we);
	}
	for (i = h->count; i-- > 0; ) {
		const struct hpack_ent *e = hpack_at(h, i);

		memcpy(p, h->buf + e->off,
		       (unsigned int)e->name_len + e->value_len);
		p += (unsigned int)e->name_len + e->value_len;
	}

	*len = w.len;
	return 1;
}

int
hpack_wire_size(const void *buf, unsigned int len)
{
	struct hpack_wire w;

	if (len < sizeof(w))
		return -1;
	memcpy(&w, buf, sizeof(w));
	if (w.magic != HPACK_WIRE_MAGIC || w.version != HPACK_WIRE_VERSION)
		return -1;
	return (int)w.size;
}

int
hpack_recovery(struct hpack *h, void *mem, unsigned int size, const void *buf,
              unsigned int len)
{
	const u8 *ents, *bytes;
	struct hpack_wire w;
	unsigned int i, left;

	if (hpack_init(h, mem, size))
		return -1;

	if (len < sizeof(w))
		return -1;
	memcpy(&w, buf, sizeof(w));

	if (w.magic != HPACK_WIRE_MAGIC || w.version != HPACK_WIRE_VERSION ||
	    w.len > len || w.size < 32 || w.size > size ||
	    w.limit > w.size || w.cap > w.limit ||
	    w.used > w.cap || w.count > w.used / 32 ||
	    w.len != (u32)sizeof(w) +
	             w.count * (u32)sizeof(struct hpack_wire_ent) +
	             (w.used - w.count * 32))
		return -1;

	h->limit = w.limit;
	h->cap = w.cap;

	ents = (const u8 *)buf + sizeof(w);
	bytes = ents + w.count * sizeof(struct hpack_wire_ent);
	left = w.used - w.count * 32;

	for (i = 0; i < w.count; i++) {
		struct hpack_wire_ent we;
		unsigned int n;

		memcpy(&we, ents + i * sizeof(we), sizeof(we));
		n = (unsigned int)we.name_len + we.value_len;
		if (n > left) {
			hpack_reset(h);
			return -1;
		}
		hpack_insert(h, bytes, we.name_len, bytes + we.name_len,
		             we.value_len);
		bytes += n;
		left -= n;
	}

	if (left || h->count != w.count || h->used != w.used) {
		hpack_reset(h);
		return -1;
	}

	h->broken = w.broken;
	h->partial = w.partial;
	h->recovered = w.recovered;
	h->inserted = w.inserted;
	h->evicted = w.evicted;
	return 0;
}

static int
hpack_emit_int(u8 *dst, unsigned int size, u8 pattern, unsigned int prefix,
               unsigned int value)
{
	unsigned int mask = (1u << prefix) - 1;
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
hpack_huff_bits(const u8 *s, unsigned int len)
{
	unsigned int i, bits = 0;

	for (i = 0; i < len; i++)
		bits += hpack_huff_sym[s[i]].len;
	return bits;
}

static void
hpack_huff_write(u8 *dst, const u8 *s, unsigned int len)
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
hpack_emit_str(u8 *dst, unsigned int size, const u8 *s, unsigned int len,
               unsigned int opts)
{
	unsigned int coded = 0, out;
	int n;

	if (opts & HPACK_EMIT_HUFFMAN) {
		unsigned int bytes = (hpack_huff_bits(s, len) + 7) / 8;

		if (bytes < len)
			coded = bytes;
	}
	out = coded ? coded : len;
	n = hpack_emit_int(dst, size, coded ? 0x80 : 0x00, 7, out);
	if (n < 0 || out > size - (unsigned int)n)
		return -1;
	if (coded)
		hpack_huff_write(dst + n, s, len);
	else
		memcpy(dst + n, s, len);
	return n + (int)out;
}

static unsigned int
hpack_static_find(const struct hpack_field *f, unsigned int *name_idx)
{
	unsigned int i;

	*name_idx = 0;
	for (i = 1; i <= HPACK_STATIC_MAX; i++) {
		const struct hpack_static_ent *e = &hpack_static[i];

		if (e->name_len != f->name_len ||
		    memcmp(hpack_static_blob + e->name_off, f->name,
		           f->name_len))
			continue;
		if (!*name_idx)
			*name_idx = i;
		if (e->value_len == f->value_len &&
		    !memcmp(hpack_static_blob + e->value_off, f->value,
		            f->value_len))
			return i;
	}
	return 0;
}

static void
hpack_emit_form(const struct hpack_field *f, unsigned int opts, u8 *pattern,
                unsigned int *prefix)
{
	if (f->flags & HPACK_F_NEVER_INDEXED) {
		*pattern = 0x10;
		*prefix = 4;
	} else if ((opts & HPACK_EMIT_INDEXING) &&
	           (f->flags & HPACK_F_INCREMENTAL)) {
		*pattern = 0x40;
		*prefix = 6;
	} else {
		*pattern = 0x00;
		*prefix = 4;
	}
}

int
hpack_emit(u8 *dst, unsigned int size, const struct hpack_field *f,
           unsigned int opts)
{
	unsigned int name_idx = 0, prefix;
	u8 pattern;
	int n, m;

	if (f->flags & HPACK_F_UNRESOLVED) {
		if (!(opts & HPACK_EMIT_UNRESOLVED))
			return -1;
		if (f->flags & HPACK_F_INDEXED)
			return hpack_emit_int(dst, size, 0x80, 7, f->index);
		hpack_emit_form(f, opts, &pattern, &prefix);
		n = hpack_emit_int(dst, size, pattern, prefix, f->index);
		if (n < 0)
			return -1;
		m = hpack_emit_str(dst + n, size - (unsigned int)n,
		                   f->value, f->value_len, opts);
		if (m < 0)
			return -1;
		return n + m;
	}

	if (opts & HPACK_EMIT_STATIC) {
		unsigned int idx = hpack_static_find(f, &name_idx);

		if (idx && !(f->flags & HPACK_F_NEVER_INDEXED) &&
		    !((opts & HPACK_EMIT_INDEXING) &&
		      (f->flags & HPACK_F_INCREMENTAL)))
			return hpack_emit_int(dst, size, 0x80, 7, idx);
	}

	hpack_emit_form(f, opts, &pattern, &prefix);
	n = hpack_emit_int(dst, size, pattern, prefix, name_idx);
	if (n < 0)
		return -1;
	if (!name_idx) {
		m = hpack_emit_str(dst + n, size - (unsigned int)n,
		                   f->name, f->name_len, opts);
		if (m < 0)
			return -1;
		n += m;
	}
	m = hpack_emit_str(dst + n, size - (unsigned int)n,
	                   f->value, f->value_len, opts);
	if (m < 0)
		return -1;
	return n + m;
}

int
hpack_decode(struct hpack *h, struct hpack_scratch *s, const u8 *block,
             unsigned int len, hpack_fn fn, void *ctx)
{
	struct hpack_in in = { .p = block, .end = block + len };
	int rc = HPACK_OK;

	while (in.p < in.end) {
		struct hpack_field f;
		u8 b = *in.p;

		memset(&f, 0, sizeof(f));

		if (b & 0x80) {
			/* §6.1 indexed header field */
			unsigned int idx;

			if ((rc = hpack_int(&in, 7, &idx)) != HPACK_OK)
				break;
			f.flags = HPACK_F_INDEXED;
			if ((rc = hpack_lookup(h, idx, &f)) != HPACK_OK) {
				if (!hpack_prejoin(h, idx))
					break;
				hpack_unresolved(&f, idx);
				rc = HPACK_OK;
			}
		} else if (b & 0x40) {
			rc = hpack_literal(h, s, &in, 6,
			                   HPACK_F_INCREMENTAL, &f);
			if (rc != HPACK_OK)
				break;
		} else if (b & 0x20) {
			unsigned int max;
			u64 ev = h->evicted;

			if ((rc = hpack_int(&in, 5, &max)) != HPACK_OK)
				break;
			if (max > h->limit) {
				rc = HPACK_E_TABLE_SIZE;
				break;
			}
			h->cap = max;
			hpack_evict(h, max);
			if (h->evicted != ev || !max)
				hpack_turnover(h);
			continue;
		} else {
			unsigned int flags =
				(b & 0x10) ? HPACK_F_NEVER_INDEXED : 0;

			rc = hpack_literal(h, s, &in, 4, flags, &f);
			if (rc != HPACK_OK)
				break;
		}

		if (fn && fn(ctx, &f)) {
			rc = HPACK_E_CALLBACK;
			break;
		}
	}

	if (rc != HPACK_OK)
		h->broken = 1;
	return rc;
}
