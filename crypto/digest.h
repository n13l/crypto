#ifndef __CRYPTO_DIGEST_H__
#define __CRYPTO_DIGEST_H__

#include <hpc/compiler.h>
#include <hpc/array.h>
#include <hpc/mem/unaligned.h>

#define DIGEST_CTXT_SIZE_MAX 512

enum algorithm_digest {
	ALGORITHM_SHA1_160 = 1,
	ALGORITHM_SHA2_224 = 2,
	ALGORITHM_SHA2_256 = 3,
	ALGORITHM_SHA2_384 = 4,
	ALGORITHM_SHA2_512 = 5,
	ALGORITHM_SHA3_224 = 6,
	ALGORITHM_SHA3_256 = 7,
	ALGORITHM_SHA3_384 = 8,
	ALGORITHM_SHA3_512 = 9,
	ALGORITHM_DIGEST_LAST
};

struct digest {
	u8 data[DIGEST_CTXT_SIZE_MAX];
	enum algorithm_digest algo;
};

struct digest_algorithm {
	unsigned int msg_size;
	unsigned int blk_size;
	unsigned int mac_size;
	unsigned int ctx_size;
	const char *name;
	const char *desc;
	unsigned int id;
	void (*init)(struct digest *);
	void (*update)(struct digest *, const u8 *, unsigned int);
	void (*digest)(struct digest *, u8 *);
	void (*copy)(struct digest *, struct digest *);
	void (*hash)(const u8 *, unsigned int, u8 *);
	const u8 *(*zero)(void);
};

void crypto_digest_register(struct digest_algorithm *alg);
struct digest_algorithm *crypto_digest_by_id(unsigned int id);

const char *digest_get_name(enum algorithm_digest id);
const char *digest_get_desc(enum algorithm_digest id);

#include <modules/built-in.h>
#include <modules/digest/sha1.h>
#include <modules/digest/sha2.h>
#include <modules/digest/sha3.h>

#ifndef __CRYPTO_DIGEST_SHA1_H__

static inline void
sha1_160_init(struct sha1 *ctx)
{
	arch_sha1_160_init(ctx);
}

static inline void
sha1_160_update(struct sha1 *ctx, const u8 *data, unsigned int len)
{
	arch_sha1_160_update(ctx, data, len);
}

static inline void
sha1_160_final(struct sha1 *ctx, u8 *out)
{
	arch_sha1_160_final(ctx, out);
}

#endif

#ifndef __CRYPTO_DIGEST_SHA2_H__

static inline void
sha224_init(struct sha256 *ctx)
{
	arch_sha2_224_init(ctx);
}

static inline void
sha256_init(struct sha256 *ctx)
{
	arch_sha2_256_init(ctx);
}

static inline void
sha256_update(struct sha256 *ctx, const u8 *data, unsigned int len)
{
	arch_sha2_256_update(ctx, data, len);
}

static inline void
sha256_final(struct sha256 *ctx, u8 *out)
{
	arch_sha2_256_final(ctx, out);
}

static inline void
sha384_init(struct sha512 *ctx)
{
	arch_sha2_384_init(ctx);
}

static inline void
sha512_init(struct sha512 *ctx)
{
	arch_sha2_512_init(ctx);
}

static inline void
sha512_update(struct sha512 *ctx, const u8 *data, unsigned int len)
{
	arch_sha2_512_update(ctx, data, len);
}

static inline void
sha512_final(struct sha512 *ctx, u8 *out)
{
	arch_sha2_512_final(ctx, out);
}

#endif

#ifndef __CRYPTO_DIGEST_SHA3_H__

static inline void
sha3_224_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_224_DIGEST_SIZE);
}

static inline void
sha3_256_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_256_DIGEST_SIZE);
}

static inline void
sha3_384_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_384_DIGEST_SIZE);
}

static inline void
sha3_512_init(struct sha3 *sha3)
{
	arch_sha3_init(sha3, SHA3_512_DIGEST_SIZE);
}

static inline void
sha3_update(struct sha3 *sha3, const u8 *data, unsigned int len)
{
	arch_sha3_256_update(sha3, data, len);
}

static inline void
sha3_final(struct sha3 *sha3, u8 *out)
{
	arch_sha3_256_final(sha3, out);
}

#endif

/*
 * Digest dispatch: a switch over the *dense* enum algorithm_digest (values
 * 1..9). Density lets the compiler pick the best lowering and fully inline it
 * -- no function-pointer call. On some targets that is an indexed jump table
 * (bounds check + one indirect jump); on others, notably modern aarch64, the
 * compiler deliberately avoids the indirect branch (cores mispredict it and it
 * gains little from the BTB) and emits a balanced tree of predictable direct
 * branches instead. Either shape is effectively free; the algorithm id is
 * public, so no constant-time masking is needed.
 */

static inline void
digest_init(struct digest *d, enum algorithm_digest algo)
{
	d->algo = algo;
	switch (algo) {
	case ALGORITHM_SHA1_160: arch_sha1_160_init((struct sha1 *)d);   return;
	case ALGORITHM_SHA2_224: arch_sha2_224_init((struct sha256 *)d); return;
	case ALGORITHM_SHA2_256: arch_sha2_256_init((struct sha256 *)d); return;
	case ALGORITHM_SHA2_384: arch_sha2_384_init((struct sha512 *)d); return;
	case ALGORITHM_SHA2_512: arch_sha2_512_init((struct sha512 *)d); return;
	case ALGORITHM_SHA3_224: arch_sha3_init((struct sha3 *)d, SHA3_224_DIGEST_SIZE); return;
	case ALGORITHM_SHA3_256: arch_sha3_init((struct sha3 *)d, SHA3_256_DIGEST_SIZE); return;
	case ALGORITHM_SHA3_384: arch_sha3_init((struct sha3 *)d, SHA3_384_DIGEST_SIZE); return;
	case ALGORITHM_SHA3_512: arch_sha3_init((struct sha3 *)d, SHA3_512_DIGEST_SIZE); return;
	default: return;
	}
}

static inline void
digest_update(struct digest *d, const u8 *data, unsigned int len)
{
	switch (d->algo) {
	case ALGORITHM_SHA1_160: arch_sha1_160_update((struct sha1 *)d, data, len);   return;
	case ALGORITHM_SHA2_224:
	case ALGORITHM_SHA2_256: arch_sha2_256_update((struct sha256 *)d, data, len); return;
	case ALGORITHM_SHA2_384:
	case ALGORITHM_SHA2_512: arch_sha2_512_update((struct sha512 *)d, data, len); return;
	case ALGORITHM_SHA3_224:
	case ALGORITHM_SHA3_256:
	case ALGORITHM_SHA3_384:
	case ALGORITHM_SHA3_512: arch_sha3_256_update((struct sha3 *)d, data, len);   return;
	default: return;
	}
}

static inline void
digest_final(struct digest *d, u8 *out)
{
	switch (d->algo) {
	case ALGORITHM_SHA1_160: arch_sha1_160_final((struct sha1 *)d, out);   return;
	case ALGORITHM_SHA2_224: arch_sha2_224_final((struct sha256 *)d, out); return;
	case ALGORITHM_SHA2_256: arch_sha2_256_final((struct sha256 *)d, out); return;
	case ALGORITHM_SHA2_384: arch_sha2_384_final((struct sha512 *)d, out); return;
	case ALGORITHM_SHA2_512: arch_sha2_512_final((struct sha512 *)d, out); return;
	case ALGORITHM_SHA3_224:
	case ALGORITHM_SHA3_256:
	case ALGORITHM_SHA3_384:
	case ALGORITHM_SHA3_512: arch_sha3_256_final((struct sha3 *)d, out);   return;
	default: return;
	}
}

/*
 * Constant-time (_ct) dispatch -- guaranteed indirect jump, no bounds branch.
 *
 * These are macros, not functions: they use GNU labels-as-values (&&label +
 * computed goto), which is only valid inside the scope that defines the labels
 * and cannot live in a static inline (address-of-label breaks under inlining).
 *
 * Difference from the switch API above: the dispatch table is rounded up to a
 * power of two and every padding slot is the _undef anchor, so an out-of-range
 * id lands on _undef instead of needing a `cmp/bhi` bounds branch. Combined
 * with ARRAY_STREAMLINED_AT_CT -- the constant-time, branchless accessor
 * (aarch64: `tst; csel`, x86_64: `xor; test; sete; neg; and`) -- the whole
 * dispatch is a masked index + table load + one indirect `goto*`, with no
 * conditional branch at all. The cycle count is independent of the id value.
 *
 * Prefer the switch API by default; reach for _ct when you specifically want a
 * guaranteed constant-time, branchless indirect-jump table (e.g. to keep a hot
 * dispatch loop free of the bounds compare). Note the indirect jump itself
 * still uses the CPU's indirect-branch predictor and can mispredict on a mixed
 * workload.
 */

#define digest_init_ct(_digest, _algo) do { \
	__label__ _sha1, _sha224, _sha256, _sha384, _sha512, \
	          _sha3_224, _sha3_256, _sha3_384, _sha3_512, _undef; \
	struct digest *_d = (_digest); \
	enum algorithm_digest _a = (_algo); \
	STATIC_ARRAY_STREAMLINED(void *, _disp, &&_undef, \
		[ALGORITHM_SHA1_160] = &&_sha1, \
		[ALGORITHM_SHA2_224] = &&_sha224, \
		[ALGORITHM_SHA2_256] = &&_sha256, \
		[ALGORITHM_SHA2_384] = &&_sha384, \
		[ALGORITHM_SHA2_512] = &&_sha512, \
		[ALGORITHM_SHA3_224] = &&_sha3_224, \
		[ALGORITHM_SHA3_256] = &&_sha3_256, \
		[ALGORITHM_SHA3_384] = &&_sha3_384, \
		[ALGORITHM_SHA3_512] = &&_sha3_512 \
	); \
	_d->algo = _a; \
	goto *ARRAY_STREAMLINED_AT_CT(_disp, _a); \
	_sha1:     arch_sha1_160_init((struct sha1 *)_d); break; \
	_sha224:   arch_sha2_224_init((struct sha256 *)_d); break; \
	_sha256:   arch_sha2_256_init((struct sha256 *)_d); break; \
	_sha384:   arch_sha2_384_init((struct sha512 *)_d); break; \
	_sha512:   arch_sha2_512_init((struct sha512 *)_d); break; \
	_sha3_224: arch_sha3_init((struct sha3 *)_d, SHA3_224_DIGEST_SIZE); break; \
	_sha3_256: arch_sha3_init((struct sha3 *)_d, SHA3_256_DIGEST_SIZE); break; \
	_sha3_384: arch_sha3_init((struct sha3 *)_d, SHA3_384_DIGEST_SIZE); break; \
	_sha3_512: arch_sha3_init((struct sha3 *)_d, SHA3_512_DIGEST_SIZE); break; \
	_undef: break; \
} while (0)

#define digest_update_ct(_digest, _data, _len) do { \
	__label__ _sha1, _sha256, _sha512, _sha3, _undef; \
	struct digest *_d = (_digest); \
	STATIC_ARRAY_STREAMLINED(void *, _disp, &&_undef, \
		[ALGORITHM_SHA1_160] = &&_sha1, \
		[ALGORITHM_SHA2_224] = &&_sha256, \
		[ALGORITHM_SHA2_256] = &&_sha256, \
		[ALGORITHM_SHA2_384] = &&_sha512, \
		[ALGORITHM_SHA2_512] = &&_sha512, \
		[ALGORITHM_SHA3_224] = &&_sha3, \
		[ALGORITHM_SHA3_256] = &&_sha3, \
		[ALGORITHM_SHA3_384] = &&_sha3, \
		[ALGORITHM_SHA3_512] = &&_sha3 \
	); \
	goto *ARRAY_STREAMLINED_AT_CT(_disp, _d->algo); \
	_sha1:   arch_sha1_160_update((struct sha1 *)_d, (_data), (_len)); break; \
	_sha256: arch_sha2_256_update((struct sha256 *)_d, (_data), (_len)); break; \
	_sha512: arch_sha2_512_update((struct sha512 *)_d, (_data), (_len)); break; \
	_sha3:   arch_sha3_256_update((struct sha3 *)_d, (_data), (_len)); break; \
	_undef:  break; \
} while (0)

#define digest_final_ct(_digest, _out) do { \
	__label__ _sha1, _sha224, _sha256, _sha384, _sha512, _sha3, _undef; \
	struct digest *_d = (_digest); \
	u8 *_o = (_out); \
	STATIC_ARRAY_STREAMLINED(void *, _disp, &&_undef, \
		[ALGORITHM_SHA1_160] = &&_sha1, \
		[ALGORITHM_SHA2_224] = &&_sha224, \
		[ALGORITHM_SHA2_256] = &&_sha256, \
		[ALGORITHM_SHA2_384] = &&_sha384, \
		[ALGORITHM_SHA2_512] = &&_sha512, \
		[ALGORITHM_SHA3_224] = &&_sha3, \
		[ALGORITHM_SHA3_256] = &&_sha3, \
		[ALGORITHM_SHA3_384] = &&_sha3, \
		[ALGORITHM_SHA3_512] = &&_sha3 \
	); \
	goto *ARRAY_STREAMLINED_AT_CT(_disp, _d->algo); \
	_sha1:   arch_sha1_160_final((struct sha1 *)_d, _o); break; \
	_sha224: arch_sha2_224_final((struct sha256 *)_d, _o); break; \
	_sha256: arch_sha2_256_final((struct sha256 *)_d, _o); break; \
	_sha384: arch_sha2_384_final((struct sha512 *)_d, _o); break; \
	_sha512: arch_sha2_512_final((struct sha512 *)_d, _o); break; \
	_sha3:   arch_sha3_256_final((struct sha3 *)_d, _o); break; \
	_undef:  break; \
} while (0)

#endif
