/*
 * TLS supported-groups registry. Backend-independent storage and lookup for
 * the group subsystem, mirroring the cipher/digest registries. Compiled once
 * per subsystem build (gated on CONFIG_CRYPTO_GROUP) regardless of which
 * backend registers into it.
 */

#include <hpc/compiler.h>
#include <crypto/ecc.h>

/* The negotiable group set is small (a couple dozen code points at most), so
 * a flat table with linear lookup keeps the sparse IANA ids cheap. */
#define CRYPTO_GROUP_MAX 64

static struct group_algorithm *groups[CRYPTO_GROUP_MAX];
static unsigned int groups_count;

void
crypto_group_register(struct group_algorithm *alg)
{
	unsigned int i;

	if (unlikely(!alg))
		return;

	/* Replace an existing registration for the same code point (a later
	 * backend wins), otherwise append. */
	for (i = 0; i < groups_count; i++) {
		if (groups[i]->id == alg->id) {
			groups[i] = alg;
			return;
		}
	}
	if (likely(groups_count < CRYPTO_GROUP_MAX))
		groups[groups_count++] = alg;
}

struct group_algorithm *
crypto_group_by_id(unsigned int id)
{
	unsigned int i;

	for (i = 0; i < groups_count; i++)
		if (groups[i]->id == id)
			return groups[i];
	return NULL;
}

void
crypto_group_enum(fn_group_enum fn)
{
	unsigned int i;

	if (unlikely(!fn))
		return;
	for (i = 0; i < groups_count; i++)
		if (fn(groups[i]))
			return;
}

const char *
crypto_group_name(unsigned int id)
{
	struct group_algorithm *g = crypto_group_by_id(id);

	return g ? g->name : NULL;
}
