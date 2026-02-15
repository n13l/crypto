/*
 * SSLKEYLOGFILE parser and lookup table (draft-ietf-tls-keylogfile-05).
 *
 * See <modules/transform/keylog.h> for the format, the one-lookup contract, the
 * two key schedules an entry's union holds, the ECH inner/outer Random rule and
 * what a build without this module does instead. This file is the whole
 * implementation: a strict line parser, a directory scan, and one global bucket
 * array of struct keylog_entry.
 *
 */

#ifndef CONFIG_CRYPTO_TRANSFORM_KEYLOG
#error "keylog.c is built only under CONFIG_CRYPTO_TRANSFORM_KEYLOG; \
without it <modules/transform/keylog.h> supplies inline no-ops instead"
#endif

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hpc/compiler.h>
#include <hpc/hash/fn.h>
#include <hpc/hash/table.h>

#include <modules/transform/keylog.h>

#ifndef CONFIG_CRYPTO_TRANSFORM_KEYLOG_BITS
#define CONFIG_CRYPTO_TRANSFORM_KEYLOG_BITS 12
#endif

#define KEYLOG_HASH_BITS CONFIG_CRYPTO_TRANSFORM_KEYLOG_BITS
#define KEYLOG_LINE_MAX 4096

_Static_assert(KEYLOG_LINE_MAX > 2 * KEYLOG_SECRET_SIZE_MAX + KEYLOG_CNONCE_HEX + 64,
               "line buffer cannot hold the longest legal line");

static DEFINE_HASHTABLE(keylog_table, KEYLOG_HASH_BITS);
static unsigned int keylog_entries;
static unsigned int keylog_stored;

struct keylog_field {
	const char *name;
	u16 version;
	u16 off;
	u16 size_off;
	u16 max;
};

static const struct keylog_field keylog_fields[KEYLOG_LABEL_MAX] = {
#define KEYLOG_FIELD(sym, str, ver, member, member_size)                        \
	[KEYLOG_##sym] = {                                                     \
		.name     = str,                                               \
		.version  = ver,                                               \
		.off      = offsetof(struct tls_keys, member),                 \
		.size_off = offsetof(struct tls_keys, member_size),            \
		.max      = sizeof(((struct tls_keys *)0)->member),            \
	},
	KEYLOG_LABEL_TABLE(KEYLOG_FIELD)
#undef KEYLOG_FIELD
};

static inline u8 *
field_data(struct tls_keys *keys, const struct keylog_field *f)
{
	return (u8 *)keys + f->off;
}

static inline u16 *
field_size(struct tls_keys *keys, const struct keylog_field *f)
{
	return (u16 *)(void *)((u8 *)keys + f->size_off);
}

const char *
keylog_label_name(enum keylog_label label)
{
	if (unlikely(label >= KEYLOG_LABEL_MAX))
		return NULL;
	return keylog_fields[label].name;
}

enum keylog_label
keylog_label_id(const char *name, size_t len)
{
	unsigned int i;

	for (i = 0; i < KEYLOG_LABEL_MAX; i++) {
		const char *it = keylog_fields[i].name;
		if (strlen(it) == len && !memcmp(it, name, len))
			return (enum keylog_label)i;
	}
	return KEYLOG_LABEL_MAX;
}

static inline u32
keylog_hash(const u8 *cnonce)
{
	return hash_buffer_u32(cnonce, KEYLOG_CNONCE_SIZE, KEYLOG_HASH_BITS);
}

unsigned int
keylog_count(void)
{
	return keylog_entries;
}

unsigned int
keylog_secrets(void)
{
	return keylog_stored;
}

const struct keylog_entry *
keylog_find(const u8 cnonce[32])
{
	u32 hash;

	if (unlikely(!cnonce))
		return NULL;

	hash = keylog_hash(cnonce);
	hash_for_each(keylog_table, hash, it, struct keylog_entry, q)
		if (!memcmp(it->cnonce, cnonce, KEYLOG_CNONCE_SIZE))
			return it;

	return NULL;
}

const struct tls_keys *
keylog_keys(const u8 cnonce[32])
{
	const struct keylog_entry *entry = keylog_find(cnonce);

	return entry ? &entry->keys : NULL;
}

const u8 *
keylog_keys_secret(const struct tls_keys *keys, enum keylog_label label,
                   u16 *size)
{
	const struct keylog_field *f;
	struct tls_keys *k;
	u16 n;

	if (size)
		*size = 0;

	if (unlikely(!keys || label >= KEYLOG_LABEL_MAX))
		return NULL;

	f = &keylog_fields[label];
	if (f->version != keys->version)
		return NULL;

	k = (struct tls_keys *)keys;
	if (!(n = *field_size(k, f)))
		return NULL;

	if (size)
		*size = n;
	return field_data(k, f);
}

/* -- parsing --------------------------------------------------------------- */

static inline int
hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int
hexdecode(const char *str, size_t len, u8 *buf, size_t bytes)
{
	size_t i;

	if (len != bytes * 2)
		return -1;

	for (i = 0; i < bytes; i++) {
		int hi = hexval((unsigned char)str[i * 2]);
		int lo = hexval((unsigned char)str[i * 2 + 1]);

		if (unlikely(hi < 0 || lo < 0))
			return -1;
		buf[i] = (u8)((hi << 4) | lo);
	}
	return 0;
}

static size_t
token(const char *p, const char *end)
{
	const char *it = p;

	while (it < end && *it != ' ' && *it != '\t')
		it++;
	return (size_t)(it - p);
}

static const char *
skip_blanks(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	return p;
}

static struct keylog_entry *
keylog_intern(const u8 *cnonce)
{
	struct keylog_entry *entry;
	u32 hash = keylog_hash(cnonce);

	hash_for_each(keylog_table, hash, it, struct keylog_entry, q)
		if (!memcmp(it->cnonce, cnonce, KEYLOG_CNONCE_SIZE))
			return it;

	if (unlikely(!(entry = calloc(1, sizeof(*entry)))))
		return NULL;

	memcpy(entry->cnonce, cnonce, KEYLOG_CNONCE_SIZE);
	hash_init(entry->q);
	hash_add(keylog_table, &entry->q, hash);
	keylog_entries++;

	return entry;
}

static void
keylog_forget(struct keylog_entry *entry, u16 version)
{
	unsigned int i;

	for (i = 0; i < KEYLOG_LABEL_MAX; i++) {
		const struct keylog_field *f = &keylog_fields[i];

		if (f->version != version)
			continue;
		if (*field_size(&entry->keys, f))
			keylog_stored--;
		memset(field_data(&entry->keys, f), 0, f->max);
		*field_size(&entry->keys, f) = 0;
	}
}

static int
keylog_select(struct keylog_entry *entry, u16 version)
{
	if (entry->keys.version == version)
		return 0;

	if (entry->keys.version > version)
		return -1;

	if (entry->keys.version)
		keylog_forget(entry, entry->keys.version);
	entry->keys.version = version;

	return 0;
}

static void
keylog_store(struct keylog_entry *entry, const struct keylog_field *f,
             const u8 *data, u16 size)
{
	u16 *stored = field_size(&entry->keys, f);
	u8 *buf = field_data(&entry->keys, f);

	if (!*stored)
		keylog_stored++;
	else if (*stored > size)
		memset(buf + size, 0, *stored - size);

	memcpy(buf, data, size);
	*stored = size;
}

int
keylog_add_line(const char *line, size_t len)
{
	u8 cnonce[KEYLOG_CNONCE_SIZE], secret[KEYLOG_SECRET_SIZE_MAX];
	const struct keylog_field *f;
	struct keylog_entry *entry;
	enum keylog_label label;
	const char *p, *end;
	int ret = 0;
	size_t n;

	if (unlikely(!line))
		return 0;

	end = line + len;
	while (end > line && (end[-1] == '\n' || end[-1] == '\r' ||
	                      end[-1] == ' ' || end[-1] == '\t'))
		end--;

	p = skip_blanks(line, end);
	if (p == end || *p == '#')
		return 0;

	/* field 1: the label */
	n = token(p, end);
	label = keylog_label_id(p, n);
	if (label == KEYLOG_LABEL_MAX)
		return 0;               /* a label this revision does not define */
	f = &keylog_fields[label];
	p = skip_blanks(p + n, end);

	/* field 2: the ClientHello Random, exactly 64 hex characters */
	n = token(p, end);
	if (hexdecode(p, n, cnonce, KEYLOG_CNONCE_SIZE))
		return 0;
	p = skip_blanks(p + n, end);
	n = token(p, end);
	if (!n || (n & 1) || n > 2 * (size_t)f->max)
		return 0;
	if (hexdecode(p, n, secret, n / 2))
		return 0;

	/* nothing may follow it */
	if (skip_blanks(p + n, end) != end)
		goto out;

	if (unlikely(!(entry = keylog_intern(cnonce)))) {
		ret = -1;
		goto out;
	}

	if (keylog_select(entry, f->version))
		goto out;               /* the other schedule owns this entry */

	keylog_store(entry, f, secret, (u16)(n / 2));
	ret = 1;
out:
	memset(secret, 0, sizeof(secret));
	return ret;
}

int
keylog_load(const char *path)
{
	char line[KEYLOG_LINE_MAX];
	unsigned int added = 0;
	FILE *f;

	if (unlikely(!path || !*path)) {
		errno = EINVAL;
		return -1;
	}

	if (!(f = fopen(path, "r")))
		return -1;

	while (fgets(line, sizeof(line), f)) {
		size_t len = strlen(line);
		if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
			int c;
			while ((c = fgetc(f)) != EOF && c != '\n')
				;
			continue;
		}
		if (keylog_add_line(line, len) > 0)
			added++;
	}

	fclose(f);
	return (int)added;
}

int
keylog_init(void)
{
	const char *path = getenv("SSLKEYLOGFILE");

	if (!path || !*path)
		return 0;

	return keylog_load(path);
}

static bool
is_keylog_name(const char *name)
{
	size_t len = strlen(name), suffix = strlen(KEYLOG_FILE_SUFFIX);

	return len > suffix && !strcmp(name + len - suffix, KEYLOG_FILE_SUFFIX);
}

static int
cmp_name(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int
keylog_load_dir(const char *dir)
{
	char **names = NULL, path[4096];
	unsigned int count = 0, size = 0, i;
	int added = 0, saved;
	struct dirent *de;
	DIR *d;

	if (unlikely(!dir || !*dir)) {
		errno = EINVAL;
		return -1;
	}

	if (!(d = opendir(dir)))
		return -1;

	while ((de = readdir(d))) {
		char *copy;

		if (!is_keylog_name(de->d_name))
			continue;

		if (count == size) {
			unsigned int want = size ? size * 2 : 16;
			char **grown = realloc(names, want * sizeof(*names));

			if (unlikely(!grown))
				break;
			names = grown;
			size = want;
		}

		if (unlikely(!(copy = strdup(de->d_name))))
			break;
		names[count++] = copy;
	}
	saved = errno;
	closedir(d);

	if (count)
		qsort(names, count, sizeof(*names), cmp_name);

	for (i = 0; i < count; i++) {
		int n;

		snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
		if ((n = keylog_load(path)) > 0)
			added += n;
		free(names[i]);
	}
	free(names);

	errno = saved;
	return added;
}

void
keylog_fini(void)
{
	unsigned int i;

	for (i = 0; i < array_size(keylog_table); i++) {
		hash_for_each_delsafe(keylog_table, i, it, struct keylog_entry, q) {
			hash_del(&it->q);
			memset(it, 0, sizeof(*it));
			free(it);
		}
	}
	keylog_entries = 0;
	keylog_stored = 0;
}
