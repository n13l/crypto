/*
 * SSLKEYLOGFILE parser and lookup table (draft-ietf-tls-keylogfile-05).
 *
 * See <modules/transform/keylog.h> for the format, the one-lookup contract, the
 * ECH inner/outer Random rule and what a build without this module does
 * instead. This file is the whole implementation: a strict line parser, a
 * directory scan, and one global bucket array of struct keylog_entry.
 *
 * Hex decoding is done here rather than through modules/transform/b16, whose
 * decoder maps a non-hex character to a wrong nibble instead of failing. A key
 * log is a file this process did not write, so a malformed line has to be
 * refused; that means a validating decoder.
 */

#ifndef CONFIG_CRYPTO_TRANSFORM_KEYLOG
#error "keylog.c is built only under CONFIG_CRYPTO_TRANSFORM_KEYLOG; \
without it <modules/transform/keylog.h> supplies inline no-ops instead"
#endif

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hpc/compiler.h>
#include <hpc/hash/fn.h>
#include <hpc/hash/table.h>

#include <modules/transform/keylog.h>

/*
 * Buckets. A key log for a capture holds one entry per connection: a few
 * thousand is ordinary, so 4096 buckets keep the chains at one or two entries
 * for a whole day of traffic while costing 32 KB of bss.
 */
#ifndef CONFIG_CRYPTO_TRANSFORM_KEYLOG_BITS
#define CONFIG_CRYPTO_TRANSFORM_KEYLOG_BITS 12
#endif

#define KEYLOG_HASH_BITS CONFIG_CRYPTO_TRANSFORM_KEYLOG_BITS

/*
 * Line buffer. The longest line the draft allows is an ECH_CONFIG: label,
 * 64 hex characters of Random and 2 * KEYLOG_SECRET_SIZE_MAX of secret, plus
 * separators and a terminator. Round that up to a page.
 */
#define KEYLOG_LINE_MAX 4096

_Static_assert(KEYLOG_LINE_MAX > 2 * KEYLOG_SECRET_SIZE_MAX + KEYLOG_CNONCE_HEX + 64,
               "line buffer cannot hold the longest legal line");

static DEFINE_HASHTABLE(keylog_table, KEYLOG_HASH_BITS);
static unsigned int keylog_entries;
static unsigned int keylog_stored;

static const char *keylog_labels[KEYLOG_LABEL_MAX] = {
#define KEYLOG_LABEL_NAME(sym, str) [KEYLOG_##sym] = str,
	KEYLOG_LABEL_TABLE(KEYLOG_LABEL_NAME)
#undef KEYLOG_LABEL_NAME
};

const char *
keylog_label_name(enum keylog_label label)
{
	if (unlikely(label >= KEYLOG_LABEL_MAX))
		return NULL;
	return keylog_labels[label];
}

enum keylog_label
keylog_label_id(const char *name, size_t len)
{
	unsigned int i;

	for (i = 0; i < KEYLOG_LABEL_MAX; i++) {
		const char *it = keylog_labels[i];
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

/*
 * The lookup. One hash, one chain walk, and the caller has every secret logged
 * for that cnonce — see the header on why this returns the entry rather than
 * one attribute.
 */
const struct keylog_entry *
keylog_find(const u8 *cnonce)
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

/*
 * Decode @len hex characters into @bytes bytes, all or nothing: an odd length,
 * a wrong length or any character that is not hex leaves @buf alone and
 * returns -1. The draft writes both cases in lower case, but readers are told
 * to accept either.
 */
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

/* the token starting at @p, bounded by @end: its length up to the next space */
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

/*
 * Find the entry for @cnonce, or create and insert one. NULL only on
 * allocation failure.
 */
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

/*
 * Store @data under @label. A label logged twice for one cnonce keeps the
 * value read last: a merged log can carry a stale line for a Random that was
 * reused, and the later line is the one the peer wrote later. Directory loads
 * are sorted for exactly this reason — which line is last has to be a property
 * of the files, not of readdir() order.
 */
static int
keylog_store(struct keylog_entry *entry, enum keylog_label label,
             const u8 *data, u16 size)
{
	struct keylog_secret *s = &entry->secret[label];
	u8 *copy;

	if (unlikely(!(copy = malloc(size))))
		return -1;
	memcpy(copy, data, size);

	if (s->data) {
		/* the material is a secret; do not leave it in the heap */
		memset((u8 *)s->data, 0, s->size);
		free((u8 *)s->data);
	} else {
		keylog_stored++;
	}
	s->data = copy;
	s->size = size;

	return 0;
}

int
keylog_add_line(const char *line, size_t len)
{
	u8 cnonce[KEYLOG_CNONCE_SIZE], secret[KEYLOG_SECRET_SIZE_MAX];
	struct keylog_entry *entry;
	enum keylog_label label;
	const char *p, *end;
	size_t n;

	if (unlikely(!line))
		return 0;

	end = line + len;
	/* tolerate CRLF and trailing blanks, whatever wrote the file */
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
	p = skip_blanks(p + n, end);

	/* field 2: the ClientHello Random, exactly 64 hex characters */
	n = token(p, end);
	if (hexdecode(p, n, cnonce, KEYLOG_CNONCE_SIZE))
		return 0;
	p = skip_blanks(p + n, end);

	/* field 3: the secret, label-dependent length */
	n = token(p, end);
	if (!n || (n & 1) || n > 2 * KEYLOG_SECRET_SIZE_MAX)
		return 0;
	if (hexdecode(p, n, secret, n / 2))
		return 0;

	/* nothing may follow it */
	if (skip_blanks(p + n, end) != end)
		return 0;

	if (unlikely(!(entry = keylog_intern(cnonce))))
		return -1;

	return keylog_store(entry, label, secret, (u16)(n / 2)) ? -1 : 1;
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

		/*
		 * No terminator means the line did not fit, so it is longer
		 * than any legal line: drain the rest and skip it, rather than
		 * parsing a prefix into a secret that is missing its tail.
		 */
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

/* -- directory scan -------------------------------------------------------- */

static bool
is_keylog_name(const char *name)
{
	size_t len = strlen(name), suffix = strlen(KEYLOG_FILE_SUFFIX);

	/* ".keylog" alone is a suffix and no name: require something before it */
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

	/*
	 * Collect the names first, then load them in sorted order: readdir()
	 * order is whatever the filesystem hands back, and it decides which of
	 * two files logging the same label for the same Random wins. A decode
	 * that changes between runs of the same daemon over the same directory
	 * is not worth the syscall this saves.
	 */
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
		/*
		 * One unreadable file does not fail the load: the others still
		 * decrypt what they cover, and a caller that wants to know about
		 * a particular file names it through keylog_load().
		 */
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
	unsigned int i, l;

	for (i = 0; i < array_size(keylog_table); i++) {
		hash_for_each_delsafe(keylog_table, i, it, struct keylog_entry, q) {
			for (l = 0; l < KEYLOG_LABEL_MAX; l++) {
				struct keylog_secret *s = &it->secret[l];
				if (!s->data)
					continue;
				memset((u8 *)s->data, 0, s->size);
				free((u8 *)s->data);
			}
			hash_del(&it->q);
			memset(it, 0, sizeof(*it));
			free(it);
		}
	}
	keylog_entries = 0;
	keylog_stored = 0;
}
