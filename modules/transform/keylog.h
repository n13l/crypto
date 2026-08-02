/*
 * SSLKEYLOGFILE — secrets keyed by ClientHello Random (cnonce)
 *
 * Reads the key log format specified by draft-ietf-tls-keylogfile-05 into one
 * global, intrusive hash table (<hpc/hash/table.h>) and hands back everything
 * logged for a ClientHello Random in a single lookup. It is a transform, not an
 * algorithm: nothing is derived here, the bytes a peer already wrote down are
 * parsed and indexed.
 *
 * Every line is
 *
 *      LABEL client_random secret
 *
 * single-space separated, client_random being the 32-byte ClientHello Random
 * as 64 hex characters and secret the material as hex of label-dependent
 * length. That second field is what this tree calls the cnonce (see
 * modules/net/tls/protocol.h), so a decoder that has parsed a ClientHello
 * already holds the lookup key.
 *
 * One lookup, then plain field access
 * ----------------------------------
 *
 * keylog_find() returns the whole struct keylog_entry: every secret the log
 * carried for that cnonce, each already decoded and allocated. A decoder hashes
 * once, keeps the pointer for the life of the session, and reads the labels it
 * needs as array elements — there is no per-attribute query, and no second
 * lookup when the next secret is wanted:
 *
 *      const struct keylog_entry *k = keylog_find(p->cnonce);
 *      if (k) {
 *              const struct keylog_secret *c = &k->secret[KEYLOG_CLIENT_TRAFFIC_SECRET_0];
 *              const struct keylog_secret *s = &k->secret[KEYLOG_SERVER_TRAFFIC_SECRET_0];
 *              if (c->data && s->data)
 *                      ...
 *      }
 *
 * The table is written once, by the load functions, and read-only afterwards:
 * lookups take no lock and no reference, and the pointers they return stay
 * valid until keylog_fini(). Loading concurrently with lookups is therefore not
 * allowed — load at startup, before any worker runs.
 *
 * Without CONFIG_CRYPTO_TRANSFORM_KEYLOG none of this is compiled: the
 * declarations below become inline stubs, so a caller needs no #ifdef of its
 * own and keylog_find() folds to a constant NULL that takes its branch with it.
 *
 * ECH (draft section "Secret Labels for ECH"). Which Random keys a line
 * depends on the label, and this matters to a passive decoder because it sees
 * both:
 *
 *   - ECH_SECRET and ECH_CONFIG always use the Random of the *outer*
 *     ClientHello.
 *   - every other label uses the *inner* Random when ECH was accepted, and
 *     the outer one otherwise.
 *
 * Since the table is keyed by whatever Random its line carried, that is two
 * lookups rather than a special case: look up the outer cnonce for ECH_SECRET,
 * decrypt the inner ClientHello, then look up the inner cnonce for the traffic
 * secrets.
 */

#ifndef __MODULES_TRANSFORM_KEYLOG_H__
#define __MODULES_TRANSFORM_KEYLOG_H__

#include <hpc/compiler.h>
#include <hpc/queue.h>
#include <stdbool.h>
#include <stddef.h>

/* The ClientHello Random: 32 bytes, 64 hex characters on the line. */
#define KEYLOG_CNONCE_SIZE 32
#define KEYLOG_CNONCE_HEX  (KEYLOG_CNONCE_SIZE * 2)

/*
 * Largest secret accepted for one label. The derived secrets are bounded by
 * the hash of the cipher suite (64 bytes at SHA-512) and the TLS 1.2 master
 * secret is 48, so this ceiling exists for ECH_CONFIG alone, which carries a
 * whole ECHConfigList and has no size fixed by the negotiated algorithms.
 * A longer value is rejected rather than truncated.
 */
#define KEYLOG_SECRET_SIZE_MAX 1024

/*
 * What keylog_load_dir() considers a key log. The draft names no extension —
 * this is the tree's convention, so a capture directory can hold a .pcap and
 * the .keylog that decrypts it side by side.
 */
#define KEYLOG_FILE_SUFFIX ".keylog"

/*
 * The labels of draft-ietf-tls-keylogfile-05, in the draft's own order: the
 * TLS 1.3 secrets, the single TLS 1.2 label, then the two ECH labels. Declared
 * once here so the enum and the name table cannot drift apart; a label outside
 * this set is ignored when read, which is what the draft's extensibility rules
 * ask for.
 */
#define KEYLOG_LABEL_TABLE(X) \
	X(CLIENT_EARLY_TRAFFIC_SECRET,      "CLIENT_EARLY_TRAFFIC_SECRET")      \
	X(EARLY_EXPORTER_SECRET,            "EARLY_EXPORTER_SECRET")            \
	X(CLIENT_HANDSHAKE_TRAFFIC_SECRET,  "CLIENT_HANDSHAKE_TRAFFIC_SECRET")  \
	X(SERVER_HANDSHAKE_TRAFFIC_SECRET,  "SERVER_HANDSHAKE_TRAFFIC_SECRET")  \
	X(CLIENT_TRAFFIC_SECRET_0,          "CLIENT_TRAFFIC_SECRET_0")          \
	X(SERVER_TRAFFIC_SECRET_0,          "SERVER_TRAFFIC_SECRET_0")          \
	X(EXPORTER_SECRET,                  "EXPORTER_SECRET")                  \
	X(CLIENT_RANDOM,                    "CLIENT_RANDOM")                    \
	X(ECH_SECRET,                       "ECH_SECRET")                       \
	X(ECH_CONFIG,                       "ECH_CONFIG")

enum keylog_label {
#define KEYLOG_LABEL_ENUM(sym, str) KEYLOG_##sym,
	KEYLOG_LABEL_TABLE(KEYLOG_LABEL_ENUM)
#undef KEYLOG_LABEL_ENUM
	/* Also the "no such label" answer of keylog_label_id(). */
	KEYLOG_LABEL_MAX
};

__BEGIN_DECLS

/*
 * One secret. @size is 0 and @data NULL for a label the log did not carry, so
 * a slot is present exactly when @data is.
 */
struct keylog_secret {
	const u8 *data;
	u16 size;
};

/*
 * Everything logged for one ClientHello Random: a slot per label, indexed by
 * enum keylog_label, each already decoded and allocated. This is what a lookup
 * returns, so reaching any secret afterwards is an array index — no query, no
 * copy, no second hash. @q is the bucket link, owned by the table.
 */
struct keylog_entry {
	u8 cnonce[KEYLOG_CNONCE_SIZE];
	struct keylog_secret secret[KEYLOG_LABEL_MAX];
	struct qnode q;
};

/**
 * The secret an entry carries for one label
 * @entry: from keylog_find(), may be NULL
 * @label: which secret
 *
 * A bounds-checked read of @entry->secret[@label], NULL for an absent slot or a
 * NULL entry, so the two failure cases a caller has — unknown cnonce, label not
 * logged — collapse into one test. Reading the array directly is equally
 * correct when the entry is known to be non-NULL.
 */
static inline const struct keylog_secret *
keylog_entry_secret(const struct keylog_entry *entry, enum keylog_label label)
{
	if (unlikely(!entry || label >= KEYLOG_LABEL_MAX))
		return NULL;
	return entry->secret[label].data ? &entry->secret[label] : NULL;
}

#ifdef CONFIG_CRYPTO_TRANSFORM_KEYLOG

/**
 * Look up everything logged for one ClientHello Random
 * @cnonce: 32 bytes of ClientHello Random
 *
 * The one lookup a decoder makes. Returns the entry with every secret already
 * decoded and allocated, or NULL when nothing was logged for that cnonce. The
 * pointer stays valid until keylog_fini(), so a session keeps it rather than
 * looking up again.
 */
const struct keylog_entry *keylog_find(const u8 *cnonce);

/**
 * Load every key log in a directory
 * @dir: directory to scan, typically <instance root>/pcap
 *
 * Reads every file whose name ends in KEYLOG_FILE_SUFFIX, in sorted order so a
 * merge is reproducible across runs, and merges them into the table. Returns
 * the number of secrets added, or -1 with errno set when @dir cannot be read —
 * ENOENT being the ordinary "no key material here" answer, not a failure.
 */
int keylog_load_dir(const char *dir);

/**
 * Load one key log file into the table
 * @path: file to read
 *
 * Adds to whatever is already there, so several files can be merged; a label
 * logged twice for one cnonce keeps the value read last. Malformed lines,
 * comments (#) and unknown labels are skipped, not fatal. Returns the number
 * of secrets added, or -1 with errno set if @path cannot be opened.
 */
int keylog_load(const char *path);

/**
 * Load the key log named by $SSLKEYLOGFILE
 *
 * Returns the number of secrets added, 0 when the variable is unset or empty
 * (not an error — it is how the feature stays off), and -1 with errno set when
 * the file is named but cannot be read.
 */
int keylog_init(void);

/**
 * Add one key log line
 * @line: the line, without its terminator (a trailing CR/LF is tolerated)
 * @len: its length
 *
 * The same parser the load functions run, for callers holding the log in memory
 * rather than in a file. Returns 1 when a secret was stored, 0 when the line
 * was skipped, -1 on allocation failure.
 */
int keylog_add_line(const char *line, size_t len);

/**
 * Release the table and every secret in it
 *
 * Zeroes the material before freeing it. Every pointer previously returned is
 * dangling afterwards.
 */
void keylog_fini(void);

/**
 * Number of ClientHello Randoms in the table
 */
unsigned int keylog_count(void);

/**
 * Number of secrets in the table, across every entry and label
 */
unsigned int keylog_secrets(void);

/**
 * The on-the-wire name of a label
 * @label: which label
 *
 * Returns NULL for a label outside the set.
 */
const char *keylog_label_name(enum keylog_label label);

/**
 * The label a name denotes
 * @name: label token, not necessarily terminated
 * @len: its length
 *
 * Returns KEYLOG_LABEL_MAX for a name this draft revision does not define.
 */
enum keylog_label keylog_label_id(const char *name, size_t len);

#else /* !CONFIG_CRYPTO_TRANSFORM_KEYLOG */

/*
 * The module is not built. Every entry point is an inline that does nothing, so
 * a decoder or a daemon calls them unconditionally and pays nothing: a lookup
 * is a constant NULL, which takes the branch that tested it out of the
 * generated code along with the body, and a load is a constant 0. The types and
 * the labels above stay declared, so code naming them still compiles.
 */

static inline const struct keylog_entry *
keylog_find(const u8 *cnonce)
{
	(void)cnonce;
	return NULL;
}

static inline int keylog_load_dir(const char *dir) { (void)dir; return 0; }
static inline int keylog_load(const char *path) { (void)path; return 0; }
static inline int keylog_init(void) { return 0; }

static inline int
keylog_add_line(const char *line, size_t len)
{
	(void)line; (void)len;
	return 0;
}

static inline void keylog_fini(void) { }
static inline unsigned int keylog_count(void) { return 0; }
static inline unsigned int keylog_secrets(void) { return 0; }

static inline const char *
keylog_label_name(enum keylog_label label)
{
	(void)label;
	return NULL;
}

static inline enum keylog_label
keylog_label_id(const char *name, size_t len)
{
	(void)name; (void)len;
	return KEYLOG_LABEL_MAX;
}

#endif /* CONFIG_CRYPTO_TRANSFORM_KEYLOG */

__END_DECLS

#endif
