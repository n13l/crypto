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
 * Two eras, one entry
 * -------------------
 *
 * A key log describes one handshake per Random, and a handshake belongs to
 * exactly one key schedule: either the RFC 8446 one, whose secrets are the
 * *_TRAFFIC_SECRET and EXPORTER_SECRET labels, or the RFC 5246 one and its
 * ancestors, whose material is the master secret and the pre-master secret it
 * was derived from. No connection has both, which is why struct tls_keys
 * carries the two as a union discriminated by @version and not as two sets of
 * fields that would be half empty in every entry.
 *
 * The buffers inside the union are inline and cut to the ceilings in
 * <modules/net/tls/bounds.h> — TLS_TRAFFIC_SECRET_MAX for a TLS 1.3 secret,
 * TLS_MASTER_SECRET_MAX for the 48 bytes of RFC 5246 §8.1, and so on — so a
 * secret costs no allocation, the length beside each buffer says how much of
 * it a line actually carried, and the sizes stay auditable against the RFCs
 * rather than against this file. Only the entry itself is allocated.
 *
 * @version is what the log's own labels imply and nothing more: a line the
 * TLS 1.3 schedule produced sets ID_TLSV13, and CLIENT_RANDOM or
 * PMS_CLIENT_RANDOM set ID_TLSV12, which stands for "TLS 1.2 and
 * below" because those two labels are the same in TLS 1.0 and 1.1. It is zero
 * until a line fixes it. Should a log carry both eras for one Random — some
 * implementations emit CLIENT_RANDOM next to the 1.3 secrets, and merged logs
 * can reuse a Random — TLS 1.3 wins and the 1.2 arm is dropped, whichever
 * order the lines arrive in: it is the arm that decrypts such a session.
 *
 * The two ECH labels are in the 1.3 arm with the rest, which is where they
 * belong even though they are keyed by a different Random: ECH exists only
 * above TLS 1.2, so an ECH line settles the entry as 1.3 as surely as a
 * traffic secret does. What is different about them is the *key*, not the arm
 * — see the ECH note at the end.
 *
 * One lookup, then plain field access
 * -----------------------------------
 *
 * keylog_keys() returns the whole struct tls_keys: every secret the log
 * carried for that cnonce, already decoded, in the same struct the decoder
 * keeps per connection (<modules/net/tls/protocol.h>). A channel hashes once
 * on its ClientHello, keeps the pointer for the life of the session, and reads
 * the fields it needs — there is no per-attribute query, and no second lookup
 * when the next secret is wanted:
 *
 *      const struct tls_keys *k = keylog_keys(cnonce);
 *
 *      if (k && k->version == ID_TLSV13) {
 *              const u8 *c = k->v13.client_traffic_secret_0;
 *              const u8 *s = k->v13.server_traffic_secret_0;
 *              u16 size    = k->v13.client_traffic_secret_0_size;
 *              ...
 *      } else if (k && k->version == ID_TLSV12) {
 *              const u8 *ms = k->v1x.master_secret;
 *              ...
 *      }
 *
 * Test @version before reading either arm. The two overlap, so a field of the
 * arm @version does not name holds whatever the other arm put there; a size of
 * zero means "not logged" only within the arm that is live.
 * keylog_keys_secret() does both checks for callers that reach a secret by
 * label rather than by name.
 *
 * The table is written once, by the load functions, and read-only afterwards:
 * lookups take no lock and no reference, and the pointers they return stay
 * valid until keylog_fini(). Loading concurrently with lookups is therefore not
 * allowed — load at startup, before any worker runs.
 *
 * Without CONFIG_CRYPTO_TRANSFORM_KEYLOG none of this is compiled: the
 * declarations below become inline stubs, so a caller needs no #ifdef of its
 * own and keylog_keys() folds to a constant NULL that takes its branch with it.
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

#include <modules/net/tls/bounds.h>
#include <modules/net/tls/protocol.h>

/* The ClientHello Random: 32 bytes, 64 hex characters on the line. */
#define KEYLOG_CNONCE_SIZE TLS_KEYLOG_CNONCE_SIZE
#define KEYLOG_CNONCE_HEX  TLS_KEYLOG_HEX(KEYLOG_CNONCE_SIZE)

/*
 * The widest field of struct tls_keys, which is what a line's secret is
 * checked against before it is decoded at all. Two labels reach past the
 * derived-secret ceiling and they do it for different reasons: the pre-master
 * secret because the group and not the hash decides its width (ffdhe8192,
 * TLS_SHARED_SECRET_MAX), and ECH_CONFIG because an ECHConfigList is a
 * structure with no algorithmic size at all, capped by the decoder at
 * TLS_ECH_CONFIG_INLINE.
 */
#define KEYLOG_SECRET_SIZE_MAX                                                 \
	(TLS_PRE_MASTER_SECRET_MAX > TLS_ECH_CONFIG_INLINE ?                   \
	 TLS_PRE_MASTER_SECRET_MAX : TLS_ECH_CONFIG_INLINE)

/*
 * What keylog_load_dir() considers a key log. The draft names no extension —
 * this is the tree's convention, so a capture directory can hold a .pcap and
 * the .keylog that decrypts it side by side.
 */
#define KEYLOG_FILE_SUFFIX ".keylog"

/*
 * The labels this revision understands: the TLS 1.3 secrets of
 * draft-ietf-tls-keylogfile-05 in the draft's own order, the two TLS 1.x
 * labels, then the two ECH ones. Declared once here so the enum, the wire
 * names and the field each label stores into cannot drift apart; a label
 * outside this set is ignored when read, which is what the draft's
 * extensibility rules ask for.
 *
 * Each row is
 *
 *      X(symbol, wire name, version, member, member's size)
 *
 * where @version is the union arm the member lives in and the two members are
 * paths into struct tls_keys. The buffer's own sizeof is the ceiling a line
 * is refused at, so there is no third size to keep in step.
 *
 * PMS_CLIENT_RANDOM and CLIENT_RANDOM are the NSS format's two TLS 1.x lines,
 * carried into the draft's syntax unchanged: the first logs the pre-master
 * secret, the second the master secret derived from it. A decoder that has the
 * master secret needs nothing else; one that has only the pre-master secret
 * has to run the PRF over it and the two Randoms itself, which is why both are
 * kept rather than only the shorter path.
 */
#define KEYLOG_LABEL_TABLE(X)                                                  \
	X(CLIENT_EARLY_TRAFFIC_SECRET, "CLIENT_EARLY_TRAFFIC_SECRET",          \
	  ID_TLSV13,                                                \
	  v13.client_early_traffic_secret,                                     \
	  v13.client_early_traffic_secret_size)                                \
	X(EARLY_EXPORTER_SECRET, "EARLY_EXPORTER_SECRET",                      \
	  ID_TLSV13,                                                \
	  v13.early_exporter_secret,                                           \
	  v13.early_exporter_secret_size)                                      \
	X(CLIENT_HANDSHAKE_TRAFFIC_SECRET, "CLIENT_HANDSHAKE_TRAFFIC_SECRET",  \
	  ID_TLSV13,                                                \
	  v13.client_handshake_traffic_secret,                                 \
	  v13.client_handshake_traffic_secret_size)                            \
	X(SERVER_HANDSHAKE_TRAFFIC_SECRET, "SERVER_HANDSHAKE_TRAFFIC_SECRET",  \
	  ID_TLSV13,                                                \
	  v13.server_handshake_traffic_secret,                                 \
	  v13.server_handshake_traffic_secret_size)                            \
	X(CLIENT_TRAFFIC_SECRET_0, "CLIENT_TRAFFIC_SECRET_0",                  \
	  ID_TLSV13,                                                \
	  v13.client_traffic_secret_0,                                         \
	  v13.client_traffic_secret_0_size)                                    \
	X(SERVER_TRAFFIC_SECRET_0, "SERVER_TRAFFIC_SECRET_0",                  \
	  ID_TLSV13,                                                \
	  v13.server_traffic_secret_0,                                         \
	  v13.server_traffic_secret_0_size)                                    \
	X(EXPORTER_SECRET, "EXPORTER_SECRET",                                  \
	  ID_TLSV13,                                                \
	  v13.exporter_secret,                                                 \
	  v13.exporter_secret_size)                                            \
	X(CLIENT_RANDOM, "CLIENT_RANDOM",                                      \
	  ID_TLSV12,                                                \
	  v1x.master_secret,                                                   \
	  v1x.master_secret_size)                                              \
	X(PMS_CLIENT_RANDOM, "PMS_CLIENT_RANDOM",                              \
	  ID_TLSV12,                                                \
	  v1x.pre_master_secret,                                               \
	  v1x.pre_master_secret_size)                                          \
	X(ECH_SECRET, "ECH_SECRET",                                            \
	  ID_TLSV13,                                                \
	  v13.ech_secret,                                                      \
	  v13.ech_secret_size)                                                 \
	X(ECH_CONFIG, "ECH_CONFIG",                                            \
	  ID_TLSV13,                                                \
	  v13.ech_config,                                                      \
	  v13.ech_config_size)

enum keylog_label {
#define KEYLOG_LABEL_ENUM(sym, str, ver, member, member_len) KEYLOG_##sym,
	KEYLOG_LABEL_TABLE(KEYLOG_LABEL_ENUM)
#undef KEYLOG_LABEL_ENUM
	/* Also the "no such label" answer of keylog_label_id(). */
	KEYLOG_LABEL_MAX
};

__BEGIN_DECLS

/*
 * One entry of the table: the Random it is keyed by and the material logged
 * under it, inline. This is what a lookup returns, so reaching any secret
 * afterwards is a field access — no query, no copy, no second hash. @q is the
 * bucket link, owned by the table.
 */
struct keylog_entry {
	u8 cnonce[KEYLOG_CNONCE_SIZE];
	struct tls_keys keys;
	struct qnode q;
};

#ifdef CONFIG_CRYPTO_TRANSFORM_KEYLOG

/**
 * The key material logged for one ClientHello Random
 * @cnonce: 32 bytes of ClientHello Random
 *
 * The lookup a decoder makes, once, on the hello that gave it the Random.
 * Returns the struct tls_keys the log filled — its @version says which arm is
 * live — or NULL when nothing was logged for that cnonce.
 *
 * The table is read-only after loading, so the pointer stays valid until
 * keylog_fini() and a session keeps it rather than copying: a channel that has
 * seen its ClientHello holds every secret the log had for it in one word.
 */
const struct tls_keys *keylog_keys(const u8 cnonce[32]);

/**
 * The table entry for one ClientHello Random
 * @cnonce: 32 bytes of ClientHello Random
 *
 * keylog_keys() with the Random still attached, for a caller that wants to
 * walk the table's own bookkeeping rather than just the material.
 */
const struct keylog_entry *keylog_find(const u8 cnonce[32]);

/**
 * The secret held for one label
 * @keys: from keylog_keys(), or a decoder's own struct; may be NULL
 * @label: which secret
 * @size: filled with its length, set to 0 when there is none; may be NULL
 *
 * Reaches a secret by label rather than by name, for a caller iterating the
 * set or holding a label it was given. Returns NULL — and sets *@size to 0 —
 * for NULL @keys, a label outside the set, a label nothing filled in, and a
 * label belonging to the union arm @keys is *not* in. That last one is why
 * this exists: the arms overlap, so the version test has to happen before the
 * size is read, and doing it here collapses every failure a caller has into
 * one test.
 *
 * It takes the struct and not the entry so that it works the same on the
 * decoder's own struct tls_keys as on the table's. Reading the named field
 * directly is equally correct once keys->version has been checked.
 */
const u8 *keylog_keys_secret(const struct tls_keys *keys,
                             enum keylog_label label, u16 *size);

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

static inline const struct tls_keys *
keylog_keys(const u8 *cnonce)
{
	(void)cnonce;
	return NULL;
}

static inline const struct keylog_entry *
keylog_find(const u8 *cnonce)
{
	(void)cnonce;
	return NULL;
}

static inline const u8 *
keylog_keys_secret(const struct tls_keys *keys, enum keylog_label label,
                   u16 *size)
{
	(void)keys; (void)label;
	if (size)
		*size = 0;
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
