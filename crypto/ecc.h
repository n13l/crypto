/*
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz>
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

#ifndef __CRYPTO_ECC_H__
#define __CRYPTO_ECC_H__

/*
 * TLS supported groups (named curves and PQ hybrids) as a pluggable
 * subsystem, mirroring the cipher/digest registries. A "group" is a
 * key-exchange group negotiated through the TLS "supported_groups" (RFC 8446
 * / RFC 4492 "elliptic_curves") and "key_share" extensions. The registry
 * carries the metadata the passive dissector needs to identify a group and
 * size its key_share, plus optional keygen/derive hooks a backend may wire to
 * an accelerated (aws-lc) or portable implementation when a private key is
 * available.
 *
 * Two backends implement this interface, selected in Kconfig exactly like the
 * cipher backends:
 *   modules/group/generic  portable, identification-only (no keygen/derive)
 *   modules/group/aws      aws-lc accelerated keygen/derive for the classical
 *                          ECDHE groups (X25519, secp256r1/384r1/521r1)
 *
 * Group identifiers are the IANA "TLS Supported Groups" code points:
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */
#include <hpc/compiler.h>

/* Group family. */
enum group_category {
	GROUP_CAT_NONE  = 0,
	GROUP_CAT_ECDHE,	/* prime/binary/montgomery curve ECDHE */
	GROUP_CAT_FFDHE,	/* finite-field DHE (RFC 7919)         */
	GROUP_CAT_HYBRID,	/* classical + post-quantum KEM hybrid */
	GROUP_CAT_LAST
};

/*
 * IANA TLS Supported Groups code points. The value is the on-the-wire u16
 * carried in the supported_groups / key_share extensions.
 */
enum group_id {
	/* Elliptic-curve groups (RFC 8422 / RFC 8446) */
	GROUP_SECP256R1            = 0x0017,
	GROUP_SECP384R1            = 0x0018,
	GROUP_SECP521R1            = 0x0019,
	GROUP_X25519               = 0x001d,
	GROUP_X448                 = 0x001e,
	/* Finite-field DHE groups (RFC 7919) */
	GROUP_FFDHE2048            = 0x0100,
	GROUP_FFDHE3072            = 0x0101,
	GROUP_FFDHE4096            = 0x0102,
	/* Post-quantum hybrids (RFC 9370 / drafts) */
	GROUP_X25519MLKEM768       = 0x11ec,
	GROUP_SECP256R1MLKEM768    = 0x11eb,
	GROUP_SECP384R1MLKEM1024   = 0x11ed,
	GROUP_X25519KYBER768D00    = 0x6399,
	GROUP_SECP256R1KYBER768D00 = 0x639a,
};

struct group_algorithm;

/*
 * keygen: sample an ephemeral private key and write the matching public
 * key_share into @pub (public_key_size bytes). Returns 0 on success.
 *
 * derive: given our @priv (private_key_size bytes) and the peer's key_share
 * @peer (@peer_len bytes), write the shared secret into @ss
 * (shared_secret_size bytes). Returns 0 on success.
 *
 * A backend that only identifies groups (the generic fallback) leaves both
 * hooks NULL.
 */
typedef int (*fn_group_keygen)(const struct group_algorithm *g,
                               u8 *priv, u8 *pub);
typedef int (*fn_group_derive)(const struct group_algorithm *g,
                               const u8 *priv,
                               const u8 *peer, unsigned int peer_len,
                               u8 *ss);
typedef int (*fn_group_enum)(struct group_algorithm *);

struct group_algorithm {
	unsigned int id;		/* IANA code point (enum group_id) */
	unsigned int category;		/* enum group_category             */
	unsigned int private_key_size;	/* ephemeral scalar length         */
	unsigned int public_key_size;	/* our key_share length            */
	unsigned int shared_secret_size;/* derived secret length           */
	unsigned int tls12;		/* usable in TLS 1.2 (RFC 4492/7919) */
	unsigned int tls13;		/* usable in TLS 1.3 (RFC 8446)    */
	const char *name;		/* IANA name, e.g. "x25519"        */
	const char *desc;		/* human-readable description      */
	fn_group_keygen keygen;
	fn_group_derive derive;
};

void crypto_group_register(struct group_algorithm *alg);
struct group_algorithm *crypto_group_by_id(unsigned int id);
void crypto_group_enum(fn_group_enum fn);

/* Convenience: IANA name for a code point, or NULL if unknown/unregistered. */
const char *crypto_group_name(unsigned int id);

#if !defined(CONFIG_MODULES) && !defined(__CRYPTO_GROUP_MODULE__)
#define __CRYPTO_GROUP_BUILT_IN_READY__
#ifdef CONFIG_CRYPTO_GROUP
#include <modules/group/built-in.h>
#endif
#undef __CRYPTO_GROUP_BUILT_IN_READY__
#endif

#endif
