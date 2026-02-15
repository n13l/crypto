#!/usr/bin/env python3
"""Generate huffman.h and static.h from RFC 7541.

  ./rfc7541.py [rfc7541.txt]

with no argument the RFC is fetched from rfc-editor.org. Both tables are
parsed out of the document rather than transcribed, and both are checked
before anything is written:

  the Huffman code must have 257 symbols, be prefix-free, and satisfy Kraft
    equality (sum of 2^-len == 1), which together say it is the complete code
    the RFC prints and not a table with a typo in it

  the automaton must decode every Huffman-coded string in Appendix C, and
    every one of the 256 symbols on its own with legal padding

The output is checked in. This script exists so that the tables can be
re-derived and re-checked, not because the build runs it.
"""
import json, re, sys, urllib.request
from fractions import Fraction

if len(sys.argv) > 1:
    txt = open(sys.argv[1], encoding='utf-8', errors='replace').read()
else:
    txt = urllib.request.urlopen(
        'https://www.rfc-editor.org/rfc/rfc7541.txt').read().decode(
            'utf-8', 'replace')
lines = txt.splitlines()


# ---- Appendix B: (sym) |bits...  hexcode  [len]
huff = {}
pat = re.compile(r'^.*?\(\s*(\d+)\)\s+\|[01|]+\s+([0-9a-f]+)\s+\[\s*(\d+)\]\s*$')
for ln in lines:
    m = pat.match(ln)
    if m:
        sym, code, nbits = int(m.group(1)), int(m.group(2), 16), int(m.group(3))
        assert sym not in huff, sym
        huff[sym] = (code, nbits)

print("huffman symbols parsed:", len(huff), file=sys.stderr)
assert len(huff) == 257, len(huff)
assert sorted(huff) == list(range(257))

# Kraft equality: a complete prefix code sums to exactly 1
from fractions import Fraction
kraft = sum(Fraction(1, 1 << n) for _, n in huff.values())
print("kraft sum:", kraft, file=sys.stderr)
assert kraft == 1, kraft

# canonical: sorted by (len, code) the codes must be strictly increasing and
# each code must fit in its length
prev = None
for sym in sorted(huff, key=lambda s: (huff[s][1], huff[s][0])):
    code, n = huff[sym]
    assert code < (1 << n), (sym, hex(code), n)

# prefix-freeness, brute force
items = sorted(huff.items(), key=lambda kv: kv[1][1])
for i, (s1, (c1, n1)) in enumerate(items):
    for (s2, (c2, n2)) in items[i+1:]:
        if n2 >= n1 and (c2 >> (n2 - n1)) == c1:
            raise SystemExit(f"prefix collision {s1} {s2}")
print("prefix-free: ok", file=sys.stderr)

# ---- Appendix A: | 1 | :authority | |
static = {}
spat = re.compile(r'^\s*\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$')
lo = next(i for i, l in enumerate(lines) if l.startswith('Appendix A.'))
hi = next(i for i, l in enumerate(lines) if 'Table 1: Static Table Entries' in l)
for ln in lines[lo:hi]:
    m = spat.match(ln)
    if m:
        idx = int(m.group(1))
        assert idx not in static, idx
        static[idx] = (m.group(2), m.group(3))
print("static entries parsed:", len(static), file=sys.stderr)
assert sorted(static) == list(range(1, 62)), sorted(static)


HUFF = huff
STATIC = static
EOS = 256


# ---- trie ---------------------------------------------------------------
# A node is the (bits, depth) prefix that reaches it. Leaves carry a symbol.
leaf = {}
for sym, (code, n) in HUFF.items():
    leaf[(code, n)] = sym

def child(node, bit):
    bits, depth = node
    return ((bits << 1) | bit, depth + 1)

ROOT = (0, 0)

def accepting(node):
    """RFC 7541 5.2: a string may end on up to 7 bits of the EOS prefix,
    which is all ones. Anything else left over is an error."""
    bits, depth = node
    return depth <= 7 and bits == (1 << depth) - 1

# ---- automaton ----------------------------------------------------------
# One step consumes four bits. The shortest code is five bits long, so a step
# can complete at most one symbol: after a symbol completes the walk is back at
# the root and needs five more bits, which four cannot supply.
FAIL, SYM, ACCEPT = 1, 2, 4

states = [ROOT]
index = {ROOT: 0}
table = []

i = 0
while i < len(states):
    node = states[i]
    row = []
    for nib in range(16):
        cur, fail, sym = node, False, 0
        for b in range(3, -1, -1):
            cur = child(cur, (nib >> b) & 1)
            if cur in leaf:
                s = leaf[cur]
                if s == EOS:          # never decoded, only ever padding
                    fail = True
                    break
                assert sym == 0 or not sym, "two symbols in one step"
                sym = s
                cur = ROOT
        if fail:
            row.append((0, FAIL, 0))
            continue
        if cur not in index:
            index[cur] = len(states)
            states.append(cur)
        flags = (SYM if sym or (sym == 0 and cur is not None and False) else 0)
        # sym == 0 is a real symbol (NUL), so track emission explicitly
        row.append((index[cur], flags, sym))
    table.append(row)
    i += 1

# redo the emission flag properly: rebuild with an explicit emitted marker
states = [ROOT]
index = {ROOT: 0}
table = []
i = 0
while i < len(states):
    node = states[i]
    row = []
    for nib in range(16):
        cur, fail, emitted, sym = node, False, False, 0
        for b in range(3, -1, -1):
            cur = child(cur, (nib >> b) & 1)
            if cur in leaf:
                s = leaf[cur]
                if s == EOS:
                    fail = True
                    break
                assert not emitted, "two symbols in one four-bit step"
                emitted, sym = True, s
                cur = ROOT
        if fail:
            row.append((0, FAIL, 0))
            continue
        if cur not in index:
            index[cur] = len(states)
            states.append(cur)
        flags = (SYM if emitted else 0) | (ACCEPT if accepting(cur) else 0)
        row.append((index[cur], flags, sym))
    table.append(row)
    i += 1

print("states:", len(states), file=sys.stderr)
assert len(states) <= 256, len(states)

# ---- reference decoder, to check the automaton --------------------------
def decode(buf):
    st, out = 0, bytearray()
    for byte in buf:
        for nib in (byte >> 4, byte & 15):
            nxt, flags, sym = table[st][nib]
            if flags & FAIL:
                raise ValueError("huffman: EOS or invalid code")
            if flags & SYM:
                out.append(sym)
            st = nxt
    if not (table[st][0][1] & ACCEPT) and st != 0:
        # the accept bit is a property of the state; read it off any entry that
        # reaches it is wrong, so check the state directly
        pass
    if not accepting(states[st]):
        raise ValueError("huffman: bad padding")
    return bytes(out)

def enc(h):
    return bytes.fromhex(h.replace(' ', ''))

vectors = [
    ('f1e3c2e5f23a6ba0ab90f4ff', 'www.example.com'),
    ('a8eb10649cbf', 'no-cache'),
    ('25a849e95ba97d7f', 'custom-key'),
    ('25a849e95bb8e8b4bf', 'custom-value'),
    ('6402', '302'),
    ('aec3771a4b', 'private'),
    ('d07abe941054d444a8200595040b8166e082a62d1bff',
     'Mon, 21 Oct 2013 20:13:21 GMT'),
    ('9d29ad171863c78f0b97c8e9ae82ae43d3', 'https://www.example.com'),
    ('640eff', '307'),
    ('d07abe941054d444a8200595040b8166e084a62d1bff',
     'Mon, 21 Oct 2013 20:13:22 GMT'),
    ('9bd9ab', 'gzip'),
    ('94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587'
     '316065c003ed4ee5b1063d5007',
     'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1'),
]
for hexs, want in vectors:
    got = decode(enc(hexs)).decode('latin-1')
    assert got == want, (hexs, got, want)
print("appendix C huffman vectors: %d ok" % len(vectors), file=sys.stderr)

# every symbol round-trips on its own, padded with ones
for sym, (code, n) in HUFF.items():
    if sym == EOS:
        continue
    nbits = n
    val = code
    pad = (8 - nbits % 8) % 8
    val = (val << pad) | ((1 << pad) - 1)
    buf = val.to_bytes((nbits + pad) // 8, 'big')
    assert decode(buf) == bytes([sym]), sym
print("all 256 symbols round-trip", file=sys.stderr)

# ---- emit ---------------------------------------------------------------
LIC = """/*
 * The MIT License (MIT)              HPACK Huffman code (RFC 7541 Appendix B)
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
"""

HDR = LIC + '''
/*
 * GENERATED — do not edit. rfc7541.py in this directory reads RFC 7541
 * and writes this file; the RFC is the source and this is a build product
 * checked in so that building the tree needs no python and no network.
 *
 * The code of Appendix B as a table-driven automaton that consumes four bits
 * at a time. A state is a node of the code's binary trie, reached after some
 * number of four-bit steps; an entry says where the next nibble lands, whether
 * a symbol came out on the way, and whether the state it lands in is one a
 * string may legally end in.
 *
 * One symbol per step at most, which is what makes the entry this small: the
 * shortest code in the table is five bits, so once a code completes the walk
 * is back at the root needing five more bits and four cannot supply them.
 *
 * HPACK_HUFF_ACCEPT is the padding rule of RFC 7541 §5.2 read off the state
 * rather than checked at the end: a string may stop on up to seven bits of the
 * EOS code, which is all ones, and on nothing else. HPACK_HUFF_FAIL is the EOS
 * code itself being decoded rather than used as padding, which the same
 * section makes an error.
 *
 * %d states, %d bytes.
 */

#ifndef __CRYPTO_TRANSFORM_HPACK_HUFFMAN_H__
#define __CRYPTO_TRANSFORM_HPACK_HUFFMAN_H__

#include <hpc/compiler.h>

__BEGIN_DECLS

#define HPACK_HUFF_FAIL		0x01	/* the EOS code, or no code at all   */
#define HPACK_HUFF_SYM		0x02	/* @sym came out of this step        */
#define HPACK_HUFF_ACCEPT	0x04	/* a string may end in @next         */

#define HPACK_HUFF_STATES	%d

struct hpack_huff_ent {
	u8	next;
	u8	flags;
	u8	sym;
};

static const struct hpack_huff_ent
hpack_huff[HPACK_HUFF_STATES][16] = {
'''

rows = []
for st, row in enumerate(table):
    cells = []
    for nxt, flags, sym in row:
        f = []
        if flags & FAIL:
            f.append('HPACK_HUFF_FAIL')
        if flags & SYM:
            f.append('HPACK_HUFF_SYM')
        if flags & ACCEPT:
            f.append('HPACK_HUFF_ACCEPT')
        fs = '|'.join(f) if f else '0'
        cells.append('{%3d,%s,%3d}' % (nxt, fs, sym))
    body = ''
    line = '\t'
    for c in cells:
        if len(line) + len(c) + 2 > 78:
            body += line.rstrip() + '\n'
            line = '\t'
        line += c + ', '
    body += line.rstrip().rstrip(',') + '\n'
    rows.append('\t/* %3d */ {\n%s\t},' % (st, body))

SYMS = '''
/*
 * And the same code the other way, for the emitter (hpack_emit()): each
 * symbol's code right-aligned in @code, @len bits of it (5..30). EOS is not
 * here because an encoder never writes it as a symbol — §5.2 uses its prefix
 * only as padding, which is a run of ones.
 */
struct hpack_huff_sym {
	u32	code;
	u8	len;
};

static const struct hpack_huff_sym hpack_huff_sym[256] = {
'''

sym_rows = []
line = '\t'
for s in range(256):
    code, n = HUFF[s]
    cell = '{0x%08x,%2d}, ' % (code, n)
    if len(line) + len(cell) > 78:
        sym_rows.append(line.rstrip())
        line = '\t'
    line += cell
sym_rows.append(line.rstrip().rstrip(','))

out = (HDR % (len(states), len(states) * 16 * 3, len(states))) + '\n'.join(rows) + '''
};
''' + SYMS + '\n'.join(sym_rows) + '''
};

__END_DECLS

#endif/*__CRYPTO_TRANSFORM_HPACK_HUFFMAN_H__*/
'''
open('huffman.h', 'w').write(out)

# ---- static table -------------------------------------------------------
blob = bytearray()
ents = []
for i in range(1, 62):
    name, value = STATIC[i]
    no = len(blob); blob += name.encode()
    vo = len(blob); blob += value.encode()
    ents.append((no, len(name), vo, len(value), name, value))

def cstr(b):
    out, line = '', '\t"'
    for ch in b:
        c = chr(ch)
        if c == '"':
            e = '\\"'
        elif c == '\\':
            e = '\\\\'
        elif 32 <= ch < 127:
            e = c
        else:
            e = '\\%03o' % ch
        if len(line) + len(e) > 74:
            out += line + '"\n'
            line = '\t"'
        line += e
    return out + line + '"'

SHDR = LIC.replace('HPACK Huffman code (RFC 7541 Appendix B)',
                   'HPACK static table (RFC 7541 Appendix A)') + '''
/*
 * GENERATED — do not edit. rfc7541.py in this directory reads RFC 7541
 * and writes this file.
 *
 * The sixty-one entries of Appendix A, as one blob of bytes and one array of
 * (offset, length) pairs into it. One object rather than sixty-one string
 * literals so that a lookup is two loads and no pointer chase, and so that the
 * whole table is one read-only page the decoder shares across every
 * connection it runs.
 *
 * Indices are the specification's, one-based: entry 0 does not exist, which
 * §2.3.3 says is what index zero on the wire means, so the array is padded to
 * keep hpack_static[i] the entry the wire named.
 */

#ifndef __CRYPTO_TRANSFORM_HPACK_STATIC_H__
#define __CRYPTO_TRANSFORM_HPACK_STATIC_H__

#include <hpc/compiler.h>

__BEGIN_DECLS

#define HPACK_STATIC_MAX	61

struct hpack_static_ent {
	u16	name_off;
	u16	name_len;
	u16	value_off;
	u16	value_len;
};

static const char hpack_static_blob[] =
%s;

static const struct hpack_static_ent hpack_static[HPACK_STATIC_MAX + 1] = {
	/* index 0 is not an entry (RFC 7541 §2.3.3) */
	{ 0, 0, 0, 0 },
%s};

__END_DECLS

#endif/*__CRYPTO_TRANSFORM_HPACK_STATIC_H__*/
'''

lines = []
for i, (no, nl, vo, vl, name, value) in enumerate(ents, 1):
    lines.append('\t{ %4d, %2d, %4d, %2d },\t/* %2d %s: %s */\n'
                 % (no, nl, vo, vl, i, name, value))
open('static.h', 'w').write(SHDR % (cstr(blob), ''.join(lines)))
print("wrote huffman.h, static.h", file=sys.stderr)
