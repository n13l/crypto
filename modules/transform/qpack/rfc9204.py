#!/usr/bin/env python3
"""Generate static.h from RFC 9204.

  ./rfc9204.py [rfc9204.txt]

with no argument the RFC is fetched from rfc-editor.org. The table is parsed
out of the document rather than transcribed, and checked before anything is
written:

  Appendix A must yield exactly 99 entries, indexed 0..98 without a gap,
    every name a lowercase field name

  the thirteen entries whose values the RFC wraps across table rows must
    come out as the exact strings spelled below — the join rule (a fragment
    ending in '-' or '/' continues the token, anything else broke at a
    space) is a heuristic about the RFC's own formatter, so the strings it
    reconstructs are pinned here rather than trusted

The Huffman code is not generated here: RFC 9204 §4.1.2 uses RFC 7541
Appendix B unchanged, so qpack.c includes the automaton hpack's generator
(../hpack/rfc7541.py) wrote.

The output is checked in. This script exists so that the table can be
re-derived and re-checked, not because the build runs it.
"""
import re, sys, urllib.request

if len(sys.argv) > 1:
    txt = open(sys.argv[1], encoding='utf-8', errors='replace').read()
else:
    txt = urllib.request.urlopen(
        'https://www.rfc-editor.org/rfc/rfc9204.txt').read().decode(
            'utf-8', 'replace')

# ---- Appendix A: | Index | Name | Value |, values wrapping across rows
m = re.search(r'^Appendix A\.  Static Table$(.*?)^Appendix B',
              txt, re.M | re.S)
assert m, 'Appendix A not found'
rows = []
for ln in m.group(1).splitlines():
    c = re.match(r'^   \|\s*(\d*)\s*\|\s(.*?)\s*\|\s(.*?)\s*\|$', ln)
    if not c:
        continue
    idx, name, val = c.group(1), c.group(2), c.group(3)
    if not idx and not rows:
        continue                       # the header row spells no index
    if idx:
        if name == 'Name':
            continue                   # the header row
        rows.append([int(idx), name, val])
    else:
        # a continuation row: the value wrapped. A fragment the formatter
        # broke inside a token ends in '-' or '/'; one it broke at a space
        # does not, and the space comes back on the join.
        assert not name, ln
        prev = rows[-1][2]
        rows[-1][2] = prev + val if prev.endswith(('-', '/')) \
                      else prev + ' ' + val

assert len(rows) == 99, len(rows)
assert [r[0] for r in rows] == list(range(99))
for _, name, _ in rows:
    assert re.fullmatch(r'[a-z0-9:!#$%&\'*+.^_`|~-]+', name), name

# the wrapped entries, pinned: the join rule reconstructed these, so they
# are asserted against the strings RFC 9204 means rather than believed
WRAPPED = {
    30: 'application/dns-message',
    41: 'public, max-age=31536000',
    44: 'application/dns-message',
    45: 'application/javascript',
    47: 'application/x-www-form-urlencoded',
    52: 'text/html; charset=utf-8',
    54: 'text/plain;charset=utf-8',
    57: 'max-age=31536000; includesubdomains',
    58: 'max-age=31536000; includesubdomains; preload',
    85: "script-src 'none'; object-src 'none'; base-uri 'none'",
}
for i, want in WRAPPED.items():
    assert rows[i][2] == want, (i, rows[i][2], want)

# ---- one blob, (offset, length) pairs into it, values deduplicated the
# same lazy way hpack's generator does it: a value that is a prefix of the
# bytes already written is pointed at rather than repeated
blob = ''
ents = []
for _, name, val in rows:
    noff = blob.find(name)
    if noff < 0 or blob[noff:noff + len(name)] != name:
        noff = len(blob)
        blob += name
    voff = blob.find(val) if val else 0
    if val and (voff < 0 or blob[voff:voff + len(val)] != val):
        voff = len(blob)
        blob += val
    ents.append((noff, len(name), voff if val else 0, len(val)))
assert len(blob) < 0x10000

LICENSE = """\
/*
 * The MIT License (MIT)              QPACK static table (RFC 9204 Appendix A)
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

out = [LICENSE]
out.append("""
/*
 * GENERATED — do not edit. rfc9204.py in this directory reads RFC 9204
 * and writes this file.
 *
 * The ninety-nine entries of Appendix A, as one blob of bytes and one array
 * of (offset, length) pairs into it — the same object hpack's static.h is,
 * for the same reasons: a lookup is two loads and no pointer chase, and the
 * whole table is one read-only page shared across every connection.
 *
 * Indices are the specification's, zero-based: unlike HPACK, QPACK numbers
 * its static table from 0 (§3.1) and has no unused first slot.
 */

#ifndef __CRYPTO_TRANSFORM_QPACK_STATIC_H__
#define __CRYPTO_TRANSFORM_QPACK_STATIC_H__

#include <hpc/compiler.h>

__BEGIN_DECLS

#define QPACK_STATIC_N\t99

struct qpack_static_ent {
\tu16\tname_off;
\tu16\tname_len;
\tu16\tvalue_off;
\tu16\tvalue_len;
};

static const char qpack_static_blob[] =
""")

esc = blob.replace('\\', '\\\\').replace('"', '\\"')
for i in range(0, len(esc), 73):
    tail = ';' if i + 73 >= len(esc) else ''
    out.append('\t"%s"%s\n' % (esc[i:i + 73], tail))

out.append("""
static const struct qpack_static_ent qpack_static[QPACK_STATIC_N] = {
""")
for i, ((noff, nlen, voff, vlen), (_, name, val)) in enumerate(zip(ents, rows)):
    label = '%s: %s' % (name, val) if val else '%s:' % name
    # a value must neither close the comment nor open one inside it
    label = label.replace('*/', '*|').replace('/*', '|*')
    out.append('\t{ %4u, %2u, %4u, %2u },\t/* %2u %s */\n'
               % (noff, nlen, voff, vlen, i, label))
out.append("""};

__END_DECLS

#endif/*__CRYPTO_TRANSFORM_QPACK_STATIC_H__*/
""")

sys.stdout.write(''.join(out))
