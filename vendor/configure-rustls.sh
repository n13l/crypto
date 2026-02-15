#!/bin/sh
#
# configure-rustls.sh - Configure the rustls vendor library (cargo).
#
# Usage: configure-rustls.sh <srctree> <objtree> <auto.conf>
#
# Mirrors configure-openssl.sh: it prepares an out-of-tree build (cargo target
# directory under the object tree, so the rustls source stays clean) and
# resolves/fetches dependencies so a later `cargo build` is ready. Cheap and
# cached via a .configured stamp.

set -e

srctree="$1"
objtree="$2"
autoconf="$3"

if [ -z "$srctree" ] || [ -z "$objtree" ] || [ -z "$autoconf" ]; then
	echo "Usage: $0 <srctree> <objtree> <auto.conf>" >&2
	exit 1
fi

srctree=$(cd "$srctree" && pwd)
objtree=$(cd "$objtree" && pwd)
autoconf="${objtree}/${autoconf}"

RUSTLS_SRC="${srctree}/vendor/rustls"
RUSTLS_OUT="${objtree}/vendor/rustls"

# Tolerant if the submodule is not initialized: configure is a no-op rather
# than a hard error, so builds that don't need rustls still succeed. Enable
# a rustls test/benchmark to make its absence fatal (see post-config.sh).
if [ ! -f "${RUSTLS_SRC}/Cargo.toml" ]; then
	echo "  SKIP    vendor/rustls configure (source not initialized)" >&2
	exit 0
fi
if ! command -v cargo >/dev/null 2>&1; then
	echo "  SKIP    vendor/rustls configure (cargo not found)" >&2
	exit 0
fi

. "$autoconf" 2>/dev/null || true

profile="release"
[ "${CONFIG_RUSTLS_DEBUG}" = "y" ] && profile="debug"
extra=$(echo "${CONFIG_RUSTLS_CARGO_ARGS}" | sed 's/^"//;s/"$//')

mkdir -p "${RUSTLS_OUT}"

stamp="${RUSTLS_OUT}/.configured"
args_hash=$(echo "${profile} ${extra}" | sha1sum | cut -d' ' -f1)
if [ -f "${stamp}" ] && [ "$(cat "${stamp}")" = "${args_hash}" ]; then
	exit 0
fi

echo "  CONFIG  vendor/rustls (cargo fetch)"
# Fetch dependencies now so the build step can run offline. Non-fatal: the
# build will fetch on demand if this fails (e.g. no network at config time).
if [ "${KBUILD_VERBOSE}" = "1" ]; then
	(cd "${RUSTLS_SRC}" && cargo fetch --locked) || \
		echo "  WARNING: cargo fetch failed; build will fetch on demand" >&2
else
	(cd "${RUSTLS_SRC}" && cargo fetch --locked) >/dev/null 2>&1 || \
		echo "  WARNING: cargo fetch failed; build will fetch on demand" >&2
fi

echo "${args_hash}" > "${stamp}"
