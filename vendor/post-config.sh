#!/bin/sh
#
# Post-configuration hook for vendor dependencies.
# Called after Kconfig generates auto.conf / .config to configure
# vendor-specific build prerequisites (e.g., OpenSSL).
#
# Usage: vendor/post-config.sh <srctree> <objtree> <config-file>

set -e

srctree="$1"
objtree="$2"
config="$3"

if [ -z "$srctree" ] || [ -z "$objtree" ] || [ -z "$config" ]; then
	echo "Usage: $0 <srctree> <objtree> <config-file>" >&2
	exit 1
fi

# Configure OpenSSL vendor library
if [ -x "$srctree/vendor/configure-openssl.sh" ]; then
	"$srctree/vendor/configure-openssl.sh" "$srctree" "$objtree" "$config"
fi

# Configure rustls vendor library
if [ -x "$srctree/vendor/configure-rustls.sh" ]; then
	"$srctree/vendor/configure-rustls.sh" "$srctree" "$objtree" "$config"
fi

# Build vendor OpenSSL when EVP test benchmarks are enabled
. "$objtree/$config" 2>/dev/null || true

need_openssl=""
[ "$CONFIG_TEST_EVP_STATIC" = "y" ] && need_openssl=y
[ "$CONFIG_TEST_EVP_DYNAMIC" = "y" ] && need_openssl=y

if [ -n "$need_openssl" ] && [ -f "$objtree/vendor/openssl/Makefile" ]; then
	stamp="$objtree/vendor/openssl/.built"
	if [ ! -f "$stamp" ] || [ "$objtree/$config" -nt "$stamp" ]; then
		echo "  BUILD   vendor/openssl"
		if [ "$KBUILD_VERBOSE" = "1" ]; then
			make -C "$objtree/vendor/openssl" -j"$(nproc)"
		else
			make -C "$objtree/vendor/openssl" -j"$(nproc)" >/dev/null 2>&1
		fi
		echo "  INSTALL vendor/openssl"
		if [ "$KBUILD_VERBOSE" = "1" ]; then
			make -C "$objtree/vendor/openssl" install_sw
		else
			make -C "$objtree/vendor/openssl" install_sw >/dev/null 2>&1
		fi
		touch "$stamp"
	fi
fi

# Build vendor rustls when the rustls benchmark is enabled, so it is available
# for the TLS performance tests.
need_rustls=""
[ "$CONFIG_TEST_RUSTLS" = "y" ] && need_rustls=y

if [ -n "$need_rustls" ]; then
	if [ ! -f "$srctree/vendor/rustls/Cargo.toml" ]; then
		echo >&2 "  ERROR: CONFIG_TEST_RUSTLS=y but rustls source is missing."
		echo >&2 "         git -C vendor/crypto submodule update --init vendor/rustls"
		exit 1
	fi
	stamp="$objtree/vendor/rustls/.built"
	if [ ! -f "$stamp" ] || [ "$objtree/$config" -nt "$stamp" ]; then
		echo "  BUILD   vendor/rustls"
		prof="--release"
		[ "$CONFIG_RUSTLS_DEBUG" = "y" ] && prof=""
		args=$(echo "${CONFIG_RUSTLS_CARGO_ARGS}" | sed 's/^"//;s/"$//')
		[ -n "$args" ] || args="-p rustls-bench"
		# Clear make's environment: some crates' build scripts (e.g.
		# tikv-jemalloc-sys) invoke make, and inheriting kbuild's MAKEFLAGS
		# (jobserver fds, -I dirs, KBUILD_*) corrupts those sub-builds. Build
		# serially (-j1): jemalloc's C compile flakily hits a gcc ICE under
		# parallel make. This runs once and is cached via the .built stamp.
		if [ "$KBUILD_VERBOSE" = "1" ]; then
			env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS -u MAKEFILES \
				cargo build -j1 $prof --manifest-path "$srctree/vendor/rustls/Cargo.toml" \
				--target-dir "$objtree/vendor/rustls" $args
		else
			env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS -u MAKEFILES \
				cargo build -j1 $prof --manifest-path "$srctree/vendor/rustls/Cargo.toml" \
				--target-dir "$objtree/vendor/rustls" $args >/dev/null 2>&1
		fi
		touch "$stamp"
	fi
fi
