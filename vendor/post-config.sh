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
