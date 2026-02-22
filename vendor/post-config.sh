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
