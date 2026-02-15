#!/bin/sh
#
# bootstrap.sh — initialize submodules for a standalone crypto build.
#
# crypto is a Kbuild package: it owns the algorithm tree (modules/) and the
# intrusive API (crypto/), and takes the build infrastructure (scripts/, arch/,
# os/ — all committed symlinks into vendor/kbuild), the shared runtime (hpc/ ->
# vendor/hpc/hpc) and its crypto vendor libraries from submodules. This script
# initializes exactly what a standalone `make defconfig && make check` needs:
#
#   vendor/kbuild           the build system itself; scripts/, arch/ and os/
#                           resolve through it, so nothing builds without it
#   vendor/hpc              the shared runtime; crypto's sources include its
#                           headers through the hpc/ symlink
#   vendor/openssl          the OpenSSL-accelerated digest backends
#                           (CONFIG_*_OSSL_*) build against it, and the default
#                           configuration selects them
#   vendor/aws-lc           the verified AES/ChaCha20 backends (CONFIG_*_AWS_*)
#                           #include its checked-in generated assembly, and the
#                           default configuration selects those too
#   vendor/rustls           the TLS benchmark library (CONFIG_TEST_RUSTLS);
#                           configure is a cheap `cargo fetch`, the build only
#                           runs when that test is enabled
#   vendor/bats-*           the bats integration-test framework, for `make check`
#
# openssl and aws-lc are both required by the DEFAULT configuration — the digest
# backends default to the OpenSSL-accelerated implementations and the
# AES/ChaCha20 cipher backends to the aws-lc (verified) assembly — so a plain
# `make defconfig && make` needs them present.
#
# Note for the integrated build: when crypto is consumed as un's vendor/crypto,
# un provides kbuild and hpc from the top (one pin for the code that gets linked)
# and initializes openssl/aws-lc/rustls itself, so this script is NOT run there —
# un's own bootstrap.sh covers it, and crypto's vendor/{kbuild,hpc} plus its own
# bats copies are deliberately left uninitialized. It is for a standalone crypto
# checkout.
#
set -e
cd "$(dirname "$0")"

echo "crypto: initializing build infrastructure + runtime (kbuild, hpc) ..."
git submodule update --init vendor/kbuild vendor/hpc

echo "crypto: initializing OpenSSL + aws-lc + rustls vendor sources ..."
git submodule update --init vendor/openssl vendor/aws-lc vendor/rustls

echo "crypto: initializing bats test framework ..."
git submodule update --init \
    vendor/bats-core vendor/bats-assert vendor/bats-file vendor/bats-support

# Do NOT run `git submodule update --init --recursive`: that would also clone
# hpc's own nested kbuild (crypto provides one from here) and every vendor tree
# below it, none of which a crypto build uses.

echo "crypto: ready. Configure and build with:"
echo "    make menuconfig      # or: make defconfig"
echo "    make -j\$(nproc)"
echo "    make check"
