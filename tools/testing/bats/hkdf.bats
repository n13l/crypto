#!/usr/bin/env bats
#
# Integration tests for the crypto HKDF module (RFC 5869). Wraps the standalone
# `hkdf` test program (crypto/tools/hkdf.c), plus an OpenSSL cross-check of the
# SHA-256 Test Case 1 vector.
#
# HKDF may be disabled in the build (CONFIG_CRYPTO_HKDF_* off); the binary then
# reports "disabled (skip)" / runs no cases, and these tests pass trivially.
#

setup_file() {
    CRYPTO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
    export CRYPTO_ROOT

    if [[ -z "${HKDF_BIN:-}" ]]; then
        for candidate in \
            "${CRYPTO_ROOT}/obj/tools/hkdf" \
            "${CRYPTO_ROOT}/obj/crypto/tools/hkdf"
        do
            [[ -x "${candidate}" ]] && { HKDF_BIN="${candidate}"; break; }
        done
    fi
    export HKDF_BIN="${HKDF_BIN:-}"
}

@test "hkdf: standalone vectors (RFC 5869)" {
    [ -n "${HKDF_BIN}" ] || skip "hkdf binary not built (run: make test)"
    run "${HKDF_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" != *"FAIL"* ]]
    # When HKDF is enabled the SHA-256 case must appear; otherwise it skips.
    [[ "${output}" == *"hkdf-sha256: ok"* || "${output}" == *"disabled (skip)"* ]]
}

@test "hkdf: sha256 RFC 5869 TC1 vs openssl" {
    command -v openssl >/dev/null || skip "openssl not available"
    # openssl 3.x 'kdf' provider; skip on older builds without it.
    openssl kdf -help >/dev/null 2>&1 || skip "openssl kdf command not available"

    local okm
    okm="$(openssl kdf -keylen 42 -kdfopt digest:SHA2-256 \
        -kdfopt hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
        -kdfopt hexsalt:000102030405060708090a0b0c \
        -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9 -binary HKDF 2>/dev/null | xxd -p | tr -d '\n')"
    [ -n "${okm}" ] || skip "openssl HKDF invocation produced no output"
    [ "${okm}" = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" ]
}
