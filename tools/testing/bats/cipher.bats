#!/usr/bin/env bats
#
# Integration tests for the crypto cipher modules (AES-128/256 CBC+GCM and
# ChaCha20-Poly1305), covering both the generic C and the aws-lc accelerated
# backends (whichever the build selected).
#
# Wraps the standalone `cipher` test program (crypto/tools/cipher.c), plus an
# independent OpenSSL cross-check of the AES-128-CBC vector.
#

setup_file() {
    CRYPTO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
    export CRYPTO_ROOT

    if [[ -z "${CIPHER_BIN:-}" ]]; then
        for candidate in \
            "${CRYPTO_ROOT}/obj/tools/cipher" \
            "${CRYPTO_ROOT}/obj/crypto/tools/cipher"
        do
            [[ -x "${candidate}" ]] && { CIPHER_BIN="${candidate}"; break; }
        done
    fi
    export CIPHER_BIN="${CIPHER_BIN:-}"
}

@test "cipher: standalone vectors (aes cbc/gcm, chacha20-poly1305)" {
    [ -n "${CIPHER_BIN}" ] || skip "cipher binary not built (run: make test)"
    run "${CIPHER_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"aes-128-gcm: ok"* ]]
    [[ "${output}" == *"aes-256-gcm: ok"* ]]
    [[ "${output}" == *"aes-128-cbc: ok"* ]]
    [[ "${output}" == *"chacha20-poly1305: ok"* ]]
    [[ "${output}" != *"FAIL"* ]]
}

@test "cipher: aes-128-cbc NIST F.2.1 vs openssl" {
    command -v openssl >/dev/null || skip "openssl not available"
    command -v xxd >/dev/null || skip "xxd not available"

    # NIST SP800-38A F.2.1 first block. Cross-check the vector the cipher
    # selftest asserts against an independent OpenSSL computation. (AES-GCM is
    # not exercised here because `openssl enc` does not support AEAD ciphers;
    # its tag is verified end-to-end by the cipher binary.)
    local key="2b7e151628aed2a6abf7158809cf4f3c"
    local iv="000102030405060708090a0b0c0d0e0f"
    local out
    out="$(printf '\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a' \
        | openssl enc -aes-128-cbc -nopad -K "${key}" -iv "${iv}" \
        | xxd -p | tr -d '\n')"
    [ "${out}" = "7649abac8119b246cee98e9b12e9197d" ]
}
