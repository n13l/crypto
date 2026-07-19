#!/usr/bin/env bats
#
# Integration tests for the crypto TLS key-exchange group subsystem
# (crypto/ecc.h). Wraps the standalone `group` test program
# (crypto/tools/group.c), which asserts the RFC 7748 X25519 known-answer and
# Diffie-Hellman vectors against whichever group backend the build selected
# (generic C or aws-lc s2n-bignum).
#

setup_file() {
    CRYPTO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
    export CRYPTO_ROOT

    if [[ -z "${GROUP_BIN:-}" ]]; then
        for candidate in \
            "${CRYPTO_ROOT}/obj/tools/group" \
            "${CRYPTO_ROOT}/obj/crypto/tools/group"
        do
            [[ -x "${candidate}" ]] && { GROUP_BIN="${candidate}"; break; }
        done
    fi
    export GROUP_BIN="${GROUP_BIN:-}"
}

@test "group: X25519 RFC 7748 scalar-mult (derive) vector" {
    [ -n "${GROUP_BIN}" ] || skip "group binary not built (run: make test)"
    run "${GROUP_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"x25519-derive: ok"* ]]
    [[ "${output}" != *"FAIL"* ]]
}

@test "group: X25519 RFC 7748 Diffie-Hellman (ECDH) vector" {
    [ -n "${GROUP_BIN}" ] || skip "group binary not built (run: make test)"
    run "${GROUP_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"x25519-ecdh: ok"* ]]
    [[ "${output}" != *"FAIL"* ]]
}

@test "group: X25519 key-agreement round-trip" {
    [ -n "${GROUP_BIN}" ] || skip "group binary not built (run: make test)"
    run "${GROUP_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"x25519-agree: ok"* ]]
    [[ "${output}" != *"FAIL"* ]]
}

@test "group: secp256r1 RFC 5903 ECDH (P-256) vectors" {
    [ -n "${GROUP_BIN}" ] || skip "group binary not built (run: make test)"
    run "${GROUP_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"secp256r1-ecdh-i: ok"* ]]
    [[ "${output}" == *"secp256r1-ecdh-r: ok"* ]]
    [[ "${output}" != *"FAIL"* ]]
}

@test "group: secp384r1 RFC 5903 ECDH (P-384) vectors" {
    [ -n "${GROUP_BIN}" ] || skip "group binary not built (run: make test)"
    run "${GROUP_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"secp384r1-ecdh-i: ok"* ]]
    [[ "${output}" == *"secp384r1-ecdh-r: ok"* ]]
    [[ "${output}" != *"FAIL"* ]]
}
