#!/usr/bin/env bats
#
# Integration tests for the crypto digest module.
#
# Wraps both the standalone `digest` test program and the cmocka
# `test_digest` binary so their results show up in the same TAP stream.
#

setup_file() {
    CRYPTO_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
    export CRYPTO_ROOT

    for candidate in \
        "${CRYPTO_ROOT}/test/digest" \
        "${CRYPTO_ROOT}/output/test/digest" \
        "${CRYPTO_ROOT}/build/test/digest"
    do
        if [[ -x "${candidate}" ]]; then
            DIGEST_BIN="${candidate}"
            break
        fi
    done
    export DIGEST_BIN="${DIGEST_BIN:-}"

    for candidate in \
        "${CRYPTO_ROOT}/test/test_digest" \
        "${CRYPTO_ROOT}/output/test/test_digest" \
        "${CRYPTO_ROOT}/build/test/test_digest"
    do
        if [[ -x "${candidate}" ]]; then
            CMOCKA_DIGEST_BIN="${candidate}"
            break
        fi
    done
    export CMOCKA_DIGEST_BIN="${CMOCKA_DIGEST_BIN:-}"
}

@test "digest: standalone binary prints sha3-256 ok" {
    [ -n "${DIGEST_BIN}" ] || skip "digest binary not built (run: make test)"
    run "${DIGEST_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == "sha3-256: ok" ]]
}

@test "digest: SHA3-256 of empty matches OpenSSL reference" {
    command -v openssl >/dev/null || skip "openssl not available"
    [ -n "${DIGEST_BIN}" ] || skip "digest binary not built"

    expected="$(printf '' | openssl dgst -sha3-256 -r | awk '{print $1}')"
    [ "${expected}" = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" ]
}

@test "digest: cmocka group passes" {
    [ -n "${CMOCKA_DIGEST_BIN}" ] || skip "cmocka test_digest not built (set CONFIG_CMOCKA=y)"
    run "${CMOCKA_DIGEST_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" != *"FAILED"* ]]
}
