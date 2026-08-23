#!/usr/bin/env bats
#
# Integration tests for the crypto digest module.
#
# Wraps the standalone `digest` test program (crypto/tools/digest.c).
#

setup_file() {
    CRYPTO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
    export CRYPTO_ROOT

    # Prefer the binary the test runner exported (run-check.sh sets <NAME>_BIN);
    # otherwise fall back to the standalone object tree.
    if [[ -z "${DIGEST_BIN:-}" ]]; then
        for candidate in \
            "${CRYPTO_ROOT}/obj/tools/digest" \
            "${CRYPTO_ROOT}/obj/crypto/tools/digest"
        do
            [[ -x "${candidate}" ]] && { DIGEST_BIN="${candidate}"; break; }
        done
    fi
    export DIGEST_BIN="${DIGEST_BIN:-}"
}

@test "digest: standalone sha3-256" {
    [ -n "${DIGEST_BIN}" ] || skip "digest binary not built (run: make test)"
    run "${DIGEST_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"sha3-256: ok"* ]]
}

# SM3 (GB/T 32905) is off in every default build and the tool says so with a
# "skip" line rather than a failure; where it is configured (configs/sm.config
# in un) the "abc" vector has to come out right.
@test "digest: standalone sm3" {
    [ -n "${DIGEST_BIN}" ] || skip "digest binary not built (run: make test)"
    run "${DIGEST_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" != *"sm3: skip"* ]] || skip "requires CONFIG_CRYPTO_SM3=y"
    [[ "${output}" == *"sm3: ok"* ]]
}

@test "digest: sha3-256 empty vs openssl" {
    command -v openssl >/dev/null || skip "openssl not available"
    [ -n "${DIGEST_BIN}" ] || skip "digest binary not built"

    expected="$(printf '' | openssl dgst -sha3-256 -r | awk '{print $1}')"
    [ "${expected}" = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" ]
}
