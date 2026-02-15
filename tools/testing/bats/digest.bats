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
    [[ "${output}" == "sha3-256: ok" ]]
}

@test "digest: sha3-256 empty vs openssl" {
    command -v openssl >/dev/null || skip "openssl not available"
    [ -n "${DIGEST_BIN}" ] || skip "digest binary not built"

    expected="$(printf '' | openssl dgst -sha3-256 -r | awk '{print $1}')"
    [ "${expected}" = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" ]
}
