#!/usr/bin/env bats
#
# Integration tests for the crypto TLS 1.2 PRF module (RFC 5246 section 5).
# Wraps the standalone `prf` test program (crypto/tools/prf.c). (No OpenSSL CLI
# equivalent exists for the TLS PRF, so correctness rests on the published
# TLS 1.2 PRF-SHA256 known-answer vector the binary asserts.)
#

setup_file() {
    CRYPTO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
    export CRYPTO_ROOT

    if [[ -z "${PRF_BIN:-}" ]]; then
        for candidate in \
            "${CRYPTO_ROOT}/obj/tools/prf" \
            "${CRYPTO_ROOT}/obj/crypto/tools/prf"
        do
            [[ -x "${candidate}" ]] && { PRF_BIN="${candidate}"; break; }
        done
    fi
    export PRF_BIN="${PRF_BIN:-}"
}

@test "prf: standalone TLS 1.2 PRF-SHA256 vector" {
    [ -n "${PRF_BIN}" ] || skip "prf binary not built (run: make test)"
    run "${PRF_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"prf-sha256: ok"* ]]
    [[ "${output}" != *"FAIL"* ]]
}
