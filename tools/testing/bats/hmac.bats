#!/usr/bin/env bats
#
# Integration tests for the crypto HMAC module (HMAC-SHA1/224/256/384/512 and
# HMAC-SHA3). Wraps the standalone `hmac` test program (crypto/tools/hmac.c),
# plus an independent OpenSSL cross-check.
#

setup_file() {
    CRYPTO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
    export CRYPTO_ROOT

    if [[ -z "${HMAC_BIN:-}" ]]; then
        for candidate in \
            "${CRYPTO_ROOT}/obj/tools/hmac" \
            "${CRYPTO_ROOT}/obj/crypto/tools/hmac"
        do
            [[ -x "${candidate}" ]] && { HMAC_BIN="${candidate}"; break; }
        done
    fi
    export HMAC_BIN="${HMAC_BIN:-}"
}

@test "hmac: standalone vectors (RFC 2202 / RFC 4231)" {
    [ -n "${HMAC_BIN}" ] || skip "hmac binary not built (run: make test)"
    run "${HMAC_BIN}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"hmac-sha1: ok"* ]]
    [[ "${output}" == *"hmac-sha256: ok"* ]]
    [[ "${output}" == *"hmac-sha384: ok"* ]]
    [[ "${output}" == *"hmac-sha512: ok"* ]]
    [[ "${output}" == *"hmac-sha3-256: ok"* ]]
    [[ "${output}" != *"FAIL"* ]]
}

@test "hmac: sha256 RFC 4231 TC2 vs openssl" {
    command -v openssl >/dev/null || skip "openssl not available"

    # RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?".
    local mac
    mac="$(printf 'what do ya want for nothing?' \
        | openssl dgst -sha256 -hmac 'Jefe' | awk '{print $NF}')"
    [ "${mac}" = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" ]
}
