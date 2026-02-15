#!/usr/bin/env bats
#
# One bats case per cmocka unit binary (tools/testing/selftests/units/Kbuild).
#
# Driving the units through bats keeps every result in the single TAP stream
# the shared runner (vendor/kbuild scripts/run-check.sh) aggregates: the runner
# discovers the built binaries and exports each as <NAME>_BIN; this suite is
# where they are run, reported and counted.
#
# The fallbacks below cover both layouts the crypto package is built in:
# standalone, where the object tree is ./obj, and hosted under a parent
# project, where it is <parent>/obj/crypto.

setup_file() {
    CRYPTO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
    export CRYPTO_ROOT
}

# unit_bin <TEST_NAME> - echo the path to a built unit binary, or nothing.
unit_bin() {
    local name="$1" var candidate
    var="$(echo "${name}" | tr '[:lower:]' '[:upper:]')_BIN"
    for candidate in \
        "${!var:-}" \
        "${CRYPTO_ROOT}/obj/tools/testing/selftests/units/${name}" \
        "${CRYPTO_ROOT}/../../obj/crypto/tools/testing/selftests/units/${name}"
    do
        [ -n "${candidate}" ] && [ -x "${candidate}" ] || continue
        echo "${candidate}"
        return 0
    done
    return 0
}

# run_unit <TEST_NAME> - run one cmocka group binary. On failure the cmocka
# output is forwarded to fd 3 so the failing group and assertion reach the
# check log; a passing unit stays quiet.
run_unit() {
    local bin
    bin="$(unit_bin "$1")"
    [ -n "${bin}" ] || skip "not built (make test)"

    run "${bin}"
    if [ "${status}" -ne 0 ]; then
        echo "${output}" >&3
    fi
    [ "${status}" -eq 0 ]
    [[ "${output}" != *"FAILED"* ]]
}

@test "units: wire cmocka group (crypto/wire.h bounds, guard-page backed)" {
    run_unit test_wire
}
