#!/usr/bin/env bash
#
# Run the crypto integration tests *and* the hpc submodule's bats tests.
#
# Mirrors vendor/hpc/tests/run-tests.sh so the two trees report results in
# the same TAP format.  When the hpc submodule is present, its bats suite
# is executed first so that a failure in the underlying primitives is
# surfaced before crypto-specific tests run.
#
set -eEu -o pipefail

export UCAP_LOG_CAPS=0
export UCAP_LOG_VERBOSE=4

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crypto_root="$(cd "${script_dir}/.." && pwd)"
hpc_root="${crypto_root}/vendor/hpc"

# Re-use the bats-core checkout shipped with the hpc submodule so we do not
# require a second copy in crypto/vendor.
bats_dir="${hpc_root}/vendor/bats-core"
if [[ -x "${bats_dir}/bin/bats" ]]; then
    export PATH="${bats_dir}/bin:${bats_dir}/libexec:${PATH}"
fi

if ! command -v bats >/dev/null 2>&1; then
    echo "error: bats not found; init submodules or install bats-core" >&2
    exit 127
fi

run_section() {
    local name="$1"; shift
    echo "# === ${name} ==="
    bats "$@"
}

# 1. hpc primitives first (only if the submodule is checked out).
if [[ -x "${hpc_root}/tests/run-tests.sh" ]]; then
    run_section "hpc submodule" "${hpc_root}/tests/"*.bats
else
    echo "# === hpc submodule === (skipped: vendor/hpc not initialised)"
fi

# 2. crypto integration tests.
run_section "crypto" "${script_dir}/"*.bats "$@"
