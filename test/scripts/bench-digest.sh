#!/bin/bash
#
# bench-digest.sh - Benchmark generic, OpenSSL and aws-lc digest implementations
#
# Configures each built-in variant, builds, runs the perf test,
# collects results into a table and generates a bar chart (PNG).
#
# Usage: scripts/bench-digest.sh [output_dir]

set -e

SRCDIR="$(cd "$(dirname "$0")/../.." && pwd)"
OBJDIR="$SRCDIR/obj"
OUTDIR="${1:-$OBJDIR/bench}"
PERF_BIN="test/perf/digest"
PERF_BIN_EVP="test/perf/digest-ossl-evp"

mkdir -p "$OUTDIR"

# Bootstrap a default config if none exists (e.g. after make distclean)
if [ ! -f "$OBJDIR/.config" ]; then
	make -C "$SRCDIR" -s defconfig 2>/dev/null
fi

cp "$OBJDIR/.config" "$OBJDIR/.config.bench-save"
trap 'mv -f "$OBJDIR/.config.bench-save" "$OBJDIR/.config"; \
      make -C "$SRCDIR" -s olddefconfig 2>/dev/null || true' EXIT

write_config() {
	local variant="$1"

	grep -v \
		-e CONFIG_MODULES \
		-e CONFIG_CRYPTO_VERIFIED \
		-e CONFIG_CRYPTO_SHA1_SEL \
		-e CONFIG_CRYPTO_SHA2_SEL \
		-e CONFIG_CRYPTO_SHA3_SEL \
		-e CONFIG_CRYPTO_SHA1_GENERIC \
		-e CONFIG_CRYPTO_SHA1_OSSL \
		-e CONFIG_CRYPTO_SHA1_AWS \
		-e CONFIG_CRYPTO_SHA1_NULL \
		-e CONFIG_CRYPTO_SHA2_GENERIC \
		-e CONFIG_CRYPTO_SHA2_OSSL \
		-e CONFIG_CRYPTO_SHA2_AWS \
		-e CONFIG_CRYPTO_SHA2_NULL \
		-e CONFIG_CRYPTO_SHA3_OSSL \
		-e CONFIG_CRYPTO_SHA3_AWS \
		-e CONFIG_CRYPTO_SHA3_NULL \
		-e CONFIG_CRYPTO_SHA1_OSSL_X86_64 \
		-e CONFIG_CRYPTO_SHA1_OSSL_ARMV8 \
		-e CONFIG_CRYPTO_SHA1_AWS_X86_64 \
		-e CONFIG_CRYPTO_SHA1_AWS_ARMV8 \
		-e CONFIG_CRYPTO_SHA2_OSSL_X86_64 \
		-e CONFIG_CRYPTO_SHA2_OSSL_ARMV8 \
		-e CONFIG_CRYPTO_SHA2_AWS_X86_64 \
		-e CONFIG_CRYPTO_SHA2_AWS_ARMV8 \
		-e CONFIG_CRYPTO_SHA3_OSSL_X86_64 \
		-e CONFIG_CRYPTO_SHA3_OSSL_ARMV8 \
		-e CONFIG_CRYPTO_SHA3_AWS_X86_64 \
		-e CONFIG_CRYPTO_SHA3_AWS_ARMV8 \
		-e 'CONFIG_CRYPTO_SHA3=' \
		-e CONFIG_CRYPTO_SHA3_DYN \
		-e CONFIG_CRYPTO_SHA1_DYN \
		-e CONFIG_CRYPTO_SHA2_DYN \
		"$OBJDIR/.config.bench-save" > "$OBJDIR/.config" || true

	cat >> "$OBJDIR/.config" <<-EOF
	# CONFIG_MODULES is not set
	# CONFIG_CRYPTO_VERIFIED is not set
	EOF

	case "$variant" in
	generic)
		cat >> "$OBJDIR/.config" <<-EOF
		CONFIG_CRYPTO_SHA1_SEL_GENERIC=y
		CONFIG_CRYPTO_SHA2_SEL_GENERIC=y
		CONFIG_CRYPTO_SHA3_SEL_C=y
		EOF
		;;
	ossl)
		cat >> "$OBJDIR/.config" <<-EOF
		CONFIG_CRYPTO_SHA1_SEL_OSSL=y
		CONFIG_CRYPTO_SHA2_SEL_OSSL=y
		CONFIG_CRYPTO_SHA3_SEL_OSSL=y
		EOF
		;;
	aws)
		cat >> "$OBJDIR/.config" <<-EOF
		CONFIG_CRYPTO_SHA1_SEL_AWS=y
		CONFIG_CRYPTO_SHA2_SEL_AWS=y
		CONFIG_CRYPTO_SHA3_SEL_AWS=y
		EOF
		;;
	esac
}

build_variant() {
	local variant="$1"

	printf "==> %-8s configuring... " "$variant"
	write_config "$variant"
	make -C "$SRCDIR" -s olddefconfig
	printf "building... "
	make -C "$SRCDIR" -s clean 2>/dev/null || true
	if ! make -C "$SRCDIR" -j"$(nproc)" test/perf/ 2>&1; then
		printf "FAILED\n"
		echo "ERROR: build failed for variant '$variant'" >&2
		return 1
	fi
	printf "done\n"
}

run_variant() {
	local variant="$1"
	local out="$OUTDIR/$variant.txt"

	printf "==> %-8s benchmarking...\n" "$variant"
	"$OBJDIR/$PERF_BIN" > "$out" 2>&1
	cat "$out"
	echo
}

# ---------- main ----------

BUILT_VARIANTS=""

for v in generic ossl aws; do
	if build_variant "$v"; then
		run_variant "$v"
		BUILT_VARIANTS="$BUILT_VARIANTS $v"
	fi
done

VARIANTS="${BUILT_VARIANTS# }"

# ---------- OpenSSL EVP (system library, config-independent) ----------

if [ -x "$OBJDIR/$PERF_BIN_EVP" ]; then
	printf "==> %-8s benchmarking...\n" "ossl-evp"
	"$OBJDIR/$PERF_BIN_EVP" > "$OUTDIR/ossl-evp.txt" 2>&1
	cat "$OUTDIR/ossl-evp.txt"
	echo
	VARIANTS="$VARIANTS ossl-evp"
fi

# ---------- Display labels ----------

display_name() {
	case "$1" in
	generic)  echo "crypto-generic" ;;
	ossl)     echo "crypto-ossl"    ;;
	aws)      echo "crypto-aws"     ;;
	ossl-evp) echo "openssl-evp"    ;;
	*)        echo "$1"             ;;
	esac
}

# ---------- Combined table ----------

echo "=========================================="
echo "           Combined Results"
echo "=========================================="
printf "%-12s" "Algorithm"
for v in $VARIANTS; do
	printf "  %14s" "$(display_name "$v")"
done
printf "\n"
printf "%-12s" "---------"
for v in $VARIANTS; do
	printf "  %14s" "--------------"
done
printf "\n"

# Collect algo list from first variant
algos=$(grep "Gbps" "$OUTDIR/generic.txt" | awk '{print $1}')

for algo in $algos; do
	printf "%-12s" "$algo"
	for v in $VARIANTS; do
		gbps=$(grep "^  $algo " "$OUTDIR/$v.txt" | \
		       grep -o '[0-9.]*  *Gbps' | awk '{print $1}')
		printf "  %11s Gbps" "${gbps:-n/a}"
	done
	printf "\n"
done

RESULTS="$OUTDIR/results.tsv"
{
	printf "Algorithm"
	for v in $VARIANTS; do printf "\t%s" "$(display_name "$v")"; done
	printf "\n"
	for algo in $algos; do
		printf "%s" "$algo"
		for v in $VARIANTS; do
			gbps=$(grep "^  $algo " "$OUTDIR/$v.txt" | \
			       grep -o '[0-9.]*  *Gbps' | awk '{print $1}')
			printf "\t%s" "${gbps:-0}"
		done
		printf "\n"
	done
} > "$RESULTS"

echo
echo "Table saved to $RESULTS"

# ---------- Generate graph ----------

GRAPH="$OUTDIR/bench-digest.png"

python3 - "$OUTDIR" "$GRAPH" "$VARIANTS" <<'PYEOF'
import sys, os, re
from collections import OrderedDict

outdir   = sys.argv[1]
graph    = sys.argv[2]
variants = sys.argv[3].split()

data = OrderedDict()
for v in variants:
    path = os.path.join(outdir, v + ".txt")
    with open(path) as f:
        for line in f:
            m = re.search(
                r'^\s+(\S+)\s+\d+\s+iters\s+[\d.]+\s+MB/s\s+([\d.]+)\s+Gbps',
                line)
            if m:
                algo, gbps = m.group(1), float(m.group(2))
                data.setdefault(algo, OrderedDict())[v] = gbps

if not data:
    print("No data to plot.")
    sys.exit(0)

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("matplotlib not available — install with: pip3 install matplotlib")
    sys.exit(0)

algos = list(data.keys())
n = len(algos)
x = np.arange(n)
width = 0.8 / max(len(variants), 1)
labels = {'generic': 'crypto-generic', 'ossl': 'crypto-ossl',
          'aws': 'crypto-aws', 'ossl-evp': 'openssl-evp'}
colors = {'generic': '#5b9bd5', 'ossl': '#ed7d31', 'aws': '#70ad47', 'ossl-evp': '#ffc000'}

fig, ax = plt.subplots(figsize=(max(10, n * 1.2), 6))

for i, v in enumerate(variants):
    vals = [data[a].get(v, 0) for a in algos]
    bars = ax.bar(x + i * width, vals, width, label=labels.get(v, v), color=colors.get(v))
    for bar, val in zip(bars, vals):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.3,
                    f'{val:.1f}', ha='center', va='bottom', fontsize=7)

ax.set_xlabel('Algorithm')
ax.set_ylabel('Throughput (Gbps)')
ax.set_title('Digest Performance: crypto-generic vs crypto-ossl vs crypto-aws vs openssl-evp')
ax.set_xticks(x + width * (len(variants) - 1) / 2)
ax.set_xticklabels(algos, rotation=30, ha='right')
ax.legend()
ax.grid(axis='y', alpha=0.3)
fig.tight_layout()
fig.savefig(graph, dpi=150)
print(f"\nGraph saved to {graph}")
PYEOF
