#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-prep
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --time=01:00:00
#SBATCH --output=results/wmi-corpus-prepare-%j.out
#SBATCH --error=results/wmi-corpus-prepare-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
mkdir -p results
export PATH="$PWD/third_party/solvers/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

SKIP_BUILD="${EUF_VIPER_CORPUS_SKIP_BUILD:-0}"
EXPECTED_BINARY_SHA256="${EUF_VIPER_EXPECTED_BINARY_SHA256:-}"
case "$SKIP_BUILD" in
  0) cargo build --release ;;
  1) test -x "$PWD/target/release/euf-viper" ;;
  *) echo "EUF_VIPER_CORPUS_SKIP_BUILD must be 0 or 1" >&2; exit 2 ;;
esac
if [ -n "$EXPECTED_BINARY_SHA256" ]; then
  ACTUAL_BINARY_SHA256="$(sha256sum "$PWD/target/release/euf-viper" | awk '{print $1}')"
  if [ "$ACTUAL_BINARY_SHA256" != "$EXPECTED_BINARY_SHA256" ]; then
    echo "euf-viper SHA-256 mismatch: expected $EXPECTED_BINARY_SHA256, got $ACTUAL_BINARY_SHA256" >&2
    exit 2
  fi
fi
scripts/bench/install_solvers.sh "$PWD/third_party/solvers" \
  > "results/solvers-${SLURM_JOB_ID}.log" 2>&1
scripts/bench/fetch_smtlib_qf_uf.sh "$PWD/benchmarks/smtlib-2025" \
  > "results/qf-uf-fetch-${SLURM_JOB_ID}.log" 2>&1

FULL_MANIFEST="$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl"
CAMPAIGN_MANIFEST="$PWD/benchmarks/smtlib-2025/qf_uf_campaign_${SLURM_JOB_ID}.jsonl"
LIMIT="${EUF_VIPER_CORPUS_LIMIT:-0}"
SEED="${EUF_VIPER_CORPUS_SEED:-euf-viper-qf-uf-wmi-20260708}"

if [ "$LIMIT" -gt 0 ]; then
  scripts/bench/sample_manifest.py "$FULL_MANIFEST" \
    --limit "$LIMIT" \
    --seed "$SEED" \
    --out "$CAMPAIGN_MANIFEST" \
    > "results/qf-uf-sample-${SLURM_JOB_ID}.log"
else
  cp "$FULL_MANIFEST" "$CAMPAIGN_MANIFEST"
fi

test -x "$PWD/target/release/euf-viper"
test -x "$PWD/third_party/solvers/bin/z3"
test -x "$PWD/third_party/solvers/bin/cvc5"
test -x "$PWD/third_party/solvers/bin/yices-smt2"
test -s "$CAMPAIGN_MANIFEST"

printf 'revision=%s\n' "${EUF_VIPER_GIT_REVISION:-unknown}"
printf 'binary_sha256=%s\n' "$(sha256sum "$PWD/target/release/euf-viper" | awk '{print $1}')"
printf 'manifest=%s\n' "$CAMPAIGN_MANIFEST"
printf 'manifest_rows=%s\n' "$(wc -l < "$CAMPAIGN_MANIFEST")"
