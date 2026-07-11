#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-bool-diff
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=01:00:00
#SBATCH --output=results/wmi-bool-diff-%j.out
#SBATCH --error=results/wmi-bool-diff-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-$PWD}"
REFERENCE_ROOT="${EUF_VIPER_REFERENCE_ROOT:-/home/bnaskrecki/euf-viper-scoped-let-58efe9d}"
VIPER_BIN="${EUF_VIPER_BIN:-$ROOT/target/release/euf-viper}"
Z3_BIN="${EUF_VIPER_Z3_BIN:-$REFERENCE_ROOT/third_party/solvers/bin/z3}"
CVC5_BIN="${EUF_VIPER_CVC5_BIN:-$REFERENCE_ROOT/third_party/solvers/bin/cvc5}"
RANDOM_CASES="${EUF_VIPER_BOOL_DIFF_CASES:-10000}"
SEED="${EUF_VIPER_BOOL_DIFF_SEED:-20260711}"
TIMEOUT="${EUF_VIPER_BOOL_DIFF_TIMEOUT:-2}"
DIRECT_NEGATED_ROOT="${EUF_VIPER_BOOL_DIFF_DIRECT_NEGATED_ROOT:-0}"
RUN_ID="${SLURM_JOB_ID:-local}"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-$RUN_ID}"
SCRATCH_OUT="$SCRATCH_ROOT/bool-data-diff-$RUN_ID"
PERSIST_OUT="$ROOT/results/bool-data-diff-$RUN_ID"

cd "$ROOT"
mkdir -p results

case "$DIRECT_NEGATED_ROOT" in
  0 | 1) ;;
  *) echo "EUF_VIPER_BOOL_DIFF_DIRECT_NEGATED_ROOT must be 0 or 1" >&2; exit 2 ;;
esac

python3 scripts/bench/differential_bool_data.py \
  --out "$SCRATCH_OUT" \
  --seed "$SEED" \
  --random-cases "$RANDOM_CASES" \
  --timeout "$TIMEOUT" \
  --viper-command "env EUF_VIPER_DIRECT_NEGATED_ROOT=$DIRECT_NEGATED_ROOT $VIPER_BIN solve {file}" \
  --z3-command "$Z3_BIN {file}" \
  --cvc5-command "$CVC5_BIN --lang=smt2 {file}"

mkdir -p "$PERSIST_OUT"
tar -czf "$PERSIST_OUT/cases.tar.gz" -C "$SCRATCH_OUT" cases
install -m 0644 \
  "$SCRATCH_OUT/manifest.jsonl" \
  "$SCRATCH_OUT/results.jsonl" \
  "$SCRATCH_OUT/summary.json" \
  "$PERSIST_OUT/"
sha256sum \
  "$PERSIST_OUT/cases.tar.gz" \
  "$PERSIST_OUT/manifest.jsonl" \
  "$PERSIST_OUT/results.jsonl" \
  "$PERSIST_OUT/summary.json"
