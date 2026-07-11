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
RANDOM_CASES="${EUF_VIPER_BOOL_DIFF_CASES:-10000}"
SEED="${EUF_VIPER_BOOL_DIFF_SEED:-20260711}"
TIMEOUT="${EUF_VIPER_BOOL_DIFF_TIMEOUT:-2}"
RUN_ID="${SLURM_JOB_ID:-local}"

cd "$ROOT"
mkdir -p results

python3 scripts/bench/differential_bool_data.py \
  --out "results/bool-data-diff-$RUN_ID" \
  --seed "$SEED" \
  --random-cases "$RANDOM_CASES" \
  --timeout "$TIMEOUT" \
  --viper-command 'target/release/euf-viper solve {file}' \
  --z3-command "$REFERENCE_ROOT/third_party/solvers/bin/z3 -smt2 {file}" \
  --cvc5-command "$REFERENCE_ROOT/third_party/solvers/bin/cvc5 --lang=smt2 {file}"

sha256sum "results/bool-data-diff-$RUN_ID/summary.json"
