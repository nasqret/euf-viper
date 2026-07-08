#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-qfuf
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --time=04:00:00
#SBATCH --output=results/wmi-corpus-%j.out
#SBATCH --error=results/wmi-corpus-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
mkdir -p results
export PATH="$PWD/third_party/solvers/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is not available on this WMI shell; install Rust or load the correct environment." >&2
  exit 127
fi

cargo build --release

scripts/bench/install_solvers.sh "$PWD/third_party/solvers" \
  > "results/solvers-${SLURM_JOB_ID}.log" 2>&1

scripts/bench/fetch_smtlib_qf_uf.sh "$PWD/benchmarks/smtlib-2025" \
  > "results/qf-uf-fetch-${SLURM_JOB_ID}.log" 2>&1

MANIFEST="$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl"
RUN_MANIFEST="$MANIFEST"
LIMIT="${EUF_VIPER_CORPUS_LIMIT:-40}"
SEED="${EUF_VIPER_CORPUS_SEED:-euf-viper-qf-uf-wmi-20260708}"
JOBS="${EUF_VIPER_CORPUS_JOBS:-${SLURM_CPUS_PER_TASK:-1}}"
PATH_REGEX="${EUF_VIPER_CORPUS_PATH_REGEX:-}"

if [ -n "$PATH_REGEX" ]; then
  MANIFEST="$PWD/benchmarks/smtlib-2025/qf_uf_filter_${SLURM_JOB_ID}.jsonl"
  scripts/bench/filter_manifest.py \
    "$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl" \
    --path-regex "$PATH_REGEX" \
    --out "$MANIFEST" \
    > "results/qf-uf-filter-${SLURM_JOB_ID}.log"
  RUN_MANIFEST="$MANIFEST"
fi

if [ "$LIMIT" -gt 0 ]; then
  RUN_MANIFEST="$PWD/benchmarks/smtlib-2025/qf_uf_sample_${LIMIT}_${SLURM_JOB_ID}.jsonl"
  scripts/bench/sample_manifest.py "$MANIFEST" \
    --limit "$LIMIT" \
    --seed "$SEED" \
    --out "$RUN_MANIFEST" \
    > "results/qf-uf-sample-${SLURM_JOB_ID}.log"
fi

scripts/bench/compare_solvers.py "$RUN_MANIFEST" \
  --viper "$PWD/target/release/euf-viper" \
  --z3 "$PWD/third_party/solvers/bin/z3" \
  --cvc5 "$PWD/third_party/solvers/bin/cvc5" \
  --yices "$PWD/third_party/solvers/bin/yices-smt2" \
  --timeout "${EUF_VIPER_CORPUS_TIMEOUT:-10}" \
  --jobs "$JOBS" \
  --resume \
  --out "results/qf-uf-corpus-${SLURM_JOB_ID}.csv" \
  --summary "results/qf-uf-corpus-${SLURM_JOB_ID}.json" \
  --progress "results/qf-uf-corpus-${SLURM_JOB_ID}.progress.json"
