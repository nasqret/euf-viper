#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-merge
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:30:00
#SBATCH --output=results/wmi-corpus-merge-%j.out
#SBATCH --error=results/wmi-corpus-merge-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
cd "$ROOT"

RUN_ID="${EUF_VIPER_RUN_ID:?set EUF_VIPER_RUN_ID}"
SHARDS="${EUF_VIPER_CORPUS_SHARDS:?set EUF_VIPER_CORPUS_SHARDS}"
TIMEOUT="${EUF_VIPER_CORPUS_TIMEOUT:?set EUF_VIPER_CORPUS_TIMEOUT}"
RESUME_RUN_ID="${EUF_VIPER_CORPUS_RESUME_RUN_ID:-}"
RETRY_SOLVERS="${EUF_VIPER_CORPUS_RETRY_SOLVERS:-}"
if [ "${EUF_VIPER_CORPUS_RETRY_RESULTS+x}" = x ]; then
  RETRY_RESULTS="$EUF_VIPER_CORPUS_RETRY_RESULTS"
else
  RETRY_RESULTS="timeout"
fi

if [ -n "$RETRY_RESULTS" ] && \
  ! [[ "$RETRY_RESULTS" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]]; then
  echo "retry results must be a comma-separated shell-safe result list" >&2
  exit 2
fi
CAMPAIGN_MANIFEST="${EUF_VIPER_CORPUS_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_campaign_${RUN_ID}.jsonl}"
INPUTS=()
for ((index = 0; index < SHARDS; index++)); do
  INPUTS+=("results/qf-uf-corpus-${RUN_ID}-shard-${index}.csv")
done

ARGS=(
  "$CAMPAIGN_MANIFEST"
  "${INPUTS[@]}"
  --solver euf-viper
  --solver z3
  --solver cvc5
  --solver yices2
  --timeout "$TIMEOUT"
  --out "results/qf-uf-corpus-${RUN_ID}.csv"
  --summary "results/qf-uf-corpus-${RUN_ID}.json"
)
if [ -n "$RESUME_RUN_ID" ]; then
  ARGS+=(--resume-run-id "$RESUME_RUN_ID")
  if [ -n "$RETRY_RESULTS" ]; then
    IFS=',' read -r -a retry_result_names <<< "$RETRY_RESULTS"
    for result in "${retry_result_names[@]}"; do
      ARGS+=(--retry-result "$result")
    done
  fi
fi
if [ -n "$RETRY_SOLVERS" ]; then
  IFS=',' read -r -a retry_solver_names <<< "$RETRY_SOLVERS"
  for solver in "${retry_solver_names[@]}"; do
    ARGS+=(--retry-solver "$solver")
  done
fi

scripts/bench/merge_shards.py "${ARGS[@]}"

scripts/bench/analyze_results.py \
  "results/qf-uf-corpus-${RUN_ID}.csv" \
  --out "results/qf-uf-corpus-${RUN_ID}-analysis.json" \
  --top 100
