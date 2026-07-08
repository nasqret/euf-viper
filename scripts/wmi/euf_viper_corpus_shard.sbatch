#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-shard
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=8
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=results/wmi-corpus-shard-%A_%a.out
#SBATCH --error=results/wmi-corpus-shard-%A_%a.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$PWD/third_party/solvers/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

RUN_ID="${EUF_VIPER_RUN_ID:?set EUF_VIPER_RUN_ID}"
SHARDS="${EUF_VIPER_CORPUS_SHARDS:?set EUF_VIPER_CORPUS_SHARDS}"
INDEX="${SLURM_ARRAY_TASK_ID:?run as a SLURM array}"
TIMEOUT="${EUF_VIPER_CORPUS_TIMEOUT:?set EUF_VIPER_CORPUS_TIMEOUT}"
JOBS="${EUF_VIPER_CORPUS_JOBS:-${SLURM_CPUS_PER_TASK:-1}}"
SHARD_DIR="$PWD/benchmarks/smtlib-2025/shards-$RUN_ID"
SHARD_MANIFEST="$SHARD_DIR/qf_uf_${INDEX}.jsonl"
CAMPAIGN_MANIFEST="$PWD/benchmarks/smtlib-2025/qf_uf_campaign_${RUN_ID}.jsonl"
OUT_PREFIX="results/qf-uf-corpus-${RUN_ID}-shard-${INDEX}"

mkdir -p "$SHARD_DIR" results
scripts/bench/shard_manifest.py \
  "$CAMPAIGN_MANIFEST" \
  --shards "$SHARDS" \
  --index "$INDEX" \
  --out "$SHARD_MANIFEST"

scripts/bench/compare_solvers.py "$SHARD_MANIFEST" \
  --viper "$PWD/target/release/euf-viper" \
  --z3 "$PWD/third_party/solvers/bin/z3" \
  --cvc5 "$PWD/third_party/solvers/bin/cvc5" \
  --yices "$PWD/third_party/solvers/bin/yices-smt2" \
  --timeout "$TIMEOUT" \
  --jobs "$JOBS" \
  --resume \
  --out "${OUT_PREFIX}.csv" \
  --summary "${OUT_PREFIX}.json" \
  --progress "${OUT_PREFIX}.progress.json"
