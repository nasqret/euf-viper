#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-eq-shadow
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=8
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=results/wmi-eq-shadow-%A_%a.out
#SBATCH --error=results/wmi-eq-shadow-%A_%a.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

RUN_ID="${EUF_VIPER_EQ_SHADOW_RUN_ID:-${SLURM_ARRAY_JOB_ID:-${SLURM_JOB_ID:?}}}"
SHARDS="${EUF_VIPER_EQ_SHADOW_SHARDS:?set EUF_VIPER_EQ_SHADOW_SHARDS}"
INDEX="${SLURM_ARRAY_TASK_ID:?run as a SLURM array}"
MANIFEST="${EUF_VIPER_EQ_SHADOW_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl}"
BENCHMARK_ROOT="${EUF_VIPER_EQ_SHADOW_BENCHMARK_ROOT:-$PWD/benchmarks/smtlib-2025/QF_UF}"
BINARY="${EUF_VIPER_EQ_SHADOW_BINARY:-$PWD/target/release/euf-viper}"
TIMEOUT="${EUF_VIPER_EQ_SHADOW_TIMEOUT:-10}"
JOBS="${EUF_VIPER_EQ_SHADOW_JOBS:-${SLURM_CPUS_PER_TASK:-1}}"
SHARD_DIR="$PWD/benchmarks/smtlib-2025/eq-shadow-shards-$RUN_ID"
SHARD_MANIFEST="$SHARD_DIR/qf_uf_${INDEX}.jsonl"
OUT_PREFIX="results/wmi-eq-shadow-${RUN_ID}-shard-${INDEX}"

mkdir -p "$SHARD_DIR" results
scripts/bench/shard_manifest.py \
  "$MANIFEST" \
  --shards "$SHARDS" \
  --index "$INDEX" \
  --out "$SHARD_MANIFEST"

scripts/bench/collect_eq_abstraction_shadow.py collect \
  "$SHARD_MANIFEST" \
  --binary "$BINARY" \
  --benchmark-root "$BENCHMARK_ROOT" \
  --timeout "$TIMEOUT" \
  --jobs "$JOBS" \
  --out "${OUT_PREFIX}.jsonl" \
  --summary "${OUT_PREFIX}.json"
