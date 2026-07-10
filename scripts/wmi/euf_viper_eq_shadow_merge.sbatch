#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-eq-shadow-merge
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:30:00
#SBATCH --output=results/wmi-eq-shadow-merge-%j.out
#SBATCH --error=results/wmi-eq-shadow-merge-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"

RUN_ID="${EUF_VIPER_EQ_SHADOW_RUN_ID:?set EUF_VIPER_EQ_SHADOW_RUN_ID}"
SHARDS="${EUF_VIPER_EQ_SHADOW_SHARDS:?set EUF_VIPER_EQ_SHADOW_SHARDS}"
MANIFEST="${EUF_VIPER_EQ_SHADOW_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl}"
INPUTS=()
for ((index = 0; index < SHARDS; index++)); do
  INPUTS+=("results/wmi-eq-shadow-${RUN_ID}-shard-${index}.jsonl")
done

scripts/bench/collect_eq_abstraction_shadow.py merge \
  "$MANIFEST" \
  "${INPUTS[@]}" \
  --out "results/wmi-eq-shadow-${RUN_ID}.jsonl" \
  --summary "results/wmi-eq-shadow-${RUN_ID}.json"
