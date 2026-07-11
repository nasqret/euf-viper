#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-ab-merge
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:30:00
#SBATCH --output=results/wmi-ab-merge-%j.out
#SBATCH --error=results/wmi-ab-merge-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
cd "$ROOT"

RUN_ID="${EUF_VIPER_AB_RUN_ID:?set EUF_VIPER_AB_RUN_ID}"
SHARDS="${EUF_VIPER_AB_SHARDS:?set EUF_VIPER_AB_SHARDS}"
REPEATS="${EUF_VIPER_AB_REPEATS:?set EUF_VIPER_AB_REPEATS}"
MANIFEST="${EUF_VIPER_AB_MANIFEST:?set EUF_VIPER_AB_MANIFEST}"
INPUTS=()
for ((index = 0; index < SHARDS; index++)); do
  INPUTS+=("results/wmi-ab-corpus-${RUN_ID}-shard-${index}.csv")
done

scripts/bench/merge_viper_ab.py \
  "$MANIFEST" \
  "${INPUTS[@]}" \
  --repeats "$REPEATS" \
  --out "results/wmi-ab-corpus-${RUN_ID}.csv" \
  --summary "results/wmi-ab-corpus-${RUN_ID}.json"
