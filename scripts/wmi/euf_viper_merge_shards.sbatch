#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-merge
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:30:00
#SBATCH --output=results/wmi-corpus-merge-%j.out
#SBATCH --error=results/wmi-corpus-merge-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"

RUN_ID="${EUF_VIPER_RUN_ID:?set EUF_VIPER_RUN_ID}"
SHARDS="${EUF_VIPER_CORPUS_SHARDS:?set EUF_VIPER_CORPUS_SHARDS}"
TIMEOUT="${EUF_VIPER_CORPUS_TIMEOUT:?set EUF_VIPER_CORPUS_TIMEOUT}"
CAMPAIGN_MANIFEST="$PWD/benchmarks/smtlib-2025/qf_uf_campaign_${RUN_ID}.jsonl"
INPUTS=()
for ((index = 0; index < SHARDS; index++)); do
  INPUTS+=("results/qf-uf-corpus-${RUN_ID}-shard-${index}.csv")
done

scripts/bench/merge_shards.py \
  "$CAMPAIGN_MANIFEST" \
  "${INPUTS[@]}" \
  --solver euf-viper \
  --solver z3 \
  --solver cvc5 \
  --solver yices2 \
  --timeout "$TIMEOUT" \
  --out "results/qf-uf-corpus-${RUN_ID}.csv" \
  --summary "results/qf-uf-corpus-${RUN_ID}.json"

scripts/bench/analyze_results.py \
  "results/qf-uf-corpus-${RUN_ID}.csv" \
  --out "results/qf-uf-corpus-${RUN_ID}-analysis.json" \
  --top 100
