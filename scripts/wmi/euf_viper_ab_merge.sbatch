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

python3 scripts/bench/merge_viper_ab.py \
  "$MANIFEST" \
  "${INPUTS[@]}" \
  --repeats "$REPEATS" \
  --out "results/wmi-ab-corpus-${RUN_ID}.csv" \
  --summary "results/wmi-ab-corpus-${RUN_ID}.json"

GATE_ARGS=(
  "results/wmi-ab-corpus-${RUN_ID}.csv"
  --out "results/wmi-ab-corpus-${RUN_ID}-promotion.json"
  --seed "${EUF_VIPER_AB_GATE_SEED:-0}"
  --bootstrap-iterations "${EUF_VIPER_AB_GATE_BOOTSTRAP_ITERATIONS:-10000}"
  --permutation-iterations "${EUF_VIPER_AB_GATE_PERMUTATION_ITERATIONS:-10000}"
  --confidence-level "${EUF_VIPER_AB_GATE_CONFIDENCE_LEVEL:-0.95}"
  --min-paired-instances "${EUF_VIPER_AB_GATE_MIN_PAIRED_INSTANCES:-1}"
  --min-median-speedup "${EUF_VIPER_AB_GATE_MIN_MEDIAN_SPEEDUP:-1.0}"
  --min-total-speedup "${EUF_VIPER_AB_GATE_MIN_TOTAL_SPEEDUP:-1.0}"
  --min-geometric-speedup "${EUF_VIPER_AB_GATE_MIN_GEOMETRIC_SPEEDUP:-1.0}"
  --max-p-value "${EUF_VIPER_AB_GATE_MAX_P_VALUE:-0.05}"
)
case "${EUF_VIPER_AB_GATE_ALLOW_COMMON_TIMEOUTS:-0}" in
  0) ;;
  1) GATE_ARGS+=(--allow-common-timeouts) ;;
  *)
    echo "EUF_VIPER_AB_GATE_ALLOW_COMMON_TIMEOUTS must be 0 or 1" >&2
    exit 2
    ;;
esac

set +e
python3 scripts/bench/paired_promotion_gate.py "${GATE_ARGS[@]}"
GATE_STATUS=$?
set -e
case "$GATE_STATUS" in
  0) printf 'promotion_gate=pass\n' ;;
  1) printf 'promotion_gate=reject\n' ;;
  *)
    printf 'promotion_gate=error status=%s\n' "$GATE_STATUS" >&2
    exit "$GATE_STATUS"
    ;;
esac
