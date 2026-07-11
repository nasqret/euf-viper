#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-parser-diff
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=8
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=results/wmi-parser-diff-%j.out
#SBATCH --error=results/wmi-parser-diff-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

PARSER_MODE="${EUF_VIPER_PARSER_MODE:?set EUF_VIPER_PARSER_MODE to tree, shadow, or stream}"
case "$PARSER_MODE" in
  tree|shadow|stream) ;;
  *) echo "EUF_VIPER_PARSER_MODE must be tree, shadow, or stream" >&2; exit 2 ;;
esac

RUN_ID="${EUF_VIPER_PARSER_RUN_ID:-${SLURM_JOB_ID:?}}"
MANIFEST="${EUF_VIPER_PARSER_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl}"
BENCHMARK_ROOT="${EUF_VIPER_PARSER_BENCHMARK_ROOT:-$PWD/benchmarks/smtlib-2025/QF_UF}"
BINARY="${EUF_VIPER_PARSER_BINARY:-$PWD/target/release/euf-viper}"
TIMEOUT="${EUF_VIPER_PARSER_TIMEOUT:-10}"
JOBS="${EUF_VIPER_PARSER_JOBS:-${SLURM_CPUS_PER_TASK:-1}}"
OUT_PREFIX="${EUF_VIPER_PARSER_OUT_PREFIX:-results/wmi-parser-diff-${RUN_ID}-${PARSER_MODE}}"

mkdir -p "$(dirname "$OUT_PREFIX")"
scripts/bench/collect_parser_differential.py \
  "$MANIFEST" \
  --binary "$BINARY" \
  --candidate-parser-mode "$PARSER_MODE" \
  --benchmark-root "$BENCHMARK_ROOT" \
  --timeout "$TIMEOUT" \
  --jobs "$JOBS" \
  --out "${OUT_PREFIX}.jsonl" \
  --summary "${OUT_PREFIX}.json"
