#!/usr/bin/env bash
#SBATCH --job-name=euf-t1-abba
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=03:00:00
#SBATCH --output=results/t1-timing-array-%A_%a.out
#SBATCH --error=results/t1-timing-array-%A_%a.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
source scripts/wmi/t1_timing_common.sh
export LANG=C LC_ALL=C TZ=UTC OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
unset EUF_VIPER_PROFILE

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
PUBLISHED_REF="${EUF_VIPER_T1_PUBLISHED_REF:?set EUF_VIPER_T1_PUBLISHED_REF}"
CAMPAIGN_ROOT="${EUF_VIPER_T1_TIMING_ROOT:?set EUF_VIPER_T1_TIMING_ROOT}"
SHARD="${SLURM_ARRAY_TASK_ID:?T1 timing requires an array task id}"
case "$SHARD" in
  0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;;
  *) echo "invalid array task id: $SHARD" >&2; exit 2 ;;
esac

t1_verify_checkout "$EXPECTED_REVISION" "$PUBLISHED_REF"
t1_verify_pinned_tool Python EUF_VIPER_PYTHON EUF_VIPER_PYTHON_SHA256 EUF_VIPER_PYTHON_VERSION
t1_verify_pinned_tool Cargo EUF_VIPER_CARGO EUF_VIPER_CARGO_SHA256 EUF_VIPER_CARGO_VERSION
t1_verify_pinned_tool Rustc EUF_VIPER_RUSTC EUF_VIPER_RUSTC_SHA256 EUF_VIPER_RUSTC_VERSION
"$EUF_VIPER_PYTHON" scripts/bench/typed_parser_timing.py run-shard \
  --root "$CAMPAIGN_ROOT" \
  --revision "$EXPECTED_REVISION" \
  --shard "$SHARD" \
  --require-linux-affinity
