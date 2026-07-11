#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-qg7-rtxc
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=results/wmi-qg7-rtxc-census-%j.out
#SBATCH --error=results/wmi-qg7-rtxc-census-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
QG7_DIR="${EUF_VIPER_QG7_CENSUS_DIR:?set EUF_VIPER_QG7_CENSUS_DIR}"
LIMIT="${EUF_VIPER_QG7_CENSUS_LIMIT:-512}"
OFFSET="${EUF_VIPER_QG7_CENSUS_OFFSET:-0}"
EXPECTED="${EUF_VIPER_QG7_CENSUS_EXPECTED:-0}"
RUN_ID="${EUF_VIPER_QG7_CENSUS_RUN_ID:-$SLURM_JOB_ID}"
OUTPUT="${EUF_VIPER_QG7_CENSUS_OUTPUT:-$ROOT/results/qg7-rtxc-census-$RUN_ID.jsonl}"
RAW_OUTPUT="${OUTPUT%.jsonl}.raw.log"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-$SLURM_JOB_ID}"
TARGET_DIR="${CARGO_TARGET_DIR:-$SCRATCH_ROOT/target}"

cd "$ROOT"
mkdir -p results "$(dirname "$OUTPUT")"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$TARGET_DIR"
export RUST_MIN_STACK="${EUF_VIPER_QG7_CENSUS_STACK_BYTES:-67108864}"
export EUF_VIPER_QG7_CENSUS_DIR="$QG7_DIR"
export EUF_VIPER_QG7_CENSUS_LIMIT="$LIMIT"
export EUF_VIPER_QG7_CENSUS_OFFSET="$OFFSET"

test -d "$QG7_DIR"
printf 'revision=%s\n' "${EUF_VIPER_GIT_REVISION:-unknown}"
printf 'qg7_dir=%s\n' "$QG7_DIR"
printf 'limit=%s offset=%s output=%s\n' "$LIMIT" "$OFFSET" "$OUTPUT"

cargo test --release --all-features \
  forbidden_orbit_probe::tests::bounded_qg7_partial_pattern_census \
  -- --ignored --exact --nocapture >"$RAW_OUTPUT"

grep -o '{"path".*}' "$RAW_OUTPUT" >"$OUTPUT"
test -s "$OUTPUT"
RECORDS="$(wc -l <"$OUTPUT" | tr -d ' ')"
if [ "$EXPECTED" -gt 0 ] && [ "$RECORDS" -ne "$EXPECTED" ]; then
  printf 'expected %s records, found %s\n' "$EXPECTED" "$RECORDS" >&2
  exit 1
fi

printf 'records=%s\n' "$RECORDS"
printf 'output_sha256=%s\n' "$(sha256sum "$OUTPUT" | awk '{print $1}')"
