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
EXPECTED="${EUF_VIPER_QG7_CENSUS_EXPECTED:?set EUF_VIPER_QG7_CENSUS_EXPECTED to the positive exact record count}"
RUN_ID="${EUF_VIPER_QG7_CENSUS_RUN_ID:-$SLURM_JOB_ID}"
OUTPUT="${EUF_VIPER_QG7_CENSUS_OUTPUT:-$ROOT/results/qg7-rtxc-census-$RUN_ID.jsonl}"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-$SLURM_JOB_ID}"
TARGET_DIR="${CARGO_TARGET_DIR:-$SCRATCH_ROOT/target}"

if [[ ! "$LIMIT" =~ ^[1-9][0-9]*$ ]] || ((LIMIT > 512)); then
  printf 'EUF_VIPER_QG7_CENSUS_LIMIT must be an integer in 1..512, got %q\n' "$LIMIT" >&2
  exit 2
fi
if [[ ! "$OFFSET" =~ ^(0|[1-9][0-9]*)$ ]]; then
  printf 'EUF_VIPER_QG7_CENSUS_OFFSET must be a nonnegative integer, got %q\n' "$OFFSET" >&2
  exit 2
fi
if [[ ! "$EXPECTED" =~ ^[1-9][0-9]*$ ]] || ((EXPECTED > LIMIT)); then
  printf 'EUF_VIPER_QG7_CENSUS_EXPECTED must be an integer in 1..%s, got %q\n' "$LIMIT" "$EXPECTED" >&2
  exit 2
fi
case "$OUTPUT" in
  *.jsonl) ;;
  *)
    printf 'EUF_VIPER_QG7_CENSUS_OUTPUT must end in .jsonl, got %q\n' "$OUTPUT" >&2
    exit 2
    ;;
esac
RAW_OUTPUT="${OUTPUT%.jsonl}.raw.log"

cd "$ROOT"
test -d "$QG7_DIR"
QG7_DIR="$(cd "$QG7_DIR" && pwd -P)"
REVISION="$(git rev-parse --verify HEAD)"
if [[ -n "${EUF_VIPER_GIT_REVISION:-}" && "$EUF_VIPER_GIT_REVISION" != "$REVISION" ]]; then
  printf 'requested revision %s does not match checked-out revision %s\n' \
    "$EUF_VIPER_GIT_REVISION" "$REVISION" >&2
  exit 2
fi

mkdir -p results "$(dirname "$OUTPUT")"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$TARGET_DIR"
export RUST_MIN_STACK="${EUF_VIPER_QG7_CENSUS_STACK_BYTES:-67108864}"
export EUF_VIPER_QG7_CENSUS_DIR="$QG7_DIR"
export EUF_VIPER_QG7_CENSUS_LIMIT="$LIMIT"
export EUF_VIPER_QG7_CENSUS_OFFSET="$OFFSET"
export EUF_VIPER_QG7_CENSUS_EXPECTED="$EXPECTED"
export EUF_VIPER_GIT_REVISION="$REVISION"

printf 'revision=%s\n' "$REVISION"
printf 'qg7_dir=%s\n' "$QG7_DIR"
printf 'limit=%s offset=%s expected=%s output=%s\n' "$LIMIT" "$OFFSET" "$EXPECTED" "$OUTPUT"

cargo test --release --all-features \
  forbidden_orbit_probe::tests::bounded_qg7_partial_pattern_census \
  -- --ignored --exact --nocapture >"$RAW_OUTPUT"

awk '
  index($0, "QG7_CENSUS_JSON:") {
    marker = index($0, "QG7_CENSUS_JSON:") + length("QG7_CENSUS_JSON:")
    print substr($0, marker)
  }
' "$RAW_OUTPUT" >"$OUTPUT"
test -s "$OUTPUT"
PROVENANCE_RECORDS="$(awk 'index($0, "\"record_type\":\"provenance\"") { count++ } END { print count + 0 }' "$OUTPUT")"
RECORDS="$(awk 'index($0, "\"record_type\":\"case\"") { count++ } END { print count + 0 }' "$OUTPUT")"
TOTAL_RECORDS="$(wc -l <"$OUTPUT" | tr -d ' ')"
if ((PROVENANCE_RECORDS != 1)); then
  printf 'expected exactly one provenance record, found %s\n' "$PROVENANCE_RECORDS" >&2
  exit 1
fi
if ((RECORDS != EXPECTED)); then
  printf 'expected %s records, found %s\n' "$EXPECTED" "$RECORDS" >&2
  exit 1
fi
if ((TOTAL_RECORDS != EXPECTED + 1)); then
  printf 'expected %s total JSONL records, found %s\n' "$((EXPECTED + 1))" "$TOTAL_RECORDS" >&2
  exit 1
fi

printf 'records=%s\n' "$RECORDS"
printf 'output_sha256=%s\n' "$(sha256sum "$OUTPUT" | awk '{print $1}')"
