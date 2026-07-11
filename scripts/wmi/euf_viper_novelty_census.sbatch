#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-census
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=results/wmi-novelty-census-%j.out
#SBATCH --error=results/wmi-novelty-census-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
MANIFEST="${EUF_VIPER_NOVELTY_CENSUS_MANIFEST:?set EUF_VIPER_NOVELTY_CENSUS_MANIFEST}"
RUN_ID="${EUF_VIPER_NOVELTY_CENSUS_RUN_ID:-$SLURM_JOB_ID}"
OUTPUT="${EUF_VIPER_NOVELTY_CENSUS_OUTPUT:-$ROOT/results/novelty-census-$RUN_ID.json}"
REVISION="${EUF_VIPER_GIT_REVISION:-unknown}"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-$SLURM_JOB_ID}"
TARGET_DIR="${CARGO_TARGET_DIR:-$SCRATCH_ROOT/target}"

cd "$ROOT"
mkdir -p results "$(dirname "$OUTPUT")"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$TARGET_DIR"
export RUST_MIN_STACK="${EUF_VIPER_NOVELTY_CENSUS_STACK_BYTES:-67108864}"
export EUF_VIPER_NOVELTY_CENSUS_MANIFEST="$MANIFEST"
export EUF_VIPER_NOVELTY_CENSUS_OUTPUT="$OUTPUT"

test -s "$MANIFEST"
printf 'revision=%s\n' "$REVISION"
printf 'manifest=%s\n' "$MANIFEST"
printf 'manifest_sha256=%s\n' "$(sha256sum "$MANIFEST" | awk '{print $1}')"
printf 'output=%s\n' "$OUTPUT"

cargo test --release --all-features \
  novelty_census::corpus_census_from_env \
  -- --ignored --exact --nocapture

test -s "$OUTPUT"
printf 'output_sha256=%s\n' "$(sha256sum "$OUTPUT" | awk '{print $1}')"
