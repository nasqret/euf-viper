#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-satsuma
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=4
#SBATCH --mem=16G
#SBATCH --time=00:30:00
#SBATCH --output=results/euf-viper-satsuma-%j.out
#SBATCH --error=results/euf-viper-satsuma-%j.err

set -euo pipefail

ROOT="${SLURM_SUBMIT_DIR:-$PWD}"
SATSUMA="${SATSUMA_BIN:-$ROOT/third_party/satsuma/build-release/satsuma}"
MODE="${SATSUMA_MODE:-fix}"
INPUT="${SATSUMA_INPUT:?set SATSUMA_INPUT}"
OUTPUT="${SATSUMA_OUTPUT:?set SATSUMA_OUTPUT}"

test -x "$SATSUMA"
/usr/bin/time -v "$SATSUMA" "$MODE" "$INPUT" > "$OUTPUT"
sha256sum "$OUTPUT"
