#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-mdd-probe
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=01:00:00
#SBATCH --output=results/wmi-mdd-probe-%j.out
#SBATCH --error=results/wmi-mdd-probe-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
CASE="${EUF_VIPER_MDD_PROBE_CASE:?set EUF_VIPER_MDD_PROBE_CASE}"
REVISION="${EUF_VIPER_GIT_REVISION:-unknown}"
TARGET_DIR="${CARGO_TARGET_DIR:-${SLURM_TMPDIR:-$ROOT}/euf-viper-mdd-target}"

cd "$ROOT"
mkdir -p results
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$TARGET_DIR"
export EUF_VIPER_MDD_PROBE_CASE="$CASE"

test -s "$CASE"
printf 'revision=%s\n' "$REVISION"
printf 'case=%s\n' "$CASE"
printf 'case_sha256=%s\n' "$(sha256sum "$CASE" | awk '{print $1}')"

cargo test --release --all-features \
  forbidden_orbit_probe::tests::probe_external_forbidden_table_mdd \
  -- --ignored --exact --nocapture
