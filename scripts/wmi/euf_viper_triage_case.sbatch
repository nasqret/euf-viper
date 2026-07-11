#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-triage
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:10:00
#SBATCH --output=results/wmi-triage-%j.out
#SBATCH --error=results/wmi-triage-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
REFERENCE_ROOT="${EUF_VIPER_REFERENCE_ROOT:-$ROOT}"
VIPER_BIN="${EUF_VIPER_BIN:-$ROOT/target/release/euf-viper}"
CASE="${EUF_VIPER_CASE:?set EUF_VIPER_CASE}"
TIMEOUT="${EUF_VIPER_TRIAGE_TIMEOUT:-10}"

cd "$ROOT"
mkdir -p results

if ! [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
  echo "triage timeout must be a positive integer" >&2
  exit 2
fi
if [ ! -f "$CASE" ]; then
  echo "missing triage case: $CASE" >&2
  exit 2
fi

sha256sum \
  "$CASE" \
  "$VIPER_BIN" \
  "$REFERENCE_ROOT/third_party/solvers/bin/z3" \
  "$REFERENCE_ROOT/third_party/solvers/bin/cvc5"

printf 'solver=euf-viper\n'
timeout "${TIMEOUT}s" "$VIPER_BIN" solve "$CASE"
printf 'solver=z3\n'
timeout "${TIMEOUT}s" "$REFERENCE_ROOT/third_party/solvers/bin/z3" "$CASE"
printf 'solver=cvc5\n'
timeout "${TIMEOUT}s" \
  "$REFERENCE_ROOT/third_party/solvers/bin/cvc5" --lang=smt2 "$CASE"
