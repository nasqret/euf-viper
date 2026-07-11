#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-soundness
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=00:30:00
#SBATCH --output=results/wmi-soundness-%j.out
#SBATCH --error=results/wmi-soundness-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-$PWD}"
FIXTURE="${EUF_VIPER_SOUNDNESS_FIXTURE:-tests/fixtures/bool_data_pigeonhole_unsat.smt2}"
UNCONDITIONAL_QUOTIENT="${EUF_VIPER_SOUNDNESS_UNCONDITIONAL_QUOTIENT:-off}"

cd "$ROOT"
mkdir -p results
export PATH="$HOME/.cargo/bin:$PATH"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-$SLURM_JOB_ID}"
TARGET_DIR="${CARGO_TARGET_DIR:-$SCRATCH_ROOT/target}"
export CARGO_TARGET_DIR="$TARGET_DIR"
BIN="$TARGET_DIR/release/euf-viper"
REVISION="${EUF_VIPER_GIT_REVISION:-unknown}"
PERSIST_BIN="${EUF_VIPER_PERSIST_BIN:-$ROOT/artifacts/euf-viper-$REVISION}"

case "$UNCONDITIONAL_QUOTIENT" in
  off | shadow | on) ;;
  *)
    echo "EUF_VIPER_SOUNDNESS_UNCONDITIONAL_QUOTIENT must be off, shadow, or on" >&2
    exit 2
    ;;
esac

cargo test --all-features
cargo build --release --all-features
sha256sum "$BIN"

run_expected() {
  local backend="$1"
  local fixture="$2"
  local expected_result="$3"
  local result

  result="$(env EUF_VIPER_BACKEND="$backend" \
    EUF_VIPER_UNCONDITIONAL_QUOTIENT="$UNCONDITIONAL_QUOTIENT" \
    "$BIN" solve "$fixture")"
  printf 'backend=%s fixture=%s result=%s\n' "$backend" "$fixture" "$result"
  test "$result" = "$expected_result"
}

for backend in auto varisat cadical cadical-refine; do
  run_expected "$backend" "$FIXTURE" unsat
  run_expected "$backend" tests/fixtures/quoted_true_sat.smt2 sat
  run_expected "$backend" tests/fixtures/quoted_not_sat.smt2 sat
done

set +e
query_order_output="$(env EUF_VIPER_UNCONDITIONAL_QUOTIENT="$UNCONDITIONAL_QUOTIENT" \
  "$BIN" solve \
  tests/fixtures/early_check_sat_rejected.smt2 2>&1)"
query_order_status=$?
set -e
printf 'fixture=%s exit=%s output=%s\n' \
  tests/fixtures/early_check_sat_rejected.smt2 \
  "$query_order_status" \
  "$query_order_output"
test "$query_order_status" -eq 2
test "$query_order_output" = \
  "command \`assert\` after \`check-sat\` is unsupported in single-query mode"

mkdir -p "$(dirname "$PERSIST_BIN")"
install -m 0755 "$BIN" "$PERSIST_BIN"
printf 'revision=%s\n' "$REVISION"
printf 'unconditional_quotient=%s\n' "$UNCONDITIONAL_QUOTIENT"
printf 'candidate_binary=%s\n' "$PERSIST_BIN"
printf 'candidate_sha256=%s\n' "$(sha256sum "$PERSIST_BIN" | awk '{print $1}')"

printf 'soundness_gate=pass\n'
