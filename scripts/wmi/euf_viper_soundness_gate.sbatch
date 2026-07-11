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

cd "$ROOT"
mkdir -p results
export PATH="$HOME/.cargo/bin:$PATH"

cargo test --all-features
cargo build --release --all-features
sha256sum target/release/euf-viper

run_expected() {
  local backend="$1"
  local fixture="$2"
  local expected_result="$3"
  local result

  result="$(env EUF_VIPER_BACKEND="$backend" \
    target/release/euf-viper solve "$fixture")"
  printf 'backend=%s fixture=%s result=%s\n' "$backend" "$fixture" "$result"
  test "$result" = "$expected_result"
}

for backend in auto varisat cadical cadical-refine; do
  run_expected "$backend" "$FIXTURE" unsat
  run_expected "$backend" tests/fixtures/quoted_true_sat.smt2 sat
  run_expected "$backend" tests/fixtures/quoted_not_sat.smt2 sat
done

set +e
query_order_output="$(target/release/euf-viper solve \
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

printf 'soundness_gate=pass\n'
