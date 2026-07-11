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

for backend in auto varisat cadical cadical-refine; do
  result="$(env EUF_VIPER_BACKEND="$backend" \
    target/release/euf-viper solve "$FIXTURE")"
  printf 'backend=%s result=%s\n' "$backend" "$result"
  test "$result" = unsat
done

printf 'soundness_gate=pass\n'
