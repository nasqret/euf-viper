#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-bench
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --time=02:00:00
#SBATCH --output=results/wmi-%j.out
#SBATCH --error=results/wmi-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
mkdir -p results
export PATH="$HOME/.cargo/bin:$PATH"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is not available on this WMI shell; install Rust or load the correct environment." >&2
  exit 127
fi

cargo build --release
./target/release/euf-viper bench --cases "${EUF_VIPER_CASES:-40}" --size "${EUF_VIPER_SIZE:-20000}" \
  > "results/euf-viper-synthetic-${SLURM_JOB_ID}.log"

if command -v z3 >/dev/null 2>&1 && [ -d "${SMTLIB_QF_UF_DIR:-}" ]; then
  python3 benches/compare_z3.py "$SMTLIB_QF_UF_DIR" --out "results/compare-z3-${SLURM_JOB_ID}.csv"
fi
