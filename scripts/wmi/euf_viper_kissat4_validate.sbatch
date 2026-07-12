#!/usr/bin/env bash
#SBATCH --job-name=euf-kissat4-validate
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=00:45:00
#SBATCH --output=results/kissat4-validate-%j.out
#SBATCH --error=results/kissat4-validate-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/euf-viper-tools/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi
DRAT_TRIM="$(command -v drat-trim || true)"
if [ -z "$DRAT_TRIM" ] || [ ! -x "$DRAT_TRIM" ]; then
  echo "drat-trim is required" >&2
  exit 2
fi

OUT="results/kissat4-validation-${SLURM_JOB_ID}"
mkdir -p "$OUT"

cargo test --locked
cargo build --release --locked --features certificates
install -m 755 target/release/euf-viper "$OUT/euf-viper-kissat-sc2021"

cargo test --locked --all-features
cargo build --release --locked --no-default-features \
  --features finite-symmetry,kissat-4,certificates
install -m 755 target/release/euf-viper "$OUT/euf-viper-kissat-4.0.4"

for binary in \
  "$OUT/euf-viper-kissat-sc2021" \
  "$OUT/euf-viper-kissat-4.0.4"
do
  "$binary" --version
  while read -r input expected; do
    actual="$("$binary" solve "$input")"
    if [ "$actual" != "$expected" ]; then
      echo "$binary returned $actual for $input, expected $expected" >&2
      exit 2
    fi
  done <<'CASES'
generated/synthetic/chain1000_sat.smt2 sat
generated/synthetic/chain1000_unsat.smt2 unsat
tests/fixtures/transitivity_unsat.smt2 unsat
tests/fixtures/predicate_congruence_unsat.smt2 unsat
tests/fixtures/bool_data_pigeonhole_unsat.smt2 unsat
CASES
done

scripts/cert/run_smoke.sh
sha256sum \
  "$OUT/euf-viper-kissat-sc2021" \
  "$OUT/euf-viper-kissat-4.0.4" \
  "$DRAT_TRIM" \
  scripts/wmi/euf_viper_kissat4_validate.sbatch \
  > "$OUT/sha256.txt"

{
  printf 'revision=%s\n' "$ACTUAL_REVISION"
  printf 'job_id=%s\n' "$SLURM_JOB_ID"
  printf 'drat_trim=%s\n' "$DRAT_TRIM"
  "$OUT/euf-viper-kissat-sc2021" --version
  "$OUT/euf-viper-kissat-4.0.4" --version
} > "$OUT/validation.txt"

printf 'validation_root=%s\n' "$OUT"
