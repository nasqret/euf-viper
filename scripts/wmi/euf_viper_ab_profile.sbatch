#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-ab
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:10:00
#SBATCH --output=results/wmi-ab-profile-%j.out
#SBATCH --error=results/wmi-ab-profile-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

if [ "${EUF_VIPER_PROFILE_BUILD:-1}" = 1 ]; then
  cargo build --release
fi

BASELINE_BIN="${EUF_VIPER_BASELINE_BIN:?set EUF_VIPER_BASELINE_BIN}"
CANDIDATE_BIN="${EUF_VIPER_CANDIDATE_BIN:-$PWD/target/release/euf-viper}"
BASELINE_BACKEND="${EUF_VIPER_BASELINE_BACKEND:-auto}"
CANDIDATE_BACKEND="${EUF_VIPER_CANDIDATE_BACKEND:-auto}"
BASELINE_CADICAL_MODE="${EUF_VIPER_BASELINE_CADICAL_MODE:-plain}"
CANDIDATE_CADICAL_MODE="${EUF_VIPER_CANDIDATE_CADICAL_MODE:-plain}"
BASELINE_KISSAT_MODE="${EUF_VIPER_BASELINE_KISSAT_MODE:-default}"
CANDIDATE_KISSAT_MODE="${EUF_VIPER_CANDIDATE_KISSAT_MODE:-default}"
BASELINE_FINITE_EQUALITY_CHANNELING="${EUF_VIPER_BASELINE_FINITE_EQUALITY_CHANNELING:-value-only}"
CANDIDATE_FINITE_EQUALITY_CHANNELING="${EUF_VIPER_CANDIDATE_FINITE_EQUALITY_CHANNELING:-all}"
BASELINE_FINITE_PREDICATE_CHANNELING="${EUF_VIPER_BASELINE_FINITE_PREDICATE_CHANNELING:-0}"
CANDIDATE_FINITE_PREDICATE_CHANNELING="${EUF_VIPER_CANDIDATE_FINITE_PREDICATE_CHANNELING:-1}"
REPEATS="${EUF_VIPER_PROFILE_REPEATS:-3}"
TIMEOUT="${EUF_VIPER_PROFILE_TIMEOUT:-10}"

CASES=(
  "QF_UF/QG-classification/qg5/iso_brn1122.smt2"
  "QF_UF/QG-classification/qg5/iso_icl520.smt2"
  "QF_UF/QG-classification/qg5/gensys_brn814.smt2"
  "QF_UF/QG-classification/qg6/dead_dnd_sk002.smt2"
  "QF_UF/QG-classification/qg6/iso_icl_repgen005.smt2"
)
if [ -n "${EUF_VIPER_PROFILE_CASES:-}" ]; then
  IFS=':' read -r -a CASES <<< "$EUF_VIPER_PROFILE_CASES"
fi

for relative_path in "${CASES[@]}"; do
  input="$PWD/benchmarks/smtlib-2025/QF_UF/$relative_path"
  for label in baseline candidate; do
    if [ "$label" = baseline ]; then
      binary="$BASELINE_BIN"
      backend="$BASELINE_BACKEND"
      cadical_mode="$BASELINE_CADICAL_MODE"
      kissat_mode="$BASELINE_KISSAT_MODE"
      finite_equality_channeling="$BASELINE_FINITE_EQUALITY_CHANNELING"
      finite_predicate_channeling="$BASELINE_FINITE_PREDICATE_CHANNELING"
    else
      binary="$CANDIDATE_BIN"
      backend="$CANDIDATE_BACKEND"
      cadical_mode="$CANDIDATE_CADICAL_MODE"
      kissat_mode="$CANDIDATE_KISSAT_MODE"
      finite_equality_channeling="$CANDIDATE_FINITE_EQUALITY_CHANNELING"
      finite_predicate_channeling="$CANDIDATE_FINITE_PREDICATE_CHANNELING"
    fi
    for repeat in $(seq 1 "$REPEATS"); do
      echo "BEGIN label=$label repeat=$repeat path=$relative_path"
      if env \
        EUF_VIPER_BACKEND="$backend" \
        EUF_VIPER_CADICAL_MODE="$cadical_mode" \
        EUF_VIPER_KISSAT_MODE="$kissat_mode" \
        EUF_VIPER_FINITE_DOMAIN=1 \
        EUF_VIPER_FINITE_EQUALITY_CHANNELING="$finite_equality_channeling" \
        EUF_VIPER_FINITE_PREDICATE_CHANNELING="$finite_predicate_channeling" \
        EUF_VIPER_PROFILE=1 \
        EUF_VIPER_AXIOM_ORDER=native \
        timeout "${TIMEOUT}s" "$binary" solve --stats "$input" 2>&1; then
        status=0
      else
        status=$?
      fi
      echo "END label=$label repeat=$repeat status=$status path=$relative_path"
    done
  done
done
