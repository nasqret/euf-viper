#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-parser-diff
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=04:30:00
#SBATCH --output=results/wmi-parser-diff-%j.out
#SBATCH --error=results/wmi-parser-diff-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
SOLVER_ROOT="${EUF_VIPER_SOLVER_ROOT:-$ROOT}"
VIPER_BIN="${EUF_VIPER_BIN:-$ROOT/target/release/euf-viper}"
PARSER_MODE="${EUF_VIPER_PARSER_DIFF_MODE:?set EUF_VIPER_PARSER_DIFF_MODE to shadow or stream}"
SEED="${EUF_VIPER_PARSER_DIFF_SEED:-0}"
RANDOM_GROUPS="${EUF_VIPER_PARSER_DIFF_RANDOM_GROUPS:-512}"
TIMEOUT="${EUF_VIPER_PARSER_DIFF_TIMEOUT:-2}"
RUN_ID="${EUF_VIPER_PARSER_DIFF_RUN_ID:-$SLURM_JOB_ID}"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-$SLURM_JOB_ID}"
SCRATCH_OUT="$SCRATCH_ROOT/parser-diff-$RUN_ID"
PERSIST_OUT="$ROOT/results/parser-diff-$RUN_ID"
CHECKPOINT="$PERSIST_OUT/checkpoint.json"

case "$PARSER_MODE" in
  shadow|stream) ;;
  *) echo "EUF_VIPER_PARSER_DIFF_MODE must be shadow or stream" >&2; exit 2 ;;
esac

cd "$ROOT"
mkdir -p "$PERSIST_OUT"

record_failure() {
  status=$?
  if [[ $status -ne 0 ]]; then
    temporary="$PERSIST_OUT/.wrapper-failure.tmp-$$"
    printf 'status=%s\nparser_mode=%s\nrun_id=%s\n' \
      "$status" "$PARSER_MODE" "$RUN_ID" > "$temporary"
    mv "$temporary" "$PERSIST_OUT/wrapper-failure.txt"
  fi
}
trap record_failure EXIT

test -x "$VIPER_BIN"
test -x "$SOLVER_ROOT/third_party/solvers/bin/z3"
test -x "$SOLVER_ROOT/third_party/solvers/bin/cvc5"
test -x "$SOLVER_ROOT/third_party/solvers/bin/yices-smt2"

sha256sum \
  "$VIPER_BIN" \
  "$SOLVER_ROOT/third_party/solvers/bin/z3" \
  "$SOLVER_ROOT/third_party/solvers/bin/cvc5" \
  "$SOLVER_ROOT/third_party/solvers/bin/yices-smt2"

scripts/bench/metamorphic_parser_diff.py \
  --out "$SCRATCH_OUT" \
  --seed "$SEED" \
  --random-groups "$RANDOM_GROUPS" \
  --timeout "$TIMEOUT" \
  --parser-mode "$PARSER_MODE" \
  --checkpoint "$CHECKPOINT" \
  --checkpoint-every 1 \
  --gate candidate \
  --viper-command "env EUF_VIPER_PARSER_MODE=$PARSER_MODE $VIPER_BIN solve {file}" \
  --z3-command "$SOLVER_ROOT/third_party/solvers/bin/z3 {file}" \
  --cvc5-command "$SOLVER_ROOT/third_party/solvers/bin/cvc5 --lang=smt2 {file}" \
  --yices-command "$SOLVER_ROOT/third_party/solvers/bin/yices-smt2 {file}"

tar -czf "$PERSIST_OUT/cases.tar.gz" -C "$SCRATCH_OUT" cases
install -m 0644 \
  "$SCRATCH_OUT/manifest.jsonl" \
  "$SCRATCH_OUT/results.jsonl" \
  "$SCRATCH_OUT/summary.json" \
  "$PERSIST_OUT/"
sha256sum \
  "$PERSIST_OUT/cases.tar.gz" \
  "$CHECKPOINT" \
  "$PERSIST_OUT/manifest.jsonl" \
  "$PERSIST_OUT/results.jsonl" \
  "$PERSIST_OUT/summary.json"
