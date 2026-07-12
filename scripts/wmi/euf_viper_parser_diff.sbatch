#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-parser-diff
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=04:30:00
#SBATCH --output=results/wmi-parser-diff-%j.out
#SBATCH --error=results/wmi-parser-diff-%j.err

set -euo pipefail

ROOT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
SOLVER_ROOT="${EUF_VIPER_SOLVER_ROOT:-$ROOT}"
VIPER_BIN="${EUF_VIPER_BIN:-$ROOT/target/release/euf-viper}"
SEED="${EUF_VIPER_PARSER_DIFF_SEED:-0}"
RANDOM_GROUPS="${EUF_VIPER_PARSER_DIFF_RANDOM_GROUPS:-512}"
TIMEOUT="${EUF_VIPER_PARSER_DIFF_TIMEOUT:-2}"
BASE_RUN_ID="${EUF_VIPER_PARSER_DIFF_RUN_ID:-${SLURM_JOB_ID:?}}"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-$SLURM_JOB_ID}"
PAIR_OUT="$ROOT/results/parser-diff-${BASE_RUN_ID}-pair"

case "$BASE_RUN_ID" in
  ""|*[!A-Za-z0-9._-]*) echo "EUF_VIPER_PARSER_DIFF_RUN_ID is unsafe" >&2; exit 2 ;;
esac

cd "$ROOT"
mkdir -p "$PAIR_OUT"

test -x "$VIPER_BIN"
test -x "$SOLVER_ROOT/third_party/solvers/bin/z3"
test -x "$SOLVER_ROOT/third_party/solvers/bin/cvc5"
test -x "$SOLVER_ROOT/third_party/solvers/bin/yices-smt2"

sha256sum \
  "$VIPER_BIN" \
  "$SOLVER_ROOT/third_party/solvers/bin/z3" \
  "$SOLVER_ROOT/third_party/solvers/bin/cvc5" \
  "$SOLVER_ROOT/third_party/solvers/bin/yices-smt2"

run_mode() (
  set -euo pipefail
  local parser_mode="$1"
  local mode_run_id="${BASE_RUN_ID}-${parser_mode}"
  local scratch_out="$SCRATCH_ROOT/parser-diff-${mode_run_id}"
  local persist_out="$ROOT/results/parser-diff-${mode_run_id}"
  local checkpoint="$persist_out/checkpoint.json"

  mkdir -p "$persist_out"

  record_failure() {
    status=$?
    if [[ $status -ne 0 ]]; then
      temporary="$persist_out/.wrapper-failure.tmp-$$"
      printf 'status=%s\nparser_mode=%s\nrun_id=%s\n' \
        "$status" "$parser_mode" "$mode_run_id" > "$temporary"
      mv "$temporary" "$persist_out/wrapper-failure.txt"
    fi
  }
  trap record_failure EXIT

  scripts/bench/metamorphic_parser_diff.py \
    --out "$scratch_out" \
    --run-id "$mode_run_id" \
    --seed "$SEED" \
    --random-groups "$RANDOM_GROUPS" \
    --timeout "$TIMEOUT" \
    --parser-mode "$parser_mode" \
    --checkpoint "$checkpoint" \
    --checkpoint-every 1 \
    --gate candidate \
    --viper-command "env EUF_VIPER_PARSER_MODE=$parser_mode $VIPER_BIN solve {file}" \
    --z3-command "$SOLVER_ROOT/third_party/solvers/bin/z3 {file}" \
    --cvc5-command "$SOLVER_ROOT/third_party/solvers/bin/cvc5 --lang=smt2 {file}" \
    --yices-command "$SOLVER_ROOT/third_party/solvers/bin/yices-smt2 {file}"

  tar -czf "$persist_out/cases.tar.gz" -C "$scratch_out" cases
  install -m 0644 \
    "$scratch_out/manifest.jsonl" \
    "$scratch_out/results.jsonl" \
    "$scratch_out/summary.json" \
    "$persist_out/"
  sha256sum \
    "$persist_out/cases.tar.gz" \
    "$checkpoint" \
    "$persist_out/manifest.jsonl" \
    "$persist_out/results.jsonl" \
    "$persist_out/summary.json"
)

run_mode shadow &
shadow_pid=$!
run_mode stream &
stream_pid=$!

shadow_status=0
stream_status=0
wait "$shadow_pid" || shadow_status=$?
wait "$stream_pid" || stream_status=$?
if [[ $shadow_status -ne 0 || $stream_status -ne 0 ]]; then
  temporary="$PAIR_OUT/.pair-failure.tmp-$$"
  printf 'shadow_status=%s\nstream_status=%s\nbase_run_id=%s\n' \
    "$shadow_status" "$stream_status" "$BASE_RUN_ID" > "$temporary"
  mv "$temporary" "$PAIR_OUT/pair-failure.txt"
  exit 1
fi

scripts/bench/metamorphic_parser_diff.py \
  --cross-mode-shadow "$ROOT/results/parser-diff-${BASE_RUN_ID}-shadow" \
  --cross-mode-stream "$ROOT/results/parser-diff-${BASE_RUN_ID}-stream" \
  --cross-mode-out "$PAIR_OUT/cross-mode-summary.json"

sha256sum "$PAIR_OUT/cross-mode-summary.json"
