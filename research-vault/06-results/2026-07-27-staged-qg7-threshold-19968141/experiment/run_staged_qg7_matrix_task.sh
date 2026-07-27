#!/usr/bin/env bash
set -euo pipefail

EXPERIMENT_ROOT="${EUF_VIPER_MATRIX_ROOT:?set matrix root}"
ORCHESTRATION_CHECKOUT="${EUF_VIPER_MATRIX_ORCHESTRATION_CHECKOUT:?set orchestration checkout}"
SOLVER_BINARY="${EUF_VIPER_MATRIX_SOLVER_BINARY:?set solver binary}"
EXPECTED_ORCHESTRATION_REVISION="${EUF_VIPER_MATRIX_ORCHESTRATION_REVISION:?set orchestration revision}"
EXPECTED_SOLVER_SHA256="${EUF_VIPER_MATRIX_SOLVER_SHA256:?set solver hash}"
EXPECTED_SELECTION_SHA256="${EUF_VIPER_MATRIX_SELECTION_SHA256:?set selection hash}"
EXPECTED_MANIFEST_SHA256="${EUF_VIPER_MATRIX_MANIFEST_SHA256:?set manifest hash}"
EXPECTED_TASK_SHA256="${EUF_VIPER_MATRIX_TASK_SHA256:?set task script hash}"
EXPECTED_SBATCH_SHA256="${EUF_VIPER_MATRIX_SBATCH_SHA256:?set sbatch script hash}"
EXPECTED_RUNNER_SHA256="${EUF_VIPER_MATRIX_RUNNER_SHA256:?set runner hash}"
EXPECTED_TOOLCHAIN_SHA256="${EUF_VIPER_MATRIX_TOOLCHAIN_SHA256:?set toolchain hash}"
SHARD_COUNT="${EUF_VIPER_MATRIX_SHARD_COUNT:-6}"
EXPECTED_CPU_MODEL="${EUF_VIPER_MATRIX_CPU_MODEL:-AMD EPYC 9654}"
TASK_ID="${SLURM_ARRAY_TASK_ID:?set array task ID}"

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

check_hash() {
  local path="$1"
  local expected="$2"
  local label="$3"
  [ -f "$path" ] && [ ! -L "$path" ] || die "$label is not a regular file"
  local actual
  actual="$(hash_file "$path")"
  [ "$actual" = "$expected" ] || \
    die "$label hash mismatch: expected $expected, got $actual"
}

[[ "$TASK_ID" =~ ^[0-9]+$ ]] || die "array task ID must be numeric"
[[ "$SHARD_COUNT" =~ ^[1-9][0-9]*$ ]] || die "shard count must be positive"
[ "$TASK_ID" -lt "$SHARD_COUNT" ] || die "array task ID exceeds shard count"
[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || die "matrix task requires one CPU"
case "$EXPERIMENT_ROOT" in /*/experiments/*) ;; *) die "matrix root escaped experiment namespace" ;; esac
case "$ORCHESTRATION_CHECKOUT" in /*/orchestration-checkouts/*) ;; *) die "orchestration checkout escaped namespace" ;; esac

TASK_PADDED="$(printf '%04d' "$TASK_ID")"
SHARD_MANIFEST="$EXPERIMENT_ROOT/shards/shard-$TASK_PADDED.jsonl"
RESULT_DIRECTORY="$EXPERIMENT_ROOT/results/shard-$TASK_PADDED"
SELECTION_SOURCE="$EXPERIMENT_ROOT/selection-source.jsonl"
FULL_MANIFEST="$EXPERIMENT_ROOT/manifest.jsonl"
TASK_SCRIPT="$EXPERIMENT_ROOT/run_staged_qg7_matrix_task.sh"
SBATCH_SCRIPT="$EXPERIMENT_ROOT/euf_viper_staged_qg7_matrix.sbatch"
RUNNER="$ORCHESTRATION_CHECKOUT/scripts/bench/compare_multiarm_williams.py"
RESOURCE_WRAPPER="$ORCHESTRATION_CHECKOUT/scripts/helios/run_with_resources.py"

test ! -e "$RESULT_DIRECTORY" || die "immutable result directory already exists"
mkdir "$RESULT_DIRECTORY"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TASK_STATUS=2
CPU_MODEL=-
AFFINITY_COUNT=-
SHARD_SHA256=-

write_receipt() {
  local task_status="$1"
  local status=failed
  local receipt="$RESULT_DIRECTORY/receipt.tsv"
  local temporary="$RESULT_DIRECTORY/.receipt.tsv.${SLURM_JOB_ID}"
  local finished_at
  [ "$task_status" -eq 0 ] && status=complete
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  test ! -e "$receipt"
  {
    printf 'schema_version\tstatus\tjob_id\tarray_job_id\tarray_task_id\torchestration_revision\tsolver_sha256\tselection_sha256\tmanifest_sha256\tshard_sha256\ttask_script_sha256\tsbatch_script_sha256\trunner_sha256\ttoolchain_sha256\tcpu_model\taffinity_cpus\tstarted_at\tfinished_at\ttask_exit_code\n'
    printf '1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$status" "$SLURM_JOB_ID" "${SLURM_ARRAY_JOB_ID:-$SLURM_JOB_ID}" "$TASK_ID" \
      "$EXPECTED_ORCHESTRATION_REVISION" "$EXPECTED_SOLVER_SHA256" \
      "$EXPECTED_SELECTION_SHA256" "$EXPECTED_MANIFEST_SHA256" "$SHARD_SHA256" \
      "$EXPECTED_TASK_SHA256" "$EXPECTED_SBATCH_SHA256" "$EXPECTED_RUNNER_SHA256" \
      "$EXPECTED_TOOLCHAIN_SHA256" "$CPU_MODEL" "$AFFINITY_COUNT" \
      "$STARTED_AT" "$finished_at" "$task_status"
  } > "$temporary"
  chmod 0444 "$temporary"
  ln "$temporary" "$receipt"
  rm -f "$temporary"
}

finalize() {
  local script_status="$?"
  trap - EXIT
  if [ ! -e "$RESULT_DIRECTORY/receipt.tsv" ]; then
    write_receipt "$TASK_STATUS" || true
  fi
  chmod -R a-w "$RESULT_DIRECTORY" || true
  return "$script_status"
}
trap finalize EXIT

module --force purge
module load GCCcore/14.3.0 Rust/1.88.0
export LANG=C
export LC_ALL=C
export TZ=UTC
export PYTHONDONTWRITEBYTECODE=1

[ "$(uname -m)" = x86_64 ] || die "matrix task must run on x86_64"
AFFINITY_COUNT="$(python3 -c 'import os; print(len(os.sched_getaffinity(0)))')"
[ "$AFFINITY_COUNT" = 1 ] || die "srun did not bind the task to exactly one CPU"
CPU_MODEL="$(LC_ALL=C lscpu | awk -F: '$1 ~ /^Model name/ {sub(/^[[:space:]]+/, "", $2); print $2}')"
case "$CPU_MODEL" in *"$EXPECTED_CPU_MODEL"*) ;; *) die "unexpected CPU model: $CPU_MODEL" ;; esac

[ "$(git -C "$ORCHESTRATION_CHECKOUT" rev-parse --verify 'HEAD^{commit}')" = \
  "$EXPECTED_ORCHESTRATION_REVISION" ] || die "orchestration revision drifted"
[ -z "$(git -C "$ORCHESTRATION_CHECKOUT" status --porcelain=v1 --untracked-files=all)" ] || \
  die "orchestration checkout is not clean"
check_hash "$SOLVER_BINARY" "$EXPECTED_SOLVER_SHA256" "solver binary"
check_hash "$SELECTION_SOURCE" "$EXPECTED_SELECTION_SHA256" "selection source"
check_hash "$FULL_MANIFEST" "$EXPECTED_MANIFEST_SHA256" "rebased manifest"
check_hash "$TASK_SCRIPT" "$EXPECTED_TASK_SHA256" "task script"
check_hash "$SBATCH_SCRIPT" "$EXPECTED_SBATCH_SHA256" "sbatch script"
check_hash "$RUNNER" "$EXPECTED_RUNNER_SHA256" "multi-arm runner"
SHARD_SHA256="$(hash_file "$SHARD_MANIFEST")"

printf 'cpu_model\t%s\naffinity_cpus\t%s\n' "$CPU_MODEL" "$AFFINITY_COUNT" \
  > "$RESULT_DIRECTORY/compute.tsv"
"$ORCHESTRATION_CHECKOUT/scripts/helios/toolchain_receipt.sh" \
  > "$RESULT_DIRECTORY/toolchain.tsv"
check_hash "$RESULT_DIRECTORY/toolchain.tsv" "$EXPECTED_TOOLCHAIN_SHA256" "toolchain receipt"

declare -a ARGUMENTS=("$SHARD_MANIFEST")
add_arm() {
  local name="$1"
  local staged="$2"
  local conflicts="$3"
  ARGUMENTS+=(
    --arm "$name"
    --arm-arg "$SOLVER_BINARY"
    --arm-arg fabric-solve
    --arm-arg=--engine
    --arm-arg quotient-portfolio
    --arm-arg '{input}'
    --arm-env EUF_VIPER_FINITE_DENSE7=0
    --arm-env "EUF_VIPER_FINITE_DENSE7_STAGED=$staged"
    --arm-env "EUF_VIPER_FINITE_DENSE7_KISSAT_CONFLICTS=$conflicts"
  )
}

add_arm baseline 0 1000
add_arm staged-0 1 0
add_arm staged-10 1 10
add_arm staged-100 1 100
add_arm staged-1000 1 1000
add_arm staged-10000 1 10000
ARGUMENTS+=(
  --blocks 1
  --timeout 2
  --out "$RESULT_DIRECTORY/raw.csv"
  --summary "$RESULT_DIRECTORY/summary.json"
)

set +e
python3 "$RESOURCE_WRAPPER" \
  --out "$RESULT_DIRECTORY/resource-usage.json" \
  -- python3 "$RUNNER" "${ARGUMENTS[@]}" \
  > "$RESULT_DIRECTORY/runner.out" \
  2> "$RESULT_DIRECTORY/runner.err"
TASK_STATUS="$?"
set -e

write_receipt "$TASK_STATUS"
[ "$TASK_STATUS" -eq 0 ] || exit "$TASK_STATUS"
exit 0
