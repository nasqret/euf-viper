#!/usr/bin/env bash
set -euo pipefail

ORCHESTRATION_CHECKOUT="${EUF_VIPER_HELIOS_ORCHESTRATION_CHECKOUT:?set orchestration checkout}"
PREPARATION_ROOT="${EUF_VIPER_HELIOS_PREPARATION_ROOT:?set preparation root}"
CAMPAIGN_ROOT="${EUF_VIPER_HELIOS_CAMPAIGN_ROOT:?set campaign root}"
EXPECTED_PREPARATION_RECEIPT_SHA256="${EUF_VIPER_HELIOS_PREPARATION_RECEIPT_SHA256:?set preparation receipt hash}"
EXPECTED_ORCHESTRATION_REVISION="${EUF_VIPER_HELIOS_ORCHESTRATION_REVISION:?set orchestration revision}"
EXPECTED_SOLVER_REVISION="${EUF_VIPER_HELIOS_SOLVER_REVISION:?set solver revision}"
EXPECTED_TOOLCHAIN_SHA256="${EUF_VIPER_HELIOS_TOOLCHAIN_SHA256:?set toolchain hash}"
SHARD_COUNT="${EUF_VIPER_HELIOS_SHARD_COUNT:?set shard count}"
SHARD_INDEX="${SLURM_ARRAY_TASK_ID:?requires a Slurm array task}"
EXPECTED_CPU_MODEL="${EUF_VIPER_HELIOS_CPU_MODEL:-AMD EPYC 9654}"

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

hash_or_dash() {
  if [ -f "$1" ]; then
    hash_file "$1"
  else
    printf '%s' '-'
  fi
}

field() {
  local path="$1"
  local key="$2"
  local value
  value="$(awk -F '\t' -v key="$key" '$1 == key {print $2}' "$path")"
  [ -n "$value" ] || die "missing $key in $path"
  printf '%s' "$value"
}

column() {
  local path="$1"
  local key="$2"
  awk -F '\t' -v key="$key" '
    NR == 1 { for (i = 1; i <= NF; i++) if ($i == key) column = i; next }
    NR == 2 && column { print $column }
  ' "$path"
}

[[ "$SHARD_COUNT" =~ ^[1-9][0-9]*$ ]] && [ "$SHARD_COUNT" -ge 2 ] || \
  die "shard count must be at least two"
[[ "$SHARD_INDEX" =~ ^[0-9]+$ ]] && [ "$SHARD_INDEX" -lt "$SHARD_COUNT" ] || \
  die "invalid shard index"
[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || die "shard task requires one CPU"

PADDED_INDEX="$(printf '%04d' "$SHARD_INDEX")"
TASK_ROOT="$CAMPAIGN_ROOT/tasks/shard-$PADDED_INDEX"
RESULT_ROOT="$CAMPAIGN_ROOT/results/shard-$PADDED_INDEX"
BOUND_LOCK="$CAMPAIGN_ROOT/bound-locks/bound-$PADDED_INDEX.json"
RESOURCE_CAPTURE="$TASK_ROOT/resource-usage.json"
RECEIPT="$TASK_ROOT/receipt.tsv"
SHARD_LOCK="$PREPARATION_ROOT/shard-locks/lock-$PADDED_INDEX.json"
PREPARATION_RECEIPT="$PREPARATION_ROOT/receipt.tsv"
PREPARATION="$PREPARATION_ROOT/preparation.tsv"
CANDIDATE="$PREPARATION_ROOT/target/release/euf-viper"

case "$TASK_ROOT" in "$CAMPAIGN_ROOT/"*) ;; *) die "task root escaped campaign" ;; esac
for path in "$PREPARATION_RECEIPT" "$PREPARATION" "$SHARD_LOCK"; do
  [ -f "$path" ] && [ ! -L "$path" ] || die "missing immutable input: $path"
done
[ "$(hash_file "$PREPARATION_RECEIPT")" = "$EXPECTED_PREPARATION_RECEIPT_SHA256" ] || \
  die "preparation receipt hash drifted"
[ "$(column "$PREPARATION_RECEIPT" status)" = complete ] || \
  die "preparation job did not complete"
[ "$(column "$PREPARATION_RECEIPT" execution_mode)" = prepare-sharded ] || \
  die "preparation receipt is not sharded"
[ "$(field "$PREPARATION" shard_count)" = "$SHARD_COUNT" ] || \
  die "preparation shard count drifted"
[ "$(field "$PREPARATION" orchestration_revision)" = "$EXPECTED_ORCHESTRATION_REVISION" ] || \
  die "preparation orchestration revision drifted"
[ "$(field "$PREPARATION" solver_revision)" = "$EXPECTED_SOLVER_REVISION" ] || \
  die "preparation solver revision drifted"
[ "$(field "$PREPARATION" campaign_root)" = "$CAMPAIGN_ROOT" ] || \
  die "preparation campaign root drifted"
[ "$(git -C "$ORCHESTRATION_CHECKOUT" rev-parse --verify 'HEAD^{commit}')" = \
  "$EXPECTED_ORCHESTRATION_REVISION" ] || die "orchestration checkout drifted"
[ -x "$CANDIDATE" ] && [ ! -L "$CANDIDATE" ] || die "candidate binary is unavailable"
EXPECTED_CANDIDATE_SHA256="$(field "$PREPARATION" candidate_binary_sha256)"
[ "$(hash_file "$CANDIDATE")" = "$EXPECTED_CANDIDATE_SHA256" ] || \
  die "candidate binary hash drifted"

test ! -e "$TASK_ROOT"
test ! -e "$RESULT_ROOT"
test ! -e "$BOUND_LOCK"
mkdir "$TASK_ROOT"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TASK_STATUS=2

write_receipt() {
  local task_status="$1"
  local status=failed
  local temporary="$TASK_ROOT/.receipt.tsv.${SLURM_JOB_ID}"
  [ "$task_status" -eq 0 ] && status=complete
  {
    printf 'schema_version\tstatus\tjob_id\tarray_job_id\tarray_task_id\tshard_index\tshard_count\tstarted_at\tfinished_at\texit_code\torchestration_revision\tsolver_revision\tpreparation_receipt_sha256\ttoolchain_sha256\tcandidate_binary_sha256\tshard_lock_sha256\tbound_lock_sha256\traw_sha256\tsummary_sha256\tresource_capture_sha256\n'
    printf '1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$status" "$SLURM_JOB_ID" "${SLURM_ARRAY_JOB_ID:-$SLURM_JOB_ID}" \
      "$SHARD_INDEX" "$SHARD_INDEX" "$SHARD_COUNT" "$STARTED_AT" \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$task_status" \
      "$EXPECTED_ORCHESTRATION_REVISION" "$EXPECTED_SOLVER_REVISION" \
      "$EXPECTED_PREPARATION_RECEIPT_SHA256" "$EXPECTED_TOOLCHAIN_SHA256" \
      "$EXPECTED_CANDIDATE_SHA256" "$(hash_or_dash "$SHARD_LOCK")" \
      "$(hash_or_dash "$BOUND_LOCK")" "$(hash_or_dash "$RESULT_ROOT/raw.jsonl")" \
      "$(hash_or_dash "$RESULT_ROOT/summary.json")" \
      "$(hash_or_dash "$RESOURCE_CAPTURE")"
  } > "$temporary"
  chmod 0444 "$temporary"
  ln "$temporary" "$RECEIPT"
  rm -f "$temporary"
}

finalize() {
  local script_status="$?"
  trap - EXIT
  [ -e "$RECEIPT" ] || write_receipt "$TASK_STATUS" || true
  [ ! -e "$BOUND_LOCK" ] || chmod a-w "$BOUND_LOCK" || true
  [ ! -d "$RESULT_ROOT" ] || chmod -R a-w "$RESULT_ROOT" || true
  chmod -R a-w "$TASK_ROOT" || true
  return "$script_status"
}
trap finalize EXIT

command -v module >/dev/null 2>&1 || die "Lmod module command is unavailable"
module --force purge
module load GCCcore/14.3.0 Rust/1.88.0
export LANG=C LC_ALL=C TZ=UTC PYTHONDONTWRITEBYTECODE=1

AFFINITY_COUNT="$(python3 - <<'PY'
import os
print(len(os.sched_getaffinity(0)))
PY
)"
[ "$AFFINITY_COUNT" = 1 ] || die "shard is not bound to exactly one CPU"
CPU_MODEL="$(LC_ALL=C lscpu | awk -F: '$1 ~ /^Model name/ {sub(/^[[:space:]]+/, "", $2); print $2}')"
case "$CPU_MODEL" in *"$EXPECTED_CPU_MODEL"*) ;; *) die "unexpected CPU model: $CPU_MODEL" ;; esac

TOOLCHAIN="$TASK_ROOT/toolchain.tsv"
"$ORCHESTRATION_CHECKOUT/scripts/helios/toolchain_receipt.sh" > "$TOOLCHAIN"
[ "$(hash_file "$TOOLCHAIN")" = "$EXPECTED_TOOLCHAIN_SHA256" ] || \
  die "shard toolchain differs from preparation"
chmod 0444 "$TOOLCHAIN"

python3 "$ORCHESTRATION_CHECKOUT/scripts/bench/bind_campaign_cpu.py" \
  "$SHARD_LOCK" --out "$BOUND_LOCK" > "$TASK_ROOT/cpu-binding.json"
python3 - "$BOUND_LOCK" "$RESULT_ROOT" <<'PY'
import json
import sys
from pathlib import Path

lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if lock["output"]["directory"] != sys.argv[2]:
    raise SystemExit("bound shard output root drifted")
PY

set +e
python3 "$ORCHESTRATION_CHECKOUT/scripts/helios/run_with_resources.py" \
  --out "$RESOURCE_CAPTURE" -- \
  python3 "$ORCHESTRATION_CHECKOUT/scripts/bench/run_locked_campaign.py" "$BOUND_LOCK"
RUNNER_STATUS="$?"
set -e
[ -s "$RESOURCE_CAPTURE" ] || die "resource wrapper did not produce a record"
[ "$RUNNER_STATUS" -eq 0 ] || exit "$RUNNER_STATUS"
python3 - "$RESULT_ROOT/summary.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if summary.get("status") != "complete":
    raise SystemExit("shard summary is not complete")
if summary.get("completed_runs") != summary.get("expected_runs"):
    raise SystemExit("shard run count is incomplete")
PY

TASK_STATUS=0
exit 0
