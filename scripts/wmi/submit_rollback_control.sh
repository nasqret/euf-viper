#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
REPOSITORY_URL="${EUF_VIPER_ROLLBACK_REPOSITORY_URL:-https://github.com/nasqret/euf-viper.git}"
PUBLISHED_REF="${EUF_VIPER_ROLLBACK_PUBLISHED_REF:-refs/heads/research-rollback-propagator}"
CORPUS_ROOT="${EUF_VIPER_ROLLBACK_CORPUS_ROOT:?set the absolute remote SMT-LIB corpus root containing QF_UF}"
CORPUS_MANIFEST="${EUF_VIPER_ROLLBACK_CORPUS_MANIFEST:-$CORPUS_ROOT/qf_uf_manifest.jsonl}"
EXPECTED_SOURCES="${EUF_VIPER_ROLLBACK_EXPECTED_SOURCES:-7503}"
TARGET_COUNT="${EUF_VIPER_ROLLBACK_TARGET_COUNT:-12}"
ANTI_TARGET_COUNT="${EUF_VIPER_ROLLBACK_ANTI_TARGET_COUNT:-12}"
SHARDS="${EUF_VIPER_ROLLBACK_SHARDS:-4}"
MAX_ACTIVE="${EUF_VIPER_ROLLBACK_MAX_ACTIVE:-8}"
TIMEOUT_S="${EUF_VIPER_ROLLBACK_TIMEOUT_S:-60}"
REPEATS="${EUF_VIPER_ROLLBACK_REPEATS:-4}"
SEED="${EUF_VIPER_ROLLBACK_SEED:-euf-viper-rollback-control-2026-07-13}"
MAX_ANTI_TARGET_BYTES="${EUF_VIPER_ROLLBACK_MAX_ANTI_TARGET_BYTES:-262144}"
MINIMUM_TARGET_SPEEDUP="${EUF_VIPER_ROLLBACK_MINIMUM_TARGET_SPEEDUP:-1.10}"
MAXIMUM_ANTI_P95_RATIO="${EUF_VIPER_ROLLBACK_MAXIMUM_ANTI_P95_RATIO:-1.10}"
MINIMUM_MULTI_ROUND_TARGETS="${EUF_VIPER_ROLLBACK_MINIMUM_MULTI_ROUND_TARGETS:-2}"
COMPARISON_COUNT=3

die() {
  echo "$*" >&2
  exit 2
}

canonical_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

positive_decimal() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]] && [ "$1" != 0 ] && [ "$1" != 0.0 ]
}

safe_remote_value() {
  [[ "$1" =~ ^[A-Za-z0-9_./:@%+-]+$ ]]
}

for value in \
  "$EXPECTED_SOURCES" \
  "$TARGET_COUNT" \
  "$ANTI_TARGET_COUNT" \
  "$SHARDS" \
  "$MAX_ACTIVE" \
  "$REPEATS" \
  "$MAX_ANTI_TARGET_BYTES" \
  "$MINIMUM_MULTI_ROUND_TARGETS"; do
  canonical_positive_integer "$value" || die "expected a canonical positive integer: $value"
done
positive_decimal "$TIMEOUT_S" || die "timeout must be a positive decimal"
positive_decimal "$MINIMUM_TARGET_SPEEDUP" || die "minimum target speedup must be positive"
positive_decimal "$MAXIMUM_ANTI_P95_RATIO" || die "maximum anti-target p95 ratio must be positive"
[ "$TARGET_COUNT" = 12 ] || die "the preregistered rollback control requires exactly 12 targets"
[ "$ANTI_TARGET_COUNT" = 12 ] || die "the preregistered rollback control requires exactly 12 anti-targets"
[ "$((REPEATS % 2))" = 0 ] || die "repeats must be even to form complete ABBA blocks"
TOTAL_ARRAY_TASKS=$((COMPARISON_COUNT * SHARDS))

for value in \
  "$REMOTE_HOST" \
  "$REMOTE_PARENT" \
  "$REPOSITORY_URL" \
  "$PUBLISHED_REF" \
  "$CORPUS_ROOT" \
  "$CORPUS_MANIFEST" \
  "$SEED"; do
  if [ -n "$value" ]; then
    safe_remote_value "$value" || die "remote value contains unsupported characters: $value"
  fi
done
case "$CORPUS_ROOT" in /*) ;; *) die "corpus root must be an absolute remote path" ;; esac
case "$CORPUS_MANIFEST" in /*) ;; *) die "corpus manifest must be an absolute remote path" ;; esac

cd "$ROOT"
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  die "tracked repository state must be clean before rollback-control submission"
fi
REVISION="$(git rev-parse HEAD)"
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || die "HEAD is not a full Git revision"
PUBLISHED_LINE="$(git ls-remote --exit-code "$REPOSITORY_URL" "$PUBLISHED_REF")"
PUBLISHED_REVISION="${PUBLISHED_LINE%%[[:space:]]*}"
if [ "$REVISION" != "$PUBLISHED_REVISION" ]; then
  die "HEAD $REVISION is not the published $PUBLISHED_REF revision $PUBLISHED_REVISION"
fi

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
safe_remote_value "$REMOTE_HOME" || die "remote HOME contains unsupported characters"
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
safe_remote_value "$REMOTE_PARENT" || die "remote campaign root contains unsupported characters"
SHORT_REVISION="${REVISION:0:12}"
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION"
RUN_ID="${EUF_VIPER_ROLLBACK_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$SHORT_REVISION}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "run ID contains unsafe characters"
RUN_ROOT="${EUF_VIPER_ROLLBACK_RUN_ROOT:-$REMOTE_WORK/results/rollback-control-$RUN_ID}"
safe_remote_value "$RUN_ROOT" || die "run root contains unsupported characters"
case "$RUN_ROOT" in
  "$REMOTE_WORK"/results/*) ;;
  *) die "run root must stay below the pinned worktree results directory" ;;
esac

SUBMISSION_DIRECTORY="$ROOT/results/rollback-control-submissions"
SUBMISSION_PATH="$SUBMISSION_DIRECTORY/$RUN_ID.json"
mkdir -p "$SUBMISSION_DIRECTORY"
[ ! -e "$SUBMISSION_PATH" ] || die "submission receipt already exists for run ID $RUN_ID"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; if [ ! -d '$REMOTE_WORK/.git' ]; then git clone --quiet '$REPOSITORY_URL' '$REMOTE_WORK'; fi; git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'; test -z \"\$(git -C '$REMOTE_WORK' status --porcelain=v1 --untracked-files=all)\"; test -d '$CORPUS_ROOT/QF_UF'; test -s '$CORPUS_MANIFEST'; mkdir -p '$REMOTE_WORK/results'; test ! -e '$RUN_ROOT'"

write_receipt() {
  local status="$1"
  local prepare_job="$2"
  local array_job="$3"
  local audit_job="$4"
  python3 - \
    "$SUBMISSION_PATH" \
    "$status" \
    "$RUN_ID" \
    "$REVISION" \
    "$REMOTE_HOST" \
    "$REMOTE_WORK" \
    "$RUN_ROOT" \
    "$CORPUS_ROOT" \
    "$CORPUS_MANIFEST" \
    "$EXPECTED_SOURCES" \
    "$TARGET_COUNT" \
    "$ANTI_TARGET_COUNT" \
    "$SHARDS" \
    "$MAX_ACTIVE" \
    "$TIMEOUT_S" \
    "$REPEATS" \
    "$SEED" \
    "$MAX_ANTI_TARGET_BYTES" \
    "$MINIMUM_TARGET_SPEEDUP" \
    "$MAXIMUM_ANTI_P95_RATIO" \
    "$MINIMUM_MULTI_ROUND_TARGETS" \
    "$prepare_job" \
    "$array_job" \
    "$audit_job" <<'PY_RECEIPT'
import json
import os
import sys
import tempfile
from pathlib import Path

(
    output_raw,
    status,
    run_id,
    revision,
    remote_host,
    remote_work,
    run_root,
    corpus_root,
    corpus_manifest,
    expected_sources,
    target_count,
    anti_target_count,
    shards,
    max_active,
    timeout_s,
    repeats,
    seed,
    max_anti_target_bytes,
    minimum_target_speedup,
    maximum_anti_p95_ratio,
    minimum_multi_round_targets,
    prepare_job,
    array_job,
    audit_job,
) = sys.argv[1:]
payload = {
    "schema": "euf-viper.rollback-control-submission.v1",
    "status": status,
    "run_id": run_id,
    "scope": "forced_rollback_same_binary_engineering_control",
    "revision": revision,
    "remote_host": remote_host,
    "remote_worktree": remote_work,
    "run_root": run_root,
    "corpus_root": corpus_root,
    "corpus_manifest": corpus_manifest,
    "expected_sources": int(expected_sources),
    "target_count": int(target_count),
    "anti_target_count": int(anti_target_count),
    "comparison_count": 3,
    "shards": int(shards),
    "max_active": int(max_active),
    "timeout_s": float(timeout_s),
    "repeats": int(repeats),
    "seed": seed,
    "max_anti_target_bytes": int(max_anti_target_bytes),
    "gates": {
        "minimum_target_speedup": float(minimum_target_speedup),
        "maximum_anti_p95_ratio": float(maximum_anti_p95_ratio),
        "minimum_multi_round_targets": int(minimum_multi_round_targets),
        "require_conflict_evidence": True,
    },
    "jobs": {
        "prepare": prepare_job or None,
        "control_array": array_job or None,
        "audit": audit_job or None,
    },
    "submission_state_may_be_incomplete": status != "submitted",
    "prepare_manifest": f"{run_root}/prepare.json",
    "final_audit": f"{run_root}/final-audit.json",
    "performance_claims": [],
}
output = Path(output_raw)
output.parent.mkdir(parents=True, exist_ok=True)
descriptor, temporary_raw = tempfile.mkstemp(
    prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
)
temporary = Path(temporary_raw)
try:
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        json.dump(payload, handle, allow_nan=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
finally:
    temporary.unlink(missing_ok=True)
PY_RECEIPT
}

PREPARE_JOB=""
ARRAY_JOB=""
AUDIT_JOB=""
write_receipt "submission_intent" "$PREPARE_JOB" "$ARRAY_JOB" "$AUDIT_JOB"

SUBMITTED_JOBS=()
cancel_partial_chain() {
  status=$?
  trap - ERR
  if [ "$status" -ne 0 ] && [ "${#SUBMITTED_JOBS[@]}" -gt 0 ]; then
    ssh "$REMOTE_HOST" "scancel ${SUBMITTED_JOBS[*]}" >/dev/null 2>&1 || true
  fi
  write_receipt "submission_interrupted" "$PREPARE_JOB" "$ARRAY_JOB" "$AUDIT_JOB" || true
  exit "$status"
}
trap cancel_partial_chain ERR

abort_partial_chain() {
  echo "$*" >&2
  if [ "${#SUBMITTED_JOBS[@]}" -gt 0 ]; then
    ssh "$REMOTE_HOST" "scancel ${SUBMITTED_JOBS[*]}" >/dev/null 2>&1 || true
  fi
  trap - ERR
  write_receipt "submission_aborted" "$PREPARE_JOB" "$ARRAY_JOB" "$AUDIT_JOB" || true
  exit 2
}

ssh "$REMOTE_HOST" "mkdir '$RUN_ROOT'"

EXPORTS="HOME=$REMOTE_HOME,EUF_VIPER_ROLLBACK_EXPECTED_REVISION=$REVISION,EUF_VIPER_ROLLBACK_RUN_ROOT=$RUN_ROOT,EUF_VIPER_ROLLBACK_CORPUS_ROOT=$CORPUS_ROOT,EUF_VIPER_ROLLBACK_CORPUS_MANIFEST=$CORPUS_MANIFEST,EUF_VIPER_ROLLBACK_EXPECTED_SOURCES=$EXPECTED_SOURCES,EUF_VIPER_ROLLBACK_TARGET_COUNT=$TARGET_COUNT,EUF_VIPER_ROLLBACK_ANTI_TARGET_COUNT=$ANTI_TARGET_COUNT,EUF_VIPER_ROLLBACK_SHARDS=$SHARDS,EUF_VIPER_ROLLBACK_TIMEOUT_S=$TIMEOUT_S,EUF_VIPER_ROLLBACK_REPEATS=$REPEATS,EUF_VIPER_ROLLBACK_SEED=$SEED,EUF_VIPER_ROLLBACK_MAX_ANTI_TARGET_BYTES=$MAX_ANTI_TARGET_BYTES,EUF_VIPER_ROLLBACK_MINIMUM_TARGET_SPEEDUP=$MINIMUM_TARGET_SPEEDUP,EUF_VIPER_ROLLBACK_MAXIMUM_ANTI_P95_RATIO=$MAXIMUM_ANTI_P95_RATIO,EUF_VIPER_ROLLBACK_MINIMUM_MULTI_ROUND_TARGETS=$MINIMUM_MULTI_ROUND_TARGETS"

PREPARE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --export='$EXPORTS' scripts/wmi/euf_viper_rollback_prepare.sbatch")"
PREPARE_CANDIDATE="${PREPARE_SUBMISSION%%;*}"
canonical_positive_integer "$PREPARE_CANDIDATE" || abort_partial_chain "invalid prepare job id: $PREPARE_SUBMISSION"
PREPARE_JOB="$PREPARE_CANDIDATE"
SUBMITTED_JOBS+=("$PREPARE_JOB")
write_receipt "submitting" "$PREPARE_JOB" "$ARRAY_JOB" "$AUDIT_JOB"

ARRAY_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --dependency='afterok:$PREPARE_JOB' --array='0-$((TOTAL_ARRAY_TASKS - 1))%$MAX_ACTIVE' --export='$EXPORTS' scripts/wmi/euf_viper_rollback_control.sbatch")"
ARRAY_CANDIDATE="${ARRAY_SUBMISSION%%;*}"
canonical_positive_integer "$ARRAY_CANDIDATE" || abort_partial_chain "invalid control-array job id: $ARRAY_SUBMISSION"
ARRAY_JOB="$ARRAY_CANDIDATE"
SUBMITTED_JOBS+=("$ARRAY_JOB")
write_receipt "submitting" "$PREPARE_JOB" "$ARRAY_JOB" "$AUDIT_JOB"

AUDIT_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --dependency='afterok:$ARRAY_JOB' --export='$EXPORTS' scripts/wmi/euf_viper_rollback_audit.sbatch")"
AUDIT_CANDIDATE="${AUDIT_SUBMISSION%%;*}"
canonical_positive_integer "$AUDIT_CANDIDATE" || abort_partial_chain "invalid audit job id: $AUDIT_SUBMISSION"
AUDIT_JOB="$AUDIT_CANDIDATE"
SUBMITTED_JOBS+=("$AUDIT_JOB")
trap - ERR
write_receipt "submitted" "$PREPARE_JOB" "$ARRAY_JOB" "$AUDIT_JOB"
cat "$SUBMISSION_PATH"
