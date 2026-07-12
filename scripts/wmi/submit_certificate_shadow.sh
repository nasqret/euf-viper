#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
REPOSITORY_URL="${EUF_VIPER_CERT_REPOSITORY_URL:-https://github.com/nasqret/euf-viper.git}"
PUBLISHED_REF="${EUF_VIPER_CERT_PUBLISHED_REF:-refs/heads/main}"
BASE_PARENT_LOCK="${EUF_VIPER_CERT_BASE_PARENT_LOCK:?set the remote base parent lock path}"
BASE_SHARD_LOCK_DIR="${EUF_VIPER_CERT_BASE_SHARD_LOCK_DIR:?set the remote base bound-lock directory}"
BASE_SHARD_RESULTS_ROOT="${EUF_VIPER_CERT_BASE_SHARD_RESULTS_ROOT:?set the remote base shard-results root}"
CORPUS_ROOT="${EUF_VIPER_CERT_CORPUS_ROOT:-}"
DRAT_TRIM="${EUF_VIPER_CERT_DRAT_TRIM:?set the explicit remote drat-trim path}"
DRAT_TRIM_SHA256="${EUF_VIPER_CERT_DRAT_TRIM_SHA256:?set the pinned drat-trim SHA-256}"
SHARDS="${EUF_VIPER_CERT_SHARDS:-64}"
MAX_ACTIVE="${EUF_VIPER_CERT_MAX_ACTIVE:-8}"
TIMEOUT_S="${EUF_VIPER_CERT_TIMEOUT_S:-60}"
CHECKER_TIMEOUT_S="${EUF_VIPER_CERT_CHECKER_TIMEOUT_S:-60}"
TIMEOUT_GRACE_S="${EUF_VIPER_CERT_TIMEOUT_GRACE_S:-0.25}"
BASE_DEPENDENCY_JOB="${EUF_VIPER_CERT_BASE_DEPENDENCY_JOB:-}"
STAGE_LABEL="${EUF_VIPER_CERT_STAGE_LABEL:-base-2s}"
EXPECTED_BUDGET="${EUF_VIPER_CERT_EXPECTED_BUDGET:-2}"

die() {
  echo "$*" >&2
  exit 2
}

positive_integer() {
  case "$1" in
    ''|0|0*|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

safe_remote_value() {
  [[ "$1" =~ ^[A-Za-z0-9_./:@%+-]+$ ]]
}

canonical_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

positive_decimal() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]] && [ "$1" != 0 ] && [ "$1" != 0.0 ]
}

nonnegative_decimal() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

positive_integer "$SHARDS" || die "EUF_VIPER_CERT_SHARDS must be a canonical positive integer"
positive_integer "$MAX_ACTIVE" || die "EUF_VIPER_CERT_MAX_ACTIVE must be a canonical positive integer"
positive_decimal "$TIMEOUT_S" || die "certificate timeout must be a positive decimal"
positive_decimal "$CHECKER_TIMEOUT_S" || die "checker timeout must be a positive decimal"
nonnegative_decimal "$TIMEOUT_GRACE_S" || die "timeout grace must be a non-negative decimal"
positive_decimal "$EXPECTED_BUDGET" || die "expected stage budget must be a positive decimal"
[[ "$STAGE_LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "stage label contains unsafe characters"
if [ -n "$BASE_DEPENDENCY_JOB" ]; then
  positive_integer "$BASE_DEPENDENCY_JOB" || die "base dependency job must be a positive integer"
fi
canonical_sha256 "$DRAT_TRIM_SHA256" || die "drat-trim SHA-256 must be 64 lowercase hex digits"
for value in \
  "$REMOTE_HOST" \
  "$REMOTE_PARENT" \
  "$REPOSITORY_URL" \
  "$PUBLISHED_REF" \
  "$BASE_PARENT_LOCK" \
  "$BASE_SHARD_LOCK_DIR" \
  "$BASE_SHARD_RESULTS_ROOT" \
  "$CORPUS_ROOT" \
  "$DRAT_TRIM"; do
  if [ -n "$value" ]; then
    safe_remote_value "$value" || die "remote values may contain only conservative path/URL characters: $value"
  fi
done
case "$BASE_PARENT_LOCK:$BASE_SHARD_LOCK_DIR:$BASE_SHARD_RESULTS_ROOT:$DRAT_TRIM" in
  /*:/*:/*:/*) ;;
  *) die "base inputs and drat-trim must be explicit absolute remote paths" ;;
esac
if [ -n "$CORPUS_ROOT" ]; then
  case "$CORPUS_ROOT" in /*) ;; *) die "corpus root must be an absolute remote path" ;; esac
fi

cd "$ROOT"
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  die "tracked repository state must be clean before certificate-shadow submission"
fi
REVISION="$(git rev-parse HEAD)"
case "$REVISION" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) die "HEAD is not a full Git revision" ;;
esac
PUBLISHED_LINE="$(git ls-remote --exit-code "$REPOSITORY_URL" "$PUBLISHED_REF")"
PUBLISHED_REVISION="${PUBLISHED_LINE%%[[:space:]]*}"
if [ "$REVISION" != "$PUBLISHED_REVISION" ]; then
  die "HEAD $REVISION is not the published $PUBLISHED_REF revision $PUBLISHED_REVISION"
fi

CHECKER_LOCAL="$ROOT/scripts/cert/check_certificate.py"
CHECKER_SHA256="$(python3 - "$CHECKER_LOCAL" <<'PY_CHECKER_HASH'
import hashlib
import sys
from pathlib import Path

path = Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY_CHECKER_HASH
)"
canonical_sha256 "$CHECKER_SHA256" || die "could not pin the certificate checker"

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
safe_remote_value "$REMOTE_HOME" || die "remote HOME contains unsupported characters"
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
SHORT_REVISION="${REVISION:0:12}"
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION"
RUN_ID="${EUF_VIPER_CERT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$SHORT_REVISION}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "run ID contains unsafe characters"
RUN_ROOT="${EUF_VIPER_CERT_RUN_ROOT:-$REMOTE_WORK/results/certificate-shadow-$STAGE_LABEL-$RUN_ID}"
safe_remote_value "$RUN_ROOT" || die "run root contains unsupported characters"
case "$RUN_ROOT" in
  "$REMOTE_WORK"/results/*) ;;
  *) die "run root must stay below the pinned worktree results directory" ;;
esac
CHECKER="$REMOTE_WORK/scripts/cert/check_certificate.py"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; if [ ! -d '$REMOTE_WORK/.git' ]; then git clone --quiet '$REPOSITORY_URL' '$REMOTE_WORK'; fi; git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'; test -z \"\$(git -C '$REMOTE_WORK' status --porcelain=v1 --untracked-files=all)\"; mkdir -p '$REMOTE_WORK/results' '$RUN_ROOT'"

REMOTE_HASHES="$(ssh "$REMOTE_HOST" "set -euo pipefail; test -x '$CHECKER'; test -x '$DRAT_TRIM'; printf '%s %s' \"\$(sha256sum '$CHECKER' | awk '{print \$1}')\" \"\$(sha256sum '$DRAT_TRIM' | awk '{print \$1}')\"")"
read -r REMOTE_CHECKER_SHA256 REMOTE_DRAT_TRIM_SHA256 <<<"$REMOTE_HASHES"
if [ "$REMOTE_CHECKER_SHA256" != "$CHECKER_SHA256" ]; then
  die "published remote checker bytes do not match the local published revision"
fi
if [ "$REMOTE_DRAT_TRIM_SHA256" != "$DRAT_TRIM_SHA256" ]; then
  die "remote drat-trim bytes do not match the explicit SHA-256 pin"
fi

EXPORTS="HOME=$REMOTE_HOME,EUF_VIPER_CERT_EXPECTED_REVISION=$REVISION,EUF_VIPER_CERT_RUN_ROOT=$RUN_ROOT,EUF_VIPER_CERT_BASE_PARENT_LOCK=$BASE_PARENT_LOCK,EUF_VIPER_CERT_BASE_SHARD_LOCK_DIR=$BASE_SHARD_LOCK_DIR,EUF_VIPER_CERT_BASE_SHARD_RESULTS_ROOT=$BASE_SHARD_RESULTS_ROOT,EUF_VIPER_CERT_SHARDS=$SHARDS,EUF_VIPER_CERT_CHECKER=$CHECKER,EUF_VIPER_CERT_CHECKER_SHA256=$CHECKER_SHA256,EUF_VIPER_CERT_DRAT_TRIM=$DRAT_TRIM,EUF_VIPER_CERT_DRAT_TRIM_SHA256=$DRAT_TRIM_SHA256,EUF_VIPER_CERT_CORPUS_ROOT=$CORPUS_ROOT,EUF_VIPER_CERT_TIMEOUT_S=$TIMEOUT_S,EUF_VIPER_CERT_CHECKER_TIMEOUT_S=$CHECKER_TIMEOUT_S,EUF_VIPER_CERT_TIMEOUT_GRACE_S=$TIMEOUT_GRACE_S,EUF_VIPER_CERT_STAGE_LABEL=$STAGE_LABEL,EUF_VIPER_CERT_EXPECTED_BUDGET=$EXPECTED_BUDGET"

SUBMITTED_JOBS=()
cancel_partial_chain() {
  status=$?
  if [ "$status" -ne 0 ] && [ "${#SUBMITTED_JOBS[@]}" -gt 0 ]; then
    ssh "$REMOTE_HOST" "scancel ${SUBMITTED_JOBS[*]}" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cancel_partial_chain ERR

abort_partial_chain() {
  echo "$*" >&2
  if [ "${#SUBMITTED_JOBS[@]}" -gt 0 ]; then
    ssh "$REMOTE_HOST" "scancel ${SUBMITTED_JOBS[*]}" >/dev/null 2>&1 || true
  fi
  trap - ERR
  exit 2
}

PREPARE_DEPENDENCY=()
if [ -n "$BASE_DEPENDENCY_JOB" ]; then
  PREPARE_DEPENDENCY=(--dependency="afterok:$BASE_DEPENDENCY_JOB")
fi
PREPARE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes ${PREPARE_DEPENDENCY[*]} --export='$EXPORTS' scripts/wmi/euf_viper_certificate_prepare.sbatch")"
PREPARE_JOB="${PREPARE_SUBMISSION%%;*}"
positive_integer "$PREPARE_JOB" || abort_partial_chain "invalid prepare job id: $PREPARE_SUBMISSION"
SUBMITTED_JOBS+=("$PREPARE_JOB")

ARRAY_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --dependency='afterok:$PREPARE_JOB' --array='0-$((SHARDS - 1))%$MAX_ACTIVE' --export='$EXPORTS' scripts/wmi/euf_viper_certificate_shard.sbatch")"
ARRAY_JOB="${ARRAY_SUBMISSION%%;*}"
positive_integer "$ARRAY_JOB" || abort_partial_chain "invalid certificate array job id: $ARRAY_SUBMISSION"
SUBMITTED_JOBS+=("$ARRAY_JOB")

AUDIT_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --dependency='afterok:$ARRAY_JOB' --export='$EXPORTS' scripts/wmi/euf_viper_certificate_audit.sbatch")"
AUDIT_JOB="${AUDIT_SUBMISSION%%;*}"
positive_integer "$AUDIT_JOB" || abort_partial_chain "invalid certificate audit job id: $AUDIT_SUBMISSION"
SUBMITTED_JOBS+=("$AUDIT_JOB")
trap - ERR

mkdir -p results/certificate-shadow-submissions
SUBMISSION_PATH="$ROOT/results/certificate-shadow-submissions/$RUN_ID.json"
python3 - \
  "$SUBMISSION_PATH" \
  "$REVISION" \
  "$REMOTE_HOST" \
  "$REMOTE_WORK" \
  "$RUN_ROOT" \
  "$BASE_PARENT_LOCK" \
  "$BASE_SHARD_LOCK_DIR" \
  "$BASE_SHARD_RESULTS_ROOT" \
  "$SHARDS" \
  "$MAX_ACTIVE" \
  "$CHECKER" \
  "$CHECKER_SHA256" \
  "$DRAT_TRIM" \
  "$DRAT_TRIM_SHA256" \
  "$STAGE_LABEL" \
  "$EXPECTED_BUDGET" \
  "$PREPARE_JOB" \
  "$ARRAY_JOB" \
  "$AUDIT_JOB" <<'PY_SUBMISSION'
import json
import os
import sys
import tempfile
from pathlib import Path

(
    output_raw,
    revision,
    remote_host,
    remote_work,
    run_root,
    parent_lock,
    shard_lock_dir,
    shard_results_root,
    shards,
    max_active,
    checker,
    checker_hash,
    drat_trim,
    drat_hash,
    stage_label,
    expected_budget,
    prepare_job,
    array_job,
    audit_job,
) = sys.argv[1:]
payload = {
    "schema_version": 1,
    "status": "submitted",
    "scope": "single_physical_stage_certificate_coverage_only",
    "physical_stage": stage_label,
    "budget_s": float(expected_budget),
    "revision": revision,
    "remote_host": remote_host,
    "remote_worktree": remote_work,
    "run_root": run_root,
    "base": {
        "parent_lock": parent_lock,
        "shard_lock_dir": shard_lock_dir,
        "shard_results_root": shard_results_root,
    },
    "shards": int(shards),
    "max_active": int(max_active),
    "tools": {
        "checker": {"path": checker, "sha256": checker_hash},
        "drat_trim": {"path": drat_trim, "sha256": drat_hash},
    },
    "jobs": {
        "prepare": prepare_job,
        "certificate_array": array_job,
        "audit": audit_job,
    },
    "final_audit": f"{run_root}/{stage_label}-audit.json",
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
        json.dump(payload, handle, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
finally:
    temporary.unlink(missing_ok=True)
print(json.dumps(payload, allow_nan=False, indent=2, sort_keys=True))
PY_SUBMISSION
