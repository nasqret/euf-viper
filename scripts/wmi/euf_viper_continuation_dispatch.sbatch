#!/usr/bin/env bash
#SBATCH --job-name=euf-cont-dispatch
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --output=results/continuation-dispatch-%j.out
#SBATCH --error=results/continuation-dispatch-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export LANG=C
export LC_ALL=C
export TZ=UTC

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
BASE_PREPARE_JOB_ID="${EUF_VIPER_BASE_PREPARE_JOB_ID:?set EUF_VIPER_BASE_PREPARE_JOB_ID}"
BASE_AUDIT_JOB_ID="${EUF_VIPER_BASE_AUDIT_JOB_ID:?set EUF_VIPER_BASE_AUDIT_JOB_ID}"
TARGET_BUDGET="${EUF_VIPER_CONTINUATION_TARGET_BUDGET:?set EUF_VIPER_CONTINUATION_TARGET_BUDGET}"
CONFIGURED_SHARDS="${EUF_VIPER_CONTINUATION_SHARDS:-64}"
MAX_ACTIVE="${EUF_VIPER_CONTINUATION_MAX_ACTIVE:-16}"
BOOTSTRAP_REPLICATES="${EUF_VIPER_CONTINUATION_BOOTSTRAP_REPLICATES:-10000}"
WALL_TIME_60="${EUF_VIPER_CONTINUATION_WALL_TIME_60:-04:00:00}"
WALL_TIME_1200="${EUF_VIPER_CONTINUATION_WALL_TIME_1200:-24:00:00}"
CHAIN_ID="${EUF_VIPER_CONTINUATION_CHAIN_ID:-${SLURM_JOB_ID:?run under Slurm}}"

positive_integer() {
  case "$2" in
    ''|0|0*|*[!0-9]*)
      echo "$1 must be a positive base-10 integer" >&2
      exit 2
      ;;
  esac
}

job_id_from_submission() {
  local submission="$1"
  PARSED_JOB_ID="${submission%%;*}"
  positive_integer "Slurm job id" "$PARSED_JOB_ID"
}

positive_integer "base prepare job id" "$BASE_PREPARE_JOB_ID"
positive_integer "base audit job id" "$BASE_AUDIT_JOB_ID"
positive_integer "configured shard count" "$CONFIGURED_SHARDS"
positive_integer "maximum active shard count" "$MAX_ACTIVE"
positive_integer "bootstrap replicate count" "$BOOTSTRAP_REPLICATES"
positive_integer "continuation chain id" "$CHAIN_ID"
case "$TARGET_BUDGET" in
  60) SOURCE_BUDGET=2; SHARD_WALL_TIME="$WALL_TIME_60" ;;
  1200) SOURCE_BUDGET=60; SHARD_WALL_TIME="$WALL_TIME_1200" ;;
  *) echo "target budget must be 60 or 1200" >&2; exit 2 ;;
esac

ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in continuation dispatcher" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty in continuation dispatcher" >&2
  exit 2
fi

RUN_ROOT="$PWD/results/p0-$BASE_PREPARE_JOB_ID"
BASE_AUDIT="$RUN_ROOT/audit/index.json"
CHAIN_ROOT="$RUN_ROOT/continuations/chain-$CHAIN_ID"
mkdir -p "$CHAIN_ROOT/submissions" "$CHAIN_ROOT/audit" "$CHAIN_ROOT/analysis"

python3 - "$BASE_AUDIT" "$BASE_PREPARE_JOB_ID" "$BASE_AUDIT_JOB_ID" "$EXPECTED_REVISION" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]).resolve()
prepare_job_id = int(sys.argv[2])
audit_job_id = int(sys.argv[3])
revision = sys.argv[4]

TOP_LEVEL_KEYS = {
    "analyses",
    "attempt",
    "environment",
    "job_id",
    "preparation_receipt",
    "prepare_job_id",
    "revision",
    "run_root",
    "scheduler_receipt",
    "schema",
    "shards",
    "source",
    "status",
    "submission_manifest_sha256",
}
ANALYSIS_KEYS = {
    "bytes",
    "device",
    "inode",
    "input_artifacts",
    "instances",
    "path",
    "promoted",
    "raw_records",
    "sha256",
    "shards",
    "status",
    "validated_process_exit",
}
PREPARATION_RECEIPT_KEYS = {
    "bytes", "device", "inode", "job_id", "path", "revision", "sha256", "status"
}
SCHEDULER_RECEIPT_KEYS = {
    "bytes", "device", "inode", "job_id", "path", "sha256", "status"
}


def reject_constant(value):
    raise ValueError(f"non-finite JSON number {value}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def exact_object(value, keys, context):
    if type(value) is not dict or set(value) != keys:
        raise SystemExit(f"{context} has an incompatible shape")
    return value


def integer(value, context, minimum=0):
    if type(value) is not int or value < minimum:
        raise SystemExit(f"{context} is invalid")
    return value


def string(value, context):
    if type(value) is not str or not value:
        raise SystemExit(f"{context} is invalid")
    return value


def digest(value, context, length=64):
    value = string(value, context)
    if len(value) != length or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise SystemExit(f"{context} is invalid")
    return value


try:
    raw = path.read_bytes()
    payload = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (OSError, UnicodeError, ValueError) as error:
    raise SystemExit(f"cannot read validated base audit {path}: {error}")
canonical = (
    json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    + "\n"
).encode("utf-8")
if canonical != raw:
    raise SystemExit("base audit is not canonical JSON")
exact_object(payload, TOP_LEVEL_KEYS, "base audit")
if payload["schema"] != "euf-viper.locked-p0-audit.v4":
    raise SystemExit("base audit has an incompatible schema")
if payload["status"] != "complete":
    raise SystemExit("base audit is not complete")
if payload["prepare_job_id"] != prepare_job_id:
    raise SystemExit("base audit prepare job id mismatch")
if payload["job_id"] != audit_job_id:
    raise SystemExit("base audit job id mismatch")
if payload["revision"] != revision:
    raise SystemExit("base audit revision mismatch")
digest(payload["revision"], "base audit revision", length=40)
integer(payload["shards"], "base audit shards", minimum=1)
string(payload["run_root"], "base audit run root")
digest(payload["submission_manifest_sha256"], "base audit submission manifest SHA-256")

attempt = exact_object(payload["attempt"], {"checkout", "id", "root"}, "base audit attempt")
for field in attempt:
    string(attempt[field], f"base audit attempt {field}")
environment = payload["environment"]
if type(environment) is not dict or not environment or any(
    type(key) is not str or not key or type(value) is not str
    for key, value in environment.items()
):
    raise SystemExit("base audit environment has an incompatible shape")
source = exact_object(
    payload["source"], {"blob_count", "blobs_sha256", "tree"}, "base audit source"
)
integer(source["blob_count"], "base audit source blob count", minimum=1)
digest(source["blobs_sha256"], "base audit source blobs SHA-256")
digest(source["tree"], "base audit source tree", length=40)

preparation = exact_object(
    payload["preparation_receipt"], PREPARATION_RECEIPT_KEYS, "base audit preparation receipt"
)
scheduler = exact_object(
    payload["scheduler_receipt"], SCHEDULER_RECEIPT_KEYS, "base audit scheduler receipt"
)
for context, receipt in (("preparation", preparation), ("scheduler", scheduler)):
    for field in ("bytes", "device", "inode"):
        integer(receipt[field], f"base audit {context} receipt {field}")
    string(receipt["path"], f"base audit {context} receipt path")
    digest(receipt["sha256"], f"base audit {context} receipt SHA-256")
if preparation["job_id"] != prepare_job_id or preparation["revision"] != revision:
    raise SystemExit("base audit preparation receipt identity mismatch")
if preparation["status"] != "prepared":
    raise SystemExit("base audit preparation receipt status is invalid")
if scheduler["job_id"] != audit_job_id or scheduler["status"] != "bound":
    raise SystemExit("base audit scheduler receipt identity mismatch")

analyses = exact_object(
    payload["analyses"], {"full", "official"}, "base audit analyses"
)
for kind, record in analyses.items():
    record = exact_object(record, ANALYSIS_KEYS, f"base audit {kind} analysis")
    analysis_path = Path(
        string(record["path"], f"base audit {kind} analysis path")
    ).resolve()
    try:
        analysis_bytes = analysis_path.read_bytes()
    except OSError as error:
        raise SystemExit(f"cannot read base {kind} analysis: {error}")
    if hashlib.sha256(analysis_bytes).hexdigest() != digest(
        record["sha256"], f"base audit {kind} analysis SHA-256"
    ):
        raise SystemExit(f"base {kind} analysis SHA-256 mismatch")
    expected_bytes = integer(
        record["bytes"], f"base audit {kind} analysis bytes", minimum=1
    )
    if len(analysis_bytes) != expected_bytes:
        raise SystemExit(f"base {kind} analysis byte count mismatch")
    for field in ("device", "inode"):
        integer(record[field], f"base audit {kind} analysis {field}")
    for field in ("instances", "raw_records", "shards"):
        integer(record[field], f"base audit {kind} analysis {field}", minimum=1)
    if type(record["promoted"]) is not bool:
        raise SystemExit(f"base audit {kind} analysis promoted flag is invalid")
    expected_status = "promoted" if record["promoted"] else "rejected"
    expected_exit = 0 if record["promoted"] else 1
    if (
        record["status"] != expected_status
        or record["validated_process_exit"] != expected_exit
    ):
        raise SystemExit(f"base audit {kind} analysis status is invalid")
    if type(record["input_artifacts"]) is not dict:
        raise SystemExit(f"base audit {kind} analysis inputs are invalid")
PY

CORPORA=(full official)
STAGE_STATUS=()
SELECTED_INSTANCES=()
SELECTED_RUNS=()
STAGE_SHARDS=()
ARRAY_JOBS=()
AUDIT_JOBS=()

for CORPUS_INDEX in 0 1; do
  CORPUS_KIND="${CORPORA[$CORPUS_INDEX]}"
  STAGE_ROOT="$CHAIN_ROOT/$CORPUS_KIND-${TARGET_BUDGET}s"
  if [ "$TARGET_BUDGET" = 60 ]; then
    SOURCE_PARENT="$RUN_ROOT/locks/$CORPUS_KIND-parent.json"
    SOURCE_LOCK_DIR="$RUN_ROOT/locks/$CORPUS_KIND"
    SOURCE_RESULTS="$RUN_ROOT/$CORPUS_KIND-2s"
  else
    PRIOR_ROOT="$CHAIN_ROOT/$CORPUS_KIND-60s"
    PRIOR_INDEX="$PRIOR_ROOT/index.json"
    PRIOR_STATUS="$(python3 - "$PRIOR_INDEX" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"cannot read prior continuation index {path}: {error}")
status = payload.get("status") if isinstance(payload, dict) else None
if status not in {"ready", "no_timeouts"}:
    raise SystemExit("prior continuation index status is invalid")
print(status)
PY
)"
    if [ "$PRIOR_STATUS" = no_timeouts ]; then
      if [ -e "$STAGE_ROOT" ]; then
        echo "unexpected 1200-second artifacts after a zero-timeout stage: $STAGE_ROOT" >&2
        exit 2
      fi
      STAGE_STATUS[$CORPUS_INDEX]=implicit_no_timeouts
      SELECTED_INSTANCES[$CORPUS_INDEX]=0
      SELECTED_RUNS[$CORPUS_INDEX]=0
      STAGE_SHARDS[$CORPUS_INDEX]=0
      ARRAY_JOBS[$CORPUS_INDEX]=-
      AUDIT_DEPENDENCY="$SLURM_JOB_ID"
    else
      SOURCE_PARENT="$PRIOR_ROOT/continuation-parent.json"
      SOURCE_LOCK_DIR="$PRIOR_ROOT/locks"
      SOURCE_RESULTS="$PRIOR_ROOT"
    fi
  fi

  if [ "${STAGE_STATUS[$CORPUS_INDEX]-}" != implicit_no_timeouts ]; then
    if [ -e "$STAGE_ROOT" ]; then
      echo "refuse to reuse continuation stage directory $STAGE_ROOT" >&2
      exit 2
    fi
    mkdir "$STAGE_ROOT"
    python3 scripts/bench/derive_timeout_continuations.py \
      --parent-lock "$SOURCE_PARENT" \
      --shard-lock-dir "$SOURCE_LOCK_DIR" \
      --shard-results-root "$SOURCE_RESULTS" \
      --target-budget "$TARGET_BUDGET" \
      --output-dir "$STAGE_ROOT" \
      > "$STAGE_ROOT/derive-summary.json"

    INDEX_FIELDS="$(python3 - "$STAGE_ROOT/index.json" "$TARGET_BUDGET" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
target = int(sys.argv[2])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"cannot read continuation index {path}: {error}")
if not isinstance(payload, dict) or payload.get("schema_version") != 1:
    raise SystemExit("continuation index has an incompatible schema")
status = payload.get("status")
instances = payload.get("selected_instances")
runs = payload.get("selected_runs")
if status not in {"ready", "no_timeouts"}:
    raise SystemExit("continuation index status is invalid")
if payload.get("target_budget_s") != target:
    raise SystemExit("continuation index target budget mismatch")
if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (instances, runs)):
    raise SystemExit("continuation index selection counts are invalid")
if (status == "ready") != (instances > 0 and runs > 0):
    raise SystemExit("continuation index status and selection counts disagree")
if status == "no_timeouts" and payload.get("continuation_lock") is not None:
    raise SystemExit("zero-timeout index unexpectedly contains a continuation lock")
print(status, instances, runs, sep="\t")
PY
    )"
    IFS=$'\t' read -r STATUS INSTANCES RUNS <<< "$INDEX_FIELDS"
    STAGE_STATUS[$CORPUS_INDEX]="$STATUS"
    SELECTED_INSTANCES[$CORPUS_INDEX]="$INSTANCES"
    SELECTED_RUNS[$CORPUS_INDEX]="$RUNS"

    if [ "$STATUS" = ready ]; then
      SHARD_COUNT="$CONFIGURED_SHARDS"
      if [ "$INSTANCES" -lt "$SHARD_COUNT" ]; then
        SHARD_COUNT="$INSTANCES"
      fi
      positive_integer "derived shard count" "$SHARD_COUNT"
      LOCK_DIR="$STAGE_ROOT/locks"
      mkdir "$LOCK_DIR"
      python3 scripts/bench/shard_campaign_lock.py \
        "$STAGE_ROOT/continuation-parent.json" \
        --count "$SHARD_COUNT" \
        --out-dir "$LOCK_DIR" \
        > "$STAGE_ROOT/shard-summary.json"
      LOCK_FILES=("$LOCK_DIR"/lock-*.json)
      if [ ! -e "${LOCK_FILES[0]}" ] || [ "${#LOCK_FILES[@]}" -ne "$SHARD_COUNT" ]; then
        echo "derived shard lock count mismatch for $CORPUS_KIND/$TARGET_BUDGET" >&2
        exit 2
      fi
      ARRAY_SUBMISSION="$(sbatch --parsable --kill-on-invalid-dep=yes \
        --dependency="afterok:$SLURM_JOB_ID" \
        --array="0-$((SHARD_COUNT - 1))%$MAX_ACTIVE" \
        --time="$SHARD_WALL_TIME" \
        --export="ALL,EUF_VIPER_EXPECTED_REVISION=$EXPECTED_REVISION,EUF_VIPER_BASE_PREPARE_JOB_ID=$BASE_PREPARE_JOB_ID,EUF_VIPER_CONTINUATION_CHAIN_ID=$CHAIN_ID,EUF_VIPER_CORPUS_KIND=$CORPUS_KIND,EUF_VIPER_CONTINUATION_TARGET_BUDGET=$TARGET_BUDGET,EUF_VIPER_CONTINUATION_SHARDS=$CONFIGURED_SHARDS,EUF_VIPER_CONTINUATION_STAGE_SHARDS=$SHARD_COUNT" \
        scripts/wmi/euf_viper_continuation_shard.sbatch)"
      job_id_from_submission "$ARRAY_SUBMISSION"
      ARRAY_JOBS[$CORPUS_INDEX]="$PARSED_JOB_ID"
      AUDIT_DEPENDENCY="$PARSED_JOB_ID"
      STAGE_SHARDS[$CORPUS_INDEX]="$SHARD_COUNT"
    else
      ARRAY_JOBS[$CORPUS_INDEX]=-
      AUDIT_DEPENDENCY="$SLURM_JOB_ID"
      STAGE_SHARDS[$CORPUS_INDEX]=0
    fi
  fi

  AUDIT_SUBMISSION="$(sbatch --parsable --kill-on-invalid-dep=yes \
    --dependency="afterok:$AUDIT_DEPENDENCY" \
    --export="ALL,EUF_VIPER_EXPECTED_REVISION=$EXPECTED_REVISION,EUF_VIPER_BASE_PREPARE_JOB_ID=$BASE_PREPARE_JOB_ID,EUF_VIPER_BASE_AUDIT_JOB_ID=$BASE_AUDIT_JOB_ID,EUF_VIPER_CONTINUATION_CHAIN_ID=$CHAIN_ID,EUF_VIPER_CORPUS_KIND=$CORPUS_KIND,EUF_VIPER_CONTINUATION_TARGET_BUDGET=$TARGET_BUDGET,EUF_VIPER_CONTINUATION_BOOTSTRAP_REPLICATES=$BOOTSTRAP_REPLICATES" \
    scripts/wmi/euf_viper_continuation_audit.sbatch)"
  job_id_from_submission "$AUDIT_SUBMISSION"
  AUDIT_JOBS[$CORPUS_INDEX]="$PARSED_JOB_ID"
done

JOIN_DEPENDENCY="afterok:${AUDIT_JOBS[0]}:${AUDIT_JOBS[1]}"
if [ "$TARGET_BUDGET" = 60 ]; then
  NEXT_SUBMISSION="$(sbatch --parsable --kill-on-invalid-dep=yes \
    --dependency="$JOIN_DEPENDENCY" \
    --export="ALL,EUF_VIPER_EXPECTED_REVISION=$EXPECTED_REVISION,EUF_VIPER_BASE_PREPARE_JOB_ID=$BASE_PREPARE_JOB_ID,EUF_VIPER_BASE_AUDIT_JOB_ID=$BASE_AUDIT_JOB_ID,EUF_VIPER_CONTINUATION_CHAIN_ID=$CHAIN_ID,EUF_VIPER_CONTINUATION_TARGET_BUDGET=1200,EUF_VIPER_CONTINUATION_SHARDS=$CONFIGURED_SHARDS,EUF_VIPER_CONTINUATION_MAX_ACTIVE=$MAX_ACTIVE,EUF_VIPER_CONTINUATION_BOOTSTRAP_REPLICATES=$BOOTSTRAP_REPLICATES,EUF_VIPER_CONTINUATION_WALL_TIME_60=$WALL_TIME_60,EUF_VIPER_CONTINUATION_WALL_TIME_1200=$WALL_TIME_1200" \
    scripts/wmi/euf_viper_continuation_dispatch.sbatch)"
  NEXT_ROLE=dispatch_1200
else
  NEXT_SUBMISSION="$(sbatch --parsable --kill-on-invalid-dep=yes \
    --dependency="$JOIN_DEPENDENCY" \
    --export="ALL,EUF_VIPER_EXPECTED_REVISION=$EXPECTED_REVISION,EUF_VIPER_BASE_PREPARE_JOB_ID=$BASE_PREPARE_JOB_ID,EUF_VIPER_BASE_AUDIT_JOB_ID=$BASE_AUDIT_JOB_ID,EUF_VIPER_CONTINUATION_CHAIN_ID=$CHAIN_ID" \
    scripts/wmi/euf_viper_continuation_finalize.sbatch)"
  NEXT_ROLE=finalize
fi
job_id_from_submission "$NEXT_SUBMISSION"
NEXT_JOB_ID="$PARSED_JOB_ID"

SUBMISSION_INDEX="$CHAIN_ROOT/submissions/$TARGET_BUDGET.json"
python3 - \
  "$SUBMISSION_INDEX" "$EXPECTED_REVISION" "$BASE_PREPARE_JOB_ID" \
  "$BASE_AUDIT_JOB_ID" "$CHAIN_ID" "$SLURM_JOB_ID" "$SOURCE_BUDGET" \
  "$TARGET_BUDGET" "$CONFIGURED_SHARDS" "$MAX_ACTIVE" \
  "${STAGE_STATUS[0]}" "${SELECTED_INSTANCES[0]}" \
  "${SELECTED_RUNS[0]}" "${STAGE_SHARDS[0]}" \
  "${ARRAY_JOBS[0]}" "${AUDIT_JOBS[0]}" \
  "${STAGE_STATUS[1]}" "${SELECTED_INSTANCES[1]}" \
  "${SELECTED_RUNS[1]}" "${STAGE_SHARDS[1]}" \
  "${ARRAY_JOBS[1]}" "${AUDIT_JOBS[1]}" \
  "$NEXT_ROLE" "$NEXT_JOB_ID" <<'PY'
import json
import os
import sys
from pathlib import Path

(
    out_raw, revision, base_prepare, base_audit, chain_id, dispatcher,
    source_budget, target_budget, configured_shards, max_active,
    full_status, full_instances, full_runs, full_shards, full_array, full_audit,
    official_status, official_instances, official_runs, official_shards,
    official_array, official_audit, next_role, next_job,
) = sys.argv[1:]

def job(value: str) -> int | None:
    return None if value == "-" else int(value)

payload = {
    "schema_version": 1,
    "status": "submitted",
    "revision": revision,
    "base_prepare_job_id": int(base_prepare),
    "base_audit_job_id": int(base_audit),
    "chain_id": int(chain_id),
    "dispatcher_job_id": int(dispatcher),
    "source_budget_s": int(source_budget),
    "target_budget_s": int(target_budget),
    "configured_shards": int(configured_shards),
    "max_active": int(max_active),
    "corpora": {
        "full": {
            "status": full_status,
            "selected_instances": int(full_instances),
            "selected_runs": int(full_runs),
            "shards": int(full_shards),
            "array_job_id": job(full_array),
            "audit_job_id": int(full_audit),
        },
        "official": {
            "status": official_status,
            "selected_instances": int(official_instances),
            "selected_runs": int(official_runs),
            "shards": int(official_shards),
            "array_job_id": job(official_array),
            "audit_job_id": int(official_audit),
        },
    },
    "next": {"role": next_role, "job_id": int(next_job)},
}
out = Path(out_raw)
if out.exists() or out.is_symlink():
    raise SystemExit(f"refuse to replace submission index {out}")
out.parent.mkdir(parents=True, exist_ok=True)
temporary = out.with_name(f".{out.name}.{os.getpid()}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
temporary.replace(out)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
