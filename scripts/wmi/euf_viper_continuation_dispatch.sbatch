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

RUN_ROOT="$(cd -- "$PWD/results/p0-$BASE_PREPARE_JOB_ID" && pwd -P)"
BASE_AUDIT="$RUN_ROOT/audit/index.json"
CHAIN_ROOT="$RUN_ROOT/continuations/chain-$CHAIN_ID"

python3 - \
  "$BASE_AUDIT" "$BASE_PREPARE_JOB_ID" "$BASE_AUDIT_JOB_ID" \
  "$EXPECTED_REVISION" "$RUN_ROOT" <<'PY'
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

finalizer_path = Path.cwd() / "scripts" / "wmi" / "finalize_locked_audit.py"
spec = importlib.util.spec_from_file_location(
    "euf_viper_continuation_dispatch_finalizer", finalizer_path
)
if spec is None or spec.loader is None:
    raise SystemExit(f"cannot load locked audit validator {finalizer_path}")
finalizer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = finalizer
try:
    spec.loader.exec_module(finalizer)
except (ImportError, OSError) as error:
    raise SystemExit(f"cannot load locked audit validator {finalizer_path}: {error}")

import strict_artifacts


def open_read_nofollow_nonblocking(path, context):
    """Open through stable directories without blocking on a substituted FIFO."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    parent_fd, fingerprints = strict_artifacts._open_directory_chain(
        absolute.parent, f"{context} parent", create=False
    )
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = -1
    try:
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise strict_artifacts.StrictArtifactError(
                f"{context}: artifact is not a regular file"
            )
        post_fd, post_fingerprints = strict_artifacts._open_directory_chain(
            absolute.parent, f"{context} parent recheck", create=False
        )
        try:
            if post_fingerprints != fingerprints:
                raise strict_artifacts.StrictArtifactError(
                    f"{context}: parent path changed while opening artifact"
                )
            path_metadata = os.stat(
                absolute.name, dir_fd=post_fd, follow_symlinks=False
            )
        finally:
            os.close(post_fd)
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or path_metadata.st_dev != metadata.st_dev
            or path_metadata.st_ino != metadata.st_ino
        ):
            raise strict_artifacts.StrictArtifactError(
                f"{context}: artifact path changed while opening"
            )
        result = descriptor
        descriptor = -1
        return absolute, result
    except OSError as error:
        raise strict_artifacts.StrictArtifactError(
            f"{context}: cannot open {absolute} without symlinks: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


finalizer.open_read_nofollow = open_read_nofollow_nonblocking

path = Path(os.path.abspath(sys.argv[1]))
prepare_job_id = int(sys.argv[2])
audit_job_id = int(sys.argv[3])
revision = sys.argv[4]
trusted_run_root = Path(os.path.abspath(sys.argv[5]))
try:
    run_root = trusted_run_root.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"cannot resolve trusted run root {trusted_run_root}: {error}")
if run_root != trusted_run_root or not run_root.is_dir():
    raise SystemExit("trusted run root is not a canonical directory")
if path != run_root / "audit" / "index.json":
    raise SystemExit("base audit path is not the trusted run index")

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
ARTIFACT_KEYS = {"bytes", "device", "inode", "path", "sha256"}
INPUT_ARTIFACT_KEYS = {"parent_lock", "shard_bundle_sha256", "shards"}
PARENT_LOCK_INDEX_KEYS = ARTIFACT_KEYS | {"identity", "lock_sha256"}
SHARD_INDEX_KEYS = {"cpu_ids", "index", "lock", "raw", "raw_records"}
SHARD_LOCK_INDEX_KEYS = ARTIFACT_KEYS | {"lock_sha256"}
PARENT_IDENTITY_KEYS = {
    "baseline_ids",
    "budgets_s",
    "campaign_id",
    "candidate_id",
    "families",
    "instances",
    "manifest_path",
    "manifest_sha256",
    "promotion_eligible",
    "repository_commit",
    "solver_binary_sha256",
    "solver_config_path",
    "solver_config_sha256",
    "taxonomy_path",
    "taxonomy_sha256",
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
        raise finalizer.AuditFinalizeError(f"{context} has an incompatible shape")
    return value


def integer(value, context, minimum=0):
    if type(value) is not int or value < minimum:
        raise finalizer.AuditFinalizeError(f"{context} is invalid")
    return value


def string(value, context):
    if type(value) is not str or not value:
        raise finalizer.AuditFinalizeError(f"{context} is invalid")
    return value


def digest(value, context, length=64):
    value = string(value, context)
    if len(value) != length or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise finalizer.AuditFinalizeError(f"{context} is invalid")
    return value


def validate_artifact_index(value, keys, context, expected_path):
    record = exact_object(value, keys, context)
    integer(record["bytes"], f"{context} bytes", minimum=1)
    integer(record["device"], f"{context} device")
    integer(record["inode"], f"{context} inode")
    if string(record["path"], f"{context} path") != str(expected_path):
        raise finalizer.AuditFinalizeError(f"{context} path is not canonical")
    digest(record["sha256"], f"{context} SHA-256")
    return record


opened = []
try:
    index = finalizer._open_artifact(path, "locked base audit index", run_root)
    opened.append(index)
    payload = json.loads(
        index.raw.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if finalizer._canonical_analysis_bytes(payload) != index.raw:
        raise finalizer.AuditFinalizeError("base audit is not canonical JSON")
    exact_object(payload, TOP_LEVEL_KEYS, "base audit")
    if payload["schema"] != "euf-viper.locked-p0-audit.v4":
        raise finalizer.AuditFinalizeError("base audit has an incompatible schema")
    if payload["status"] != "complete":
        raise finalizer.AuditFinalizeError("base audit is not complete")
    if payload["prepare_job_id"] != prepare_job_id:
        raise finalizer.AuditFinalizeError("base audit prepare job id mismatch")
    if payload["job_id"] != audit_job_id:
        raise finalizer.AuditFinalizeError("base audit job id mismatch")
    if payload["revision"] != revision:
        raise finalizer.AuditFinalizeError("base audit revision mismatch")
    digest(payload["revision"], "base audit revision", length=40)
    shard_count = integer(payload["shards"], "base audit shards", minimum=1)
    if string(payload["run_root"], "base audit run root") != str(run_root):
        raise finalizer.AuditFinalizeError(
            "base audit run root differs from the trusted run root"
        )
    digest(
        payload["submission_manifest_sha256"],
        "base audit submission manifest SHA-256",
    )

    attempt = exact_object(
        payload["attempt"], {"checkout", "id", "root"}, "base audit attempt"
    )
    for field in attempt:
        string(attempt[field], f"base audit attempt {field}")
    environment = payload["environment"]
    if type(environment) is not dict or not environment or any(
        type(key) is not str or not key or type(value) is not str
        for key, value in environment.items()
    ):
        raise finalizer.AuditFinalizeError(
            "base audit environment has an incompatible shape"
        )
    source = exact_object(
        payload["source"],
        {"blob_count", "blobs_sha256", "tree"},
        "base audit source",
    )
    integer(source["blob_count"], "base audit source blob count", minimum=1)
    digest(source["blobs_sha256"], "base audit source blobs SHA-256")
    digest(source["tree"], "base audit source tree", length=40)

    preparation = validate_artifact_index(
        payload["preparation_receipt"],
        PREPARATION_RECEIPT_KEYS,
        "base audit preparation receipt",
        run_root / "prepare.json",
    )
    scheduler = validate_artifact_index(
        payload["scheduler_receipt"],
        SCHEDULER_RECEIPT_KEYS,
        "base audit scheduler receipt",
        run_root / "audit" / "scheduler.json",
    )
    if preparation["job_id"] != prepare_job_id or preparation["revision"] != revision:
        raise finalizer.AuditFinalizeError(
            "base audit preparation receipt identity mismatch"
        )
    if preparation["status"] != "prepared":
        raise finalizer.AuditFinalizeError(
            "base audit preparation receipt status is invalid"
        )
    if scheduler["job_id"] != audit_job_id or scheduler["status"] != "bound":
        raise finalizer.AuditFinalizeError(
            "base audit scheduler receipt identity mismatch"
        )

    analysis_records = exact_object(
        payload["analyses"], {"full", "official"}, "base audit analyses"
    )
    validated_analyses = {}
    for kind, record_value in analysis_records.items():
        context = f"base audit {kind} analysis"
        record = validate_artifact_index(
            record_value,
            ANALYSIS_KEYS,
            context,
            run_root / "audit" / kind / "global.json",
        )
        for field in ("instances", "raw_records", "shards"):
            integer(record[field], f"{context} {field}", minimum=1)
        if record["shards"] != shard_count:
            raise finalizer.AuditFinalizeError(f"{context} shard count disagrees")
        if type(record["promoted"]) is not bool:
            raise finalizer.AuditFinalizeError(
                f"{context} promoted flag is invalid"
            )
        expected_status = "promoted" if record["promoted"] else "rejected"
        expected_exit = 0 if record["promoted"] else 1
        if (
            record["status"] != expected_status
            or record["validated_process_exit"] != expected_exit
        ):
            raise finalizer.AuditFinalizeError(f"{context} status is invalid")

        inputs = exact_object(
            record["input_artifacts"], INPUT_ARTIFACT_KEYS, f"{context} inputs"
        )
        parent = validate_artifact_index(
            inputs["parent_lock"],
            PARENT_LOCK_INDEX_KEYS,
            f"{context} parent lock",
            run_root / "locks" / f"{kind}-parent.json",
        )
        digest(parent["lock_sha256"], f"{context} parent lock self-hash")
        exact_object(
            parent["identity"],
            PARENT_IDENTITY_KEYS,
            f"{context} parent lock identity",
        )
        digest(inputs["shard_bundle_sha256"], f"{context} shard bundle SHA-256")
        shard_records = inputs["shards"]
        if type(shard_records) is not list or len(shard_records) != shard_count:
            raise finalizer.AuditFinalizeError(
                f"{context} inputs have an incompatible shard list"
            )
        for index_value, shard_value in enumerate(shard_records):
            shard_context = f"{context} shard {index_value}"
            shard = exact_object(shard_value, SHARD_INDEX_KEYS, shard_context)
            if shard["index"] != index_value:
                raise finalizer.AuditFinalizeError(
                    f"{shard_context} index is not contiguous"
                )
            integer(shard["raw_records"], f"{shard_context} raw records", minimum=1)
            cpu_ids = shard["cpu_ids"]
            if (
                type(cpu_ids) is not list
                or not cpu_ids
                or any(type(cpu_id) is not int or cpu_id < 0 for cpu_id in cpu_ids)
                or len(set(cpu_ids)) != len(cpu_ids)
            ):
                raise finalizer.AuditFinalizeError(
                    f"{shard_context} CPU ids are invalid"
                )
            suffix = f"{index_value:04d}"
            lock = validate_artifact_index(
                shard["lock"],
                SHARD_LOCK_INDEX_KEYS,
                f"{shard_context} lock",
                run_root / "locks" / kind / f"bound-{suffix}.json",
            )
            digest(lock["lock_sha256"], f"{shard_context} lock self-hash")
            validate_artifact_index(
                shard["raw"],
                ARTIFACT_KEYS,
                f"{shard_context} raw results",
                run_root / f"{kind}-2s" / f"shard-{suffix}" / "raw.jsonl",
            )
        validated_analyses[kind] = {
            "sha256": record["sha256"],
            "process_exit": record["validated_process_exit"],
        }

    live_analyses, current_inputs, audit_artifacts = finalizer._open_current_audit(
        run_root, shard_count, validated_analyses
    )
    opened.extend(audit_artifacts)
    for kind, analysis in live_analyses.items():
        value = analysis.value
        expected_record = {
            **finalizer._artifact_index(analysis),
            "input_artifacts": current_inputs[kind],
            "instances": value["inputs"]["instances"],
            "promoted": value["promoted"],
            "raw_records": value["inputs"]["raw_records"],
            "shards": len(value["inputs"]["shards"]),
            "status": value["status"],
            "validated_process_exit": validated_analyses[kind]["process_exit"],
        }
        if not finalizer._same_json(analysis_records[kind], expected_record):
            raise finalizer.AuditFinalizeError(
                f"base audit {kind} analysis or input binding drifted"
            )

    preparation_path = run_root / "prepare.json"
    preparation_preview = finalizer._open_artifact(
        preparation_path, "preparation receipt preview", run_root
    )
    opened.append(preparation_preview)
    preparation_value = finalizer._canonical_receipt_object(
        preparation_preview, finalizer.PREPARATION_KEYS
    )
    preparation_environment = preparation_value.get("environment")
    if type(preparation_environment) is not dict:
        raise finalizer.AuditFinalizeError(
            "preparation receipt environment is invalid"
        )
    shared_corpus = string(
        preparation_environment.get("EUF_VIPER_SHARED_CORPUS"),
        "preparation receipt shared corpus",
    )
    provenance = {
        "attempt": attempt,
        "environment": environment,
        "execution_environment": preparation_value["execution_environment"],
        "manifest_sha256": payload["submission_manifest_sha256"],
        "parameters": {
            "shared_corpus": shared_corpus,
            "shards": str(shard_count),
        },
        "revision": revision,
        "runtime_tools": preparation_value["runtime_tools"],
        "source_blob_count": source["blob_count"],
        "source_blobs_sha256": source["blobs_sha256"],
        "source_tree": source["tree"],
        "stage": "audit",
    }
    verified_preparation, preparation_artifacts = finalizer._verify_preparation_receipt(
        preparation_path,
        preparation["sha256"],
        provenance,
        run_root,
        prepare_job_id,
        shard_count,
        current_inputs,
    )
    opened.extend(preparation_artifacts)
    preparation_artifact = preparation_artifacts[0]
    if stat.S_IMODE(preparation_artifact.metadata.st_mode) != 0o400:
        raise finalizer.AuditFinalizeError("preparation receipt mode is not 0400")
    expected_preparation = {
        **finalizer._artifact_index(preparation_artifact),
        "job_id": verified_preparation["job"]["id"],
        "revision": verified_preparation["revision"],
        "status": verified_preparation["status"],
    }
    if not finalizer._same_json(preparation, expected_preparation):
        raise finalizer.AuditFinalizeError(
            "base audit preparation receipt binding drifted"
        )

    expected_scheduler_payload = finalizer._scheduler_payload(
        provenance,
        run_root,
        prepare_job_id,
        audit_job_id,
        shard_count,
        preparation_path,
        preparation["sha256"],
        validated_analyses,
        current_inputs,
    )
    scheduler_artifact = finalizer._verify_scheduler_receipt(
        run_root / "audit" / "scheduler.json",
        scheduler["sha256"],
        expected_scheduler_payload,
        run_root,
    )
    opened.append(scheduler_artifact)
    expected_scheduler = {
        **finalizer._artifact_index(scheduler_artifact),
        "job_id": audit_job_id,
        "status": "bound",
    }
    if not finalizer._same_json(scheduler, expected_scheduler):
        raise finalizer.AuditFinalizeError(
            "base audit scheduler receipt binding drifted"
        )

    finalizer._verify_opened_artifacts(opened)
except (
    finalizer.AuditFinalizeError,
    strict_artifacts.StrictArtifactError,
    json.JSONDecodeError,
    KeyError,
    OSError,
    TypeError,
    UnicodeError,
    ValueError,
) as error:
    raise SystemExit(f"base audit validation failed: {error}")
finally:
    for artifact in opened:
        os.close(artifact.descriptor)
PY

mkdir -p "$CHAIN_ROOT/submissions" "$CHAIN_ROOT/audit" "$CHAIN_ROOT/analysis"

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
