#!/bin/bash
#SBATCH --job-name=euf-p0-audit
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=/dev/null
#SBATCH --error=/dev/null

set -euo pipefail
umask 077

ATTEMPT_ID="${EUF_VIPER_ATTEMPT_ID:?set EUF_VIPER_ATTEMPT_ID}"
ATTEMPT_ROOT="${EUF_VIPER_ATTEMPT_ROOT:?set EUF_VIPER_ATTEMPT_ROOT}"
CHECKOUT="${EUF_VIPER_CHECKOUT:?set EUF_VIPER_CHECKOUT}"
EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
PYTHON_BIN="${EUF_VIPER_PYTHON:?set EUF_VIPER_PYTHON}"
PYTHON_SHA256="${EUF_VIPER_PYTHON_SHA256:?set EUF_VIPER_PYTHON_SHA256}"
SHA256SUM_BIN="${EUF_VIPER_SHA256SUM:?set EUF_VIPER_SHA256SUM}"
PROVENANCE_HELPER_SHA256="${EUF_VIPER_PROVENANCE_HELPER_SHA256:?set EUF_VIPER_PROVENANCE_HELPER_SHA256}"
SUBMISSION_MANIFEST="${EUF_VIPER_SUBMISSION_MANIFEST:?set EUF_VIPER_SUBMISSION_MANIFEST}"
SUBMISSION_MANIFEST_SHA256="${EUF_VIPER_SUBMISSION_MANIFEST_SHA256:?set EUF_VIPER_SUBMISSION_MANIFEST_SHA256}"
PREPARE_JOB_ID="${EUF_VIPER_PREPARE_JOB_ID:?set EUF_VIPER_PREPARE_JOB_ID}"
PREPARE_RECEIPT_SHA256="${EUF_VIPER_PREPARE_RECEIPT_SHA256:?set EUF_VIPER_PREPARE_RECEIPT_SHA256}"
SHARDS="${EUF_VIPER_LOCKED_SHARDS:?set EUF_VIPER_LOCKED_SHARDS}"
PROVENANCE_HELPER="$CHECKOUT/scripts/wmi/hermetic_provenance.py"
EXECUTION_CLOSURE_HELPER="$CHECKOUT/scripts/wmi/execution_closure.py"

case "$PREPARE_JOB_ID" in *[!0-9]*|'') echo "invalid prepare job id" >&2; exit 2 ;; esac
case "$PREPARE_RECEIPT_SHA256" in
  *[!0-9a-f]*|'') echo "invalid prepare receipt SHA-256" >&2; exit 2 ;;
esac
if [ "${#PREPARE_RECEIPT_SHA256}" -ne 64 ]; then
  echo "invalid prepare receipt SHA-256 length" >&2
  exit 2
fi
case "$SHARDS" in ''|0|0*|*[!0-9]*) echo "invalid shard count" >&2; exit 2 ;; esac

hash_file() {
  local OUTPUT
  OUTPUT="$("$SHA256SUM_BIN" "$1")"
  printf '%s' "${OUTPUT%% *}"
}

BOUND_PYTHON_CODE='import fcntl, hashlib, os, stat, sys
path, expected, python_expected, *arguments = sys.argv[1:]
python_descriptor = os.dup(9)
try:
    python_before = os.fstat(python_descriptor)
    python_chunks = []
    while True:
        block = os.read(python_descriptor, 1024 * 1024)
        if not block:
            break
        python_chunks.append(block)
    python_after = os.fstat(python_descriptor)
finally:
    os.close(python_descriptor)
python_identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
if python_identity(python_before) != python_identity(python_after) or hashlib.sha256(b"".join(python_chunks)).hexdigest() != python_expected:
    raise SystemExit("bound Python executable descriptor mismatch")
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    before = os.fstat(descriptor)
    chunks = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
raw = b"".join(chunks)
identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
if not stat.S_ISREG(after.st_mode) or identity(before) != identity(after) or len(raw) != after.st_size:
    raise SystemExit("bound Python helper changed while read")
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit("bound Python helper SHA-256 mismatch")
sealed = os.memfd_create("euf-viper-bound-helper", os.MFD_ALLOW_SEALING)
offset = 0
while offset < len(raw):
    written = os.write(sealed, raw[offset:])
    if written <= 0:
        raise SystemExit("short bound Python helper write")
    offset += written
os.fchmod(sealed, 0o400)
fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
os.lseek(sealed, 0, os.SEEK_SET)
sealed_chunks = []
while True:
    block = os.read(sealed, 1024 * 1024)
    if not block:
        break
    sealed_chunks.append(block)
if hashlib.sha256(b"".join(sealed_chunks)).hexdigest() != expected:
    raise SystemExit("sealed Python helper SHA-256 mismatch")
helper = f"/proc/self/fd/{sealed}"
sys.argv = [helper, *arguments]
scope = {"__name__": "__main__", "__file__": helper, "__package__": None, "__cached__": None}
exec(compile(raw, helper, "exec"), scope, scope)'

python_bound_bootstrap() {
  local SCRIPT="$1" EXPECTED="$2"
  shift 2
  (
    exec 9<"$PYTHON_BIN"
    if [ "$(hash_file /proc/self/fd/9)" != "$PYTHON_SHA256" ]; then
      echo "bound Python descriptor SHA-256 mismatch" >&2
      exit 2
    fi
    /proc/self/fd/9 -B -I -S -c "$BOUND_PYTHON_CODE" \
      "$SCRIPT" "$EXPECTED" "$PYTHON_SHA256" "$@"
  )
}
if [ "$(hash_file "$PYTHON_BIN")" != "$PYTHON_SHA256" ] || \
   [ "$(hash_file "$PROVENANCE_HELPER")" != "$PROVENANCE_HELPER_SHA256" ] || \
   [ "$(hash_file "$SUBMISSION_MANIFEST")" != "$SUBMISSION_MANIFEST_SHA256" ]; then
  echo "receipt-bound audit bootstrap SHA-256 mismatch" >&2
  exit 2
fi

VERIFIED_PROVENANCE="$(python_bound_bootstrap "$PROVENANCE_HELPER" \
  "$PROVENANCE_HELPER_SHA256" verify \
  --manifest "$SUBMISSION_MANIFEST" \
  --expected-sha256 "$SUBMISSION_MANIFEST_SHA256" \
  --stage audit)"
EXECUTION_FIELDS="$("$PYTHON_BIN" -B -I -S -c '
import json, sys
value = json.loads(sys.argv[1]); environment = value["execution_environment"]
fields = [environment[name] for name in (
    "HOME", "PATH", "RUSTUP_HOME", "CARGO_TARGET_DIR", "TMPDIR",
    "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
)]
fields.append(value["runtime_tools"]["env"]["realpath"])
fields.append(value["runtime_tools"]["mkdir"]["realpath"])
fields.append(value["execution_closure_helper_sha256"])
if any("\t" in item or "\n" in item for item in fields): raise SystemExit("unsafe environment")
print("\t".join(fields))
' "$VERIFIED_PROVENANCE")"
IFS=$'\t' read -r PRIVATE_HOME RUNTIME_PATH RUSTUP_HOME CARGO_TARGET_DIR \
  PRIVATE_TMP XDG_CACHE_HOME XDG_CONFIG_HOME ENV_BIN MKDIR_BIN \
  EXECUTION_CLOSURE_HELPER_SHA256 <<<"$EXECUTION_FIELDS"

if [ "$(hash_file "$EXECUTION_CLOSURE_HELPER")" != "$EXECUTION_CLOSURE_HELPER_SHA256" ]; then
  echo "receipt-bound execution-closure helper SHA-256 mismatch" >&2
  exit 2
fi

clean_env() {
  local RECEIPT_ENV=()
  if [ -n "${SEALED_BUILD_RECEIPT:-}" ]; then
    RECEIPT_ENV=("EUF_VIPER_SEALED_BUILD_RECEIPT=$SEALED_BUILD_RECEIPT")
  fi
  "$ENV_BIN" -i HOME="$PRIVATE_HOME" LANG=C LC_ALL=C PATH="$RUNTIME_PATH" \
    RUSTUP_HOME="$RUSTUP_HOME" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    TMPDIR="$PRIVATE_TMP" TZ=UTC XDG_CACHE_HOME="$XDG_CACHE_HOME" \
    XDG_CONFIG_HOME="$XDG_CONFIG_HOME" EUF_VIPER_DESCRIPTOR_EXECUTION=required \
    "${RECEIPT_ENV[@]}" "$@"
}
python_clean() {
  clean_env "$PYTHON_BIN" -B -I -S "$@"
}
python_bound() {
  local SCRIPT="$1" EXPECTED="$2"
  shift 2
  (
    exec 9<"$PYTHON_BIN"
    if [ "$(hash_file /proc/self/fd/9)" != "$PYTHON_SHA256" ]; then
      echo "bound Python descriptor SHA-256 mismatch" >&2
      exit 2
    fi
    clean_env /proc/self/fd/9 -B -I -S -c "$BOUND_PYTHON_CODE" \
      "$SCRIPT" "$EXPECTED" "$PYTHON_SHA256" "$@"
  )
}

cd "$CHECKOUT"
RUN_ROOT="$ATTEMPT_ROOT/results/p0-${PREPARE_JOB_ID}"
PREPARE_RECEIPT="$RUN_ROOT/prepare.json"
python_bound "$PROVENANCE_HELPER" \
  "$PROVENANCE_HELPER_SHA256" verify-preparation-receipt \
  --receipt "$PREPARE_RECEIPT" \
  --provenance "$VERIFIED_PROVENANCE" \
  --run-root "$RUN_ROOT" \
  --prepare-job "$PREPARE_JOB_ID" \
  --expected-sha256 "$PREPARE_RECEIPT_SHA256" \
  >/dev/null

EXECUTION_CLOSURE_FIELDS="$(python_clean -c '
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
closure = value["execution_closure"]
print(closure["path"] + "\t" + closure["sha256"])
' "$PREPARE_RECEIPT")"
IFS=$'\t' read -r EXECUTION_CLOSURE_MANIFEST EXECUTION_CLOSURE_SHA256 \
  <<<"$EXECUTION_CLOSURE_FIELDS"
RUNTIME_DATA_FIELDS="$(python_clean -c '
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
print(value["corpus"]["root"] + "\t" + value["sealed_build"]["receipt_path"])
' "$PREPARE_RECEIPT")"
IFS=$'\t' read -r CORPUS_ROOT SEALED_BUILD_RECEIPT <<<"$RUNTIME_DATA_FIELDS"
python_bound "$EXECUTION_CLOSURE_HELPER" "$EXECUTION_CLOSURE_HELPER_SHA256" verify \
  --manifest "$EXECUTION_CLOSURE_MANIFEST" \
  --expected-sha256 "$EXECUTION_CLOSURE_SHA256" \
  >"$RUN_ROOT/execution-closure-audit.json"
RUNTIME_STAGING="$RUN_ROOT/runtime-closure-staging-audit"
python_clean -c 'from pathlib import Path; import sys; Path(sys.argv[1]).mkdir(mode=0o700, exist_ok=True)' \
  "$RUNTIME_STAGING"

closed_python() {
  python_bound "$EXECUTION_CLOSURE_HELPER" "$EXECUTION_CLOSURE_HELPER_SHA256" launch \
    --manifest "$EXECUTION_CLOSURE_MANIFEST" \
    --expected-sha256 "$EXECUTION_CLOSURE_SHA256" \
    --staging-root "$RUNTIME_STAGING" \
    --cwd "$CHECKOUT" \
    --read-only-root "$CORPUS_ROOT" \
    --writable-root "$RUN_ROOT" \
    -- "$PYTHON_BIN" -B -I -S "$@"
}

FULL_ANALYSIS_SHA256=""
FULL_ANALYSIS_EXIT=""
OFFICIAL_ANALYSIS_SHA256=""
OFFICIAL_ANALYSIS_EXIT=""
for KIND in full official; do
  "$MKDIR_BIN" -p "$RUN_ROOT/audit/$KIND"
  ANALYSIS_OUTPUT="$RUN_ROOT/audit/$KIND/global.json"
  if [ -e "$ANALYSIS_OUTPUT" ] || [ -L "$ANALYSIS_OUTPUT" ]; then
    printf '%s analysis output already exists; refusing stale evidence\n' \
      "$KIND" >&2
    exit 2
  fi
  for ((INDEX=0; INDEX<SHARDS; INDEX++)); do
    PADDED="$(printf '%04d' "$INDEX")"
    test -s "$RUN_ROOT/locks/$KIND/bound-$PADDED.json"
    test -s "$RUN_ROOT/$KIND-2s/shard-$PADDED/raw.jsonl"
    test -s "$RUN_ROOT/$KIND-2s/shard-$PADDED/summary.json"
  done
  if closed_python "$CHECKOUT/scripts/bench/analyze_campaign.py" \
      --parent-lock "$RUN_ROOT/locks/$KIND-parent.json" \
      --shard-lock-dir "$RUN_ROOT/locks/$KIND" \
      --shard-results-root "$RUN_ROOT/$KIND-2s" \
      --bootstrap-replicates 10000 \
      --confidence-level 0.95 \
      --out "$ANALYSIS_OUTPUT"; then
    ANALYSIS_STATUS=0
  else
    ANALYSIS_STATUS=$?
  fi
  case "$ANALYSIS_STATUS" in
    0) ;;
    1)
      printf '%s analysis completed with statistical rejection\n' "$KIND" >&2
      ;;
    2)
      printf '%s analysis rejected its lock/raw input\n' "$KIND" >&2
      exit 2
      ;;
    3)
      printf '%s analysis could not publish its output\n' "$KIND" >&2
      exit 3
      ;;
    4)
      printf '%s analysis failed internally\n' "$KIND" >&2
      exit 4
      ;;
    *)
      printf '%s analysis returned unexpected status %s\n' \
        "$KIND" "$ANALYSIS_STATUS" >&2
      exit "$ANALYSIS_STATUS"
      ;;
  esac
  VALIDATION_JSON="$(closed_python \
    "$CHECKOUT/scripts/wmi/finalize_locked_audit.py" \
    --run-root "$RUN_ROOT" \
    --shards "$SHARDS" \
    --validate-analysis "$KIND" \
    --expected-analysis-exit "$ANALYSIS_STATUS")"
  VALIDATED_SHA256="$(python_clean -c '
import json, sys
value = json.loads(sys.argv[1])
kind, expected_exit = sys.argv[2], int(sys.argv[3])
if (
    value.get("schema") != "euf-viper.locked-analysis-validation.v1"
    or value.get("kind") != kind
    or value.get("expected_analysis_exit") != expected_exit
    or value.get("promoted") is not (expected_exit == 0)
):
    raise SystemExit("analysis validation receipt fields disagree")
digest = value.get("analysis_sha256")
if not isinstance(digest, str) or len(digest) != 64 or any(
    character not in "0123456789abcdef" for character in digest
):
    raise SystemExit("analysis validation receipt hash is malformed")
print(digest)
' "$VALIDATION_JSON" "$KIND" "$ANALYSIS_STATUS")"
  case "$KIND" in
    full)
      FULL_ANALYSIS_SHA256="$VALIDATED_SHA256"
      FULL_ANALYSIS_EXIT="$ANALYSIS_STATUS"
      ;;
    official)
      OFFICIAL_ANALYSIS_SHA256="$VALIDATED_SHA256"
      OFFICIAL_ANALYSIS_EXIT="$ANALYSIS_STATUS"
      ;;
  esac
done

SCHEDULER_RECEIPT="$RUN_ROOT/audit/scheduler.json"
closed_python "$CHECKOUT/scripts/wmi/finalize_locked_audit.py" \
  --write-scheduler-receipt \
  --out "$SCHEDULER_RECEIPT" \
  --provenance "$VERIFIED_PROVENANCE" \
  --run-root "$RUN_ROOT" \
  --prepare-job "$PREPARE_JOB_ID" \
  --shards "$SHARDS" \
  --audit-job "$SLURM_JOB_ID" \
  --preparation-receipt "$PREPARE_RECEIPT" \
  --preparation-receipt-sha256 "$PREPARE_RECEIPT_SHA256" \
  --full-analysis-sha256 "$FULL_ANALYSIS_SHA256" \
  --full-analysis-exit "$FULL_ANALYSIS_EXIT" \
  --official-analysis-sha256 "$OFFICIAL_ANALYSIS_SHA256" \
  --official-analysis-exit "$OFFICIAL_ANALYSIS_EXIT" \
  >/dev/null
SCHEDULER_RECEIPT_SHA256="$(hash_file "$SCHEDULER_RECEIPT")"

FINAL_PROVENANCE="$(python_bound_bootstrap "$PROVENANCE_HELPER" \
  "$PROVENANCE_HELPER_SHA256" verify \
  --manifest "$SUBMISSION_MANIFEST" \
  --expected-sha256 "$SUBMISSION_MANIFEST_SHA256" \
  --stage audit)"
if [ "$FINAL_PROVENANCE" != "$VERIFIED_PROVENANCE" ]; then
  echo "provenance changed during final audit" >&2
  exit 2
fi

closed_python "$CHECKOUT/scripts/wmi/finalize_locked_audit.py" \
  --out "$RUN_ROOT/audit/index.json" \
  --provenance "$VERIFIED_PROVENANCE" \
  --run-root "$RUN_ROOT" \
  --prepare-job "$PREPARE_JOB_ID" \
  --shards "$SHARDS" \
  --audit-job "$SLURM_JOB_ID" \
  --preparation-receipt "$PREPARE_RECEIPT" \
  --preparation-receipt-sha256 "$PREPARE_RECEIPT_SHA256" \
  --scheduler-receipt "$SCHEDULER_RECEIPT" \
  --scheduler-receipt-sha256 "$SCHEDULER_RECEIPT_SHA256" \
  --full-analysis-sha256 "$FULL_ANALYSIS_SHA256" \
  --full-analysis-exit "$FULL_ANALYSIS_EXIT" \
  --official-analysis-sha256 "$OFFICIAL_ANALYSIS_SHA256" \
  --official-analysis-exit "$OFFICIAL_ANALYSIS_EXIT"

printf 'audit=%s\n' "$RUN_ROOT/audit/index.json"
