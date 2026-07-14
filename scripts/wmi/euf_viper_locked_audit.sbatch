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
SHARDS="${EUF_VIPER_LOCKED_SHARDS:?set EUF_VIPER_LOCKED_SHARDS}"
PROVENANCE_HELPER="$CHECKOUT/scripts/wmi/hermetic_provenance.py"

case "$PREPARE_JOB_ID" in *[!0-9]*|'') echo "invalid prepare job id" >&2; exit 2 ;; esac
case "$SHARDS" in ''|0|0*|*[!0-9]*) echo "invalid shard count" >&2; exit 2 ;; esac

hash_file() {
  local OUTPUT
  OUTPUT="$("$SHA256SUM_BIN" "$1")"
  printf '%s' "${OUTPUT%% *}"
}
if [ "$(hash_file "$PYTHON_BIN")" != "$PYTHON_SHA256" ] || \
   [ "$(hash_file "$PROVENANCE_HELPER")" != "$PROVENANCE_HELPER_SHA256" ] || \
   [ "$(hash_file "$SUBMISSION_MANIFEST")" != "$SUBMISSION_MANIFEST_SHA256" ]; then
  echo "receipt-bound audit bootstrap SHA-256 mismatch" >&2
  exit 2
fi

VERIFIED_PROVENANCE="$("$PYTHON_BIN" -B -I -S "$PROVENANCE_HELPER" verify \
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
if any("\t" in item or "\n" in item for item in fields): raise SystemExit("unsafe environment")
print("\t".join(fields))
' "$VERIFIED_PROVENANCE")"
IFS=$'\t' read -r PRIVATE_HOME RUNTIME_PATH RUSTUP_HOME CARGO_TARGET_DIR \
  PRIVATE_TMP XDG_CACHE_HOME XDG_CONFIG_HOME ENV_BIN MKDIR_BIN <<<"$EXECUTION_FIELDS"

clean_env() {
  "$ENV_BIN" -i HOME="$PRIVATE_HOME" LANG=C LC_ALL=C PATH="$RUNTIME_PATH" \
    RUSTUP_HOME="$RUSTUP_HOME" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    TMPDIR="$PRIVATE_TMP" TZ=UTC XDG_CACHE_HOME="$XDG_CACHE_HOME" \
    XDG_CONFIG_HOME="$XDG_CONFIG_HOME" "$@"
}
python_clean() {
  clean_env "$PYTHON_BIN" -B -I -S "$@"
}

cd "$CHECKOUT"
RUN_ROOT="$ATTEMPT_ROOT/results/p0-${PREPARE_JOB_ID}"
PREPARE_RECEIPT="$RUN_ROOT/prepare.json"
PREPARATION_BINDING="$(python_clean "$PROVENANCE_HELPER" verify-preparation-receipt \
  --receipt "$PREPARE_RECEIPT" \
  --provenance "$VERIFIED_PROVENANCE" \
  --run-root "$RUN_ROOT" \
  --prepare-job "$PREPARE_JOB_ID")"

for KIND in full official; do
  "$MKDIR_BIN" -p "$RUN_ROOT/audit/$KIND"
  for ((INDEX=0; INDEX<SHARDS; INDEX++)); do
    PADDED="$(printf '%04d' "$INDEX")"
    test -s "$RUN_ROOT/locks/$KIND/bound-$PADDED.json"
    test -s "$RUN_ROOT/$KIND-2s/shard-$PADDED/raw.jsonl"
    test -s "$RUN_ROOT/$KIND-2s/shard-$PADDED/summary.json"
  done
  if python_clean scripts/bench/analyze_campaign.py \
      --parent-lock "$RUN_ROOT/locks/$KIND-parent.json" \
      --shard-lock-dir "$RUN_ROOT/locks/$KIND" \
      --shard-results-root "$RUN_ROOT/$KIND-2s" \
      --bootstrap-replicates 10000 \
      --confidence-level 0.95 \
      --out "$RUN_ROOT/audit/$KIND/global.json"; then
    :
  else
    STATUS=$?
    if [ "$STATUS" -ne 1 ]; then
      exit "$STATUS"
    fi
  fi
done

FINAL_PROVENANCE="$("$PYTHON_BIN" -B -I -S "$PROVENANCE_HELPER" verify \
  --manifest "$SUBMISSION_MANIFEST" \
  --expected-sha256 "$SUBMISSION_MANIFEST_SHA256" \
  --stage audit)"
if [ "$FINAL_PROVENANCE" != "$VERIFIED_PROVENANCE" ]; then
  echo "provenance changed during final audit" >&2
  exit 2
fi

python_clean - "$RUN_ROOT/audit/index.json" "$VERIFIED_PROVENANCE" \
  "$RUN_ROOT" "$PREPARE_JOB_ID" "$SHARDS" "$SLURM_JOB_ID" \
  "$PREPARATION_BINDING" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

(
    raw_out, raw_provenance, raw_run_root, prepare_job, shards, audit_job,
    raw_preparation_binding,
) = sys.argv[1:]
out = Path(raw_out)
run_root = Path(raw_run_root).resolve(strict=True)
provenance = json.loads(raw_provenance)
payload = {
    "schema": "euf-viper.locked-p0-audit.v2",
    "status": "complete",
    "attempt": provenance["attempt"],
    "analyses": {},
    "environment": provenance["environment"],
    "job_id": int(audit_job),
    "prepare_job_id": int(prepare_job),
    "preparation_receipt": json.loads(raw_preparation_binding),
    "revision": provenance["revision"],
    "run_root": str(run_root),
    "shards": int(shards),
    "source": {
        "blob_count": provenance["source_blob_count"],
        "blobs_sha256": provenance["source_blobs_sha256"],
        "tree": provenance["source_tree"],
    },
    "submission_manifest_sha256": provenance["manifest_sha256"],
}
for kind in ("full", "official"):
    path = run_root / "audit" / kind / "global.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    payload["analyses"][kind] = {
        "instances": data.get("inputs", {}).get("instances"),
        "path": str(path.resolve(strict=True)),
        "promoted": data.get("promoted"),
        "raw_records": data.get("inputs", {}).get("raw_records"),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "shards": len(data.get("inputs", {}).get("shards", [])),
        "status": data.get("status"),
    }
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(descriptor, "wb", closefd=False) as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
finally:
    os.close(descriptor)
directory = os.open(out.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY

printf 'audit=%s\n' "$RUN_ROOT/audit/index.json"
