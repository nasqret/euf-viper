#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREPARE_SUBMISSION_RECEIPT="${1:?usage: submit_locked_p0_dependents.sh PREPARE-SUBMISSION-RECEIPT PREPARE-RECEIPT-SHA256}"
PREPARE_RECEIPT_SHA256="${2:?usage: submit_locked_p0_dependents.sh PREPARE-SUBMISSION-RECEIPT PREPARE-RECEIPT-SHA256}"

case "$PREPARE_RECEIPT_SHA256" in
  *[!0-9a-f]*|'') echo "prepare receipt SHA-256 must be lowercase hexadecimal" >&2; exit 2 ;;
esac
if [ "${#PREPARE_RECEIPT_SHA256}" -ne 64 ]; then
  echo "prepare receipt SHA-256 must contain exactly 64 digits" >&2
  exit 2
fi

cd "$ROOT"
python3 -B -I -S scripts/wmi/hermetic_provenance.py audit-submit-environment >/dev/null

FIELDS="$(python3 -B -I -S - "$PREPARE_SUBMISSION_RECEIPT" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]).resolve(strict=True)
raw = path.read_bytes()
value = json.loads(raw)
canonical = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
if raw != canonical:
    raise SystemExit("prepare submission receipt is not canonical JSON")
if value.get("schema") != "euf-viper.locked-p0-prepare-submission.v3":
    raise SystemExit("prepare submission receipt schema mismatch")
if value.get("status") != "prepare_submitted":
    raise SystemExit("prepare submission is not awaiting external receipt capture")
provenance = value["provenance"]
tools = provenance["runtime_tools"]
attempt = provenance["attempt"]
fields = [
    str(path), hashlib.sha256(raw).hexdigest(), value["remote_host"],
    attempt["id"], attempt["root"], attempt["checkout"], provenance["manifest"],
    provenance["manifest_sha256"], tools["python"]["path"],
    tools["python"]["sha256"], tools["sbatch"]["path"],
    tools["sha256sum"]["path"], provenance["provenance_helper_sha256"],
    value["revision"], str(value["shards"]), str(value["max_active"]),
    value["prepare_job"], value["prepare_receipt"], value["shared_corpus"],
]
if any("\t" in item or "\n" in item or "," in item for item in fields):
    raise SystemExit("prepare submission receipt contains an unsafe field")
print("\t".join(fields))
PY
)"
IFS=$'\t' read -r PREPARE_RECEIPT_PATH PREPARE_SUBMISSION_SHA256 REMOTE_HOST \
  ATTEMPT_ID ATTEMPT_ROOT CHECKOUT SUBMISSION_MANIFEST SUBMISSION_MANIFEST_SHA256 \
  PYTHON_BIN PYTHON_SHA256 SBATCH_BIN SHA256SUM_BIN PROVENANCE_HELPER_SHA256 \
  REVISION SHARDS MAX_ACTIVE PREPARE_JOB REMOTE_PREPARE_RECEIPT SHARED_CORPUS \
  <<<"$FIELDS"

case "$SHARDS" in ''|0|0*|*[!0-9]*) echo "invalid frozen shard count" >&2; exit 2 ;; esac
case "$MAX_ACTIVE" in ''|0|0*|*[!0-9]*) echo "invalid frozen max-active count" >&2; exit 2 ;; esac
case "$PREPARE_JOB" in ''|*[!0-9]*) echo "invalid prepare job identity" >&2; exit 2 ;; esac

COMMON_EXPORTS="EUF_VIPER_ATTEMPT_ID=$ATTEMPT_ID,EUF_VIPER_ATTEMPT_ROOT=$ATTEMPT_ROOT,EUF_VIPER_CHECKOUT=$CHECKOUT,EUF_VIPER_EXPECTED_REVISION=$REVISION,EUF_VIPER_PYTHON=$PYTHON_BIN,EUF_VIPER_PYTHON_SHA256=$PYTHON_SHA256,EUF_VIPER_PROVENANCE_HELPER_SHA256=$PROVENANCE_HELPER_SHA256,EUF_VIPER_SHA256SUM=$SHA256SUM_BIN,EUF_VIPER_SUBMISSION_MANIFEST=$SUBMISSION_MANIFEST,EUF_VIPER_SUBMISSION_MANIFEST_SHA256=$SUBMISSION_MANIFEST_SHA256"

for VALUE in "$ATTEMPT_ROOT" "$CHECKOUT" "$SUBMISSION_MANIFEST" \
  "$PYTHON_BIN" "$SBATCH_BIN" "$SHA256SUM_BIN" "$REMOTE_PREPARE_RECEIPT"; do
  case "$VALUE" in
    *','*|*$'\n'*|*$'\t'*) echo "receipt-bound path is not export-safe" >&2; exit 2 ;;
  esac
done

printf -v Q_ATTEMPT_ID '%q' "$ATTEMPT_ID"
printf -v Q_ATTEMPT_ROOT '%q' "$ATTEMPT_ROOT"
printf -v Q_CHECKOUT '%q' "$CHECKOUT"
printf -v Q_REVISION '%q' "$REVISION"
printf -v Q_PYTHON_BIN '%q' "$PYTHON_BIN"
printf -v Q_PYTHON_SHA256 '%q' "$PYTHON_SHA256"
printf -v Q_SHA256SUM_BIN '%q' "$SHA256SUM_BIN"
printf -v Q_HELPER_SHA256 '%q' "$PROVENANCE_HELPER_SHA256"
printf -v Q_MANIFEST '%q' "$SUBMISSION_MANIFEST"
printf -v Q_MANIFEST_SHA256 '%q' "$SUBMISSION_MANIFEST_SHA256"
printf -v Q_PREPARE_JOB '%q' "$PREPARE_JOB"
printf -v Q_PREPARE_RECEIPT '%q' "$REMOTE_PREPARE_RECEIPT"
printf -v Q_PREPARE_SHA256 '%q' "$PREPARE_RECEIPT_SHA256"

# This is the external orchestration boundary: dependents are not submitted until
# the caller supplies the digest and the remote receipt is accepted under it.
REMOTE_BINDING="$(ssh "$REMOTE_HOST" "/bin/bash -s -- $Q_ATTEMPT_ID $Q_ATTEMPT_ROOT $Q_CHECKOUT $Q_REVISION $Q_PYTHON_BIN $Q_PYTHON_SHA256 $Q_SHA256SUM_BIN $Q_HELPER_SHA256 $Q_MANIFEST $Q_MANIFEST_SHA256 $Q_PREPARE_JOB $Q_PREPARE_RECEIPT $Q_PREPARE_SHA256" <<'REMOTE_VERIFY'
set -euo pipefail
ATTEMPT_ID="$1"
ATTEMPT_ROOT="$2"
CHECKOUT="$3"
REVISION="$4"
PYTHON_BIN="$5"
PYTHON_SHA256="$6"
SHA256SUM_BIN="$7"
HELPER_SHA256="$8"
MANIFEST="$9"
MANIFEST_SHA256="${10}"
PREPARE_JOB="${11}"
PREPARE_RECEIPT="${12}"
PREPARE_SHA256="${13}"
HELPER="$CHECKOUT/scripts/wmi/hermetic_provenance.py"

hash_file() {
  local output
  output="$("$SHA256SUM_BIN" "$1")"
  printf '%s' "${output%% *}"
}
if [ "$(hash_file "$PYTHON_BIN")" != "$PYTHON_SHA256" ] || \
   [ "$(hash_file "$HELPER")" != "$HELPER_SHA256" ] || \
   [ "$(hash_file "$MANIFEST")" != "$MANIFEST_SHA256" ] || \
   [ "$(hash_file "$PREPARE_RECEIPT")" != "$PREPARE_SHA256" ]; then
  echo "external preparation binding changed before dependent submission" >&2
  exit 2
fi

export EUF_VIPER_ATTEMPT_ID="$ATTEMPT_ID"
export EUF_VIPER_ATTEMPT_ROOT="$ATTEMPT_ROOT"
export EUF_VIPER_CHECKOUT="$CHECKOUT"
export EUF_VIPER_EXPECTED_REVISION="$REVISION"
export EUF_VIPER_PYTHON="$PYTHON_BIN"
export EUF_VIPER_PYTHON_SHA256="$PYTHON_SHA256"
export EUF_VIPER_PROVENANCE_HELPER_SHA256="$HELPER_SHA256"
export EUF_VIPER_SHA256SUM="$SHA256SUM_BIN"
export EUF_VIPER_SUBMISSION_MANIFEST="$MANIFEST"
export EUF_VIPER_SUBMISSION_MANIFEST_SHA256="$MANIFEST_SHA256"
export EUF_VIPER_PREPARE_JOB_ID="$PREPARE_JOB"
export EUF_VIPER_PREPARE_RECEIPT_SHA256="$PREPARE_SHA256"
export EUF_VIPER_CORPUS_KIND=full

PROVENANCE="$("$PYTHON_BIN" -B -I -S "$HELPER" verify \
  --manifest "$MANIFEST" --expected-sha256 "$MANIFEST_SHA256" --stage shard)"
"$PYTHON_BIN" -B -I -S "$HELPER" verify-preparation-receipt \
  --receipt "$PREPARE_RECEIPT" \
  --expected-sha256 "$PREPARE_SHA256" \
  --provenance "$PROVENANCE" \
  --run-root "$ATTEMPT_ROOT/results/p0-$PREPARE_JOB" \
  --prepare-job "$PREPARE_JOB"
REMOTE_VERIFY
)"
if [ "$(python3 -B -I -S -c 'import json,sys; print(json.loads(sys.argv[1])["receipt_sha256"])' "$REMOTE_BINDING")" != "$PREPARE_RECEIPT_SHA256" ]; then
  echo "remote preparation verifier returned a different receipt digest" >&2
  exit 2
fi

FULL_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_PREPARE_JOB_ID=$PREPARE_JOB,EUF_VIPER_PREPARE_RECEIPT_SHA256=$PREPARE_RECEIPT_SHA256,EUF_VIPER_CORPUS_KIND=full"
OFFICIAL_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_PREPARE_JOB_ID=$PREPARE_JOB,EUF_VIPER_PREPARE_RECEIPT_SHA256=$PREPARE_RECEIPT_SHA256,EUF_VIPER_CORPUS_KIND=official"
AUDIT_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_PREPARE_JOB_ID=$PREPARE_JOB,EUF_VIPER_PREPARE_RECEIPT_SHA256=$PREPARE_RECEIPT_SHA256,EUF_VIPER_LOCKED_SHARDS=$SHARDS"

printf -v Q_CHECKOUT '%q' "$CHECKOUT"
printf -v Q_SBATCH '%q' "$SBATCH_BIN"
printf -v Q_FULL_EXPORTS '%q' "$FULL_EXPORTS"
printf -v Q_OFFICIAL_EXPORTS '%q' "$OFFICIAL_EXPORTS"
printf -v Q_AUDIT_EXPORTS '%q' "$AUDIT_EXPORTS"
printf -v Q_FULL_STDOUT '%q' "$ATTEMPT_ROOT/logs/full-%A_%a.out"
printf -v Q_FULL_STDERR '%q' "$ATTEMPT_ROOT/logs/full-%A_%a.err"
printf -v Q_OFFICIAL_STDOUT '%q' "$ATTEMPT_ROOT/logs/official-%A_%a.out"
printf -v Q_OFFICIAL_STDERR '%q' "$ATTEMPT_ROOT/logs/official-%A_%a.err"
printf -v Q_AUDIT_STDOUT '%q' "$ATTEMPT_ROOT/logs/audit-%j.out"
printf -v Q_AUDIT_STDERR '%q' "$ATTEMPT_ROOT/logs/audit-%j.err"

FULL_SUBMISSION="$(ssh "$REMOTE_HOST" "cd $Q_CHECKOUT && $Q_SBATCH --parsable --kill-on-invalid-dep=yes --array=0-$((SHARDS - 1))%$MAX_ACTIVE --chdir=$Q_CHECKOUT --output=$Q_FULL_STDOUT --error=$Q_FULL_STDERR --export=$Q_FULL_EXPORTS scripts/wmi/euf_viper_locked_shard.sbatch")"
FULL_JOB="${FULL_SUBMISSION%%;*}"
case "$FULL_JOB" in *[!0-9]*|'') echo "invalid full array job id: $FULL_SUBMISSION" >&2; exit 2 ;; esac

OFFICIAL_SUBMISSION="$(ssh "$REMOTE_HOST" "cd $Q_CHECKOUT && $Q_SBATCH --parsable --kill-on-invalid-dep=yes --array=0-$((SHARDS - 1))%$MAX_ACTIVE --chdir=$Q_CHECKOUT --output=$Q_OFFICIAL_STDOUT --error=$Q_OFFICIAL_STDERR --export=$Q_OFFICIAL_EXPORTS scripts/wmi/euf_viper_locked_shard.sbatch")"
OFFICIAL_JOB="${OFFICIAL_SUBMISSION%%;*}"
case "$OFFICIAL_JOB" in *[!0-9]*|'') echo "invalid official array job id: $OFFICIAL_SUBMISSION" >&2; exit 2 ;; esac

AUDIT_SUBMISSION="$(ssh "$REMOTE_HOST" "cd $Q_CHECKOUT && $Q_SBATCH --parsable --kill-on-invalid-dep=yes --dependency=afterok:$FULL_JOB:$OFFICIAL_JOB --chdir=$Q_CHECKOUT --output=$Q_AUDIT_STDOUT --error=$Q_AUDIT_STDERR --export=$Q_AUDIT_EXPORTS scripts/wmi/euf_viper_locked_audit.sbatch")"
AUDIT_JOB="${AUDIT_SUBMISSION%%;*}"
case "$AUDIT_JOB" in *[!0-9]*|'') echo "invalid audit job id: $AUDIT_SUBMISSION" >&2; exit 2 ;; esac

RECEIPT="$ROOT/results/locked-p0-dependents-$ATTEMPT_ID.json"
python3 -B -I -S - "$RECEIPT" "$PREPARE_RECEIPT_PATH" \
  "$PREPARE_SUBMISSION_SHA256" "$PREPARE_RECEIPT_SHA256" "$REMOTE_BINDING" \
  "$FULL_EXPORTS" "$OFFICIAL_EXPORTS" "$AUDIT_EXPORTS" \
  "$FULL_JOB" "$OFFICIAL_JOB" "$AUDIT_JOB" <<'PY'
import json
import os
import sys
from pathlib import Path

(
    raw_out, prepare_submission, prepare_submission_sha256,
    prepare_receipt_sha256, raw_binding, full_exports, official_exports,
    audit_exports, full_job, official_job, audit_job,
) = sys.argv[1:]
path = Path(raw_out)

def exports(raw):
    result = {}
    for item in raw.split(","):
        name, separator, value = item.partition("=")
        if not separator or name in result:
            raise SystemExit("invalid dependent export binding")
        result[name] = value
    return dict(sorted(result.items()))

payload = {
    "schema": "euf-viper.locked-p0-dependent-submission.v3",
    "status": "submitted",
    "prepare_submission": {
        "path": str(Path(prepare_submission).resolve(strict=True)),
        "sha256": prepare_submission_sha256,
    },
    "prepare_receipt_sha256": prepare_receipt_sha256,
    "remote_preparation_binding": json.loads(raw_binding),
    "jobs": {"audit": audit_job, "full": full_job, "official": official_job},
    "submission_environment": {
        "audit": exports(audit_exports),
        "full": exports(full_exports),
        "official": exports(official_exports),
    },
}
path.parent.mkdir(parents=True, exist_ok=True)
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    os.write(descriptor, encoded)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
