#!/usr/bin/env bash
#SBATCH --job-name=euf-t9-stage1
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=t9-stage1-%j.out
#SBATCH --error=t9-stage1-%j.err

set -euo pipefail

REPO_ROOT_INPUT="${EUF_VIPER_T9_REPO_ROOT:?set absolute clean harness checkout root}"
RUN_BASE_INPUT="${EUF_VIPER_T9_RUN_BASE:?set absolute external run base}"
STAGE0_ROOT_INPUT="${EUF_VIPER_T9_STAGE0_ROOT:?set absolute immutable Stage0 root}"
case "$REPO_ROOT_INPUT:$RUN_BASE_INPUT:$STAGE0_ROOT_INPUT" in
  /*:/*:/*) ;;
  *)
    echo "checkout, run base, and Stage0 root must be absolute" >&2
    exit 2
    ;;
esac
for directory in "$REPO_ROOT_INPUT" "$RUN_BASE_INPUT" "$STAGE0_ROOT_INPUT"; do
  if [ ! -d "$directory" ]; then
    echo "required directory is missing: $directory" >&2
    exit 2
  fi
done
REPO_ROOT="$(cd "$REPO_ROOT_INPUT" && pwd -P)"
RUN_BASE="$(cd "$RUN_BASE_INPUT" && pwd -P)"
STAGE0_ROOT="$(cd "$STAGE0_ROOT_INPUT" && pwd -P)"
SUBMIT_ROOT="$(cd "${SLURM_SUBMIT_DIR:-$PWD}" && pwd -P)"
case "$RUN_BASE:$STAGE0_ROOT" in
  "$REPO_ROOT":*|"$REPO_ROOT"/*:*|*:"$REPO_ROOT"|*:"$REPO_ROOT"/*)
    echo "run base and Stage0 root must be outside the harness checkout" >&2
    exit 2
    ;;
esac
if [ "$SUBMIT_ROOT" != "$RUN_BASE" ]; then
  echo "submit directory must equal the external run base" >&2
  exit 2
fi

export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set exact harness revision}"
BINARY_REVISION="${EUF_VIPER_T9_BINARY_REVISION:?set exact Stage0 binary revision}"
PYTHON="${EUF_VIPER_PYTHON:?set absolute Python path}"
PYTHON_SHA256="${EUF_VIPER_PYTHON_SHA256:?set Python SHA-256}"
PYTHON_VERSION="${EUF_VIPER_PYTHON_VERSION:?set exact Python version}"
YICES="${EUF_VIPER_YICES:?set absolute Yices path}"
YICES_SHA256="${EUF_VIPER_YICES_SHA256:?set Yices SHA-256}"
YICES_VERSION="${EUF_VIPER_YICES_VERSION:?set exact Yices first version line}"
BINARY="$STAGE0_ROOT/target/release/euf-viper"
BINARY_SHA256="${EUF_VIPER_T9_BINARY_SHA256:?set Stage0 binary SHA-256}"
STAGE0_RECORDS="$STAGE0_ROOT/records.jsonl"
STAGE0_SUMMARY="$STAGE0_ROOT/summary.json"
STAGE0_RECEIPT="$STAGE0_ROOT/audit-receipt.json"
EXPECTED_RECORDS_SHA256="${EUF_VIPER_T9_RECORDS_SHA256:?set Stage0 records SHA-256}"
EXPECTED_SUMMARY_SHA256="${EUF_VIPER_T9_SUMMARY_SHA256:?set Stage0 summary SHA-256}"
EXPECTED_RECEIPT_SHA256="${EUF_VIPER_T9_RECEIPT_SHA256:?set Stage0 receipt SHA-256}"

canonical_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
    *) return 0 ;;
  esac
}

for revision in "$EXPECTED_REVISION" "$BINARY_REVISION"; do
  [ "${#revision}" -eq 40 ] || {
    echo "revision is not a full hash" >&2
    exit 2
  }
  case "$revision" in
    *[!0-9a-f]*) echo "revision is not canonical" >&2; exit 2 ;;
  esac
done
for digest in \
  "$PYTHON_SHA256" "$YICES_SHA256" "$BINARY_SHA256" \
  "$EXPECTED_RECORDS_SHA256" "$EXPECTED_SUMMARY_SHA256" "$EXPECTED_RECEIPT_SHA256"; do
  canonical_sha256 "$digest" || {
    echo "input SHA-256 is not canonical" >&2
    exit 2
  }
done
for executable in "$PYTHON" "$YICES" "$BINARY"; do
  [ -x "$executable" ] || {
    echo "required executable is missing: $executable" >&2
    exit 2
  }
done
for artifact in "$STAGE0_RECORDS" "$STAGE0_SUMMARY" "$STAGE0_RECEIPT"; do
  [ -f "$artifact" ] || {
    echo "required Stage0 artifact is missing: $artifact" >&2
    exit 2
  }
  [ "$(stat -c '%a' "$artifact")" = 400 ] || {
    echo "Stage0 artifact is not immutable mode 0400: $artifact" >&2
    exit 2
  }
done
[ "$(sha256sum "$PYTHON" | awk '{print $1}')" = "$PYTHON_SHA256" ] || {
  echo "Python SHA-256 mismatch" >&2
  exit 2
}
[ "$($PYTHON --version 2>&1)" = "$PYTHON_VERSION" ] || {
  echo "Python version mismatch" >&2
  exit 2
}
[ "$(sha256sum "$YICES" | awk '{print $1}')" = "$YICES_SHA256" ] || {
  echo "Yices SHA-256 mismatch" >&2
  exit 2
}
[ "$($YICES --version | sed -n '1p')" = "$YICES_VERSION" ] || {
  echo "Yices version mismatch" >&2
  exit 2
}
[ "$(sha256sum "$BINARY" | awk '{print $1}')" = "$BINARY_SHA256" ] || {
  echo "Stage0 binary SHA-256 mismatch" >&2
  exit 2
}
[ "$(sha256sum "$STAGE0_RECORDS" | awk '{print $1}')" = "$EXPECTED_RECORDS_SHA256" ] || exit 2
[ "$(sha256sum "$STAGE0_SUMMARY" | awk '{print $1}')" = "$EXPECTED_SUMMARY_SHA256" ] || exit 2
[ "$(sha256sum "$STAGE0_RECEIPT" | awk '{print $1}')" = "$EXPECTED_RECEIPT_SHA256" ] || exit 2

cd "$REPO_ROOT"
[ "$(git rev-parse HEAD^{commit})" = "$EXPECTED_REVISION" ] || {
  echo "harness revision mismatch" >&2
  exit 2
}
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || {
  echo "harness checkout is dirty" >&2
  exit 2
}
git diff --quiet "$BINARY_REVISION"..HEAD -- Cargo.lock Cargo.toml build.rs src vendor || {
  echo "solver or dependency sources differ from the Stage0 binary revision" >&2
  exit 2
}

SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-$HOME/euf-viper/benchmarks/smtlib-2025}"
MANIFEST="$SHARED_CORPUS/qf_uf_manifest.jsonl"
CORPUS_ROOT="$SHARED_CORPUS/QF_UF"
CONTROL_MANIFEST="$REPO_ROOT/campaigns/t9-rollback-control-manifest-20260713.jsonl"
RUN_ROOT="$RUN_BASE/t9-stage1-${SLURM_JOB_ID}"
mkdir -m 700 "$RUN_ROOT"
RAW="$RUN_ROOT/raw.jsonl"
SUMMARY="$RUN_ROOT/summary.json"
RECEIPT="$RUN_ROOT/audit-receipt.json"
RUNNER="$REPO_ROOT/scripts/bench/run_t9_stage1.py"
AUDITOR="$REPO_ROOT/scripts/bench/audit_t9_stage1.py"

"$PYTHON" -B "$RUNNER" \
  --manifest "$MANIFEST" \
  --control-manifest "$CONTROL_MANIFEST" \
  --corpus-root "$CORPUS_ROOT" \
  --stage0-records "$STAGE0_RECORDS" \
  --stage0-summary "$STAGE0_SUMMARY" \
  --stage0-receipt "$STAGE0_RECEIPT" \
  --binary "$BINARY" \
  --binary-sha256 "$BINARY_SHA256" \
  --yices "$YICES" \
  --yices-sha256 "$YICES_SHA256" \
  --yices-version "$YICES_VERSION" \
  --raw-out "$RAW" \
  --summary-out "$SUMMARY" \
  > "$RUN_ROOT/stage1.stdout"

"$PYTHON" -B "$AUDITOR" \
  --manifest "$MANIFEST" \
  --control-manifest "$CONTROL_MANIFEST" \
  --corpus-root "$CORPUS_ROOT" \
  --stage0-records "$STAGE0_RECORDS" \
  --stage0-summary "$STAGE0_SUMMARY" \
  --stage0-receipt "$STAGE0_RECEIPT" \
  --binary "$BINARY" \
  --yices "$YICES" \
  --yices-version "$YICES_VERSION" \
  --runner "$RUNNER" \
  --raw "$RAW" \
  --summary "$SUMMARY" \
  --receipt-out "$RECEIPT" \
  > "$RUN_ROOT/audit.stdout"

"$PYTHON" -B - "$RUN_ROOT/metadata.json" "$SUMMARY" "$RECEIPT" "$EXPECTED_REVISION" <<'PY'
import hashlib
import json
import os
import platform
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


output, summary_path, receipt_path, revision = map(Path, sys.argv[1:])
summary = json.loads(summary_path.read_text(encoding="ascii"))
receipt = json.loads(receipt_path.read_text(encoding="ascii"))
payload = {
    "schema": "euf-viper.t9-stage1-wmi-run.v1",
    "status": "completed",
    "scientific_decision": summary["decision"],
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "hostname": platform.node(),
    "harness_revision": str(revision),
    "cpu_affinity": summary["cpu_affinity"],
    "summary_sha256": sha256(summary_path),
    "receipt_sha256": sha256(receipt_path),
    "receipt_status": receipt["status"],
}
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as handle:
    handle.write(encoded)
    handle.flush()
    os.fsync(handle.fileno())
output.chmod(0o400)
PY

printf 't9_stage1_status=completed scientific_decision=%s run_root=%s\n' \
  "$($PYTHON -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["decision"])' "$SUMMARY")" \
  "$RUN_ROOT"
