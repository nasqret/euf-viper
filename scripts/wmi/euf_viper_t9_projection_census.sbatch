#!/usr/bin/env bash
#SBATCH --job-name=euf-t9-census
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --output=results/t9-projection-census-%j.out
#SBATCH --error=results/t9-projection-census-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1
export RUSTUP_TOOLCHAIN=1.93.0

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set exact expected revision}"
EXPECTED_MANIFEST_SHA256="32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
EXPECTED_SOURCE_SET_SHA256="6b3c316cd90d8093bba184522dd3238892e06b6215fc2a8e8b510e1b5b19ba60"
EXPECTED_CONTROL_MANIFEST_SHA256="85c18f76bc4908477e906eb0706cb06724ef23ef0536112651fe75e86ff18390"
EXPECTED_SOURCES=7503
EXPECTED_QG_SOURCES=6396
export EXPECTED_MANIFEST_SHA256 EXPECTED_SOURCE_SET_SHA256
export EXPECTED_CONTROL_MANIFEST_SHA256 EXPECTED_SOURCES EXPECTED_QG_SOURCES
CARGO="${EUF_VIPER_CARGO:?set absolute cargo path}"
CARGO_SHA256="${EUF_VIPER_CARGO_SHA256:?set cargo SHA-256}"
CARGO_VERSION="${EUF_VIPER_CARGO_VERSION:?set exact cargo version}"
RUSTC="${EUF_VIPER_RUSTC:?set absolute rustc path}"
RUSTC_SHA256="${EUF_VIPER_RUSTC_SHA256:?set rustc SHA-256}"
RUSTC_VERSION="${EUF_VIPER_RUSTC_VERSION:?set exact rustc version}"
PYTHON="${EUF_VIPER_PYTHON:?set absolute Python path}"
PYTHON_SHA256="${EUF_VIPER_PYTHON_SHA256:?set Python SHA-256}"
PYTHON_VERSION="${EUF_VIPER_PYTHON_VERSION:?set exact Python version}"

canonical_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
    *) return 0 ;;
  esac
}

if [ "${#EXPECTED_REVISION}" -ne 40 ]; then
  echo "EUF_VIPER_EXPECTED_REVISION must be 40 lowercase hexadecimal characters" >&2
  exit 2
fi
case "$EXPECTED_REVISION" in
  *[!0-9a-f]*)
    echo "EUF_VIPER_EXPECTED_REVISION must be 40 lowercase hexadecimal characters" >&2
    exit 2
    ;;
esac
canonical_sha256 "$EXPECTED_MANIFEST_SHA256" || {
  echo "frozen manifest SHA-256 is not canonical" >&2
  exit 2
}
canonical_sha256 "$EXPECTED_SOURCE_SET_SHA256" || {
  echo "frozen source-set SHA-256 is not canonical" >&2
  exit 2
}
canonical_sha256 "$EXPECTED_CONTROL_MANIFEST_SHA256" || {
  echo "frozen control-manifest SHA-256 is not canonical" >&2
  exit 2
}
canonical_sha256 "$CARGO_SHA256" || {
  echo "EUF_VIPER_CARGO_SHA256 is not canonical" >&2
  exit 2
}
canonical_sha256 "$RUSTC_SHA256" || {
  echo "EUF_VIPER_RUSTC_SHA256 is not canonical" >&2
  exit 2
}
canonical_sha256 "$PYTHON_SHA256" || {
  echo "EUF_VIPER_PYTHON_SHA256 is not canonical" >&2
  exit 2
}
case "$CARGO:$RUSTC:$PYTHON" in
  /*:/*:/*) ;;
  *)
    echo "cargo, rustc, and Python paths must be absolute" >&2
    exit 2
    ;;
esac
for tool in "$CARGO" "$RUSTC" "$PYTHON"; do
  if [ ! -x "$tool" ]; then
    echo "required executable is missing: $tool" >&2
    exit 2
  fi
done
if [ "$(sha256sum "$CARGO" | awk '{print $1}')" != "$CARGO_SHA256" ]; then
  echo "cargo SHA-256 mismatch" >&2
  exit 2
fi
if [ "$(sha256sum "$RUSTC" | awk '{print $1}')" != "$RUSTC_SHA256" ]; then
  echo "rustc SHA-256 mismatch" >&2
  exit 2
fi
if [ "$(sha256sum "$PYTHON" | awk '{print $1}')" != "$PYTHON_SHA256" ]; then
  echo "Python SHA-256 mismatch" >&2
  exit 2
fi
if [ "$($CARGO --version)" != "$CARGO_VERSION" ]; then
  echo "cargo version mismatch" >&2
  exit 2
fi
if [ "$($RUSTC --version)" != "$RUSTC_VERSION" ]; then
  echo "rustc version mismatch" >&2
  exit 2
fi
if [ "$($PYTHON --version 2>&1)" != "$PYTHON_VERSION" ]; then
  echo "Python version mismatch" >&2
  exit 2
fi

ACTUAL_REVISION="$(git rev-parse HEAD^{commit})"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi

SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-$HOME/euf-viper/benchmarks/smtlib-2025}"
MANIFEST="${EUF_VIPER_T9_MANIFEST:-$SHARED_CORPUS/qf_uf_manifest.jsonl}"
CORPUS_ROOT="${EUF_VIPER_T9_CORPUS_ROOT:-$SHARED_CORPUS/QF_UF}"
CONTROL_MANIFEST="$PWD/campaigns/t9-rollback-control-manifest-20260713.jsonl"
DESIGN_NOTE="$PWD/research-vault/02-design/2026-07-15-t9-clique-gated-ackermann-escape.md"
if [ ! -s "$MANIFEST" ] || [ ! -d "$CORPUS_ROOT/QF_UF" ]; then
  echo "missing T9 manifest or QF_UF corpus root" >&2
  exit 2
fi
if [ ! -s "$CONTROL_MANIFEST" ] || [ ! -s "$DESIGN_NOTE" ]; then
  echo "missing frozen T9 control manifest or design note" >&2
  exit 2
fi
ACTUAL_MANIFEST_SHA256="$(sha256sum "$MANIFEST" | awk '{print $1}')"
if [ "$ACTUAL_MANIFEST_SHA256" != "$EXPECTED_MANIFEST_SHA256" ]; then
  echo "manifest SHA-256 mismatch" >&2
  exit 2
fi
ACTUAL_CONTROL_MANIFEST_SHA256="$(sha256sum "$CONTROL_MANIFEST" | awk '{print $1}')"
if [ "$ACTUAL_CONTROL_MANIFEST_SHA256" != "$EXPECTED_CONTROL_MANIFEST_SHA256" ]; then
  echo "control manifest SHA-256 mismatch" >&2
  exit 2
fi
if [ "$(wc -l < "$CONTROL_MANIFEST" | tr -d ' ')" != "24" ] \
  || [ "$(wc -c < "$CONTROL_MANIFEST" | tr -d ' ')" != "12998" ]; then
  echo "control manifest population or byte count mismatch" >&2
  exit 2
fi

RUN_ROOT="$PWD/results/t9-projection-census-${SLURM_JOB_ID}"
mkdir -p "$RUN_ROOT"
export CARGO_TARGET_DIR="$RUN_ROOT/target"
export RUSTC
"$CARGO" build --locked --all-features --release
BINARY="$CARGO_TARGET_DIR/release/euf-viper"
if [ ! -x "$BINARY" ]; then
  echo "release binary was not produced" >&2
  exit 2
fi

"$PYTHON" scripts/bench/run_t9_projection_census.py \
  "$MANIFEST" \
  --corpus-root "$CORPUS_ROOT" \
  --binary "$BINARY" \
  --records-out "$RUN_ROOT/records.jsonl" \
  --summary-out "$RUN_ROOT/summary.json" \
  --timeout-seconds 30 \
  > "$RUN_ROOT/census.stdout"

"$PYTHON" scripts/bench/audit_t9_projection_census.py \
  "$MANIFEST" \
  --corpus-root "$CORPUS_ROOT" \
  --binary "$BINARY" \
  --records "$RUN_ROOT/records.jsonl" \
  --summary "$RUN_ROOT/summary.json" \
  --receipt-out "$RUN_ROOT/audit-receipt.json" \
  > "$RUN_ROOT/audit.stdout"

"$PYTHON" - \
  "$RUN_ROOT/metadata.json" \
  "$RUN_ROOT" \
  "$MANIFEST" \
  "$BINARY" \
  "$CONTROL_MANIFEST" \
  "$DESIGN_NOTE" <<'PY'
import hashlib
import json
import os
import platform
import stat
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


metadata_path = Path(sys.argv[1])
run_root = Path(sys.argv[2])
manifest = Path(sys.argv[3])
binary = Path(sys.argv[4])
control_manifest = Path(sys.argv[5])
design_note = Path(sys.argv[6])
receipt = json.loads((run_root / "audit-receipt.json").read_text(encoding="ascii"))
if receipt.get("status") != "pass":
    raise SystemExit("T9 audit receipt is not a pass")
if receipt.get("source_count") != 7503 or receipt.get("qg_source_count") != 6396:
    raise SystemExit("T9 audit receipt population mismatch")
if receipt.get("control_source_count") != 24:
    raise SystemExit("T9 audit receipt control population mismatch")
artifacts_record = receipt.get("artifacts")
if not isinstance(artifacts_record, dict):
    raise SystemExit("T9 audit receipt artifacts are missing")
expected_contract = {
    "manifest_sha256": os.environ["EXPECTED_MANIFEST_SHA256"],
    "source_set_sha256": os.environ["EXPECTED_SOURCE_SET_SHA256"],
    "control_manifest_sha256": os.environ["EXPECTED_CONTROL_MANIFEST_SHA256"],
}
for field, expected in expected_contract.items():
    if artifacts_record.get(field) != expected:
        raise SystemExit(f"T9 audit receipt {field} mismatch")
artifacts = {
    "manifest": manifest,
    "control_manifest": control_manifest,
    "design_note": design_note,
    "binary": binary,
    "cargo_lock": Path("Cargo.lock"),
    "runner": Path("scripts/bench/run_t9_projection_census.py"),
    "auditor": Path("scripts/bench/audit_t9_projection_census.py"),
    "records": run_root / "records.jsonl",
    "summary": run_root / "summary.json",
    "audit_receipt": run_root / "audit-receipt.json",
    "census_stdout": run_root / "census.stdout",
    "audit_stdout": run_root / "audit.stdout",
}
payload = {
    "schema": "euf-viper.t9-projection-wmi-run.v1",
    "status": "completed",
    "revision": os.environ["EUF_VIPER_EXPECTED_REVISION"],
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "hostname": platform.node(),
    "resource_contract": {"cpus": 1, "memory_bytes": 8 * 1024**3},
    "scientific_contract": {
        "sources": int(os.environ["EXPECTED_SOURCES"]),
        "qg_sources": int(os.environ["EXPECTED_QG_SOURCES"]),
        "manifest_sha256": os.environ["EXPECTED_MANIFEST_SHA256"],
        "source_set_sha256": os.environ["EXPECTED_SOURCE_SET_SHA256"],
        "control_manifest_sha256": os.environ[
            "EXPECTED_CONTROL_MANIFEST_SHA256"
        ],
        "projection_sat_calls": 0,
    },
    "toolchain": {
        "cargo_path": os.environ["EUF_VIPER_CARGO"],
        "cargo_sha256": os.environ["EUF_VIPER_CARGO_SHA256"],
        "cargo_version": os.environ["EUF_VIPER_CARGO_VERSION"],
        "rustc_path": os.environ["EUF_VIPER_RUSTC"],
        "rustc_sha256": os.environ["EUF_VIPER_RUSTC_SHA256"],
        "rustc_version": os.environ["EUF_VIPER_RUSTC_VERSION"],
        "python_path": os.environ["EUF_VIPER_PYTHON"],
        "python_sha256": os.environ["EUF_VIPER_PYTHON_SHA256"],
        "python_version": os.environ["EUF_VIPER_PYTHON_VERSION"],
        "rustup_toolchain": os.environ["RUSTUP_TOOLCHAIN"],
    },
    "artifacts": {
        name: {"path": str(path.resolve()), "sha256": sha256(path)}
        for name, path in artifacts.items()
    },
}
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
descriptor = os.open(metadata_path, flags, 0o600)
try:
    offset = 0
    while offset < len(encoded):
        written = os.write(descriptor, encoded[offset:])
        if written <= 0:
            raise SystemExit("short metadata write")
        offset += written
    os.fsync(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.read(descriptor, len(encoded) + 1) != encoded:
        raise SystemExit("metadata descriptor verification failed")
    os.fchmod(descriptor, 0o400)
    os.fsync(descriptor)
    metadata_stat = os.fstat(descriptor)
    named_stat = os.stat(metadata_path, follow_symlinks=False)
    if (metadata_stat.st_dev, metadata_stat.st_ino) != (
        named_stat.st_dev,
        named_stat.st_ino,
    ):
        raise SystemExit("metadata pathname was replaced")
    if stat.S_IMODE(named_stat.st_mode) != 0o400:
        raise SystemExit("metadata mode is not immutable")
finally:
    os.close(descriptor)
PY

printf 't9_census_root=%s\n' "$RUN_ROOT"
printf 't9_census_revision=%s\n' "$ACTUAL_REVISION"
printf 't9_census_manifest_sha256=%s\n' "$ACTUAL_MANIFEST_SHA256"
printf 't9_census_source_set_sha256=%s\n' "$EXPECTED_SOURCE_SET_SHA256"
printf 't9_census_control_manifest_sha256=%s\n' "$ACTUAL_CONTROL_MANIFEST_SHA256"
