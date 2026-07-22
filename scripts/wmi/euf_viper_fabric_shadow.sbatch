#!/usr/bin/env bash
#SBATCH --job-name=euf-fabric-shadow
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=08:00:00
#SBATCH --output=results/fabric-shadow-%j.out
#SBATCH --error=results/fabric-shadow-%j.err

set -euo pipefail

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

canonical_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

positive_integer() {
  case "$1" in
    ''|0|0*|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

canonical_file() {
  local configured="$1"
  local label="$2"
  local resolved

  case "$configured" in
    /*) ;;
    *) die "$label must be an absolute path: $configured" ;;
  esac
  [ ! -L "$configured" ] || die "$label must not be a symlink: $configured"
  [ -f "$configured" ] || die "$label is not a regular file: $configured"
  resolved="$(readlink -f -- "$configured")" || die "cannot resolve $label: $configured"
  [ "$resolved" = "$configured" ] || die "$label must be its canonical path: $resolved"
}

canonical_executable() {
  local configured="$1"
  local label="$2"

  canonical_file "$configured" "$label"
  [ -x "$configured" ] || die "$label is not executable: $configured"
}

canonical_directory() {
  local configured="$1"
  local label="$2"
  local resolved

  case "$configured" in
    /*) ;;
    *) die "$label must be an absolute path: $configured" ;;
  esac
  [ ! -L "$configured" ] || die "$label must not be a symlink: $configured"
  [ -d "$configured" ] || die "$label is not a directory: $configured"
  resolved="$(readlink -f -- "$configured")" || die "cannot resolve $label: $configured"
  [ "$resolved" = "$configured" ] || die "$label must be its canonical path: $resolved"
}

[ "${EUF_VIPER_FABRIC_SHADOW_ENABLE:-0}" = 1 ] || \
  die "Fabric shadow census is default-off; set EUF_VIPER_FABRIC_SHADOW_ENABLE=1"

JOB_ID="${SLURM_JOB_ID:?run this wrapper under Slurm}"
ROOT="${SLURM_SUBMIT_DIR:?SLURM_SUBMIT_DIR is required}"
WORK_ROOT="${EUF_VIPER_FABRIC_WORK_ROOT:?set EUF_VIPER_FABRIC_WORK_ROOT}"
RUN_ROOT="${EUF_VIPER_FABRIC_RUN_ROOT:?set EUF_VIPER_FABRIC_RUN_ROOT}"
MANIFEST="${EUF_VIPER_FABRIC_MANIFEST:?set EUF_VIPER_FABRIC_MANIFEST}"
CORPUS_ROOT="${EUF_VIPER_FABRIC_CORPUS_ROOT:?set EUF_VIPER_FABRIC_CORPUS_ROOT}"
EXPECTED_MANIFEST_SHA256="${EUF_VIPER_FABRIC_MANIFEST_SHA256:?set EUF_VIPER_FABRIC_MANIFEST_SHA256}"
EXPECTED_SOURCES="${EUF_VIPER_FABRIC_EXPECTED_SOURCES:?set EUF_VIPER_FABRIC_EXPECTED_SOURCES}"
EXPECTED_REVISION="${EUF_VIPER_FABRIC_EXPECTED_REVISION:?set EUF_VIPER_FABRIC_EXPECTED_REVISION}"
MODE="${EUF_VIPER_FABRIC_MODE:?set EUF_VIPER_FABRIC_MODE}"
RESUME="${EUF_VIPER_FABRIC_RESUME:-0}"
INSTANCE_TIMEOUT_S="${EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S:-60}"
CARGO="${EUF_VIPER_FABRIC_CARGO:?set EUF_VIPER_FABRIC_CARGO}"
EXPECTED_CARGO_SHA256="${EUF_VIPER_FABRIC_CARGO_SHA256:?set EUF_VIPER_FABRIC_CARGO_SHA256}"
EXPECTED_CARGO_VERSION="${EUF_VIPER_FABRIC_CARGO_VERSION:?set EUF_VIPER_FABRIC_CARGO_VERSION}"
RUSTC="${EUF_VIPER_FABRIC_RUSTC:?set EUF_VIPER_FABRIC_RUSTC}"
EXPECTED_RUSTC_SHA256="${EUF_VIPER_FABRIC_RUSTC_SHA256:?set EUF_VIPER_FABRIC_RUSTC_SHA256}"
EXPECTED_RUSTC_VERSION="${EUF_VIPER_FABRIC_RUSTC_VERSION:?set EUF_VIPER_FABRIC_RUSTC_VERSION}"
PYTHON="${EUF_VIPER_FABRIC_PYTHON:?set EUF_VIPER_FABRIC_PYTHON}"
EXPECTED_PYTHON_SHA256="${EUF_VIPER_FABRIC_PYTHON_SHA256:?set EUF_VIPER_FABRIC_PYTHON_SHA256}"
EXPECTED_PYTHON_VERSION="${EUF_VIPER_FABRIC_PYTHON_VERSION:?set EUF_VIPER_FABRIC_PYTHON_VERSION}"

case "$MODE" in
  full|smoke) ;;
  *) die "EUF_VIPER_FABRIC_MODE must be full or smoke" ;;
esac
case "$RESUME" in
  0|1) ;;
  *) die "EUF_VIPER_FABRIC_RESUME must be 0 or 1" ;;
esac
[[ "$INSTANCE_TIMEOUT_S" =~ ^[0-9]+([.][0-9]+)?$ ]] || \
  die "EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S must be a positive finite decimal"
positive_integer "$EXPECTED_SOURCES" || \
  die "EUF_VIPER_FABRIC_EXPECTED_SOURCES must be a canonical positive integer"
if [ "$MODE" = full ] && [ "$EXPECTED_SOURCES" != 7503 ]; then
  die "full Fabric shadow census requires exactly 7503 manifest rows"
fi
if [ "${SLURM_CPUS_PER_TASK:-}" != 1 ]; then
  die "Fabric shadow census requires exactly one allocated CPU"
fi

for value in \
  "$EXPECTED_MANIFEST_SHA256" \
  "$EXPECTED_CARGO_SHA256" \
  "$EXPECTED_RUSTC_SHA256" \
  "$EXPECTED_PYTHON_SHA256"; do
  canonical_sha256 "$value" || die "tool and manifest pins must be lowercase SHA-256 values"
done

case "$ROOT:$WORK_ROOT:$RUN_ROOT" in
  /*:/*:/*) ;;
  *) die "submit, work, and run roots must be absolute" ;;
esac
for value in "$ROOT" "$WORK_ROOT" "$RUN_ROOT"; do
  case "$value" in
    *'/../'*|*/..) die "root paths must not contain parent traversal: $value" ;;
  esac
done

ROOT="$(readlink -f -- "$ROOT")" || die "cannot resolve Slurm submit directory"
[ -d "$WORK_ROOT" ] || die "Fabric work root does not exist: $WORK_ROOT"
WORK_ROOT="$(readlink -f -- "$WORK_ROOT")" || die "cannot resolve Fabric work root"
HOME_ROOT="$(readlink -f -- "${HOME:?HOME is required}")" || die "cannot resolve HOME"
case "$WORK_ROOT" in
  /work/*) ;;
  *) die "Fabric work root must be below absolute /work" ;;
esac
case "$WORK_ROOT" in
  "$HOME_ROOT"|"$HOME_ROOT"/*) die "Fabric work root must be outside HOME" ;;
esac
case "$ROOT" in
  "$WORK_ROOT"/checkouts/*) ;;
  *) die "Slurm submit directory must be a pinned checkout below the Fabric work root" ;;
esac
case "$RUN_ROOT" in
  "$WORK_ROOT"/runs/*) ;;
  *) die "Fabric run root must stay below the Fabric work root runs directory" ;;
esac

canonical_file "$MANIFEST" "Fabric manifest"
canonical_directory "$CORPUS_ROOT" "Fabric corpus root"
for generated_root in "$ROOT" "$RUN_ROOT"; do
  case "$generated_root" in
    "$CORPUS_ROOT"|"$CORPUS_ROOT"/*)
      die "generated Fabric paths must stay outside the read-only corpus root"
      ;;
  esac
done
canonical_executable "$CARGO" "pinned cargo"
canonical_executable "$RUSTC" "pinned rustc"
canonical_executable "$PYTHON" "pinned python"

ACTUAL_CARGO_SHA256="$(sha256sum "$CARGO" | awk '{print $1}')"
ACTUAL_RUSTC_SHA256="$(sha256sum "$RUSTC" | awk '{print $1}')"
ACTUAL_PYTHON_SHA256="$(sha256sum "$PYTHON" | awk '{print $1}')"
[ "$ACTUAL_CARGO_SHA256" = "$EXPECTED_CARGO_SHA256" ] || die "cargo hash mismatch"
[ "$ACTUAL_RUSTC_SHA256" = "$EXPECTED_RUSTC_SHA256" ] || die "rustc hash mismatch"
[ "$ACTUAL_PYTHON_SHA256" = "$EXPECTED_PYTHON_SHA256" ] || die "python hash mismatch"

ACTUAL_CARGO_VERSION="$("$CARGO" --version)"
ACTUAL_RUSTC_VERSION="$("$RUSTC" --version)"
ACTUAL_PYTHON_VERSION="$("$PYTHON" --version 2>&1)"
[ "$ACTUAL_CARGO_VERSION" = "$EXPECTED_CARGO_VERSION" ] || die "cargo version mismatch"
[ "$ACTUAL_RUSTC_VERSION" = "$EXPECTED_RUSTC_VERSION" ] || die "rustc version mismatch"
[ "$ACTUAL_PYTHON_VERSION" = "$EXPECTED_PYTHON_VERSION" ] || die "python version mismatch"
"$PYTHON" -c \
  'import math, sys; value = float(sys.argv[1]); raise SystemExit(not (math.isfinite(value) and value > 0))' \
  "$INSTANCE_TIMEOUT_S" || \
  die "EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S must be finite and positive"
case "$ACTUAL_CARGO_VERSION" in
  'cargo 1.93.0 '*) ;;
  *) die "Fabric census requires cargo 1.93.0, got $ACTUAL_CARGO_VERSION" ;;
esac
case "$ACTUAL_RUSTC_VERSION" in
  'rustc 1.93.0 '*) ;;
  *) die "Fabric census requires rustc 1.93.0, got $ACTUAL_RUSTC_VERSION" ;;
esac

cd "$ROOT"
[ "$(git rev-parse --show-toplevel)" = "$ROOT" ] || die "submit directory is not the repository root"
ACTUAL_REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
[ "$ACTUAL_REVISION" = "$EXPECTED_REVISION" ] || \
  die "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "pinned Fabric checkout must be completely clean"
grep -Fqx 'channel = "1.93.0"' rust-toolchain.toml || \
  die "rust-toolchain.toml does not pin Rust 1.93.0"

RUNNER="$ROOT/scripts/bench/run_fabric_shadow.py"
canonical_file "$RUNNER" "Fabric shadow runner"
RUNNER_SHA256="$(sha256sum "$RUNNER" | awk '{print $1}')"

read -r OBSERVED_SOURCES ACTUAL_MANIFEST_SHA256 < <(
  "$PYTHON" - "$MANIFEST" <<'PY_MANIFEST'
import hashlib
import sys
from pathlib import Path

path = Path(sys.argv[1])
digest = hashlib.sha256()
rows = 0
with path.open("rb") as handle:
    for line in handle:
        digest.update(line)
        if not line.strip():
            raise SystemExit("manifest contains an empty row")
        rows += 1
print(rows, digest.hexdigest())
PY_MANIFEST
)
[ "$OBSERVED_SOURCES" = "$EXPECTED_SOURCES" ] || \
  die "manifest row mismatch: expected $EXPECTED_SOURCES, got $OBSERVED_SOURCES"
[ "$ACTUAL_MANIFEST_SHA256" = "$EXPECTED_MANIFEST_SHA256" ] || \
  die "manifest hash mismatch before Fabric census"

export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export RAYON_NUM_THREADS=1
export CARGO_BUILD_JOBS=1
export PYTHONDONTWRITEBYTECODE=1
export RUSTC
unset CARGO_ENCODED_RUSTFLAGS RUSTFLAGS EUF_VIPER_PROFILE

umask 077
mkdir -p "$WORK_ROOT/runs"
if [ "$RESUME" = 0 ]; then
  mkdir "$RUN_ROOT" || die "fresh Fabric run root already exists: $RUN_ROOT"
else
  [ -d "$RUN_ROOT" ] || die "resume run root does not exist: $RUN_ROOT"
fi

ACTIVE_LOCK="$RUN_ROOT/.active"
mkdir "$ACTIVE_LOCK" || die "Fabric run root is already active: $RUN_ROOT"
release_lock() {
  rmdir "$ACTIVE_LOCK" 2>/dev/null || true
}
trap release_lock EXIT

STAGING_ROOT="$RUN_ROOT/.artifacts.partial"
FINAL_ROOT="$RUN_ROOT/artifacts"
RECORDS="$STAGING_ROOT/fabric-shadow.jsonl"
SUMMARY_CANDIDATE="$STAGING_ROOT/.summary.$JOB_ID.tmp"
SUMMARY="$STAGING_ROOT/summary.json"
METADATA_CANDIDATE="$STAGING_ROOT/.slurm.$JOB_ID.tmp"
METADATA="$STAGING_ROOT/slurm.json"
STDOUT_CANDIDATE="$STAGING_ROOT/.stdout.$JOB_ID.tmp"
STDERR_CANDIDATE="$STAGING_ROOT/.stderr.$JOB_ID.tmp"
STDOUT_LOG="$STAGING_ROOT/stdout.log"
STDERR_LOG="$STAGING_ROOT/stderr.log"
PERSISTED_SOLVER="$STAGING_ROOT/euf-viper"

[ ! -e "$FINAL_ROOT" ] && [ ! -L "$FINAL_ROOT" ] || \
  die "Fabric run already has published artifacts: $FINAL_ROOT"
if [ "$RESUME" = 0 ]; then
  mkdir "$STAGING_ROOT" || die "staging root already exists: $STAGING_ROOT"
else
  [ -d "$STAGING_ROOT" ] && [ ! -L "$STAGING_ROOT" ] || \
    die "resume staging root is missing or unsafe: $STAGING_ROOT"
  [ -s "$RECORDS" ] || die "resume requires a nonempty partial records journal"
  canonical_executable "$PERSISTED_SOLVER" "persisted Fabric solver"
fi
[ ! -e "$SUMMARY_CANDIDATE" ] && [ ! -L "$SUMMARY_CANDIDATE" ] || \
  die "job-specific summary staging path already exists"
[ ! -e "$METADATA_CANDIDATE" ] && [ ! -L "$METADATA_CANDIDATE" ] || \
  die "job-specific metadata staging path already exists"
[ ! -e "$STDOUT_CANDIDATE" ] && [ ! -L "$STDOUT_CANDIDATE" ] || \
  die "job-specific stdout staging path already exists"
[ ! -e "$STDERR_CANDIDATE" ] && [ ! -L "$STDERR_CANDIDATE" ] || \
  die "job-specific stderr staging path already exists"

exec 3>&1 4>&2
exec >"$STDOUT_CANDIDATE" 2>"$STDERR_CANDIDATE"

BUILD_ROOT="$WORK_ROOT/cargo-targets/slurm-$JOB_ID"
case "$BUILD_ROOT" in
  /work/*) ;;
  *) die "Cargo build root must stay below absolute /work" ;;
esac
case "$BUILD_ROOT" in
  "$CORPUS_ROOT"|"$CORPUS_ROOT"/*)
    die "Cargo build root must stay outside the read-only corpus root"
    ;;
esac
mkdir -p "$BUILD_ROOT/target"
export CARGO_TARGET_DIR="$BUILD_ROOT/target"
export PATH="$(dirname "$RUSTC"):$(dirname "$CARGO"):/usr/local/bin:/usr/bin:/bin"

"$CARGO" build --release --locked --features fabric
BUILT_SOLVER="$CARGO_TARGET_DIR/release/euf-viper"
canonical_executable "$BUILT_SOLVER" "built Fabric solver"
BUILT_SOLVER_SHA256="$(sha256sum "$BUILT_SOLVER" | awk '{print $1}')"

if [ "$RESUME" = 0 ]; then
  SOLVER_CANDIDATE="$STAGING_ROOT/.euf-viper.$JOB_ID.tmp"
  install -m 0555 "$BUILT_SOLVER" "$SOLVER_CANDIDATE"
  mv "$SOLVER_CANDIDATE" "$PERSISTED_SOLVER"
else
  PERSISTED_SOLVER_SHA256="$(sha256sum "$PERSISTED_SOLVER" | awk '{print $1}')"
  [ "$PERSISTED_SOLVER_SHA256" = "$BUILT_SOLVER_SHA256" ] || \
    die "rebuilt solver differs from the solver bound to the partial census"
fi
PERSISTED_SOLVER_SHA256="$(sha256sum "$PERSISTED_SOLVER" | awk '{print $1}')"

RUN_ARGS=(
  "$MANIFEST"
  --solver "$PERSISTED_SOLVER"
  --corpus-root "$CORPUS_ROOT"
  --timeout-s "$INSTANCE_TIMEOUT_S"
  --out-jsonl "$RECORDS"
  --summary "$SUMMARY_CANDIDATE"
  --jobs 1
)
if [ "$RESUME" = 1 ]; then
  RUN_ARGS+=(--resume)
fi
"$PYTHON" scripts/bench/run_fabric_shadow.py "${RUN_ARGS[@]}"

[ -s "$RECORDS" ] || die "Fabric runner did not produce records"
[ -s "$SUMMARY_CANDIDATE" ] || die "Fabric runner did not produce a summary"
mv -f "$SUMMARY_CANDIDATE" "$SUMMARY"

[ "$(git rev-parse --verify 'HEAD^{commit}')" = "$EXPECTED_REVISION" ] || \
  die "repository revision drifted during Fabric census"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "repository changed during Fabric census"
[ "$(sha256sum "$MANIFEST" | awk '{print $1}')" = "$EXPECTED_MANIFEST_SHA256" ] || \
  die "manifest changed during Fabric census"
[ "$(sha256sum "$RUNNER" | awk '{print $1}')" = "$RUNNER_SHA256" ] || \
  die "Fabric runner changed during census"
[ "$(sha256sum "$PERSISTED_SOLVER" | awk '{print $1}')" = "$PERSISTED_SOLVER_SHA256" ] || \
  die "Fabric solver changed during census"

exec 1>&3 2>&4
exec 3>&- 4>&-
mv -f "$STDOUT_CANDIDATE" "$STDOUT_LOG"
mv -f "$STDERR_CANDIDATE" "$STDERR_LOG"

"$PYTHON" - \
  "$METADATA_CANDIDATE" \
  "$RECORDS" \
  "$SUMMARY" \
  "$PERSISTED_SOLVER" \
  "$STDOUT_LOG" \
  "$STDERR_LOG" \
  "$FINAL_ROOT" \
  "$MANIFEST" \
  "$CORPUS_ROOT" \
  "$EXPECTED_MANIFEST_SHA256" \
  "$EXPECTED_SOURCES" \
  "$EXPECTED_REVISION" \
  "$INSTANCE_TIMEOUT_S" \
  "$MODE" \
  "$RESUME" \
  "$RUNNER" \
  "$RUNNER_SHA256" \
  "$PYTHON" \
  "$ACTUAL_PYTHON_SHA256" \
  "$ACTUAL_PYTHON_VERSION" \
  "$CARGO" \
  "$ACTUAL_CARGO_SHA256" \
  "$ACTUAL_CARGO_VERSION" \
  "$RUSTC" \
  "$ACTUAL_RUSTC_SHA256" \
  "$ACTUAL_RUSTC_VERSION" <<'PY_METADATA'
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    output_raw,
    records_raw,
    summary_raw,
    solver_raw,
    stdout_raw,
    stderr_raw,
    final_root_raw,
    manifest_raw,
    corpus_root_raw,
    manifest_hash,
    expected_sources_raw,
    revision,
    instance_timeout_raw,
    mode,
    resume_raw,
    runner_raw,
    runner_hash,
    python_raw,
    python_hash,
    python_version,
    cargo_raw,
    cargo_hash,
    cargo_version,
    rustc_raw,
    rustc_hash,
    rustc_version,
) = sys.argv[1:]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


records = Path(records_raw)
summary = Path(summary_raw)
solver = Path(solver_raw)
stdout = Path(stdout_raw)
stderr = Path(stderr_raw)
expected_sources = int(expected_sources_raw)
observed_sources = 0
with records.open("r", encoding="ascii") as handle:
    for line_number, line in enumerate(handle, 1):
        if not line.strip():
            raise SystemExit(f"empty Fabric record at line {line_number}")
        record = json.loads(line)
        if type(record) is not dict:
            raise SystemExit(f"Fabric record {line_number} is not an object")
        if record.get("solver_result_emitted") is not False:
            raise SystemExit(
                f"Fabric record {line_number} makes or omits the required "
                "solver_result_emitted=false declaration"
            )
        observed_sources += 1
if observed_sources != expected_sources:
    raise SystemExit(
        f"Fabric record count mismatch: expected {expected_sources}, "
        f"got {observed_sources}"
    )
summary_payload = json.loads(summary.read_text(encoding="ascii"))
if type(summary_payload) is not dict:
    raise SystemExit("Fabric summary is not a JSON object")

final_root = Path(final_root_raw)
payload = {
    "schema": "euf-viper.fabric-shadow-wmi-run.v1",
    "status": "artifact_complete",
    "scope": {
        "stage": "F0",
        "mode": "semantic_substrate_shadow_census",
        "default_behavior_change": False,
        "solver_result_claim": False,
        "performance_claim": False,
        "promotion_claim": False,
        "solver_result_claims_allowed": 0,
    },
    "revision": revision,
    "corpus_mode": mode,
    "resume": resume_raw == "1",
    "single_core": True,
    "jobs": 1,
    "instance_timeout_s": float(instance_timeout_raw),
    "manifest": {
        "path": manifest_raw,
        "corpus_root": corpus_root_raw,
        "corpus_access": "read_only",
        "sha256": manifest_hash,
        "expected_sources": expected_sources,
        "observed_records": observed_sources,
    },
    "slurm": {
        "job_id": os.environ["SLURM_JOB_ID"],
        "job_name": os.environ.get("SLURM_JOB_NAME"),
        "cluster": os.environ.get("SLURM_CLUSTER_NAME"),
        "partition": os.environ.get("SLURM_JOB_PARTITION"),
        "account": os.environ.get("SLURM_JOB_ACCOUNT"),
        "node_list": os.environ.get("SLURM_JOB_NODELIST"),
        "cpus_per_task": int(os.environ["SLURM_CPUS_PER_TASK"]),
        "submit_dir": os.environ["SLURM_SUBMIT_DIR"],
    },
    "tools": {
        "runner": {"path": runner_raw, "sha256": runner_hash},
        "python": {
            "path": python_raw,
            "sha256": python_hash,
            "version": python_version,
        },
        "cargo": {
            "path": cargo_raw,
            "sha256": cargo_hash,
            "version": cargo_version,
        },
        "rustc": {
            "path": rustc_raw,
            "sha256": rustc_hash,
            "version": rustc_version,
        },
    },
    "artifacts": {
        "records": {
            "path": str(final_root / "fabric-shadow.jsonl"),
            "sha256": sha256(records),
            "bytes": records.stat().st_size,
        },
        "summary": {
            "path": str(final_root / "summary.json"),
            "sha256": sha256(summary),
            "bytes": summary.stat().st_size,
        },
        "solver": {
            "path": str(final_root / "euf-viper"),
            "sha256": sha256(solver),
            "bytes": solver.stat().st_size,
        },
        "stdout": {
            "path": str(final_root / "stdout.log"),
            "sha256": sha256(stdout),
            "bytes": stdout.stat().st_size,
        },
        "stderr": {
            "path": str(final_root / "stderr.log"),
            "sha256": sha256(stderr),
            "bytes": stderr.stat().st_size,
        },
    },
    "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
encoded = (
    json.dumps(payload, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
    + "\n"
).encode("ascii")
output = Path(output_raw)
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as handle:
    handle.write(encoded)
    handle.flush()
    os.fsync(handle.fileno())
PY_METADATA

mv "$METADATA_CANDIDATE" "$METADATA"
[ ! -e "$FINAL_ROOT" ] && [ ! -L "$FINAL_ROOT" ] || \
  die "refuse to replace published Fabric artifacts"
mv "$STAGING_ROOT" "$FINAL_ROOT"
cat "$FINAL_ROOT/slurm.json"
