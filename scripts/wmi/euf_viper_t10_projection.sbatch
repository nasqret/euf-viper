#!/usr/bin/env bash
#SBATCH --job-name=euf-t10-census
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --output=t10-projection-census-%j.out
#SBATCH --error=t10-projection-census-%j.err

set -uo pipefail
umask 077

REPO_ROOT_INPUT="${EUF_VIPER_T10_REPO_ROOT:?set absolute clean /work checkout root}"
RUN_BASE_INPUT="${EUF_VIPER_T10_RUN_BASE:?set absolute external /work run base}"
CARGO_HOME_INPUT="${CARGO_HOME:?set absolute external /work Cargo home}"
case "$REPO_ROOT_INPUT:$RUN_BASE_INPUT:$CARGO_HOME_INPUT" in
  /*:/*:/*) ;;
  *)
    echo "checkout, run base, and Cargo home must be absolute" >&2
    exit 2
    ;;
esac
for directory in "$REPO_ROOT_INPUT" "$RUN_BASE_INPUT" "$CARGO_HOME_INPUT"; do
  if [ ! -d "$directory" ]; then
    echo "required directory is missing: $directory" >&2
    exit 2
  fi
done

REPO_ROOT="$(cd "$REPO_ROOT_INPUT" && pwd -P)"
RUN_BASE="$(cd "$RUN_BASE_INPUT" && pwd -P)"
CARGO_HOME="$(cd "$CARGO_HOME_INPUT" && pwd -P)"
SUBMIT_ROOT="$(cd "${SLURM_SUBMIT_DIR:-$PWD}" && pwd -P)"
case "$REPO_ROOT:$RUN_BASE:$CARGO_HOME" in
  /work/*:/work/*:/work/*) ;;
  *)
    echo "checkout, run base, and Cargo home must resolve under /work" >&2
    exit 2
    ;;
esac
case "$RUN_BASE:$CARGO_HOME" in
  "$REPO_ROOT":*|"$REPO_ROOT"/*:*|*:"$REPO_ROOT"|*:"$REPO_ROOT"/*)
    echo "run base and Cargo home must be outside the checkout" >&2
    exit 2
    ;;
esac
if [ "$SUBMIT_ROOT" != "$RUN_BASE" ]; then
  echo "submit directory must equal the external /work run base" >&2
  exit 2
fi

SLURM_JOB_ID="${SLURM_JOB_ID:?SLURM_JOB_ID is required}"
RUN_ROOT="$RUN_BASE/t10-projection-census-${SLURM_JOB_ID}"
if ! mkdir "$RUN_ROOT"; then
  echo "refusing to reuse T10 run root: $RUN_ROOT" >&2
  exit 2
fi

RUN_STATUS="preflight"
SCIENTIFIC_STATUS="not_run"
BUILD_EXIT=125
CENSUS_EXIT=125
AUDIT_EXIT=125
GATE_EXIT=125
ACTUAL_REVISION="unknown"
ACTUAL_TREE="unknown"
BINARY_SHA256="unknown"
BINARY_BYTES=0
CPU_AFFINITY="unknown"

finalize_evidence() {
  local shell_exit=$?
  trap - EXIT
  set +e
  export RUN_STATUS SCIENTIFIC_STATUS BUILD_EXIT CENSUS_EXIT AUDIT_EXIT GATE_EXIT
  export ACTUAL_REVISION ACTUAL_TREE BINARY_SHA256 BINARY_BYTES CPU_AFFINITY
  export SHELL_EXIT="$shell_exit"
  if [ -n "${PYTHON:-}" ] && [ -x "${PYTHON:-}" ]; then
    "$PYTHON" - "$RUN_ROOT/metadata.json" "$RUN_ROOT" "${MANIFEST:-}" \
      "${CONTROL_MANIFEST:-}" "${BINARY:-}" "$REPO_ROOT" <<'PY'
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


def artifact(path: Path) -> dict[str, object]:
    if path.is_symlink():
        raise SystemExit(f"artifact is a symlink: {path}")
    current = path.stat()
    if not stat.S_ISREG(current.st_mode):
        raise SystemExit(f"artifact is not regular: {path}")
    return {
        "path": str(path.resolve(strict=True)),
        "bytes": current.st_size,
        "sha256": sha256(path),
        "mode": stat.S_IMODE(current.st_mode),
    }


metadata_path = Path(sys.argv[1])
run_root = Path(sys.argv[2])
manifest = Path(sys.argv[3]) if sys.argv[3] else None
control_manifest = Path(sys.argv[4]) if sys.argv[4] else None
binary = Path(sys.argv[5]) if sys.argv[5] else None
repo_root = Path(sys.argv[6])
named = {
    "preflight_stdout": run_root / "preflight.stdout",
    "preflight_stderr": run_root / "preflight.stderr",
    "design_contract": run_root / "design-contract.md",
    "build_stdout": run_root / "build.stdout",
    "build_stderr": run_root / "build.stderr",
    "census_stdout": run_root / "census.stdout",
    "census_stderr": run_root / "census.stderr",
    "audit_stdout": run_root / "audit.stdout",
    "audit_stderr": run_root / "audit.stderr",
    "gate_stdout": run_root / "gate.stdout",
    "gate_stderr": run_root / "gate.stderr",
    "records": run_root / "records.jsonl",
    "summary": run_root / "summary.json",
    "audit_receipt": run_root / "audit-receipt.json",
    "runner": repo_root / "scripts/bench/run_t10_projection_census.py",
    "auditor": repo_root / "scripts/bench/audit_t10_projection_census.py",
    "hardened_stage0": repo_root / "scripts/bench/run_t9_projection_census.py",
    "wmi_wrapper": repo_root / "scripts/wmi/euf_viper_t10_projection.sbatch",
    "cargo_lock": repo_root / "Cargo.lock",
    "pinned_cargo": Path(os.environ["EUF_VIPER_CARGO"]).resolve(strict=True),
    "pinned_rustc": Path(os.environ["EUF_VIPER_RUSTC"]).resolve(strict=True),
    "pinned_python": Path(os.environ["EUF_VIPER_PYTHON"]).resolve(strict=True),
}
if manifest is not None:
    named["manifest"] = manifest
if control_manifest is not None:
    named["control_manifest"] = control_manifest
if binary is not None:
    named["binary"] = binary
artifacts = {
    name: artifact(path)
    for name, path in named.items()
    if path.exists()
}
recorded_binary_sha256 = os.environ["BINARY_SHA256"]
if recorded_binary_sha256 != "unknown" and artifacts.get("binary", {}).get(
    "sha256"
) != recorded_binary_sha256:
    raise SystemExit("final binary SHA-256 differs from the built binary binding")
for name, expected in (
    ("pinned_cargo", os.environ["EUF_VIPER_CARGO_SHA256"]),
    ("pinned_rustc", os.environ["EUF_VIPER_RUSTC_SHA256"]),
    ("pinned_python", os.environ["EUF_VIPER_PYTHON_SHA256"]),
):
    if artifacts[name]["sha256"] != expected:
        raise SystemExit(f"final {name} SHA-256 differs from its preflight binding")
audit_status = "missing"
receipt_path = run_root / "audit-receipt.json"
if receipt_path.is_file():
    try:
        receipt = json.loads(
            receipt_path.read_text(encoding="ascii"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant {value}")
            ),
        )
        audit_status = receipt.get("status", "missing")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        audit_status = "invalid"
payload = {
    "schema": "euf-viper.t10-projection-wmi-run.v1",
    "status": os.environ["RUN_STATUS"],
    "scientific_status": os.environ["SCIENTIFIC_STATUS"],
    "step_exit_codes": {
        "build": int(os.environ["BUILD_EXIT"]),
        "census": int(os.environ["CENSUS_EXIT"]),
        "audit": int(os.environ["AUDIT_EXIT"]),
        "gate": int(os.environ["GATE_EXIT"]),
        "shell": int(os.environ["SHELL_EXIT"]),
    },
    "expected_revision": os.environ.get("EUF_VIPER_EXPECTED_REVISION", "missing"),
    "actual_revision": os.environ["ACTUAL_REVISION"],
    "expected_tree": os.environ.get("EUF_VIPER_EXPECTED_TREE", "missing"),
    "actual_tree": os.environ["ACTUAL_TREE"],
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "hostname": platform.node(),
    "resource_contract": {
        "tasks": 1,
        "cpus": 1,
        "cpu_affinity": os.environ["CPU_AFFINITY"],
        "memory_bytes": 8 * 1024**3,
        "cargo_build_jobs": 1,
    },
    "environment_contract": {
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "RAYON_NUM_THREADS": "1",
        "CARGO_BUILD_JOBS": "1",
        "RUSTUP_TOOLCHAIN": "1.93.0",
    },
    "scientific_contract": {
        "sources": 7503,
        "qg_sources": 6396,
        "selected_sources": [
            {
                "relative_path": (
                    "QF_UF/2018-Goel-hwbench/"
                    "QF_UF_sokoban.2.prop1_ab_br_max.smt2"
                ),
                "sha256": (
                    "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112"
                ),
            }
        ],
        "manifest_sha256": (
            "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
        ),
        "source_set_sha256": (
            "6b3c316cd90d8093bba184522dd3238892e06b6215fc2a8e8b510e1b5b19ba60"
        ),
        "control_manifest_sha256": (
            "85c18f76bc4908477e906eb0706cb06724ef23ef0536112651fe75e86ff18390"
        ),
        "projector_argv": ["project-t10", "FILE"],
        "sat_calls": 0,
    },
    "design_contract": {
        "commit": "05de7841ac005e2a251d71e1a2394f8980cbdd17",
        "tree": "18dcfeca26b5cb72bc443476dc92203f04b412c2",
        "path": (
            "research-vault/02-design/"
            "2026-07-17-t10-closed-atom-ackermann-kernel.md"
        ),
        "blob": "4bde59e6aca9f89a8dae305e129e77febbefc1ca",
        "sha256": "8d42a123a5a08b880701e6be0fe9e037da98d49d569fadcba567c3c37f033d8c",
    },
    "toolchain": {
        "cargo_path": os.environ.get("EUF_VIPER_CARGO", "missing"),
        "cargo_sha256": os.environ.get("EUF_VIPER_CARGO_SHA256", "missing"),
        "cargo_version": os.environ.get("EUF_VIPER_CARGO_VERSION", "missing"),
        "rustc_path": os.environ.get("EUF_VIPER_RUSTC", "missing"),
        "rustc_sha256": os.environ.get("EUF_VIPER_RUSTC_SHA256", "missing"),
        "rustc_version": os.environ.get("EUF_VIPER_RUSTC_VERSION", "missing"),
        "python_path": os.environ.get("EUF_VIPER_PYTHON", "missing"),
        "python_sha256": os.environ.get("EUF_VIPER_PYTHON_SHA256", "missing"),
        "python_version": os.environ.get("EUF_VIPER_PYTHON_VERSION", "missing"),
        "rustup_toolchain": "1.93.0",
    },
    "binary_sha256": os.environ["BINARY_SHA256"],
    "binary_bytes": int(os.environ["BINARY_BYTES"]),
    "audit_status": audit_status,
    "artifacts": artifacts,
}
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
    "ascii"
)
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
    descriptor_stat = os.fstat(descriptor)
    named_stat = os.stat(metadata_path, follow_symlinks=False)
    if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
        named_stat.st_dev,
        named_stat.st_ino,
    ):
        raise SystemExit("metadata pathname was replaced")
    if stat.S_IMODE(named_stat.st_mode) != 0o400:
        raise SystemExit("metadata mode is not immutable")
finally:
    os.close(descriptor)
PY
    local metadata_exit=$?
    if [ "$metadata_exit" -ne 0 ]; then
      echo "T10 evidence finalizer failed with exit $metadata_exit" >&2
      if [ "$shell_exit" -eq 0 ]; then
        shell_exit=$metadata_exit
      fi
    fi
  else
    echo "T10 evidence finalizer could not execute the pinned Python" >&2
    if [ "$shell_exit" -eq 0 ]; then
      shell_exit=2
    fi
  fi
  exit "$shell_exit"
}
trap finalize_evidence EXIT

exec 3>"$RUN_ROOT/preflight.stdout"
exec 4>"$RUN_ROOT/preflight.stderr"
preflight_fail() {
  echo "$1" >&4
  RUN_STATUS="preflight_fail"
  SCIENTIFIC_STATUS="not_run"
  exit 2
}

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set exact expected revision}"
EXPECTED_TREE="${EUF_VIPER_EXPECTED_TREE:?set exact expected tree}"
EXPECTED_MANIFEST_SHA256="32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
EXPECTED_SOURCE_SET_SHA256="6b3c316cd90d8093bba184522dd3238892e06b6215fc2a8e8b510e1b5b19ba60"
EXPECTED_CONTROL_MANIFEST_SHA256="85c18f76bc4908477e906eb0706cb06724ef23ef0536112651fe75e86ff18390"
EXPECTED_SOURCES=7503
EXPECTED_QG_SOURCES=6396
DESIGN_COMMIT="05de7841ac005e2a251d71e1a2394f8980cbdd17"
DESIGN_TREE="18dcfeca26b5cb72bc443476dc92203f04b412c2"
DESIGN_PATH="research-vault/02-design/2026-07-17-t10-closed-atom-ackermann-kernel.md"
DESIGN_BLOB="4bde59e6aca9f89a8dae305e129e77febbefc1ca"
DESIGN_SHA256="8d42a123a5a08b880701e6be0fe9e037da98d49d569fadcba567c3c37f033d8c"
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
export CARGO_HOME CARGO RUSTC PYTHON

canonical_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
    *) return 0 ;;
  esac
}
canonical_oid() {
  [ "${#1}" -eq 40 ] || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
    *) return 0 ;;
  esac
}

canonical_oid "$EXPECTED_REVISION" || preflight_fail "expected revision is not canonical"
canonical_oid "$EXPECTED_TREE" || preflight_fail "expected tree is not canonical"
for digest in "$EXPECTED_MANIFEST_SHA256" "$EXPECTED_SOURCE_SET_SHA256" \
  "$EXPECTED_CONTROL_MANIFEST_SHA256" "$CARGO_SHA256" "$RUSTC_SHA256" \
  "$PYTHON_SHA256" "$DESIGN_SHA256"; do
  canonical_sha256 "$digest" || preflight_fail "a frozen SHA-256 is not canonical"
done
case "$CARGO:$RUSTC:$PYTHON" in
  /*:/*:/*) ;;
  *) preflight_fail "cargo, rustc, and Python paths must be absolute" ;;
esac
for tool in "$CARGO" "$RUSTC" "$PYTHON"; do
  [ -x "$tool" ] || preflight_fail "required executable is missing: $tool"
done

for forbidden in EUF_VIPER_T10_ACKERMANN EUF_VIPER_T9_ACKERMANN \
  EUF_VIPER_T10_STAGE1 EUF_VIPER_TIMING_MODE EUF_VIPER_SOLVER_MODE; do
  if [ -n "${!forbidden+x}" ]; then
    preflight_fail "forbidden timing/solver mode variable is set: $forbidden"
  fi
done

export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1
export CARGO_BUILD_JOBS=1
export RUSTUP_TOOLCHAIN=1.93.0

[ "${SLURM_NTASKS:-1}" = "1" ] || preflight_fail "SLURM_NTASKS must be exactly 1"
[ "${SLURM_CPUS_PER_TASK:-}" = "1" ] || preflight_fail "SLURM_CPUS_PER_TASK must be exactly 1"

if [ "$(sha256sum "$CARGO" | awk '{print $1}')" != "$CARGO_SHA256" ]; then
  preflight_fail "cargo SHA-256 mismatch"
fi
if [ "$(sha256sum "$RUSTC" | awk '{print $1}')" != "$RUSTC_SHA256" ]; then
  preflight_fail "rustc SHA-256 mismatch"
fi
if [ "$(sha256sum "$PYTHON" | awk '{print $1}')" != "$PYTHON_SHA256" ]; then
  preflight_fail "Python SHA-256 mismatch"
fi
[ "$($CARGO --version)" = "$CARGO_VERSION" ] || preflight_fail "cargo version mismatch"
[ "$($RUSTC --version)" = "$RUSTC_VERSION" ] || preflight_fail "rustc version mismatch"
[ "$($PYTHON --version 2>&1)" = "$PYTHON_VERSION" ] || preflight_fail "Python version mismatch"

CPU_AFFINITY="$($PYTHON - <<'PY'
import os

if not hasattr(os, "sched_getaffinity"):
    raise SystemExit("sched_getaffinity is unavailable")
cpus = sorted(os.sched_getaffinity(0))
if len(cpus) != 1:
    raise SystemExit(f"expected one logical CPU, got {cpus}")
print(cpus[0])
PY
)" || preflight_fail "batch shell is not pinned to one logical CPU"
export CPU_AFFINITY

cd "$REPO_ROOT" || preflight_fail "cannot enter exact checkout"
ACTUAL_REVISION="$(git rev-parse HEAD^{commit})" || preflight_fail "cannot read checkout revision"
ACTUAL_TREE="$(git rev-parse HEAD^{tree})" || preflight_fail "cannot read checkout tree"
[ "$ACTUAL_REVISION" = "$EXPECTED_REVISION" ] || preflight_fail "revision mismatch"
[ "$ACTUAL_TREE" = "$EXPECTED_TREE" ] || preflight_fail "tree mismatch"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || preflight_fail "repository state is dirty"
[ "$(git rev-parse "$DESIGN_COMMIT^{commit}")" = "$DESIGN_COMMIT" ] \
  || preflight_fail "immutable design commit is unavailable"
[ "$(git rev-parse "$DESIGN_COMMIT^{tree}")" = "$DESIGN_TREE" ] \
  || preflight_fail "immutable design tree mismatch"
[ "$(git rev-parse "$DESIGN_COMMIT:$DESIGN_PATH")" = "$DESIGN_BLOB" ] \
  || preflight_fail "immutable design blob mismatch"
git cat-file blob "$DESIGN_BLOB" > "$RUN_ROOT/design-contract.md" \
  || preflight_fail "cannot preserve immutable design bytes"
[ "$(sha256sum "$RUN_ROOT/design-contract.md" | awk '{print $1}')" = "$DESIGN_SHA256" ] \
  || preflight_fail "immutable design byte hash mismatch"
chmod 0400 "$RUN_ROOT/design-contract.md" || preflight_fail "cannot freeze design bytes"

SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-$HOME/euf-viper/benchmarks/smtlib-2025}"
MANIFEST="${EUF_VIPER_T10_MANIFEST:-$SHARED_CORPUS/qf_uf_manifest.jsonl}"
CORPUS_ROOT="${EUF_VIPER_T10_CORPUS_ROOT:-$SHARED_CORPUS/QF_UF}"
CONTROL_MANIFEST="$REPO_ROOT/campaigns/t9-rollback-control-manifest-20260713.jsonl"
export MANIFEST CONTROL_MANIFEST
[ -s "$MANIFEST" ] || preflight_fail "missing accepted T10 manifest"
[ -d "$CORPUS_ROOT/QF_UF" ] || preflight_fail "missing QF_UF corpus root"
[ -s "$CONTROL_MANIFEST" ] || preflight_fail "missing frozen rollback control manifest"
[ "$(sha256sum "$MANIFEST" | awk '{print $1}')" = "$EXPECTED_MANIFEST_SHA256" ] \
  || preflight_fail "manifest SHA-256 mismatch"
[ "$(sha256sum "$CONTROL_MANIFEST" | awk '{print $1}')" = "$EXPECTED_CONTROL_MANIFEST_SHA256" ] \
  || preflight_fail "control manifest SHA-256 mismatch"
[ "$(wc -l < "$CONTROL_MANIFEST" | tr -d ' ')" = "24" ] \
  || preflight_fail "control manifest row count mismatch"
[ "$(wc -c < "$CONTROL_MANIFEST" | tr -d ' ')" = "12998" ] \
  || preflight_fail "control manifest byte count mismatch"

printf 'revision=%s\n' "$ACTUAL_REVISION" >&3
printf 'tree=%s\n' "$ACTUAL_TREE" >&3
printf 'cpu_affinity=%s\n' "$CPU_AFFINITY" >&3
printf 'manifest_sha256=%s\n' "$EXPECTED_MANIFEST_SHA256" >&3
printf 'source_set_sha256=%s\n' "$EXPECTED_SOURCE_SET_SHA256" >&3
printf 'design_sha256=%s\n' "$DESIGN_SHA256" >&3

RUN_STATUS="building"
export CARGO_TARGET_DIR="$RUN_ROOT/target"
"$CARGO" build --locked --all-features --release --jobs 1 \
  >"$RUN_ROOT/build.stdout" 2>"$RUN_ROOT/build.stderr"
BUILD_EXIT=$?
if [ "$BUILD_EXIT" -ne 0 ]; then
  RUN_STATUS="build_fail"
  SCIENTIFIC_STATUS="not_run"
  exit "$BUILD_EXIT"
fi
BINARY="$CARGO_TARGET_DIR/release/euf-viper"
export BINARY
[ -x "$BINARY" ] || preflight_fail "release binary was not produced"
BINARY_SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
BINARY_BYTES="$(wc -c < "$BINARY" | tr -d ' ')"
canonical_sha256 "$BINARY_SHA256" || preflight_fail "release binary SHA-256 is invalid"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] \
  || preflight_fail "build changed the exact checkout"

RUN_STATUS="census_running"
"$PYTHON" scripts/bench/run_t10_projection_census.py \
  "$MANIFEST" \
  --corpus-root "$CORPUS_ROOT" \
  --binary "$BINARY" \
  --records-out "$RUN_ROOT/records.jsonl" \
  --summary-out "$RUN_ROOT/summary.json" \
  --timeout-seconds 30 \
  >"$RUN_ROOT/census.stdout" 2>"$RUN_ROOT/census.stderr"
CENSUS_EXIT=$?
if [ "$CENSUS_EXIT" -ne 0 ]; then
  RUN_STATUS="scientific_fail"
  SCIENTIFIC_STATUS="census_fail"
  exit "$CENSUS_EXIT"
fi

RUN_STATUS="audit_running"
"$PYTHON" scripts/bench/audit_t10_projection_census.py \
  "$MANIFEST" \
  --corpus-root "$CORPUS_ROOT" \
  --binary "$BINARY" \
  --records "$RUN_ROOT/records.jsonl" \
  --summary "$RUN_ROOT/summary.json" \
  --receipt-out "$RUN_ROOT/audit-receipt.json" \
  >"$RUN_ROOT/audit.stdout" 2>"$RUN_ROOT/audit.stderr"
AUDIT_EXIT=$?
if [ "$AUDIT_EXIT" -ne 0 ]; then
  RUN_STATUS="scientific_fail"
  SCIENTIFIC_STATUS="audit_fail"
  exit "$AUDIT_EXIT"
fi

RUN_STATUS="gate_running"
"$PYTHON" - "$RUN_ROOT/audit-receipt.json" >"$RUN_ROOT/gate.stdout" 2>"$RUN_ROOT/gate.stderr" <<'PY'
import json
import math
import sys
from pathlib import Path


def reject_duplicate(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key}")
        result[key] = value
    return result


receipt = json.loads(
    Path(sys.argv[1]).read_text(encoding="ascii"),
    object_pairs_hook=reject_duplicate,
    parse_constant=lambda value: (_ for _ in ()).throw(
        ValueError(f"non-finite constant {value}")
    ),
)
if receipt.get("status") != "pass":
    raise SystemExit("T10 audit receipt is not a pass")
if receipt.get("source_count") != 7503 or receipt.get("qg_source_count") != 6396:
    raise SystemExit("T10 audit receipt population mismatch")
if receipt.get("selected_count") != 1 or receipt.get("replayed_selected_count") != 1:
    raise SystemExit("T10 selected/replayed population mismatch")
expected_path = (
    "QF_UF/2018-Goel-hwbench/"
    "QF_UF_sokoban.2.prop1_ab_br_max.smt2"
)
if receipt.get("selected_paths") != [expected_path]:
    raise SystemExit("T10 selected path mismatch")
if receipt.get("selected_projection_sha256") != receipt.get(
    "replayed_selected_projection_sha256"
):
    raise SystemExit("T10 selected replay digest mismatch")
binding = receipt.get("selected_projection_bindings")
if not isinstance(binding, list) or len(binding) != 1:
    raise SystemExit("T10 selected projection binding is missing")
row = binding[0]
if row.get("source_sha256") != (
    "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112"
):
    raise SystemExit("T10 selected source hash mismatch")
if not 1 <= row.get("closed_clauses", 0) <= 4096:
    raise SystemExit("T10 selected clause count is outside the gate")
if not 1 <= row.get("literal_slots", 0) <= 16384:
    raise SystemExit("T10 selected literal slots are outside the gate")
if not 1 <= row.get("max_clause_width", 0) <= 4:
    raise SystemExit("T10 selected clause width is outside the gate")
print("T10_STAGE0_PASS")
PY
GATE_EXIT=$?
if [ "$GATE_EXIT" -ne 0 ]; then
  RUN_STATUS="scientific_fail"
  SCIENTIFIC_STATUS="gate_fail"
  exit "$GATE_EXIT"
fi

RUN_STATUS="completed"
SCIENTIFIC_STATUS="pass"
printf 't10_census_root=%s\n' "$RUN_ROOT"
printf 't10_census_revision=%s\n' "$ACTUAL_REVISION"
printf 't10_census_tree=%s\n' "$ACTUAL_TREE"
printf 't10_census_binary_sha256=%s\n' "$BINARY_SHA256"
exit 0
