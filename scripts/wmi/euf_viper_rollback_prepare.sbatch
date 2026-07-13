#!/bin/bash
#SBATCH --job-name=euf-rollback-prepare
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=results/rollback-prepare-%j.out
#SBATCH --error=results/rollback-prepare-%j.err

set -euo pipefail
umask 077

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export LANG=C
export LC_ALL=C
export TZ=UTC
export CARGO_BUILD_JOBS=1
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export RAYON_NUM_THREADS=1

PYTHON_BIN="$(command -v python3)"
[ -n "$PYTHON_BIN" ] && [ -x "$PYTHON_BIN" ] || {
  echo "rollback preparation requires an executable python3" >&2
  exit 2
}

EXPECTED_REVISION="${EUF_VIPER_ROLLBACK_EXPECTED_REVISION:?set expected revision}"
RUN_ROOT="${EUF_VIPER_ROLLBACK_RUN_ROOT:?set rollback run root}"
CORPUS_ROOT="${EUF_VIPER_ROLLBACK_CORPUS_ROOT:?set corpus root}"
CORPUS_MANIFEST="${EUF_VIPER_ROLLBACK_CORPUS_MANIFEST:?set corpus manifest}"
EXPECTED_SOURCES="${EUF_VIPER_ROLLBACK_EXPECTED_SOURCES:?set expected source count}"
TARGET_COUNT="${EUF_VIPER_ROLLBACK_TARGET_COUNT:?set target count}"
ANTI_TARGET_COUNT="${EUF_VIPER_ROLLBACK_ANTI_TARGET_COUNT:?set anti-target count}"
SHARDS="${EUF_VIPER_ROLLBACK_SHARDS:?set shard count}"
TIMEOUT_S="${EUF_VIPER_ROLLBACK_TIMEOUT_S:?set timeout}"
REPEATS="${EUF_VIPER_ROLLBACK_REPEATS:?set repeats}"
SEED="${EUF_VIPER_ROLLBACK_SEED:?set selection seed}"
MAX_ANTI_TARGET_BYTES="${EUF_VIPER_ROLLBACK_MAX_ANTI_TARGET_BYTES:?set anti-target byte cap}"
MINIMUM_TARGET_SPEEDUP="${EUF_VIPER_ROLLBACK_MINIMUM_TARGET_SPEEDUP:?set target speed gate}"
MAXIMUM_ANTI_P95_RATIO="${EUF_VIPER_ROLLBACK_MAXIMUM_ANTI_P95_RATIO:?set anti-target gate}"
MINIMUM_MULTI_ROUND_TARGETS="${EUF_VIPER_ROLLBACK_MINIMUM_MULTI_ROUND_TARGETS:?set multi-round gate}"

canonical_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

for value in \
  "$EXPECTED_SOURCES" \
  "$TARGET_COUNT" \
  "$ANTI_TARGET_COUNT" \
  "$SHARDS" \
  "$REPEATS" \
  "$MAX_ANTI_TARGET_BYTES" \
  "$MINIMUM_MULTI_ROUND_TARGETS"; do
  canonical_positive_integer "$value" || { echo "invalid positive integer: $value" >&2; exit 2; }
done
[ "$TARGET_COUNT" = 12 ] || { echo "expected exactly 12 rollback targets" >&2; exit 2; }
[ "$ANTI_TARGET_COUNT" = 12 ] || { echo "expected exactly 12 anti-targets" >&2; exit 2; }
[ "$((ANTI_TARGET_COUNT % 2))" = 0 ] || { echo "anti-target count must be balanced" >&2; exit 2; }
[ "$((REPEATS % 2))" = 0 ] || { echo "repeats must form complete ABBA blocks" >&2; exit 2; }
if [ "${SLURM_CPUS_PER_TASK:-1}" != 1 ]; then
  echo "rollback preparation requires exactly one allocated core" >&2
  exit 2
fi
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in rollback preparation" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "repository must be completely clean in rollback preparation" >&2
  exit 2
fi
if [ ! -d "$CORPUS_ROOT/QF_UF" ] || [ ! -s "$CORPUS_MANIFEST" ]; then
  echo "rollback corpus root or source manifest is missing" >&2
  exit 2
fi
if [ ! -d "$RUN_ROOT" ]; then
  echo "submitter must reserve the rollback run root" >&2
  exit 2
fi
if [ -n "$(find "$RUN_ROOT" -mindepth 1 -print -quit)" ]; then
  echo "rollback run root is not empty; use a new run ID" >&2
  exit 2
fi

BUILDER="$PWD/scripts/bench/build_rollback_control_manifest.py"
RUNNER="$PWD/scripts/bench/compare_rollback_control.py"
AUDITOR="$PWD/scripts/bench/audit_rollback_control.py"
for tool in "$BUILDER" "$RUNNER" "$AUDITOR"; do
  [ -f "$tool" ] || { echo "missing rollback campaign tool: $tool" >&2; exit 2; }
done

mkdir "$RUN_ROOT/bin" "$RUN_ROOT/shards"
cargo build --release --locked
install -m 0555 target/release/euf-viper "$RUN_ROOT/bin/euf-viper"
BINARY_SHA256="$(sha256sum "$RUN_ROOT/bin/euf-viper" | awk '{print $1}')"
CORPUS_MANIFEST_SHA256="$(sha256sum "$CORPUS_MANIFEST" | awk '{print $1}')"
BUILDER_SHA256="$(sha256sum "$BUILDER" | awk '{print $1}')"
RUNNER_SHA256="$(sha256sum "$RUNNER" | awk '{print $1}')"
AUDITOR_SHA256="$(sha256sum "$AUDITOR" | awk '{print $1}')"
CARGO_LOCK_SHA256="$(sha256sum Cargo.lock | awk '{print $1}')"

CONTROL_MANIFEST="$RUN_ROOT/control-manifest.jsonl"
CONTROL_SUMMARY="$RUN_ROOT/control-manifest-summary.json"
"$PYTHON_BIN" "$BUILDER" \
  "$CORPUS_MANIFEST" \
  --out "$CONTROL_MANIFEST" \
  --summary "$CONTROL_SUMMARY" \
  --corpus-root "$CORPUS_ROOT" \
  --anti-targets-per-status "$((ANTI_TARGET_COUNT / 2))" \
  --max-anti-target-bytes "$MAX_ANTI_TARGET_BYTES" \
  --seed "$SEED"

PREFLIGHT_JOURNAL="$RUN_ROOT/preflight.jsonl"
PREFLIGHT_SUMMARY="$RUN_ROOT/preflight-summary.json"
CONTROL_ROWS=$((TARGET_COUNT + ANTI_TARGET_COUNT))
srun --exclusive --ntasks=1 --cpus-per-task=1 --cpu-bind=cores \
  "$PYTHON_BIN" "$RUNNER" \
  "$CONTROL_MANIFEST" \
  --binary "$RUN_ROOT/bin/euf-viper" \
  --comparison current \
  --timeout 5 \
  --repeats 2 \
  --require-single-cpu \
  --shard-index "$TARGET_COUNT" \
  --shard-count "$CONTROL_ROWS" \
  --corpus-root "$CORPUS_ROOT" \
  --out "$PREFLIGHT_JOURNAL" \
  --summary "$PREFLIGHT_SUMMARY"

"$PYTHON_BIN" - "$PREFLIGHT_SUMMARY" <<'PY_PREFLIGHT_GATE'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
if summary.get("schema_version") != "rollback-control-summary-v1":
    raise SystemExit("rollback preflight has an unexpected summary schema")
if summary.get("comparison") != "current":
    raise SystemExit("rollback preflight comparison drift")
if summary.get("observations") != 4 or summary.get("expected_observations") != 4:
    raise SystemExit("rollback preflight did not complete one exact ABBA block")
if summary.get("outcomes") != {
    "baseline": {"correct": 2},
    "candidate": {"correct": 2},
}:
    raise SystemExit("rollback preflight has a wrong, unsupported, or missing result")
PY_PREFLIGHT_GATE

"$PYTHON_BIN" - \
  "$RUN_ROOT/prepare.json" \
  "$EXPECTED_REVISION" \
  "$RUN_ROOT" \
  "$CORPUS_ROOT" \
  "$CORPUS_MANIFEST" \
  "$CORPUS_MANIFEST_SHA256" \
  "$EXPECTED_SOURCES" \
  "$CONTROL_MANIFEST" \
  "$CONTROL_SUMMARY" \
  "$PREFLIGHT_JOURNAL" \
  "$PREFLIGHT_SUMMARY" \
  "$RUN_ROOT/bin/euf-viper" \
  "$BINARY_SHA256" \
  "$BUILDER" \
  "$BUILDER_SHA256" \
  "$RUNNER" \
  "$RUNNER_SHA256" \
  "$AUDITOR" \
  "$AUDITOR_SHA256" \
  "$CARGO_LOCK_SHA256" \
  "$(cargo --version)" \
  "$(rustc --version)" \
  "$TARGET_COUNT" \
  "$ANTI_TARGET_COUNT" \
  "$SHARDS" \
  "$TIMEOUT_S" \
  "$REPEATS" \
  "$SEED" \
  "$MAX_ANTI_TARGET_BYTES" \
  "$MINIMUM_TARGET_SPEEDUP" \
  "$MAXIMUM_ANTI_P95_RATIO" \
  "$MINIMUM_MULTI_ROUND_TARGETS" <<'PY_PREPARE'
import hashlib
import json
import math
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def positive_float(raw: str, label: str) -> float:
    value = float(raw)
    if not math.isfinite(value) or value <= 0:
        raise RuntimeError(f"{label} must be finite and positive")
    return value


def atomic_write(path: Path, payload: bytes) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to overwrite {path}")
    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


(
    output_raw,
    revision,
    run_root_raw,
    corpus_root_raw,
    corpus_manifest_raw,
    corpus_manifest_hash,
    expected_sources_raw,
    control_manifest_raw,
    control_summary_raw,
    preflight_journal_raw,
    preflight_summary_raw,
    binary_raw,
    binary_hash,
    builder_raw,
    builder_hash,
    runner_raw,
    runner_hash,
    auditor_raw,
    auditor_hash,
    cargo_lock_hash,
    cargo_version,
    rustc_version,
    target_count_raw,
    anti_target_count_raw,
    shards_raw,
    timeout_raw,
    repeats_raw,
    seed,
    max_anti_bytes_raw,
    minimum_speedup_raw,
    maximum_anti_ratio_raw,
    minimum_multi_round_raw,
) = sys.argv[1:]

output = Path(output_raw).resolve()
run_root = Path(run_root_raw).resolve(strict=True)
corpus_root = Path(corpus_root_raw).resolve(strict=True)
corpus_manifest = Path(corpus_manifest_raw).resolve(strict=True)
control_manifest = Path(control_manifest_raw).resolve(strict=True)
control_summary = Path(control_summary_raw).resolve(strict=True)
preflight_journal = Path(preflight_journal_raw).resolve(strict=True)
preflight_summary = Path(preflight_summary_raw).resolve(strict=True)
binary = Path(binary_raw).resolve(strict=True)
builder = Path(builder_raw).resolve(strict=True)
runner = Path(runner_raw).resolve(strict=True)
auditor = Path(auditor_raw).resolve(strict=True)

if output.parent != run_root:
    raise RuntimeError("prepare manifest must be written directly in the run root")
if sha256_file(corpus_manifest) != corpus_manifest_hash:
    raise RuntimeError("corpus manifest changed during preparation")
if sha256_file(binary) != binary_hash:
    raise RuntimeError("prepared binary changed during preparation")
for path, expected in (
    (builder, builder_hash),
    (runner, runner_hash),
    (auditor, auditor_hash),
):
    if sha256_file(path) != expected:
        raise RuntimeError(f"campaign tool changed during preparation: {path}")

source_lines = corpus_manifest.read_text(encoding="utf-8").splitlines()
expected_sources = int(expected_sources_raw)
if len(source_lines) != expected_sources:
    raise RuntimeError(
        f"source population mismatch: expected {expected_sources}, got {len(source_lines)}"
    )
selected = [json.loads(line) for line in control_manifest.read_text(encoding="utf-8").splitlines()]
target_count = int(target_count_raw)
anti_target_count = int(anti_target_count_raw)
counts = Counter(row.get("control_class") for row in selected)
if counts != Counter({"target": target_count, "anti-target": anti_target_count}):
    raise RuntimeError(f"control class counts are wrong: {dict(counts)}")
relative_paths = [row.get("relative_path") for row in selected]
if len(relative_paths) != len(set(relative_paths)) or any(
    type(path) is not str for path in relative_paths
):
    raise RuntimeError("control manifest has duplicate or malformed relative paths")
if relative_paths[:target_count] != sorted(relative_paths[:target_count]):
    raise RuntimeError("target portion of control manifest is not canonically ordered")

source_bindings = [
    {
        "bytes": row["bytes"],
        "control_class": row["control_class"],
        "relative_path": row["relative_path"],
        "sha256": row["sha256"],
        "status": row["status"],
    }
    for row in selected
]
source_set_sha256 = hashlib.sha256(canonical_bytes(source_bindings)).hexdigest()
summary = json.loads(control_summary.read_text(encoding="ascii"))
manifest_sha256 = sha256_file(control_manifest)
if summary.get("output_manifest_sha256") != manifest_sha256:
    raise RuntimeError("control manifest summary hash mismatch")

payload = {
    "schema": "euf-viper.rollback-control-prepare.v1",
    "revision": revision,
    "run_root": str(run_root),
    "corpus": {
        "root": str(corpus_root),
        "manifest": str(corpus_manifest),
        "manifest_sha256": corpus_manifest_hash,
        "source_count": len(source_lines),
    },
    "workset": {
        "manifest": str(control_manifest),
        "manifest_sha256": manifest_sha256,
        "summary": str(control_summary),
        "summary_sha256": sha256_file(control_summary),
        "source_set_sha256": source_set_sha256,
        "target_count": target_count,
        "anti_target_count": anti_target_count,
        "rows": len(selected),
    },
    "preflight": {
        "comparison": "current",
        "journal": str(preflight_journal),
        "journal_sha256": sha256_file(preflight_journal),
        "summary": str(preflight_summary),
        "summary_sha256": sha256_file(preflight_summary),
        "manifest_index": target_count,
        "repeats": 2,
        "timeout_s": 5.0,
    },
    "binary": {"path": str(binary), "binary_sha256": binary_hash},
    "tools": {
        "builder": {"path": str(builder), "sha256": builder_hash},
        "runner": {"path": str(runner), "sha256": runner_hash},
        "auditor": {"path": str(auditor), "sha256": auditor_hash},
    },
    "build": {
        "cargo_lock_sha256": cargo_lock_hash,
        "cargo_version": cargo_version,
        "rustc_version": rustc_version,
    },
    "campaign": {
        "comparisons": ["current", "model-cuts", "dynamic"],
        "shards": int(shards_raw),
        "timeout_s": positive_float(timeout_raw, "timeout"),
        "repeats": int(repeats_raw),
        "seed": seed,
        "max_anti_target_bytes": int(max_anti_bytes_raw),
        "abba_schedule": "baseline,candidate,candidate,baseline",
    },
    "gates": {
        "minimum_target_speedup": positive_float(
            minimum_speedup_raw, "minimum target speedup"
        ),
        "maximum_anti_p95_ratio": positive_float(
            maximum_anti_ratio_raw, "maximum anti-target p95 ratio"
        ),
        "minimum_multi_round_targets": int(minimum_multi_round_raw),
        "require_conflict_evidence": True,
    },
    "performance_claims": [],
}
atomic_write(output, canonical_bytes(payload))
PY_PREPARE

chmod 0444 \
  "$CONTROL_MANIFEST" \
  "$CONTROL_SUMMARY" \
  "$PREFLIGHT_JOURNAL" \
  "$PREFLIGHT_SUMMARY" \
  "$RUN_ROOT/prepare.json"
