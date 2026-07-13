#!/bin/bash
#SBATCH --job-name=euf-rollback-control
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=12:00:00
#SBATCH --output=results/rollback-control-%A_%a.out
#SBATCH --error=results/rollback-control-%A_%a.err

set -euo pipefail
umask 077

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export RAYON_NUM_THREADS=1

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

if [ "${1:-}" = "--bound-child" ]; then
  [ "$#" -ge 4 ] || { echo "bound child requires affinity path, comparison, and command" >&2; exit 2; }
  AFFINITY_PATH="$2"
  CHILD_COMPARISON="$3"
  shift 3
  python3 - "$AFFINITY_PATH" "$CHILD_COMPARISON" <<'PY_AFFINITY'
import json
import os
import platform
import sys
from pathlib import Path

output = Path(sys.argv[1])
if output.exists():
    raise SystemExit(f"refusing to overwrite affinity evidence {output}")
affinity = sorted(os.sched_getaffinity(0))
if not affinity:
    raise SystemExit("bound child has an empty CPU affinity")
payload = {
    "schema": "euf-viper.rollback-control-affinity.v1",
    "affinity": affinity,
    "affinity_count": len(affinity),
    "comparison": sys.argv[2],
    "cpus_per_task": int(os.environ.get("SLURM_CPUS_PER_TASK", "0")),
    "host": platform.node(),
    "slurm_array_job_id": os.environ.get("SLURM_ARRAY_JOB_ID"),
    "slurm_array_task_id": os.environ.get("SLURM_ARRAY_TASK_ID"),
    "slurm_job_id": os.environ.get("SLURM_JOB_ID"),
}
temporary = output.with_name(f".{output.name}.tmp")
temporary.write_text(
    json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True)
    + "\n",
    encoding="ascii",
)
temporary.replace(output)
PY_AFFINITY
  exec "$@"
fi

canonical_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

canonical_nonnegative_integer() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
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
[ "$((REPEATS % 2))" = 0 ] || { echo "repeats must form complete ABBA blocks" >&2; exit 2; }
TASK_ID="${SLURM_ARRAY_TASK_ID:?rollback control must run as an array task}"
canonical_nonnegative_integer "$TASK_ID" || { echo "invalid array task id" >&2; exit 2; }
COMPARISON_COUNT=3
TOTAL_TASKS=$((COMPARISON_COUNT * SHARDS))
if [ "$TASK_ID" -ge "$TOTAL_TASKS" ]; then
  echo "array task $TASK_ID is outside the three-comparison shard cross-product" >&2
  exit 2
fi
if [ "${SLURM_CPUS_PER_TASK:-1}" != 1 ]; then
  echo "rollback control requires exactly one allocated core" >&2
  exit 2
fi
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in rollback control" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "repository must be completely clean in rollback control" >&2
  exit 2
fi

CURRENT=current
MODEL_CUTS=model-cuts
DYNAMIC=dynamic
COMPARISONS=("$CURRENT" "$MODEL_CUTS" "$DYNAMIC")
COMPARISON_INDEX=$((TASK_ID / SHARDS))
SHARD_INDEX=$((TASK_ID % SHARDS))
COMPARISON="${COMPARISONS[$COMPARISON_INDEX]}"
PADDED="$(printf '%04d' "$SHARD_INDEX")"
PREPARE="$RUN_ROOT/prepare.json"
MANIFEST="$RUN_ROOT/control-manifest.jsonl"
BINARY="$RUN_ROOT/bin/euf-viper"
RUNNER="$PWD/scripts/bench/compare_rollback_control.py"
OUTPUT_DIRECTORY="$RUN_ROOT/shards/$COMPARISON"
JOURNAL="$OUTPUT_DIRECTORY/shard-$PADDED.jsonl"
SUMMARY="$OUTPUT_DIRECTORY/shard-$PADDED-summary.json"
AFFINITY="$OUTPUT_DIRECTORY/shard-$PADDED-affinity.json"

mkdir -p "$OUTPUT_DIRECTORY"
for path in "$JOURNAL" "$SUMMARY" "$AFFINITY"; do
  [ ! -e "$path" ] || { echo "refusing to overwrite rollback shard artifact $path" >&2; exit 2; }
done

python3 - \
  "$PREPARE" \
  "$EXPECTED_REVISION" \
  "$RUN_ROOT" \
  "$CORPUS_ROOT" \
  "$CORPUS_MANIFEST" \
  "$EXPECTED_SOURCES" \
  "$TARGET_COUNT" \
  "$ANTI_TARGET_COUNT" \
  "$SHARDS" \
  "$TIMEOUT_S" \
  "$REPEATS" \
  "$SEED" \
  "$MAX_ANTI_TARGET_BYTES" \
  "$MINIMUM_TARGET_SPEEDUP" \
  "$MAXIMUM_ANTI_P95_RATIO" \
  "$MINIMUM_MULTI_ROUND_TARGETS" \
  "$MANIFEST" \
  "$BINARY" \
  "$RUNNER" <<'PY_PREFLIGHT'
import hashlib
import json
import math
import sys
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


def positive_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value) or value <= 0:
        raise RuntimeError("campaign threshold is not finite and positive")
    return value


(
    prepare_raw,
    revision,
    run_root_raw,
    corpus_root_raw,
    corpus_manifest_raw,
    expected_sources_raw,
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
    manifest_raw,
    binary_raw,
    runner_raw,
) = sys.argv[1:]
prepare_path = Path(prepare_raw).resolve(strict=True)
prepare = json.loads(prepare_path.read_text(encoding="ascii"))
run_root = Path(run_root_raw).resolve(strict=True)
corpus_root = Path(corpus_root_raw).resolve(strict=True)
corpus_manifest = Path(corpus_manifest_raw).resolve(strict=True)
manifest = Path(manifest_raw).resolve(strict=True)
binary = Path(binary_raw).resolve(strict=True)
runner = Path(runner_raw).resolve(strict=True)

if prepare.get("schema") != "euf-viper.rollback-control-prepare.v1":
    raise RuntimeError("unexpected rollback prepare schema")
if prepare.get("revision") != revision or prepare.get("run_root") != str(run_root):
    raise RuntimeError("rollback prepare revision or run-root drift")
if prepare.get("corpus") != {
    "root": str(corpus_root),
    "manifest": str(corpus_manifest),
    "manifest_sha256": sha256_file(corpus_manifest),
    "source_count": int(expected_sources_raw),
}:
    raise RuntimeError("rollback corpus binding drift")
workset = prepare.get("workset", {})
if workset.get("manifest") != str(manifest):
    raise RuntimeError("rollback workset path drift")
if workset.get("manifest_sha256") != sha256_file(manifest):
    raise RuntimeError("rollback workset manifest hash drift")
if workset.get("target_count") != int(target_count_raw):
    raise RuntimeError("rollback target count drift")
if workset.get("anti_target_count") != int(anti_target_count_raw):
    raise RuntimeError("rollback anti-target count drift")
if prepare.get("binary") != {
    "path": str(binary),
    "binary_sha256": sha256_file(binary),
}:
    raise RuntimeError("rollback binary binding drift")
if prepare.get("tools", {}).get("runner") != {
    "path": str(runner),
    "sha256": sha256_file(runner),
}:
    raise RuntimeError("rollback runner binding drift")
expected_campaign = {
    "comparisons": ["current", "model-cuts", "dynamic"],
    "shards": int(shards_raw),
    "timeout_s": positive_float(timeout_raw),
    "repeats": int(repeats_raw),
    "seed": seed,
    "max_anti_target_bytes": int(max_anti_bytes_raw),
    "abba_schedule": "baseline,candidate,candidate,baseline",
}
if prepare.get("campaign") != expected_campaign:
    raise RuntimeError("rollback campaign configuration drift")
expected_gates = {
    "minimum_target_speedup": positive_float(minimum_speedup_raw),
    "maximum_anti_p95_ratio": positive_float(maximum_anti_ratio_raw),
    "minimum_multi_round_targets": int(minimum_multi_round_raw),
    "require_conflict_evidence": True,
}
if prepare.get("gates") != expected_gates:
    raise RuntimeError("rollback gate configuration drift")

rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
if len(rows) != int(target_count_raw) + int(anti_target_count_raw):
    raise RuntimeError("rollback workset row count drift")
bindings = []
for row in rows:
    source = (corpus_root / row["relative_path"]).resolve(strict=True)
    if source.stat().st_size != row["bytes"] or sha256_file(source) != row["sha256"]:
        raise RuntimeError(f"selected source drift: {row['relative_path']}")
    bindings.append(
        {
            "bytes": row["bytes"],
            "control_class": row["control_class"],
            "relative_path": row["relative_path"],
            "sha256": row["sha256"],
            "status": row["status"],
        }
    )
source_set_sha256 = hashlib.sha256(canonical_bytes(bindings)).hexdigest()
if workset.get("source_set_sha256") != source_set_sha256:
    raise RuntimeError("selected source-set binding drift")
PY_PREFLIGHT

srun --exclusive --ntasks=1 --cpus-per-task=1 --cpu-bind=cores \
  /bin/bash "$PWD/scripts/wmi/euf_viper_rollback_control.sbatch" \
  --bound-child "$AFFINITY" "$COMPARISON" \
  python3 "$RUNNER" \
  "$MANIFEST" \
  --binary "$BINARY" \
  --comparison "$COMPARISON" \
  --timeout "$TIMEOUT_S" \
  --repeats "$REPEATS" \
  --require-single-cpu \
  --shard-index "$SHARD_INDEX" \
  --shard-count "$SHARDS" \
  --corpus-root "$CORPUS_ROOT" \
  --out "$JOURNAL" \
  --summary "$SUMMARY"

python3 - "$AFFINITY" "$COMPARISON" <<'PY_VERIFY_AFFINITY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
if payload.get("schema") != "euf-viper.rollback-control-affinity.v1":
    raise SystemExit("invalid rollback affinity evidence schema")
if payload.get("comparison") != sys.argv[2]:
    raise SystemExit("rollback affinity comparison drift")
if payload.get("cpus_per_task") != 1 or not payload.get("affinity"):
    raise SystemExit("rollback comparison lacks one-core affinity evidence")
PY_VERIFY_AFFINITY

chmod 0444 "$JOURNAL" "$SUMMARY" "$AFFINITY"
