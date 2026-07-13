#!/usr/bin/env bash
#SBATCH --job-name=euf-kissat4-merge
#SBATCH --partition=cpu_idle
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=00:45:00
#SBATCH --output=results/kissat4-paired-merge-%j.out
#SBATCH --error=results/kissat4-paired-merge-%j.err

set -euo pipefail

ROOT="${SLURM_SUBMIT_DIR:-$PWD}"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export LANG=C
export LC_ALL=C
export TZ=UTC

# shellcheck source=euf_viper_kissat4_paired_common.sh
source "$ROOT/scripts/wmi/euf_viper_kissat4_paired_common.sh"

EXPECTED_REVISION="${EUF_VIPER_KISSAT4_EXPECTED_REVISION:?set EUF_VIPER_KISSAT4_EXPECTED_REVISION}"
EXPECTED_SCRIPT_BUNDLE="${EUF_VIPER_KISSAT4_SCRIPT_BUNDLE_SHA256:?set EUF_VIPER_KISSAT4_SCRIPT_BUNDLE_SHA256}"
VALIDATION_ROOT="${EUF_VIPER_KISSAT4_VALIDATION_ROOT:-$KISSAT4_DEFAULT_VALIDATION_ROOT}"
SOURCE_MANIFEST="${EUF_VIPER_KISSAT4_MANIFEST:?set EUF_VIPER_KISSAT4_MANIFEST}"
SOURCE_MANIFEST_SHA256="${EUF_VIPER_KISSAT4_MANIFEST_SHA256:?set EUF_VIPER_KISSAT4_MANIFEST_SHA256}"
RUN_ID="${EUF_VIPER_KISSAT4_RUN_ID:?set EUF_VIPER_KISSAT4_RUN_ID}"
SHARDS="${EUF_VIPER_KISSAT4_SHARDS:?set EUF_VIPER_KISSAT4_SHARDS}"
REPEATS="${EUF_VIPER_KISSAT4_REPEATS:-3}"
TIMEOUT="${EUF_VIPER_KISSAT4_TIMEOUT:-2}"
WARMUPS="${EUF_VIPER_KISSAT4_WARMUPS:-1}"
BROAD_MIN_PAIRED="${EUF_VIPER_KISSAT4_BROAD_MIN_PAIRED:-100}"
BROAD_MIN_SPEEDUP="${EUF_VIPER_KISSAT4_BROAD_MIN_SPEEDUP:-1.0}"
BROAD_MAX_P_VALUE="${EUF_VIPER_KISSAT4_BROAD_MAX_P_VALUE:-0.05}"
BROAD_ITERATIONS="${EUF_VIPER_KISSAT4_BROAD_ITERATIONS:-10000}"

kissat4_require_positive_int EUF_VIPER_KISSAT4_RUN_ID "$RUN_ID"
kissat4_require_positive_int EUF_VIPER_KISSAT4_SHARDS "$SHARDS"
kissat4_require_positive_int EUF_VIPER_KISSAT4_REPEATS "$REPEATS"
kissat4_require_positive_int EUF_VIPER_KISSAT4_TIMEOUT "$TIMEOUT"
kissat4_require_nonnegative_int EUF_VIPER_KISSAT4_WARMUPS "$WARMUPS"
kissat4_require_positive_int EUF_VIPER_KISSAT4_BROAD_MIN_PAIRED "$BROAD_MIN_PAIRED"
kissat4_require_positive_int EUF_VIPER_KISSAT4_BROAD_ITERATIONS "$BROAD_ITERATIONS"
kissat4_require_positive_decimal EUF_VIPER_KISSAT4_BROAD_MIN_SPEEDUP "$BROAD_MIN_SPEEDUP"
kissat4_require_probability EUF_VIPER_KISSAT4_BROAD_MAX_P_VALUE "$BROAD_MAX_P_VALUE"
[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || kissat4_die "SLURM_CPUS_PER_TASK must be exactly 1"
[ -n "${SLURM_JOB_ID:-}" ] || kissat4_die "SLURM_JOB_ID is required"
[ -f "$SOURCE_MANIFEST" ] || kissat4_die "missing source manifest: $SOURCE_MANIFEST"
[ "$(kissat4_sha256 "$SOURCE_MANIFEST")" = "$SOURCE_MANIFEST_SHA256" ] || \
  kissat4_die "source manifest changed after submission"
kissat4_check_repository "$EXPECTED_REVISION"
kissat4_check_script_bundle "$EXPECTED_SCRIPT_BUNDLE"
kissat4_check_binaries "$VALIDATION_ROOT"

if [ "${1:-}" != "--bound-step" ]; then
  SCRIPT="$ROOT/scripts/wmi/euf_viper_kissat4_paired_merge.sbatch"
  exec srun --exclusive --exact --nodes=1 --ntasks=1 --cpus-per-task=1 \
    --cpu-bind=threads /bin/bash "$SCRIPT" --bound-step
fi

kissat4_check_repository "$EXPECTED_REVISION"
kissat4_check_script_bundle "$EXPECTED_SCRIPT_BUNDLE"
kissat4_check_binaries "$VALIDATION_ROOT"

PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] && [ -x "$PYTHON" ] || kissat4_die "python3 is required"
AFFINITY_JSON="$($PYTHON - <<'PY_AFFINITY'
import json
import os

if not hasattr(os, "sched_getaffinity"):
    raise SystemExit("sched_getaffinity is required")
print(json.dumps(sorted(os.sched_getaffinity(0))))
PY_AFFINITY
)"
AFFINITY_COUNT="$($PYTHON -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$AFFINITY_JSON")"
[ "$AFFINITY_COUNT" = 1 ] || kissat4_die "Slurm step affinity is not exactly one CPU: $AFFINITY_JSON"

RUN_ROOT="$ROOT/results/kissat4-paired-$RUN_ID"
MERGE_ROOT="$RUN_ROOT/broad/merge"
mkdir -p "$MERGE_ROOT"
RUNTIME_ENV_FILE="$MERGE_ROOT/runtime.env"
SCRIPT_HASH_FILE="$MERGE_ROOT/script-sha256.txt"
printf '%s\n' "${KISSAT4_RUNTIME_SETTINGS[@]}" > "$RUNTIME_ENV_FILE"
kissat4_emit_script_hashes > "$SCRIPT_HASH_FILE"

CSV_INPUTS=()
SHARD_RESULTS=()
for ((index = 0; index < SHARDS; index++)); do
  padded="$(printf '%04d' "$index")"
  CSV_INPUTS+=("$RUN_ROOT/broad/shards/$padded/paired.csv")
  SHARD_RESULTS+=("$RUN_ROOT/broad/shards/$padded/result.json")
done

SHARD_AUDIT="$MERGE_ROOT/shard-audit.json"
"$PYTHON" - "$SHARD_AUDIT" "$RUN_ID" "$SHARDS" "$REPEATS" "$TIMEOUT" "$WARMUPS" "$EXPECTED_REVISION" \
  "$EXPECTED_SCRIPT_BUNDLE" "$SOURCE_MANIFEST_SHA256" "$RUNTIME_ENV_FILE" \
  "${SHARD_RESULTS[@]}" <<'PY_AUDIT'
import hashlib
import json
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_env(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        if key in result:
            raise SystemExit(f"duplicate expected runtime key: {key}")
        result[key] = value
    return result


out = Path(sys.argv[1])
run_id = int(sys.argv[2])
shards = int(sys.argv[3])
repeats = int(sys.argv[4])
timeout = int(sys.argv[5])
warmups = int(sys.argv[6])
revision = sys.argv[7]
script_bundle = sys.argv[8]
source_manifest_sha256 = sys.argv[9]
expected_environment = parse_env(Path(sys.argv[10]))
paths = list(map(Path, sys.argv[11:]))
if len(paths) != shards:
    raise SystemExit("shard result count mismatch")

records = []
for index, path in enumerate(paths):
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read shard result {path}: {error}")
    expected = {
        "status": "complete",
        "stage": "broad",
        "run_id": run_id,
        "revision": revision,
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise SystemExit(f"{path}: {key} mismatch")
    if record.get("sharding") != {"count": shards, "index": index}:
        raise SystemExit(f"{path}: sharding mismatch")
    if record.get("scripts", {}).get("bundle_sha256") != script_bundle:
        raise SystemExit(f"{path}: script bundle mismatch")
    if record.get("manifest", {}).get("source_sha256") != source_manifest_sha256:
        raise SystemExit(f"{path}: source manifest mismatch")
    environments = record.get("environments", {})
    if environments.get("solver") != expected_environment:
        raise SystemExit(f"{path}: solver environment mismatch")
    if environments.get("arms_identical") is not True:
        raise SystemExit(f"{path}: arm environments were not identical")
    execution = record.get("execution", {})
    if execution.get("repeats") != repeats:
        raise SystemExit(f"{path}: repeat count mismatch")
    if execution.get("timeout_s") != timeout:
        raise SystemExit(f"{path}: timeout mismatch")
    if execution.get("warmups") != warmups:
        raise SystemExit(f"{path}: warmup count mismatch")
    affinity = execution.get("affinity")
    if not isinstance(affinity, list) or len(affinity) != 1 or affinity != [execution.get("cpu_id")]:
        raise SystemExit(f"{path}: single-CPU affinity mismatch")
    binaries = record.get("binaries", {})
    expected_hashes = {
        "baseline": "d7321602b8cc86683ccb41e90bea7b843a5059caad62d1eba347bb3e69c70362",
        "candidate": "ecbcfebb1f39c725c1d0266442c7dcc80083b8347e3b77d90bfb5646bd4ea6b6",
    }
    for label, digest in expected_hashes.items():
        if binaries.get(label, {}).get("sha256") != digest:
            raise SystemExit(f"{path}: {label} binary mismatch")
    csv = Path(record.get("outputs", {}).get("csv", ""))
    manifest = Path(record.get("manifest", {}).get("path", ""))
    for artifact in (csv, manifest):
        if not artifact.is_file():
            raise SystemExit(f"{path}: missing artifact {artifact}")
        recorded = record.get("artifacts", {}).get(str(artifact.resolve()))
        if recorded != sha256(artifact):
            raise SystemExit(f"{path}: artifact SHA-256 mismatch for {artifact}")
    records.append(
        {
            "index": index,
            "result": str(path.resolve()),
            "result_sha256": sha256(path),
            "csv": str(csv.resolve()),
            "csv_sha256": sha256(csv),
            "manifest": str(manifest.resolve()),
            "manifest_sha256": sha256(manifest),
        }
    )

payload = {
    "schema_version": 1,
    "status": "complete",
    "run_id": run_id,
    "revision": revision,
    "shards": records,
}
temporary = out.with_name(f".{out.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(out)
PY_AUDIT

MERGED_CSV="$MERGE_ROOT/paired.csv"
MERGED_SUMMARY="$MERGE_ROOT/summary.json"
PROMOTION="$MERGE_ROOT/promotion.json"
RESULT="$MERGE_ROOT/result.json"
set +e
"$PYTHON" scripts/bench/merge_viper_ab.py "$SOURCE_MANIFEST" \
  "${CSV_INPUTS[@]}" \
  --repeats "$REPEATS" \
  --out "$MERGED_CSV" \
  --summary "$MERGED_SUMMARY"
MERGE_STATUS=$?
set -e

GATE_STATUS=-1
if [ "$MERGE_STATUS" = 0 ]; then
  set +e
  "$PYTHON" scripts/bench/paired_promotion_gate.py "$MERGED_CSV" \
    --out "$PROMOTION" \
    --seed "$KISSAT4_VALIDATION_JOB_ID" \
    --bootstrap-iterations "$BROAD_ITERATIONS" \
    --permutation-iterations "$BROAD_ITERATIONS" \
    --confidence-level 0.95 \
    --min-paired-instances "$BROAD_MIN_PAIRED" \
    --min-median-speedup "$BROAD_MIN_SPEEDUP" \
    --min-total-speedup "$BROAD_MIN_SPEEDUP" \
    --min-geometric-speedup "$BROAD_MIN_SPEEDUP" \
    --max-p-value "$BROAD_MAX_P_VALUE" \
    --allow-candidate-timeout-improvements
  GATE_STATUS=$?
  set -e
fi

export KISSAT4_MERGE_STATUS="$MERGE_STATUS"
export KISSAT4_GATE_STATUS="$GATE_STATUS"
export KISSAT4_AFFINITY_JSON="$AFFINITY_JSON"
export KISSAT4_EXPECTED_REVISION="$EXPECTED_REVISION"
export KISSAT4_EXPECTED_SCRIPT_BUNDLE="$EXPECTED_SCRIPT_BUNDLE"
export KISSAT4_RUN_ID="$RUN_ID"
export KISSAT4_SHARDS="$SHARDS"
export KISSAT4_SOURCE_MANIFEST_SHA256="$SOURCE_MANIFEST_SHA256"
export KISSAT4_VALIDATION_ROOT="$VALIDATION_ROOT"
export KISSAT4_TIMEOUT="$TIMEOUT"
export KISSAT4_REPEATS="$REPEATS"
export KISSAT4_WARMUPS="$WARMUPS"
export KISSAT4_BROAD_MIN_PAIRED="$BROAD_MIN_PAIRED"
export KISSAT4_BROAD_MIN_SPEEDUP="$BROAD_MIN_SPEEDUP"
export KISSAT4_BROAD_MAX_P_VALUE="$BROAD_MAX_P_VALUE"
export KISSAT4_BROAD_ITERATIONS="$BROAD_ITERATIONS"

"$PYTHON" - "$RESULT" "$SOURCE_MANIFEST" "$SCRIPT_HASH_FILE" "$RUNTIME_ENV_FILE" \
  "$SHARD_AUDIT" "$MERGED_CSV" "$MERGED_SUMMARY" "$PROMOTION" <<'PY_RESULT'
import hashlib
import json
import os
import platform
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


out, manifest, scripts_file, runtime_file, shard_audit, csv, summary, promotion = map(Path, sys.argv[1:])
merge_status = int(os.environ["KISSAT4_MERGE_STATUS"])
gate_status = int(os.environ["KISSAT4_GATE_STATUS"])
if merge_status != 0 or gate_status not in {0, 1}:
    status = "error"
elif gate_status == 1:
    status = "rejected"
else:
    status = "passed"
artifacts = {}
for path in (manifest, scripts_file, runtime_file, shard_audit, csv, summary, promotion):
    if path.is_file():
        artifacts[str(path.resolve())] = sha256(path)
script_hashes = {}
for line in scripts_file.read_text(encoding="utf-8").splitlines():
    digest, path = line.split("  ", 1)
    script_hashes[path] = digest
runtime = {}
for line in runtime_file.read_text(encoding="utf-8").splitlines():
    key, value = line.split("=", 1)
    runtime[key] = value

payload = {
    "schema_version": 1,
    "campaign": "kissat-sc2021-vs-kissat-4.0.4",
    "status": status,
    "stage": "broad-merge",
    "run_id": int(os.environ["KISSAT4_RUN_ID"]),
    "revision": os.environ["KISSAT4_EXPECTED_REVISION"],
    "validation": {
        "job_id": 144945,
        "revision": "d7c14dac90615717b06e063274c42296a46e01a3",
        "root": os.environ["KISSAT4_VALIDATION_ROOT"],
    },
    "binaries": {
        "baseline_sha256": "d7321602b8cc86683ccb41e90bea7b843a5059caad62d1eba347bb3e69c70362",
        "candidate_sha256": "ecbcfebb1f39c725c1d0266442c7dcc80083b8347e3b77d90bfb5646bd4ea6b6",
    },
    "manifest": {
        "path": str(manifest.resolve()),
        "sha256": os.environ["KISSAT4_SOURCE_MANIFEST_SHA256"],
    },
    "scripts": {
        "bundle_sha256": os.environ["KISSAT4_EXPECTED_SCRIPT_BUNDLE"],
        "files": script_hashes,
    },
    "solver_environment": runtime,
    "execution": {
        "merge_exit_code": merge_status,
        "gate_exit_code": gate_status,
        "affinity": json.loads(os.environ["KISSAT4_AFFINITY_JSON"]),
        "timeout_s": int(os.environ["KISSAT4_TIMEOUT"]),
        "repeats": int(os.environ["KISSAT4_REPEATS"]),
        "warmups": int(os.environ["KISSAT4_WARMUPS"]),
    },
    "gate": {
        "policy": "allow_candidate_timeout_improvements",
        "min_paired_instances": int(os.environ["KISSAT4_BROAD_MIN_PAIRED"]),
        "min_median_speedup": float(os.environ["KISSAT4_BROAD_MIN_SPEEDUP"]),
        "min_total_speedup": float(os.environ["KISSAT4_BROAD_MIN_SPEEDUP"]),
        "min_geometric_speedup": float(os.environ["KISSAT4_BROAD_MIN_SPEEDUP"]),
        "max_p_value": float(os.environ["KISSAT4_BROAD_MAX_P_VALUE"]),
        "bootstrap_iterations": int(os.environ["KISSAT4_BROAD_ITERATIONS"]),
        "permutation_iterations": int(os.environ["KISSAT4_BROAD_ITERATIONS"]),
    },
    "shards": int(os.environ["KISSAT4_SHARDS"]),
    "slurm": {
        "cluster_name": os.environ.get("SLURM_CLUSTER_NAME"),
        "cpus_per_task": int(os.environ["SLURM_CPUS_PER_TASK"]),
        "job_id": int(os.environ["SLURM_JOB_ID"]),
        "job_name": os.environ.get("SLURM_JOB_NAME"),
        "node_list": os.environ.get("SLURM_JOB_NODELIST"),
        "partition": os.environ.get("SLURM_JOB_PARTITION"),
        "step_id": os.environ.get("SLURM_STEP_ID"),
        "submit_dir": os.environ.get("SLURM_SUBMIT_DIR"),
        "hostname": platform.node(),
    },
    "outputs": {
        "csv": str(csv.resolve()),
        "summary": str(summary.resolve()),
        "promotion": str(promotion.resolve()),
        "shard_audit": str(shard_audit.resolve()),
        "result": str(out.resolve()),
    },
    "artifacts": artifacts,
}
temporary = out.with_name(f".{out.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(out)
print(json.dumps({"result": str(out), "stage": "broad-merge", "status": status}, sort_keys=True))
PY_RESULT

case "$MERGE_STATUS:$GATE_STATUS" in
  0:0) exit 0 ;;
  0:1) exit 1 ;;
  *) exit 2 ;;
esac
