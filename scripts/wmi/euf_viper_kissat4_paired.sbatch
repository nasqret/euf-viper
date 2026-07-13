#!/usr/bin/env bash
#SBATCH --job-name=euf-kissat4-paired
#SBATCH --partition=cpu_idle
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=results/kissat4-paired-%A_%a.out
#SBATCH --error=results/kissat4-paired-%A_%a.err

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
STAGE="${EUF_VIPER_KISSAT4_STAGE:?set EUF_VIPER_KISSAT4_STAGE to sample or broad}"

case "$STAGE" in
  sample|broad) ;;
  *) kissat4_die "stage must be sample or broad" ;;
esac
[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || kissat4_die "SLURM_CPUS_PER_TASK must be exactly 1"
[ -n "${SLURM_JOB_ID:-}" ] || kissat4_die "SLURM_JOB_ID is required"
[ -f "$SOURCE_MANIFEST" ] || kissat4_die "missing source manifest: $SOURCE_MANIFEST"
[ "$(kissat4_sha256 "$SOURCE_MANIFEST")" = "$SOURCE_MANIFEST_SHA256" ] || \
  kissat4_die "source manifest changed after submission"
kissat4_check_repository "$EXPECTED_REVISION"
kissat4_check_script_bundle "$EXPECTED_SCRIPT_BUNDLE"
kissat4_check_binaries "$VALIDATION_ROOT"

if [ "${1:-}" != "--bound-step" ]; then
  SCRIPT="$ROOT/scripts/wmi/euf_viper_kissat4_paired.sbatch"
  exec srun --exclusive --exact --nodes=1 --ntasks=1 --cpus-per-task=1 \
    --cpu-bind=threads bash "$SCRIPT" --bound-step
fi

# Recheck immutable inputs inside the timed step, after Slurm has established
# the CPU affinity inherited by every solver child.
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
CPU_ID="$($PYTHON -c 'import json,sys; print(json.loads(sys.argv[1])[0])' "$AFFINITY_JSON")"

if [ "$STAGE" = sample ]; then
  RUN_ID="${EUF_VIPER_KISSAT4_RUN_ID:-$SLURM_JOB_ID}"
  [ "$RUN_ID" = "$SLURM_JOB_ID" ] || \
    kissat4_die "sample run id must equal its SLURM job id"
  SAMPLE_LIMIT="${EUF_VIPER_KISSAT4_SAMPLE_LIMIT:-64}"
  SAMPLE_SEED="${EUF_VIPER_KISSAT4_SAMPLE_SEED:-144945}"
  SAMPLE_MIN_PAIRED="${EUF_VIPER_KISSAT4_SAMPLE_MIN_PAIRED:-20}"
  SAMPLE_MIN_SPEEDUP="${EUF_VIPER_KISSAT4_SAMPLE_MIN_SPEEDUP:-0.95}"
  kissat4_require_positive_int EUF_VIPER_KISSAT4_SAMPLE_LIMIT "$SAMPLE_LIMIT"
  kissat4_require_nonnegative_int EUF_VIPER_KISSAT4_SAMPLE_SEED "$SAMPLE_SEED"
  kissat4_require_positive_int EUF_VIPER_KISSAT4_SAMPLE_MIN_PAIRED "$SAMPLE_MIN_PAIRED"
  kissat4_require_positive_decimal EUF_VIPER_KISSAT4_SAMPLE_MIN_SPEEDUP "$SAMPLE_MIN_SPEEDUP"
  [ "$SAMPLE_MIN_PAIRED" -le "$SAMPLE_LIMIT" ] || \
    kissat4_die "sample minimum paired count exceeds sample limit"
  STAGE_ROOT="$ROOT/results/kissat4-paired-$RUN_ID/sample"
  MANIFEST="$STAGE_ROOT/manifest.jsonl"
  mkdir -p "$STAGE_ROOT"
  kissat4_make_sample_manifest "$SOURCE_MANIFEST" "$SAMPLE_LIMIT" "$SAMPLE_SEED" "$MANIFEST"
  SHARD_INDEX=""
  SHARDS=""
else
  RUN_ID="${EUF_VIPER_KISSAT4_RUN_ID:?set EUF_VIPER_KISSAT4_RUN_ID}"
  SHARDS="${EUF_VIPER_KISSAT4_SHARDS:?set EUF_VIPER_KISSAT4_SHARDS}"
  SHARD_INDEX="${SLURM_ARRAY_TASK_ID:?broad stage requires an array task id}"
  kissat4_require_positive_int EUF_VIPER_KISSAT4_RUN_ID "$RUN_ID"
  kissat4_require_positive_int EUF_VIPER_KISSAT4_SHARDS "$SHARDS"
  kissat4_require_nonnegative_int SLURM_ARRAY_TASK_ID "$SHARD_INDEX"
  [ "$SHARD_INDEX" -lt "$SHARDS" ] || kissat4_die "array index is outside shard range"
  PADDED_INDEX="$(printf '%04d' "$SHARD_INDEX")"
  STAGE_ROOT="$ROOT/results/kissat4-paired-$RUN_ID/broad/shards/$PADDED_INDEX"
  MANIFEST="$STAGE_ROOT/manifest.jsonl"
  mkdir -p "$STAGE_ROOT"
  "$PYTHON" scripts/bench/shard_manifest.py "$SOURCE_MANIFEST" \
    --shards "$SHARDS" --index "$SHARD_INDEX" --out "$MANIFEST"
fi

MANIFEST_SHA256="$(kissat4_sha256 "$MANIFEST")"
kissat4_verify_manifest "$MANIFEST" "$MANIFEST_SHA256" "$STAGE_ROOT/manifest-verification.json"

TIMEOUT="${EUF_VIPER_KISSAT4_TIMEOUT:-2}"
REPEATS="${EUF_VIPER_KISSAT4_REPEATS:-3}"
WARMUPS="${EUF_VIPER_KISSAT4_WARMUPS:-1}"
kissat4_require_positive_int EUF_VIPER_KISSAT4_TIMEOUT "$TIMEOUT"
kissat4_require_positive_int EUF_VIPER_KISSAT4_REPEATS "$REPEATS"
kissat4_require_nonnegative_int EUF_VIPER_KISSAT4_WARMUPS "$WARMUPS"

RUNTIME_ENV_FILE="$STAGE_ROOT/runtime.env"
UNSET_ENV_FILE="$STAGE_ROOT/explicitly-unset.env"
BASE_ENV_FILE="$STAGE_ROOT/base.env"
SCRIPT_HASH_FILE="$STAGE_ROOT/script-sha256.txt"
printf '%s\n' "${KISSAT4_RUNTIME_SETTINGS[@]}" > "$RUNTIME_ENV_FILE"
printf '%s\n' "${KISSAT4_EXPLICITLY_UNSET[@]}" > "$UNSET_ENV_FILE"
kissat4_emit_script_hashes > "$SCRIPT_HASH_FILE"

BASE_ENV=(
  "HOME=$HOME"
  "LANG=C"
  "LC_ALL=C"
  "OMP_NUM_THREADS=1"
  "OPENBLAS_NUM_THREADS=1"
  "MKL_NUM_THREADS=1"
  "PATH=/usr/bin:/bin"
  "PYTHONHASHSEED=0"
  "RUST_BACKTRACE=0"
  "TZ=UTC"
  "EUF_VIPER_GIT_REVISION=$EXPECTED_REVISION"
  "SLURM_ARRAY_JOB_ID=${SLURM_ARRAY_JOB_ID:-}"
  "SLURM_ARRAY_TASK_ID=${SLURM_ARRAY_TASK_ID:-}"
  "SLURM_CLUSTER_NAME=${SLURM_CLUSTER_NAME:-}"
  "SLURM_CPUS_PER_TASK=${SLURM_CPUS_PER_TASK:-}"
  "SLURM_JOB_ID=${SLURM_JOB_ID:-}"
  "SLURM_JOB_NAME=${SLURM_JOB_NAME:-}"
  "SLURM_JOB_NODELIST=${SLURM_JOB_NODELIST:-}"
  "SLURM_JOB_PARTITION=${SLURM_JOB_PARTITION:-}"
  "SLURM_STEP_ID=${SLURM_STEP_ID:-}"
  "SLURM_SUBMIT_DIR=${SLURM_SUBMIT_DIR:-}"
)
printf '%s\n' "${BASE_ENV[@]}" > "$BASE_ENV_FILE"

AB_ENV_ARGS=()
for setting in "${KISSAT4_RUNTIME_SETTINGS[@]}"; do
  AB_ENV_ARGS+=(--baseline-env "$setting" --candidate-env "$setting")
done

CSV="$STAGE_ROOT/paired.csv"
SUMMARY="$STAGE_ROOT/summary.json"
PROMOTION="$STAGE_ROOT/promotion.json"
RESULT="$STAGE_ROOT/result.json"
set +e
env -i "${BASE_ENV[@]}" "$PYTHON" scripts/bench/compare_viper_ab.py \
  "$MANIFEST" \
  --baseline "$KISSAT4_SC2021_BIN" \
  --candidate "$KISSAT4_MODERN_BIN" \
  "${AB_ENV_ARGS[@]}" \
  --timeout "$TIMEOUT" \
  --repeats "$REPEATS" \
  --warmups "$WARMUPS" \
  --out "$CSV" \
  --summary "$SUMMARY"
COMPARE_STATUS=$?
set -e

GATE_STATUS=-1
if [ "$STAGE" = sample ] && [ "$COMPARE_STATUS" = 0 ]; then
  set +e
  "$PYTHON" scripts/bench/paired_promotion_gate.py "$CSV" \
    --out "$PROMOTION" \
    --seed "$SAMPLE_SEED" \
    --bootstrap-iterations 2000 \
    --permutation-iterations 2000 \
    --confidence-level 0.95 \
    --min-paired-instances "$SAMPLE_MIN_PAIRED" \
    --min-median-speedup "$SAMPLE_MIN_SPEEDUP" \
    --min-total-speedup "$SAMPLE_MIN_SPEEDUP" \
    --min-geometric-speedup "$SAMPLE_MIN_SPEEDUP" \
    --max-p-value 1.0 \
    --allow-candidate-timeout-improvements
  GATE_STATUS=$?
  set -e
fi

export KISSAT4_RESULT_STAGE="$STAGE"
export KISSAT4_RESULT_RUN_ID="$RUN_ID"
export KISSAT4_RESULT_SHARDS="$SHARDS"
export KISSAT4_RESULT_SHARD_INDEX="$SHARD_INDEX"
export KISSAT4_RESULT_CPU_ID="$CPU_ID"
export KISSAT4_RESULT_AFFINITY_JSON="$AFFINITY_JSON"
export KISSAT4_RESULT_COMPARE_STATUS="$COMPARE_STATUS"
export KISSAT4_RESULT_GATE_STATUS="$GATE_STATUS"
export KISSAT4_RESULT_MANIFEST_SHA256="$MANIFEST_SHA256"
export KISSAT4_RESULT_SOURCE_MANIFEST="$SOURCE_MANIFEST"
export KISSAT4_RESULT_SOURCE_MANIFEST_SHA256="$SOURCE_MANIFEST_SHA256"
export KISSAT4_RESULT_EXPECTED_REVISION="$EXPECTED_REVISION"
export KISSAT4_RESULT_SCRIPT_BUNDLE="$EXPECTED_SCRIPT_BUNDLE"
export KISSAT4_RESULT_TIMEOUT="$TIMEOUT"
export KISSAT4_RESULT_REPEATS="$REPEATS"
export KISSAT4_RESULT_WARMUPS="$WARMUPS"
export KISSAT4_RESULT_VALIDATION_ROOT="$VALIDATION_ROOT"
export KISSAT4_RESULT_SAMPLE_LIMIT="${SAMPLE_LIMIT:-}"
export KISSAT4_RESULT_SAMPLE_SEED="${SAMPLE_SEED:-}"
export KISSAT4_RESULT_SAMPLE_MIN_PAIRED="${SAMPLE_MIN_PAIRED:-}"
export KISSAT4_RESULT_SAMPLE_MIN_SPEEDUP="${SAMPLE_MIN_SPEEDUP:-}"

"$PYTHON" - "$RESULT" "$MANIFEST" "$STAGE_ROOT/manifest-verification.json" \
  "$RUNTIME_ENV_FILE" "$UNSET_ENV_FILE" "$BASE_ENV_FILE" "$SCRIPT_HASH_FILE" \
  "$CSV" "$SUMMARY" "$PROMOTION" <<'PY_RESULT'
import hashlib
import json
import os
import platform
import sys
from pathlib import Path


def parse_env(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        if key in result:
            raise SystemExit(f"duplicate environment key: {key}")
        result[key] = value
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


out, manifest, manifest_verification, runtime_file, unset_file, base_file, scripts_file, csv, summary, promotion = map(Path, sys.argv[1:])
compare_status = int(os.environ["KISSAT4_RESULT_COMPARE_STATUS"])
gate_status = int(os.environ["KISSAT4_RESULT_GATE_STATUS"])
stage = os.environ["KISSAT4_RESULT_STAGE"]
if compare_status != 0:
    status = "error"
elif stage == "sample" and gate_status == 1:
    status = "rejected"
elif stage == "sample" and gate_status != 0:
    status = "error"
else:
    status = "passed" if stage == "sample" else "complete"

script_hashes = {}
for line in scripts_file.read_text(encoding="utf-8").splitlines():
    digest, path = line.split("  ", 1)
    script_hashes[path] = digest
artifacts = {}
for path in (manifest, manifest_verification, runtime_file, unset_file, base_file, scripts_file, csv, summary, promotion):
    if path.is_file():
        artifacts[str(path.resolve())] = sha256(path)

payload = {
    "schema_version": 1,
    "campaign": "kissat-sc2021-vs-kissat-4.0.4",
    "status": status,
    "stage": stage,
    "run_id": int(os.environ["KISSAT4_RESULT_RUN_ID"]),
    "revision": os.environ["KISSAT4_RESULT_EXPECTED_REVISION"],
    "validation": {
        "job_id": 144945,
        "revision": "d7c14dac90615717b06e063274c42296a46e01a3",
        "root": os.environ["KISSAT4_RESULT_VALIDATION_ROOT"],
    },
    "binaries": {
        "baseline": {
            "name": "euf-viper-kissat-sc2021",
            "path": str((Path(os.environ["KISSAT4_RESULT_VALIDATION_ROOT"]) / "euf-viper-kissat-sc2021").resolve()),
            "sha256": "d7321602b8cc86683ccb41e90bea7b843a5059caad62d1eba347bb3e69c70362",
            "version": "euf-viper 0.1.0 (sat=kissat-sc2021)",
        },
        "candidate": {
            "name": "euf-viper-kissat-4.0.4",
            "path": str((Path(os.environ["KISSAT4_RESULT_VALIDATION_ROOT"]) / "euf-viper-kissat-4.0.4").resolve()),
            "sha256": "ecbcfebb1f39c725c1d0266442c7dcc80083b8347e3b77d90bfb5646bd4ea6b6",
            "version": "euf-viper 0.1.0 (sat=kissat-4.0.4)",
        },
    },
    "manifest": {
        "path": str(manifest.resolve()),
        "sha256": os.environ["KISSAT4_RESULT_MANIFEST_SHA256"],
        "source_path": str(Path(os.environ["KISSAT4_RESULT_SOURCE_MANIFEST"]).resolve()),
        "source_sha256": os.environ["KISSAT4_RESULT_SOURCE_MANIFEST_SHA256"],
    },
    "scripts": {
        "bundle_sha256": os.environ["KISSAT4_RESULT_SCRIPT_BUNDLE"],
        "files": script_hashes,
    },
    "environments": {
        "base": parse_env(base_file),
        "solver": parse_env(runtime_file),
        "explicitly_unset": unset_file.read_text(encoding="utf-8").splitlines(),
        "arms_identical": True,
    },
    "execution": {
        "timeout_s": int(os.environ["KISSAT4_RESULT_TIMEOUT"]),
        "repeats": int(os.environ["KISSAT4_RESULT_REPEATS"]),
        "warmups": int(os.environ["KISSAT4_RESULT_WARMUPS"]),
        "compare_exit_code": compare_status,
        "gate_exit_code": gate_status,
        "cpu_id": int(os.environ["KISSAT4_RESULT_CPU_ID"]),
        "affinity": json.loads(os.environ["KISSAT4_RESULT_AFFINITY_JSON"]),
    },
    "gate": {
        "policy": "allow_candidate_timeout_improvements" if stage == "sample" else None,
        "sample_limit": int(os.environ["KISSAT4_RESULT_SAMPLE_LIMIT"]) if stage == "sample" else None,
        "sample_seed": int(os.environ["KISSAT4_RESULT_SAMPLE_SEED"]) if stage == "sample" else None,
        "min_paired_instances": int(os.environ["KISSAT4_RESULT_SAMPLE_MIN_PAIRED"]) if stage == "sample" else None,
        "min_median_speedup": float(os.environ["KISSAT4_RESULT_SAMPLE_MIN_SPEEDUP"]) if stage == "sample" else None,
        "min_total_speedup": float(os.environ["KISSAT4_RESULT_SAMPLE_MIN_SPEEDUP"]) if stage == "sample" else None,
        "min_geometric_speedup": float(os.environ["KISSAT4_RESULT_SAMPLE_MIN_SPEEDUP"]) if stage == "sample" else None,
        "max_p_value": 1.0 if stage == "sample" else None,
    },
    "sharding": {
        "count": int(os.environ["KISSAT4_RESULT_SHARDS"]) if os.environ["KISSAT4_RESULT_SHARDS"] else None,
        "index": int(os.environ["KISSAT4_RESULT_SHARD_INDEX"]) if os.environ["KISSAT4_RESULT_SHARD_INDEX"] else None,
    },
    "slurm": {
        "array_job_id": os.environ.get("SLURM_ARRAY_JOB_ID"),
        "array_task_id": os.environ.get("SLURM_ARRAY_TASK_ID"),
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
        "promotion": str(promotion.resolve()) if stage == "sample" else None,
        "manifest_verification": str(manifest_verification.resolve()),
        "result": str(out.resolve()),
    },
    "artifacts": artifacts,
}
temporary = out.with_name(f".{out.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(out)
print(json.dumps({"result": str(out), "stage": stage, "status": status}, sort_keys=True))
PY_RESULT

case "$COMPARE_STATUS:$STAGE:$GATE_STATUS" in
  0:sample:0|0:broad:-1) exit 0 ;;
  0:sample:1) exit 1 ;;
  *) exit 2 ;;
esac
