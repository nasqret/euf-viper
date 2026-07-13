#!/bin/bash
#SBATCH --job-name=euf-rollback-audit
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --output=results/rollback-audit-%j.out
#SBATCH --error=results/rollback-audit-%j.err

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
[ "$((REPEATS % 2))" = 0 ] || { echo "repeats must form complete ABBA blocks" >&2; exit 2; }
if [ "${SLURM_CPUS_PER_TASK:-1}" != 1 ]; then
  echo "rollback audit requires exactly one allocated core" >&2
  exit 2
fi
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in rollback audit" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "repository must be completely clean in rollback audit" >&2
  exit 2
fi

PREPARE="$RUN_ROOT/prepare.json"
MANIFEST="$RUN_ROOT/control-manifest.jsonl"
BINARY="$RUN_ROOT/bin/euf-viper"
AUDITOR="$PWD/scripts/bench/audit_rollback_control.py"
FINAL_AUDIT="$RUN_ROOT/final-audit.json"
[ ! -e "$FINAL_AUDIT" ] || { echo "final rollback audit already exists" >&2; exit 2; }
BINARY_SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
MANIFEST_SHA256="$(sha256sum "$MANIFEST" | awk '{print $1}')"
AUDITOR_SHA256="$(sha256sum "$AUDITOR" | awk '{print $1}')"

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
  "$MANIFEST_SHA256" \
  "$BINARY" \
  "$BINARY_SHA256" \
  "$AUDITOR" \
  "$AUDITOR_SHA256" <<'PY_AUDIT_PREFLIGHT'
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
    manifest_hash,
    binary_raw,
    binary_hash,
    auditor_raw,
    auditor_hash,
) = sys.argv[1:]
prepare_path = Path(prepare_raw).resolve(strict=True)
prepare = json.loads(prepare_path.read_text(encoding="ascii"))
run_root = Path(run_root_raw).resolve(strict=True)
corpus_root = Path(corpus_root_raw).resolve(strict=True)
corpus_manifest = Path(corpus_manifest_raw).resolve(strict=True)
manifest = Path(manifest_raw).resolve(strict=True)
binary = Path(binary_raw).resolve(strict=True)
auditor = Path(auditor_raw).resolve(strict=True)
shards = int(shards_raw)

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
if manifest_hash != sha256_file(manifest):
    raise RuntimeError("rollback manifest changed during audit preflight")
workset = prepare.get("workset", {})
if workset.get("manifest") != str(manifest) or workset.get("manifest_sha256") != manifest_hash:
    raise RuntimeError("rollback workset binding drift")
if workset.get("target_count") != int(target_count_raw):
    raise RuntimeError("rollback target count drift")
if workset.get("anti_target_count") != int(anti_target_count_raw):
    raise RuntimeError("rollback anti-target count drift")
if prepare.get("binary") != {"path": str(binary), "binary_sha256": binary_hash}:
    raise RuntimeError("rollback binary binding drift")
if binary_hash != sha256_file(binary):
    raise RuntimeError("rollback binary changed during audit preflight")
if prepare.get("tools", {}).get("auditor") != {
    "path": str(auditor),
    "sha256": auditor_hash,
} or auditor_hash != sha256_file(auditor):
    raise RuntimeError("rollback auditor binding drift")
if prepare.get("campaign") != {
    "comparisons": ["current", "model-cuts", "dynamic"],
    "shards": shards,
    "timeout_s": positive_float(timeout_raw),
    "repeats": int(repeats_raw),
    "seed": seed,
    "max_anti_target_bytes": int(max_anti_bytes_raw),
    "abba_schedule": "baseline,candidate,candidate,baseline",
}:
    raise RuntimeError("rollback campaign configuration drift")
if prepare.get("gates") != {
    "minimum_target_speedup": positive_float(minimum_speedup_raw),
    "maximum_anti_p95_ratio": positive_float(maximum_anti_ratio_raw),
    "minimum_multi_round_targets": int(minimum_multi_round_raw),
    "require_conflict_evidence": True,
}:
    raise RuntimeError("rollback gate configuration drift")

rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
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
if hashlib.sha256(canonical_bytes(bindings)).hexdigest() != workset.get("source_set_sha256"):
    raise RuntimeError("selected source-set binding drift")

expected_paths: set[Path] = set()
for comparison in ("current", "model-cuts", "dynamic"):
    for shard in range(shards):
        prefix = run_root / "shards" / comparison / f"shard-{shard:04d}"
        journal = Path(f"{prefix}.jsonl")
        summary_path = Path(f"{prefix}-summary.json")
        affinity_path = Path(f"{prefix}-affinity.json")
        expected_paths.update((journal, summary_path, affinity_path))
        for path in (journal, summary_path, affinity_path):
            if not path.is_file():
                raise RuntimeError(f"missing rollback shard artifact {path}")
        summary = json.loads(summary_path.read_text(encoding="ascii"))
        claimed_summary_hash = summary.get("summary_sha256")
        summary_for_hash = dict(summary)
        summary_for_hash["summary_sha256"] = ""
        if hashlib.sha256(canonical_bytes(summary_for_hash)).hexdigest() != claimed_summary_hash:
            raise RuntimeError(f"summary self-hash mismatch: {summary_path}")
        if summary.get("journal_sha256") != sha256_file(journal):
            raise RuntimeError(f"summary journal hash mismatch: {summary_path}")
        if summary.get("manifest_sha256") != manifest_hash:
            raise RuntimeError(f"summary manifest hash mismatch: {summary_path}")
        if summary.get("binary_sha256") != binary_hash:
            raise RuntimeError(f"summary binary hash mismatch: {summary_path}")
        if summary.get("comparison") != comparison or summary.get("shard") != {
            "count": shards,
            "index": shard,
            "mechanism": "manifest-index-modulo",
        }:
            raise RuntimeError(f"summary comparison/shard mismatch: {summary_path}")
        first_line = journal.open("r", encoding="utf-8").readline()
        plan = json.loads(first_line)
        affinity = json.loads(affinity_path.read_text(encoding="ascii"))
        if affinity.get("comparison") != comparison or affinity.get("cpus_per_task") != 1:
            raise RuntimeError(f"affinity sidecar mismatch: {affinity_path}")
        if affinity.get("affinity") != plan.get("cpu_affinity", {}).get("cpu_ids"):
            raise RuntimeError(f"journal/affinity CPU mismatch: {journal}")
        if len(affinity.get("affinity", [])) != 1:
            raise RuntimeError(f"rollback shard was not pinned to one CPU: {journal}")

actual_paths = {path for path in (run_root / "shards").rglob("*") if path.is_file()}
if actual_paths != expected_paths:
    missing = sorted(str(path) for path in expected_paths - actual_paths)
    extra = sorted(str(path) for path in actual_paths - expected_paths)
    raise RuntimeError(f"rollback shard cross-product mismatch: missing={missing}, extra={extra}")
PY_AUDIT_PREFLIGHT

JOURNAL_ARGS=()
for comparison in current model-cuts dynamic; do
  for ((shard = 0; shard < SHARDS; shard++)); do
    PADDED="$(printf '%04d' "$shard")"
    JOURNAL_ARGS+=(--journal "$RUN_ROOT/shards/$comparison/shard-$PADDED.jsonl")
  done
done

set +e
srun --exclusive --ntasks=1 --cpus-per-task=1 --cpu-bind=cores \
  /bin/bash -c 'exec "$@"' bash \
  python3 "$AUDITOR" \
  "$MANIFEST" \
  "${JOURNAL_ARGS[@]}" \
  --repeats "$REPEATS" \
  --minimum-multi-round-targets "$MINIMUM_MULTI_ROUND_TARGETS" \
  --target-speedup "$MINIMUM_TARGET_SPEEDUP" \
  --anti-target-overhead "$MAXIMUM_ANTI_P95_RATIO" \
  --require-single-cpu \
  --out "$FINAL_AUDIT"
AUDIT_STATUS=$?
set -e
if [ ! -s "$FINAL_AUDIT" ]; then
  echo "rollback auditor did not emit a final artifact" >&2
  exit 2
fi
chmod 0444 "$FINAL_AUDIT"
exit "$AUDIT_STATUS"
