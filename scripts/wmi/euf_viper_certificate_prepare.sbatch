#!/usr/bin/env bash
#SBATCH --job-name=euf-cert-prepare
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --output=results/certificate-prepare-%j.out
#SBATCH --error=results/certificate-prepare-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1

EXPECTED_REVISION="${EUF_VIPER_CERT_EXPECTED_REVISION:?set EUF_VIPER_CERT_EXPECTED_REVISION}"
RUN_ROOT="${EUF_VIPER_CERT_RUN_ROOT:?set EUF_VIPER_CERT_RUN_ROOT}"
PARENT_LOCK="${EUF_VIPER_CERT_BASE_PARENT_LOCK:?set EUF_VIPER_CERT_BASE_PARENT_LOCK}"
SHARD_LOCK_DIR="${EUF_VIPER_CERT_BASE_SHARD_LOCK_DIR:?set EUF_VIPER_CERT_BASE_SHARD_LOCK_DIR}"
SHARD_RESULTS_ROOT="${EUF_VIPER_CERT_BASE_SHARD_RESULTS_ROOT:?set EUF_VIPER_CERT_BASE_SHARD_RESULTS_ROOT}"
SHARDS="${EUF_VIPER_CERT_SHARDS:?set EUF_VIPER_CERT_SHARDS}"
CHECKER="${EUF_VIPER_CERT_CHECKER:?set EUF_VIPER_CERT_CHECKER}"
CHECKER_SHA256="${EUF_VIPER_CERT_CHECKER_SHA256:?set EUF_VIPER_CERT_CHECKER_SHA256}"
DRAT_TRIM="${EUF_VIPER_CERT_DRAT_TRIM:?set EUF_VIPER_CERT_DRAT_TRIM}"
DRAT_TRIM_SHA256="${EUF_VIPER_CERT_DRAT_TRIM_SHA256:?set EUF_VIPER_CERT_DRAT_TRIM_SHA256}"
CORPUS_ROOT="${EUF_VIPER_CERT_CORPUS_ROOT:-}"
TIMEOUT_S="${EUF_VIPER_CERT_TIMEOUT_S:-60}"
CHECKER_TIMEOUT_S="${EUF_VIPER_CERT_CHECKER_TIMEOUT_S:-60}"
TIMEOUT_GRACE_S="${EUF_VIPER_CERT_TIMEOUT_GRACE_S:-0.25}"
STAGE_LABEL="${EUF_VIPER_CERT_STAGE_LABEL:-base-2s}"
EXPECTED_BUDGET="${EUF_VIPER_CERT_EXPECTED_BUDGET:-2}"

case "$SHARDS" in
  ''|0|0*|*[!0-9]*)
    echo "EUF_VIPER_CERT_SHARDS must be a canonical positive integer" >&2
    exit 2
    ;;
esac
if [ "${SLURM_CPUS_PER_TASK:-1}" != 1 ]; then
  echo "certificate preparation requires exactly one allocated core" >&2
  exit 2
fi
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in certificate preparation" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "repository must be completely clean in certificate preparation" >&2
  exit 2
fi
case "$STAGE_LABEL" in ''|*[!A-Za-z0-9._-]*) echo "invalid certificate stage label" >&2; exit 2 ;; esac
if [ -e "$RUN_ROOT/$STAGE_LABEL-audit.json" ]; then
  echo "certificate run already has a final audit; use a new run ID" >&2
  exit 2
fi

mkdir -p "$RUN_ROOT/shards"

python3 - \
  "$PARENT_LOCK" \
  "$SHARD_LOCK_DIR" \
  "$SHARD_RESULTS_ROOT" \
  "$RUN_ROOT/prepare.json" \
  "$EXPECTED_REVISION" \
  "$SHARDS" \
  "$CHECKER" \
  "$CHECKER_SHA256" \
  "$DRAT_TRIM" \
  "$DRAT_TRIM_SHA256" \
  "$CORPUS_ROOT" \
  "$TIMEOUT_S" \
  "$CHECKER_TIMEOUT_S" \
  "$TIMEOUT_GRACE_S" \
  "$STAGE_LABEL" \
  "$EXPECTED_BUDGET" <<'PY_PREPARE'
import collections
import importlib.util
import math
import sys
from pathlib import Path


ROOT = Path.cwd().resolve()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def positive_float(raw: str, label: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise RuntimeError(f"{label} must be a number") from error
    if not math.isfinite(value) or value <= 0:
        raise RuntimeError(f"{label} must be finite and positive")
    return value


def nonnegative_float(raw: str, label: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise RuntimeError(f"{label} must be a number") from error
    if not math.isfinite(value) or value < 0:
        raise RuntimeError(f"{label} must be finite and non-negative")
    return value


def resolve_existing(raw: str, label: str, *, directory: bool = False) -> Path:
    try:
        path = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeError(f"cannot resolve {label}: {error}") from error
    expected = path.is_dir() if directory else path.is_file()
    if not expected:
        kind = "directory" if directory else "file"
        raise RuntimeError(f"{label} is not a {kind}: {path}")
    if "\n" in str(path) or "\r" in str(path):
        raise RuntimeError(f"{label} contains a line break")
    return path


(
    parent_raw,
    lock_dir_raw,
    results_root_raw,
    output_raw,
    revision,
    shard_count_raw,
    checker_raw,
    checker_hash,
    drat_raw,
    drat_hash,
    corpus_root_raw,
    timeout_raw,
    checker_timeout_raw,
    grace_raw,
    stage_label,
    expected_budget_raw,
) = sys.argv[1:]

shadow = load_module(
    "certificate_shadow_prepare",
    ROOT / "scripts" / "cert" / "shadow_campaign.py",
)
analyzer = load_module(
    "certificate_shadow_analyzer",
    ROOT / "scripts" / "bench" / "analyze_campaign.py",
)

parent_lock = resolve_existing(parent_raw, "base parent lock")
lock_dir = resolve_existing(lock_dir_raw, "base shard lock directory", directory=True)
results_root = resolve_existing(
    results_root_raw, "base shard results root", directory=True
)
output = Path(output_raw).expanduser().resolve()
shard_count = int(shard_count_raw)
timeout_s = positive_float(timeout_raw, "certificate timeout")
checker_timeout_s = positive_float(checker_timeout_raw, "checker timeout")
timeout_grace_s = nonnegative_float(grace_raw, "timeout grace")
expected_budget_s = positive_float(expected_budget_raw, "expected stage budget")
corpus_root = (
    resolve_existing(corpus_root_raw, "corpus root", directory=True)
    if corpus_root_raw
    else None
)

if not shadow._is_sha256(checker_hash):
    raise RuntimeError("checker SHA-256 is not canonical")
if not shadow._is_sha256(drat_hash):
    raise RuntimeError("drat-trim SHA-256 is not canonical")
checker = shadow.resolve_executable(checker_raw, "certificate checker")
drat_trim = shadow.resolve_executable(drat_raw, "drat-trim")
if shadow.sha256_file(checker) != checker_hash:
    raise RuntimeError("certificate checker SHA-256 mismatch")
if shadow.sha256_file(drat_trim) != drat_hash:
    raise RuntimeError("drat-trim SHA-256 mismatch")

try:
    shard_pairs = analyzer.discover_shard_pairs(lock_dir, results_root)
    campaign = analyzer.load_sharded_locked_campaign(parent_lock, shard_pairs)
except analyzer.CampaignInputError as error:
    raise RuntimeError(
        "base global sharded campaign validation failed: " + "; ".join(error.errors)
    ) from error
if len(shard_pairs) != shard_count:
    raise RuntimeError(
        f"base shard count mismatch: discovered {len(shard_pairs)}, expected {shard_count}"
    )

base_lock = campaign["lock"]
if [float(value) for value in base_lock["budgets_s"]] != [expected_budget_s]:
    raise RuntimeError("certificate shadow source budget differs from the expected physical stage")

candidate = shadow._candidate_solver(campaign["lock"])
global_selected = set()
for (relative_path, _budget_s, solver_id), observation in campaign[
    "observations"
].items():
    if solver_id != "euf-viper":
        continue
    if observation["binary_sha256"] != candidate["sha256"]:
        raise RuntimeError(f"candidate binary hash drift for {relative_path!r}")
    if (
        observation["result"] in shadow.DECISIVE_RESULTS
        and observation["result"] == observation["expected_status"]
    ):
        global_selected.add(relative_path)
selected_union = set()
selection_records = []
selected_works = []
shard_records = []
selected_results = collections.Counter()
for provenance in campaign["shards"]:
    index = provenance["index"]
    lock_path = Path(provenance["lock"]).resolve(strict=True)
    raw_path = Path(provenance["raw"]).resolve(strict=True)
    child = shadow.load_validated_campaign(lock_path, raw_path)
    works = shadow.derive_work_records(
        child, lock_path, corpus_root=corpus_root
    )
    selected_works.extend(works)
    child_candidate = shadow._candidate_solver(child["lock"])
    if child_candidate["sha256"] != candidate["sha256"]:
        raise RuntimeError(f"candidate solver hash differs in base shard {index}")
    binary = shadow.resolve_executable(
        child_candidate["binary"], f"base shard {index} euf-viper binary"
    )
    if shadow.sha256_file(binary) != candidate["sha256"]:
        raise RuntimeError(f"candidate binary bytes drift in base shard {index}")

    for work in works:
        relative_path = work["relative_path"]
        if relative_path in selected_union:
            raise RuntimeError(f"duplicate selected base row {relative_path!r}")
        selected_union.add(relative_path)
        selected_results[work["expected_result"]] += 1
        selection_records.append(
            {
                "relative_path": relative_path,
                "source_sha256": work["source_sha256"],
                "expected_result": work["expected_result"],
                "decisive_budgets_s": work["decisive_budgets_s"],
            }
        )

    shard_records.append(
        {
            "index": index,
            "lock": str(lock_path),
            "lock_file_sha256": provenance["lock_file_sha256"],
            "lock_sha256": provenance["lock_sha256"],
            "raw": str(raw_path),
            "raw_sha256": provenance["raw_sha256"],
            "raw_records": provenance["raw_records"],
            "binary": str(binary),
            "binary_sha256": candidate["sha256"],
            "selected_instances": len(works),
            "workset_sha256": shadow.sha256_bytes(
                shadow.canonical_bytes([work["work_sha256"] for work in works])
            ),
        }
    )

if selected_union != global_selected:
    missing = sorted(global_selected - selected_union)
    extra = sorted(selected_union - global_selected)
    raise RuntimeError(
        "selected child/global row mismatch: "
        f"missing={missing[:10]!r}, extra={extra[:10]!r}"
    )
if [item["index"] for item in shard_records] != list(range(shard_count)):
    raise RuntimeError("base shard indices are not the exact contiguous array")

selection_records.sort(key=lambda item: item["relative_path"])
parser_canary = shadow.validate_independent_parser_workset(selected_works)
if parser_canary["selected_instances"] != len(selection_records):
    raise RuntimeError("independent parser canary selection cardinality mismatch")
payload = {
    "schema_version": 1,
    "status": "validated",
    "scope": "single_physical_stage_certificate_coverage_only",
    "revision": revision,
    "base": {
        "parent_lock": str(parent_lock),
        "parent_lock_file_sha256": campaign["lock_file_sha256"],
        "parent_lock_sha256": campaign["lock"]["lock_sha256"],
        "shard_bundle_sha256": campaign["shard_bundle_sha256"],
        "raw_records": campaign["raw_records"],
        "shards": shard_records,
    },
    "tools": {
        "checker": {"path": str(checker), "sha256": checker_hash},
        "drat_trim": {"path": str(drat_trim), "sha256": drat_hash},
    },
    "configuration": {
        "corpus_root": str(corpus_root) if corpus_root is not None else None,
        "timeout_s": timeout_s,
        "checker_timeout_s": checker_timeout_s,
        "timeout_grace_s": timeout_grace_s,
        "certificate_partition": "validated_base_shard_index",
        "physical_stage": stage_label,
        "budget_s": expected_budget_s,
        "certificate_shards": shard_count,
        "cpus_per_task": 1,
    },
    "selection": {
        "selected_instances": len(selection_records),
        "selected_results": dict(sorted(selected_results.items())),
        "selection_sha256": shadow.sha256_bytes(
            shadow.canonical_bytes(selection_records)
        ),
    },
    "parser_canary": parser_canary,
}
shadow._atomic_write(output, shadow.canonical_bytes(payload))
print(f"validated_base_bundle={campaign['shard_bundle_sha256']}")
print(f"selected_instances={len(selection_records)}")
print(f"parser_canary_sha256={parser_canary['workset_sha256']}")
print(f"prepare_manifest={output}")
PY_PREPARE
