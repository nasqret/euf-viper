#!/usr/bin/env bash
#SBATCH --job-name=euf-t6-dag-census
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=32G
#SBATCH --time=02:00:00
#SBATCH --output=results/t6-bool-dag-census-%j.out
#SBATCH --error=results/t6-bool-dag-census-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
EXPECTED_MANIFEST_SHA256="${EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256:?set EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256}"
ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi

MANIFEST="${EUF_VIPER_T6_MANIFEST:-$PWD/campaigns/t6-theory-dag-hard10-v1.json}"
CORPUS_ROOT="${EUF_VIPER_T6_CORPUS_ROOT:?set EUF_VIPER_T6_CORPUS_ROOT}"
if [ ! -s "$MANIFEST" ]; then
  echo "missing frozen T6 manifest: $MANIFEST" >&2
  exit 2
fi
if [ ! -d "$CORPUS_ROOT" ]; then
  echo "missing T6 corpus root: $CORPUS_ROOT" >&2
  exit 2
fi
ACTUAL_MANIFEST_SHA256="$(sha256sum "$MANIFEST" | awk '{print $1}')"
if [ "$ACTUAL_MANIFEST_SHA256" != "$EXPECTED_MANIFEST_SHA256" ]; then
  echo "manifest hash mismatch: expected $EXPECTED_MANIFEST_SHA256, got $ACTUAL_MANIFEST_SHA256" >&2
  exit 2
fi

OUT="$PWD/results/t6-bool-dag-census-${SLURM_JOB_ID}"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-t6-${SLURM_JOB_ID}}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SCRATCH_ROOT/target}"
export RUST_MIN_STACK="${EUF_VIPER_T6_STACK_BYTES:-134217728}"
export EUF_VIPER_T6_MANIFEST="$MANIFEST"
export EUF_VIPER_T6_CORPUS_ROOT="$CORPUS_ROOT"
export EUF_VIPER_T6_OUTPUT="$OUT/report.json"
export EUF_VIPER_EXPECTED_REVISION="$EXPECTED_REVISION"
mkdir -p "$OUT"

cargo test --release --all-features \
  t6_bool_dag_census::tests::hard10_census_from_env \
  -- --ignored --exact --nocapture \
  > "$OUT/run.txt"

python3 - "$OUT/metadata.json" "$OUT/report.json" "$OUT/run.txt" "$MANIFEST" <<'PY'
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


metadata_path, report_path, run_path, manifest_path = map(Path, sys.argv[1:])
report = json.loads(report_path.read_text(encoding="ascii"))
if report.get("schema") != "euf-viper.t6-theory-dag-census.v1":
    raise SystemExit("unexpected T6 report schema")
if report.get("analysis_revision") != os.environ["EUF_VIPER_EXPECTED_REVISION"]:
    raise SystemExit("T6 report revision mismatch")
manifest = report.get("manifest")
if not isinstance(manifest, dict) or manifest.get("sources") != 10:
    raise SystemExit("T6 report does not contain exactly 10 frozen sources")
if manifest.get("canonical_path_list_sha256") != (
    "43f367dfa7bc1684cb48828415249b59779416d17ad1fb2af50d4c8366bf2523"
):
    raise SystemExit("T6 report path-list digest mismatch")
sources = report.get("sources")
if not isinstance(sources, list) or len(sources) != 10:
    raise SystemExit("T6 report source array mismatch")
if [row.get("sequence") for row in sources] != list(range(10)):
    raise SystemExit("T6 report source sequence mismatch")
for row in sources:
    projections = row.get("projections")
    if not isinstance(projections, dict) or set(projections) != {
        "A_tree_no_sharing",
        "B_generic_source_dag",
        "C_root_union_dag",
        "D_full_typed_euf_dag",
    }:
        raise SystemExit("T6 report projection-arm mismatch")
    for projection in projections.values():
        cnf = projection.get("cnf")
        if not isinstance(cnf, dict):
            raise SystemExit("T6 report projection has no CNF accounting")
        required = {
            "variables",
            "clauses",
            "literal_slots",
            "unit_clauses",
            "two_watch_entries",
        }
        if not required.issubset(cnf):
            raise SystemExit("T6 report projection accounting is incomplete")
gate = report.get("gate")
if not isinstance(gate, dict) or gate.get("decision") not in {"pass", "reject"}:
    raise SystemExit("T6 report gate decision is invalid")
if gate.get("required_qualifying_sources") != 8:
    raise SystemExit("T6 report qualifying-source threshold drift")
qualifying = gate.get("qualifying_sources")
if type(qualifying) is not int or not 0 <= qualifying <= 10:
    raise SystemExit("T6 report qualifying-source count is invalid")
expected_decision = "pass" if qualifying >= 8 else "reject"
if gate["decision"] != expected_decision:
    raise SystemExit("T6 report gate decision is inconsistent")

artifacts = {
    "manifest": manifest_path,
    "report": report_path,
    "run": run_path,
}
payload = {
    "schema": "euf-viper.t6-theory-dag-wmi-run.v1",
    "state": "completed",
    "analysis_kind": "source_only_structural_projection",
    "revision": os.environ["EUF_VIPER_EXPECTED_REVISION"],
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "hostname": platform.node(),
    "gate": {
        "decision": gate["decision"],
        "qualifying_sources": qualifying,
        "required_qualifying_sources": 8,
    },
    "validation": {
        "expected_sources": 10,
        "observed_sources": len(sources),
        "parser_source_cap_failures": 0,
    },
    "artifacts": {
        name: {"path": str(path.resolve()), "sha256": sha256(path)}
        for name, path in artifacts.items()
    },
}
temporary = metadata_path.with_name(f".{metadata_path.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(metadata_path)
PY

printf 'census_root=%s\n' "$OUT"
printf 'revision=%s\n' "$ACTUAL_REVISION"
printf 'report_sha256=%s\n' "$(sha256sum "$OUT/report.json" | awk '{print $1}')"
