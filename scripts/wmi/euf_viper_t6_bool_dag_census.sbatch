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
export CARGO_BUILD_JOBS="${SLURM_CPUS_PER_TASK:-1}"

CARGO="${EUF_VIPER_CARGO:-$HOME/.cargo/bin/cargo}"
RUST_TOOLCHAIN="1.96.0"
EXPECTED_CARGO_RESOLVED="${EUF_VIPER_CARGO_RESOLVED:?set EUF_VIPER_CARGO_RESOLVED}"
EXPECTED_CARGO_SHA256="${EUF_VIPER_CARGO_SHA256:?set EUF_VIPER_CARGO_SHA256}"
EXPECTED_CARGO_VERSION="${EUF_VIPER_CARGO_VERSION:?set EUF_VIPER_CARGO_VERSION}"
case "$CARGO" in
  /*) ;;
  *) echo "EUF_VIPER_CARGO must be an absolute path: $CARGO" >&2; exit 127 ;;
esac
case "$EXPECTED_CARGO_RESOLVED" in
  /*) ;;
  *) echo "EUF_VIPER_CARGO_RESOLVED must be an absolute path" >&2; exit 2 ;;
esac
if [ ! -f "$CARGO" ] || [ ! -x "$CARGO" ]; then
  echo "pinned cargo is not an executable file: $CARGO" >&2
  exit 127
fi
if ! ACTUAL_CARGO_RESOLVED="$(readlink -f -- "$CARGO")"; then
  echo "failed to resolve pinned cargo: $CARGO" >&2
  exit 127
fi
if [ "$ACTUAL_CARGO_RESOLVED" != "$EXPECTED_CARGO_RESOLVED" ]; then
  echo "cargo resolved-path mismatch: expected $EXPECTED_CARGO_RESOLVED, got $ACTUAL_CARGO_RESOLVED" >&2
  exit 2
fi
if [ ! -f "$ACTUAL_CARGO_RESOLVED" ] || [ ! -x "$ACTUAL_CARGO_RESOLVED" ]; then
  echo "resolved cargo is not an executable file: $ACTUAL_CARGO_RESOLVED" >&2
  exit 127
fi
if [ "${#EXPECTED_CARGO_SHA256}" -ne 64 ]; then
  echo "EUF_VIPER_CARGO_SHA256 must be a lowercase SHA-256" >&2
  exit 2
fi
case "$EXPECTED_CARGO_SHA256" in
  *[!0-9a-f]*) echo "EUF_VIPER_CARGO_SHA256 must be a lowercase SHA-256" >&2; exit 2 ;;
esac
ACTUAL_CARGO_SHA256="$(sha256sum "$ACTUAL_CARGO_RESOLVED" | awk '{print $1}')"
if [ "$ACTUAL_CARGO_SHA256" != "$EXPECTED_CARGO_SHA256" ]; then
  echo "cargo hash mismatch: expected $EXPECTED_CARGO_SHA256, got $ACTUAL_CARGO_SHA256" >&2
  exit 2
fi
ACTUAL_CARGO_VERSION="$("$CARGO" +1.96.0 --version)"
if [ "$ACTUAL_CARGO_VERSION" != "$EXPECTED_CARGO_VERSION" ]; then
  echo "cargo version mismatch: expected $EXPECTED_CARGO_VERSION, got $ACTUAL_CARGO_VERSION" >&2
  exit 2
fi
export EUF_VIPER_CARGO="$CARGO"
export EUF_VIPER_CARGO_RESOLVED="$ACTUAL_CARGO_RESOLVED"
export EUF_VIPER_CARGO_SHA256="$ACTUAL_CARGO_SHA256"
export EUF_VIPER_CARGO_VERSION="$ACTUAL_CARGO_VERSION"
export PATH="$(dirname "$CARGO"):$PATH"
printf 'cargo_configured=%s\ncargo_resolved=%s\ncargo_sha256=%s\ncargo_version=%s\ntoolchain=%s\n' \
  "$CARGO" "$ACTUAL_CARGO_RESOLVED" "$ACTUAL_CARGO_SHA256" \
  "$ACTUAL_CARGO_VERSION" "$RUST_TOOLCHAIN"

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
EXPECTED_MANIFEST_SHA256="33a9f0016570dc07dc4c9aed2f575633eb5a2ee10d21177c97a4e86b65507c78"
ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi

MANIFEST="${EUF_VIPER_T6_MANIFEST:-$PWD/campaigns/t6-theory-dag-p0-qg12-v1.json}"
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
printf 'configured=%s\nresolved=%s\nsha256=%s\nversion=%s\ntoolchain=%s\n' \
  "$CARGO" "$ACTUAL_CARGO_RESOLVED" "$ACTUAL_CARGO_SHA256" \
  "$ACTUAL_CARGO_VERSION" "$RUST_TOOLCHAIN" \
  > "$OUT/cargo-toolchain.txt"

"$CARGO" +1.96.0 test --release --locked --all-features \
  t6_bool_dag_census::tests::p0_qg12_census_from_env \
  -- --ignored --exact --nocapture \
  > "$OUT/run.txt"

python3 - "$OUT/metadata.json" "$OUT/report.json" "$OUT/run.txt" "$MANIFEST" \
  "$OUT/cargo-toolchain.txt" <<'PY'
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


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value):
    raise SystemExit(f"non-finite JSON number {value!r}")


def load_strict_json(path: Path):
    try:
        return json.loads(
            path.read_text(encoding="ascii"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid strict JSON in {path}: {error}") from error


metadata_path, report_path, run_path, manifest_path, cargo_path = map(Path, sys.argv[1:])
report = load_strict_json(report_path)
if report.get("schema") != "euf-viper.t6-theory-dag-census.v2":
    raise SystemExit("unexpected T6 report schema")
if report.get("analysis_revision") != os.environ["EUF_VIPER_EXPECTED_REVISION"]:
    raise SystemExit("T6 report revision mismatch")
manifest = report.get("manifest")
if not isinstance(manifest, dict) or manifest.get("sources") != 12:
    raise SystemExit("T6 report does not contain exactly 12 frozen sources")
if manifest.get("file_sha256") != (
    "33a9f0016570dc07dc4c9aed2f575633eb5a2ee10d21177c97a4e86b65507c78"
):
    raise SystemExit("T6 report manifest artifact hash mismatch")
if manifest.get("canonical_path_list_sha256") != (
    "1fd24c2c5fa8eafd07a39f28c96d828e0e0aa1072fd032db413c60f34270b6fa"
):
    raise SystemExit("T6 report path-list digest mismatch")
if manifest.get("source_records_sha256") != (
    "f274424dcfdf3bd155fe12f7aedb99f8a80dfcb54c0625899dfba8377fff5b0b"
):
    raise SystemExit("T6 report source-record digest mismatch")
sources = report.get("sources")
if not isinstance(sources, list) or len(sources) != 12:
    raise SystemExit("T6 report source array mismatch")
if [row.get("sequence") for row in sources] != list(range(12)):
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
if gate.get("scope") != "current_p0_qg7_derived_10_of_12":
    raise SystemExit("T6 report gate scope drift")
if gate.get("pass_semantics") != (
    "source_only_projection_gate_no_implementation_or_promotion"
):
    raise SystemExit("T6 report gate pass semantics drift")
if gate.get("required_qualifying_sources") != 10:
    raise SystemExit("T6 report qualifying-source threshold drift")
qualifying = gate.get("qualifying_sources")
if type(qualifying) is not int or not 0 <= qualifying <= 12:
    raise SystemExit("T6 report qualifying-source count is invalid")
expected_decision = "pass" if qualifying >= 10 else "reject"
if gate["decision"] != expected_decision:
    raise SystemExit("T6 report gate decision is inconsistent")
if report.get("population_status") != "accepted":
    raise SystemExit("T6 accepted-population status drift")
if report.get("projection_status") != "completed":
    raise SystemExit("T6 completed-projection status drift")
if report.get("implementation_or_promotion_eligible") is not False:
    raise SystemExit("T6 promotion eligibility drift")

artifacts = {
    "cargo_toolchain": cargo_path,
    "manifest": manifest_path,
    "report": report_path,
    "run": run_path,
}
payload = {
    "schema": "euf-viper.t6-theory-dag-wmi-run.v2",
    "state": "completed",
    "analysis_kind": "source_only_structural_projection",
    "revision": os.environ["EUF_VIPER_EXPECTED_REVISION"],
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "hostname": platform.node(),
    "cargo": {
        "configured_path": os.environ["EUF_VIPER_CARGO"],
        "resolved_path": os.environ["EUF_VIPER_CARGO_RESOLVED"],
        "sha256": os.environ["EUF_VIPER_CARGO_SHA256"],
        "version": os.environ["EUF_VIPER_CARGO_VERSION"],
        "toolchain": "1.96.0",
    },
    "gate": {
        "scope": gate["scope"],
        "decision": gate["decision"],
        "qualifying_sources": qualifying,
        "required_qualifying_sources": 10,
        "implementation_or_promotion_eligible": False,
    },
    "population_status": "accepted",
    "projection_status": "completed",
    "implementation_or_promotion_eligible": False,
    "validation": {
        "expected_sources": 12,
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
