#!/usr/bin/env bash
#SBATCH --job-name=euf-cqram-census
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=64G
#SBATCH --time=08:00:00
#SBATCH --output=results/component-quotient-census-%j.out
#SBATCH --error=results/component-quotient-census-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1
export PYTHONHASHSEED=0

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
EXPECTED_SOURCES="${EUF_VIPER_COMPONENT_QUOTIENT_EXPECTED_SOURCES:-7503}"
if [ "$EXPECTED_SOURCES" != 7503 ]; then
  echo "component quotient census requires exactly 7503 sources" >&2
  exit 2
fi
ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi

SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-$HOME/euf-viper/benchmarks/smtlib-2025}"
if [ ! -e "$PWD/benchmarks/smtlib-2025" ] && \
   [ -s "$SHARED_CORPUS/qf_uf_manifest.jsonl" ]; then
  ln -s "$SHARED_CORPUS" "$PWD/benchmarks/smtlib-2025"
fi
MANIFEST="${EUF_VIPER_COMPONENT_QUOTIENT_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl}"
LOCK="$PWD/campaigns/component-quotient-ram-census-v1.json"
if [ ! -s "$MANIFEST" ]; then
  echo "missing nonempty census manifest: $MANIFEST" >&2
  exit 2
fi
if [ ! -s "$LOCK" ]; then
  echo "missing component quotient campaign lock: $LOCK" >&2
  exit 2
fi

OUT="$PWD/results/component-quotient-census-${SLURM_JOB_ID}"
mkdir -p "$OUT"
python3 scripts/bench/census_component_quotient_ram.py \
  "$MANIFEST" \
  --repository-root "$PWD" \
  --lock "$LOCK" \
  --records-out "$OUT/records.jsonl" \
  --aggregate-out "$OUT/aggregate.json" \
  --targets-out "$OUT/targets.jsonl" \
  > "$OUT/run.txt"

python3 scripts/bench/verify_component_quotient_ram_bundle.py \
  "$MANIFEST" \
  --repository-root "$PWD" \
  --lock "$LOCK" \
  --records "$OUT/records.jsonl" \
  --aggregate "$OUT/aggregate.json" \
  --targets "$OUT/targets.jsonl" \
  --receipt-out "$OUT/verification.json" \
  --require-validity \
  > "$OUT/verification.txt"

python3 - \
  "$OUT/metadata.json" \
  "$MANIFEST" \
  "$EXPECTED_SOURCES" \
  "$OUT/verification.json" <<'PY'
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


out = Path(sys.argv[1])
root = out.parent
manifest = Path(sys.argv[2]).resolve()
expected_sources = int(sys.argv[3])
verification_path = Path(sys.argv[4])
verification = json.loads(verification_path.read_text(encoding="ascii"))
expected_hashes = {
    "lock_sha256",
    "input_manifest_sha256",
    "portable_source_set_sha256",
    "analyzer_sha256",
    "parser_sha256",
    "taxonomy_builder_sha256",
    "records_jsonl_sha256",
    "terminal_record_sha256",
    "derived_target_manifest_sha256",
    "aggregate_json_sha256",
    "recomputed_gates_sha256",
}
if (
    not isinstance(verification, dict)
    or set(verification)
    != {
        "schema",
        "verified",
        "campaign_id",
        "interpretation",
        "sources",
        "targets",
        "validity_pass",
        "implementation_allowed",
        "decoder_oracle_sha256",
        "hashes",
    }
    or verification.get("schema")
    != "euf-viper.component-quotient-ram-bundle-verification.v1"
    or verification.get("campaign_id")
    != "t5-component-quotient-ram-opportunity-census-v1"
    or verification.get("interpretation")
    != "structural_projection_only_no_solver_invocation_no_timing_claim"
    or verification.get("verified") is not True
    or verification.get("validity_pass") is not True
    or verification.get("sources") != expected_sources
    or type(verification.get("targets")) is not int
    or verification["targets"] < 0
    or verification.get("decoder_oracle_sha256")
    != "7562fb7e9953604bd61a68689466e617013bb798bc2657d0c8522e488262af89"
    or type(verification.get("implementation_allowed")) is not bool
    or not isinstance(verification.get("hashes"), dict)
    or set(verification["hashes"]) != expected_hashes
    or any(
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in verification["hashes"].values()
    )
):
    raise SystemExit("component quotient strict bundle verification did not pass")

artifacts = {
    "manifest": manifest,
    "lock": Path("campaigns/component-quotient-ram-census-v1.json"),
    "analyzer": Path("scripts/bench/census_component_quotient_ram.py"),
    "verifier": Path("scripts/bench/verify_component_quotient_ram_bundle.py"),
    "parser": Path("scripts/cert/independent_qfuf.py"),
    "taxonomy_builder": Path("scripts/bench/build_family_manifest.py"),
    "records": root / "records.jsonl",
    "aggregate": root / "aggregate.json",
    "targets": root / "targets.jsonl",
    "run": root / "run.txt",
    "verification": verification_path,
    "verification_run": root / "verification.txt",
}
payload = {
    "schema": "euf-viper.component-quotient-ram-wmi-run.v1",
    "status": "completed",
    "revision": os.environ["EUF_VIPER_EXPECTED_REVISION"],
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "hostname": platform.node(),
    "validation": {
        "expected_sources": expected_sources,
        "observed_sources": verification["sources"],
        "validity_pass": verification["validity_pass"],
        "decoder_oracle_sha256": verification["decoder_oracle_sha256"],
        "implementation_allowed": verification["implementation_allowed"],
        "verification_receipt_sha256": sha256(verification_path),
    },
    "artifacts": {
        name: {"path": str(path.resolve()), "sha256": sha256(path)}
        for name, path in artifacts.items()
    },
}
temporary = out.with_name(f".{out.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(out)
PY

printf 'census_root=%s\n' "$OUT"
printf 'revision=%s\n' "$ACTUAL_REVISION"
