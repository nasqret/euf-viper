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
  --require-validity \
  > "$OUT/run.txt"

python3 - "$OUT/metadata.json" "$MANIFEST" "$EXPECTED_SOURCES" <<'PY'
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


def canonical_sha256(value: object) -> str:
    encoded = (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


out = Path(sys.argv[1])
root = out.parent
manifest = Path(sys.argv[2]).resolve()
expected_sources = int(sys.argv[3])
aggregate = json.loads((root / "aggregate.json").read_text(encoding="ascii"))
sources = aggregate.get("sources")
gates = aggregate.get("gates")
hashes = aggregate.get("hashes")
decoder_oracle = aggregate.get("decoder_oracle")
if not isinstance(sources, dict) or sources.get("observed") != expected_sources:
    raise SystemExit("component quotient census source cardinality mismatch")
if not isinstance(gates, dict) or gates.get("validity", {}).get("pass") is not True:
    raise SystemExit("component quotient census validity gate did not pass")
if (
    not isinstance(decoder_oracle, dict)
    or decoder_oracle.get("executed") is not True
    or decoder_oracle.get("passed") is not True
    or not isinstance(decoder_oracle.get("sha256"), str)
    or len(decoder_oracle["sha256"]) != 64
    or any(
        character not in "0123456789abcdef"
        for character in decoder_oracle["sha256"]
    )
):
    raise SystemExit("component quotient bounded decoder oracle did not pass")
oracle_evidence = dict(decoder_oracle)
oracle_sha256 = oracle_evidence.pop("sha256")
if canonical_sha256(oracle_evidence) != oracle_sha256:
    raise SystemExit("component quotient bounded decoder oracle SHA-256 mismatch")
if not isinstance(hashes, dict):
    raise SystemExit("component quotient census aggregate lacks hashes")
if hashes.get("records_jsonl_sha256") != sha256(root / "records.jsonl"):
    raise SystemExit("component quotient census records hash mismatch")
if hashes.get("derived_target_manifest_sha256") != sha256(root / "targets.jsonl"):
    raise SystemExit("component quotient census target hash mismatch")

artifacts = {
    "manifest": manifest,
    "lock": Path("campaigns/component-quotient-ram-census-v1.json"),
    "analyzer": Path("scripts/bench/census_component_quotient_ram.py"),
    "parser": Path("scripts/cert/independent_qfuf.py"),
    "taxonomy_builder": Path("scripts/bench/build_family_manifest.py"),
    "records": root / "records.jsonl",
    "aggregate": root / "aggregate.json",
    "targets": root / "targets.jsonl",
    "run": root / "run.txt",
}
payload = {
    "schema": "euf-viper.component-quotient-ram-wmi-run.v1",
    "status": "completed",
    "revision": os.environ["EUF_VIPER_EXPECTED_REVISION"],
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "hostname": platform.node(),
    "validation": {
        "expected_sources": expected_sources,
        "observed_sources": sources["observed"],
        "validity_pass": True,
        "decoder_oracle_sha256": oracle_sha256,
        "implementation_allowed": gates["implementation_allowed"],
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
