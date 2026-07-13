#!/usr/bin/env bash
#SBATCH --job-name=euf-range-census
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=results/guarded-range-census-%j.out
#SBATCH --error=results/guarded-range-census-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export LANG=C
export LC_ALL=C
export TZ=UTC

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
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
MANIFEST="${EUF_VIPER_RANGE_CENSUS_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl}"
if [ ! -s "$MANIFEST" ]; then
  echo "missing nonempty census manifest: $MANIFEST" >&2
  exit 2
fi

OUT="$PWD/results/guarded-range-census-${SLURM_JOB_ID}"
mkdir -p "$OUT"
python3 scripts/bench/census_guarded_adequate_ranges.py \
  "$MANIFEST" \
  --repository-root "$PWD" \
  --records-out "$OUT/records.jsonl" \
  --aggregate-out "$OUT/aggregate.json" \
  > "$OUT/run.txt"

python3 - "$OUT/metadata.json" "$MANIFEST" <<'PY'
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
artifacts = {
    "manifest": manifest,
    "analyzer": Path("scripts/bench/census_guarded_adequate_ranges.py"),
    "parser": Path("scripts/cert/independent_qfuf.py"),
    "records": root / "records.jsonl",
    "aggregate": root / "aggregate.json",
    "run": root / "run.txt",
}
payload = {
    "schema": "euf-viper.guard-range-hall-wmi-run.v1",
    "status": "completed",
    "revision": os.environ["EUF_VIPER_EXPECTED_REVISION"],
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "hostname": platform.node(),
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
