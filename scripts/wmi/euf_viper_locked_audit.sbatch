#!/usr/bin/env bash
#SBATCH --job-name=euf-p0-audit
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=results/p0-audit-%j.out
#SBATCH --error=results/p0-audit-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export LANG=C
export LC_ALL=C
export TZ=UTC

PREPARE_JOB_ID="${EUF_VIPER_PREPARE_JOB_ID:?set EUF_VIPER_PREPARE_JOB_ID}"
EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
SHARDS="${EUF_VIPER_LOCKED_SHARDS:-64}"
RUN_ROOT="$PWD/results/p0-${PREPARE_JOB_ID}"

if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in audit job" >&2
  exit 2
fi

for KIND in full official; do
  mkdir -p "$RUN_ROOT/audit/$KIND"
  for ((INDEX=0; INDEX<SHARDS; INDEX++)); do
    PADDED="$(printf '%04d' "$INDEX")"
    test -s "$RUN_ROOT/locks/$KIND/bound-$PADDED.json"
    test -s "$RUN_ROOT/$KIND-2s/shard-$PADDED/raw.jsonl"
    test -s "$RUN_ROOT/$KIND-2s/shard-$PADDED/summary.json"
  done
  if python3 scripts/bench/analyze_campaign.py \
      --parent-lock "$RUN_ROOT/locks/$KIND-parent.json" \
      --shard-lock-dir "$RUN_ROOT/locks/$KIND" \
      --shard-results-root "$RUN_ROOT/$KIND-2s" \
      --bootstrap-replicates 10000 \
      --confidence-level 0.95 \
      --out "$RUN_ROOT/audit/$KIND/global.json"; then
    :
  else
    STATUS=$?
    if [ "$STATUS" -ne 1 ]; then
      exit "$STATUS"
    fi
  fi
done

python3 - "$RUN_ROOT/audit/index.json" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

out = Path(sys.argv[1])
root = out.parent
shards = int(os.environ.get("EUF_VIPER_LOCKED_SHARDS", "64"))
payload = {
    "schema_version": 1,
    "status": "complete",
    "prepare_job_id": int(os.environ["EUF_VIPER_PREPARE_JOB_ID"]),
    "revision": os.environ["EUF_VIPER_EXPECTED_REVISION"],
    "shards": shards,
    "analyses": {},
}
for kind in ("full", "official"):
    path = root / kind / "global.json"
    data = json.loads(path.read_text())
    payload["analyses"][kind] = {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "status": data.get("status"),
        "promoted": data.get("promoted"),
        "instances": data.get("inputs", {}).get("instances"),
        "raw_records": data.get("inputs", {}).get("raw_records"),
        "shards": len(data.get("inputs", {}).get("shards", [])),
    }
temporary = out.with_name(f".{out.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(out)
PY

printf 'audit=%s\n' "$RUN_ROOT/audit/index.json"
