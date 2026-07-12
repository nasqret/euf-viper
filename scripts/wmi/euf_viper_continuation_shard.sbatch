#!/usr/bin/env bash
#SBATCH --job-name=euf-cont-shard
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=10G
#SBATCH --time=24:00:00
#SBATCH --output=results/continuation-shard-%A_%a.out
#SBATCH --error=results/continuation-shard-%A_%a.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export LANG=C
export LC_ALL=C
export TZ=UTC

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
BASE_PREPARE_JOB_ID="${EUF_VIPER_BASE_PREPARE_JOB_ID:?set EUF_VIPER_BASE_PREPARE_JOB_ID}"
CHAIN_ID="${EUF_VIPER_CONTINUATION_CHAIN_ID:?set EUF_VIPER_CONTINUATION_CHAIN_ID}"
CORPUS_KIND="${EUF_VIPER_CORPUS_KIND:?set EUF_VIPER_CORPUS_KIND}"
TARGET_BUDGET="${EUF_VIPER_CONTINUATION_TARGET_BUDGET:?set EUF_VIPER_CONTINUATION_TARGET_BUDGET}"
CONFIGURED_SHARDS="${EUF_VIPER_CONTINUATION_SHARDS:?set EUF_VIPER_CONTINUATION_SHARDS}"
STAGE_SHARDS="${EUF_VIPER_CONTINUATION_STAGE_SHARDS:?set EUF_VIPER_CONTINUATION_STAGE_SHARDS}"
ARRAY_INDEX="${SLURM_ARRAY_TASK_ID:?run as a Slurm array}"

case "$CORPUS_KIND" in full|official) ;; *) echo "corpus kind must be full or official" >&2; exit 2 ;; esac
case "$TARGET_BUDGET" in 60|1200) ;; *) echo "target budget must be 60 or 1200" >&2; exit 2 ;; esac
for VALUE in "$BASE_PREPARE_JOB_ID" "$CHAIN_ID" "$CONFIGURED_SHARDS" "$STAGE_SHARDS"; do
  case "$VALUE" in ''|0|0*|*[!0-9]*) echo "invalid positive integer: $VALUE" >&2; exit 2 ;; esac
done
case "$ARRAY_INDEX" in ''|*[!0-9]*) echo "invalid Slurm array index" >&2; exit 2 ;; esac
if [ "$ARRAY_INDEX" -ge "$STAGE_SHARDS" ]; then
  echo "Slurm array index exceeds the exact stage shard count" >&2
  exit 2
fi

if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in continuation shard" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty in continuation shard" >&2
  exit 2
fi

RUN_ROOT="$PWD/results/p0-$BASE_PREPARE_JOB_ID"
STAGE_ROOT="$RUN_ROOT/continuations/chain-$CHAIN_ID/$CORPUS_KIND-${TARGET_BUDGET}s"
INDEX="$(printf '%04d' "$ARRAY_INDEX")"
PREPARED_LOCK="$STAGE_ROOT/locks/lock-$INDEX.json"
BOUND_LOCK="$STAGE_ROOT/locks/bound-$INDEX.json"
RESULT_ROOT="$STAGE_ROOT/shard-$INDEX"

python3 - "$STAGE_ROOT/index.json" "$TARGET_BUDGET" "$CONFIGURED_SHARDS" "$STAGE_SHARDS" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
target = int(sys.argv[2])
configured = int(sys.argv[3])
actual_shards = int(sys.argv[4])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"cannot read continuation index {path}: {error}")
selected = payload.get("selected_instances") if isinstance(payload, dict) else None
if payload.get("schema_version") != 1 or payload.get("status") != "ready":
    raise SystemExit("array execution requires a ready continuation index")
if payload.get("target_budget_s") != target:
    raise SystemExit("continuation index target budget mismatch")
if not isinstance(selected, int) or isinstance(selected, bool) or selected < 1:
    raise SystemExit("continuation selected_instances is invalid")
if actual_shards != min(configured, selected):
    raise SystemExit("stage shard count is not min(configured, selected_instances)")
PY

test -s "$PREPARED_LOCK"
if [ -e "$BOUND_LOCK" ] || [ -e "$RESULT_ROOT" ]; then
  echo "refuse to replace bound lock or raw shard artifacts for $CORPUS_KIND/$TARGET_BUDGET/$INDEX" >&2
  exit 2
fi
python3 scripts/bench/bind_campaign_cpu.py "$PREPARED_LOCK" \
  --out "$BOUND_LOCK" \
  > "$STAGE_ROOT/locks/binding-$INDEX.json"
python3 scripts/bench/run_locked_campaign.py "$BOUND_LOCK"
test -s "$RESULT_ROOT/raw.jsonl"
test -s "$RESULT_ROOT/summary.json"
