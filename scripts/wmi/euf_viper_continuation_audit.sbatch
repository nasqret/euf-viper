#!/usr/bin/env bash
#SBATCH --job-name=euf-cont-audit
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=06:00:00
#SBATCH --output=results/continuation-audit-%j.out
#SBATCH --error=results/continuation-audit-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export LANG=C
export LC_ALL=C
export TZ=UTC

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
BASE_PREPARE_JOB_ID="${EUF_VIPER_BASE_PREPARE_JOB_ID:?set EUF_VIPER_BASE_PREPARE_JOB_ID}"
BASE_AUDIT_JOB_ID="${EUF_VIPER_BASE_AUDIT_JOB_ID:?set EUF_VIPER_BASE_AUDIT_JOB_ID}"
CHAIN_ID="${EUF_VIPER_CONTINUATION_CHAIN_ID:?set EUF_VIPER_CONTINUATION_CHAIN_ID}"
CORPUS_KIND="${EUF_VIPER_CORPUS_KIND:?set EUF_VIPER_CORPUS_KIND}"
TARGET_BUDGET="${EUF_VIPER_CONTINUATION_TARGET_BUDGET:?set EUF_VIPER_CONTINUATION_TARGET_BUDGET}"
BOOTSTRAP_REPLICATES="${EUF_VIPER_CONTINUATION_BOOTSTRAP_REPLICATES:-10000}"

case "$CORPUS_KIND" in full|official) ;; *) echo "corpus kind must be full or official" >&2; exit 2 ;; esac
case "$TARGET_BUDGET" in 60|1200) ;; *) echo "target budget must be 60 or 1200" >&2; exit 2 ;; esac
for VALUE in "$BASE_PREPARE_JOB_ID" "$BASE_AUDIT_JOB_ID" "$CHAIN_ID" "$BOOTSTRAP_REPLICATES"; do
  case "$VALUE" in ''|0|0*|*[!0-9]*) echo "invalid positive integer: $VALUE" >&2; exit 2 ;; esac
done
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in continuation audit" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty in continuation audit" >&2
  exit 2
fi

RUN_ROOT="$PWD/results/p0-$BASE_PREPARE_JOB_ID"
CHAIN_ROOT="$RUN_ROOT/continuations/chain-$CHAIN_ID"
BASE_PARENT="$RUN_ROOT/locks/$CORPUS_KIND-parent.json"
BASE_LOCK_DIR="$RUN_ROOT/locks/$CORPUS_KIND"
BASE_RESULTS="$RUN_ROOT/$CORPUS_KIND-2s"
STAGE_ARGUMENTS=()

index_status() {
  python3 - "$1" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"cannot read continuation index {path}: {error}")
status = payload.get("status") if isinstance(payload, dict) else None
if status not in {"ready", "no_timeouts"}:
    raise SystemExit("continuation index status is invalid")
print(status)
PY
}

append_stage() {
  local stage_root="$1"
  local status
  status="$(index_status "$stage_root/index.json")"
  if [ "$status" = ready ]; then
    STAGE_ARGUMENTS+=(--stage "$stage_root/index.json" "$stage_root/locks" "$stage_root")
  else
    if [ -e "$stage_root/locks" ]; then
      echo "zero-timeout stage unexpectedly has shard locks: $stage_root" >&2
      exit 2
    fi
    STAGE_ARGUMENTS+=(--stage "$stage_root/index.json" - -)
  fi
  APPENDED_STAGE_STATUS="$status"
}

STAGE_60_ROOT="$CHAIN_ROOT/$CORPUS_KIND-60s"
append_stage "$STAGE_60_ROOT"
STAGE_60_STATUS="$APPENDED_STAGE_STATUS"
if [ "$TARGET_BUDGET" = 1200 ] && [ "$STAGE_60_STATUS" = ready ]; then
  append_stage "$CHAIN_ROOT/$CORPUS_KIND-1200s"
elif [ "$TARGET_BUDGET" = 1200 ] && [ -e "$CHAIN_ROOT/$CORPUS_KIND-1200s" ]; then
  echo "1200-second stage exists after a zero-timeout 60-second stage" >&2
  exit 2
fi

if [ "$TARGET_BUDGET" = 60 ]; then
  OUTPUT="$CHAIN_ROOT/audit/$CORPUS_KIND-60.json"
else
  OUTPUT="$CHAIN_ROOT/analysis/$CORPUS_KIND.json"
fi
TEMPORARY="$OUTPUT.tmp.$SLURM_JOB_ID"
mkdir -p "$(dirname "$OUTPUT")"
if [ -e "$TEMPORARY" ]; then
  echo "temporary analysis output already exists: $TEMPORARY" >&2
  exit 2
fi
trap 'rm -f "$TEMPORARY"' EXIT

set +e
python3 scripts/bench/analyze_staged_campaign.py \
  --base-parent-lock "$BASE_PARENT" \
  --base-shard-lock-dir "$BASE_LOCK_DIR" \
  --base-shard-results-root "$BASE_RESULTS" \
  "${STAGE_ARGUMENTS[@]}" \
  --candidate euf-viper \
  --bootstrap-replicates "$BOOTSTRAP_REPLICATES" \
  --confidence-level 0.95 \
  --out "$TEMPORARY"
ANALYSIS_STATUS=$?
set -e
if [ "$ANALYSIS_STATUS" -ne 0 ] && [ "$ANALYSIS_STATUS" -ne 1 ]; then
  exit "$ANALYSIS_STATUS"
fi

python3 - "$TEMPORARY" "$OUTPUT" "$TARGET_BUDGET" <<'PY'
import json
import os
import sys
from pathlib import Path

temporary = Path(sys.argv[1])
output = Path(sys.argv[2])
target = int(sys.argv[3])
try:
    payload = json.loads(temporary.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"cannot read staged analysis: {error}")
if not isinstance(payload, dict) or payload.get("schema_version") != 1:
    raise SystemExit("staged analysis has an incompatible schema")
if payload.get("status") not in {"promoted", "rejected"}:
    raise SystemExit("staged analysis status is invalid")
inputs = payload.get("inputs")
assumptions = payload.get("assumptions")
budgets = inputs.get("budgets_s") if isinstance(inputs, dict) else None
if not isinstance(budgets, list) or 2.0 not in budgets or float(target) not in budgets:
    raise SystemExit("staged analysis budget coverage is incomplete")
if target == 1200:
    if budgets != [2.0, 60.0, 1200.0]:
        raise SystemExit("final staged analysis does not cover the declared budget ladder")
    if not isinstance(assumptions, dict) or assumptions.get("complete_declared_budget_ladder") is not True:
        raise SystemExit("final staged analysis is not globally complete")
if output.exists() or output.is_symlink():
    if output.read_bytes() != temporary.read_bytes():
        raise SystemExit(f"refuse to replace analysis artifact {output}")
    temporary.unlink()
else:
    os.replace(temporary, output)
PY
trap - EXIT
printf 'analysis=%s\n' "$OUTPUT"
