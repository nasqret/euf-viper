#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
DEPENDENCY="${EUF_VIPER_COMPONENT_QUOTIENT_DEPENDENCY:-}"
PUBLISHED_REF="${EUF_VIPER_COMPONENT_QUOTIENT_PUBLISHED_REF:-origin/main}"
EXPECTED_SOURCES="${EUF_VIPER_COMPONENT_QUOTIENT_EXPECTED_SOURCES:-7503}"

if [ -n "$DEPENDENCY" ]; then
  case "$DEPENDENCY" in
    *[!0-9]*) echo "dependency must be a numeric SLURM job id" >&2; exit 2 ;;
  esac
fi
if [ "$EXPECTED_SOURCES" != 7503 ]; then
  echo "component quotient census requires exactly 7503 sources" >&2
  exit 2
fi

cd "$ROOT"
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state must be clean before WMI submission" >&2
  exit 2
fi
REVISION="$(git rev-parse HEAD)"
PUBLISHED_REVISION="$(git rev-parse "$PUBLISHED_REF")"
if [ "$REVISION" != "$PUBLISHED_REVISION" ]; then
  echo "HEAD $REVISION is not published as $PUBLISHED_REF $PUBLISHED_REVISION" >&2
  exit 2
fi
SHORT_REVISION="$(git rev-parse --short=12 HEAD)"
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION-cqram-census"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; if [ ! -d '$REMOTE_WORK/.git' ]; then git clone --quiet https://github.com/nasqret/euf-viper.git '$REMOTE_WORK'; fi; git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'"

SBATCH_ARGS=(--parsable)
if [ -n "$DEPENDENCY" ]; then
  SBATCH_ARGS+=(--dependency="afterok:$DEPENDENCY")
fi
SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && mkdir -p results && sbatch ${SBATCH_ARGS[*]} --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_COMPONENT_QUOTIENT_EXPECTED_SOURCES='$EXPECTED_SOURCES' scripts/wmi/euf_viper_component_quotient_census.sbatch")"
JOB_ID="${SUBMISSION%%;*}"
case "$JOB_ID" in
  *[!0-9]*|'') echo "invalid census job id: $SUBMISSION" >&2; exit 2 ;;
esac

mkdir -p results
python3 - "$ROOT/results/component-quotient-census-submission-$JOB_ID.json" <<PY
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "schema": "euf-viper.component-quotient-ram-wmi-submission.v1",
    "status": "submitted",
    "revision": "$REVISION",
    "published_ref": "$PUBLISHED_REF",
    "remote_host": "$REMOTE_HOST",
    "remote_worktree": "$REMOTE_WORK",
    "dependency": "$DEPENDENCY" or None,
    "expected_sources": int("$EXPECTED_SOURCES"),
    "job_id": "$JOB_ID",
}
temporary = path.with_name(f".{path.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
