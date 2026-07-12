#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
SHARDS="${EUF_VIPER_LOCKED_SHARDS:-64}"
MAX_ACTIVE="${EUF_VIPER_LOCKED_MAX_ACTIVE:-16}"

case "$SHARDS" in
  ''|0|0*|*[!0-9]*)
    echo "shards and max-active must be positive integers" >&2
    exit 2
    ;;
esac
case "$MAX_ACTIVE" in
  ''|0|0*|*[!0-9]*)
    echo "shards and max-active must be positive integers" >&2
    exit 2
    ;;
esac

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
REMOTE_MAIN="$(git rev-parse origin/main)"
if [ "$REVISION" != "$REMOTE_MAIN" ]; then
  echo "HEAD $REVISION is not published as origin/main $REMOTE_MAIN" >&2
  exit 2
fi
SHORT_REVISION="$(git rev-parse --short=12 HEAD)"
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; if [ ! -d '$REMOTE_WORK/.git' ]; then git clone --quiet https://github.com/nasqret/euf-viper.git '$REMOTE_WORK'; fi; git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'"

PREPARE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && mkdir -p results && sbatch --parsable --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_LOCKED_SHARDS='$SHARDS' scripts/wmi/euf_viper_locked_prepare.sbatch")"
PREPARE_JOB="${PREPARE_SUBMISSION%%;*}"
case "$PREPARE_JOB" in *[!0-9]*|'') echo "invalid prepare job id: $PREPARE_SUBMISSION" >&2; exit 2 ;; esac

FULL_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --dependency=afterok:'$PREPARE_JOB' --array=0-$((SHARDS - 1))%'$MAX_ACTIVE' --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_PREPARE_JOB_ID='$PREPARE_JOB',EUF_VIPER_CORPUS_KIND=full scripts/wmi/euf_viper_locked_shard.sbatch")"
FULL_JOB="${FULL_SUBMISSION%%;*}"
case "$FULL_JOB" in *[!0-9]*|'') echo "invalid full job id: $FULL_SUBMISSION" >&2; exit 2 ;; esac

OFFICIAL_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --dependency=afterok:'$PREPARE_JOB' --array=0-$((SHARDS - 1))%'$MAX_ACTIVE' --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_PREPARE_JOB_ID='$PREPARE_JOB',EUF_VIPER_CORPUS_KIND=official scripts/wmi/euf_viper_locked_shard.sbatch")"
OFFICIAL_JOB="${OFFICIAL_SUBMISSION%%;*}"
case "$OFFICIAL_JOB" in *[!0-9]*|'') echo "invalid official job id: $OFFICIAL_SUBMISSION" >&2; exit 2 ;; esac

AUDIT_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --dependency=afterok:'$FULL_JOB':'$OFFICIAL_JOB' --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_PREPARE_JOB_ID='$PREPARE_JOB',EUF_VIPER_LOCKED_SHARDS='$SHARDS' scripts/wmi/euf_viper_locked_audit.sbatch")"
AUDIT_JOB="${AUDIT_SUBMISSION%%;*}"
case "$AUDIT_JOB" in *[!0-9]*|'') echo "invalid audit job id: $AUDIT_SUBMISSION" >&2; exit 2 ;; esac

mkdir -p results
python3 - "$ROOT/results/locked-p0-submission-$PREPARE_JOB.json" <<PY
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "schema_version": 1,
    "status": "submitted",
    "revision": "$REVISION",
    "remote_host": "$REMOTE_HOST",
    "remote_worktree": "$REMOTE_WORK",
    "shards": int("$SHARDS"),
    "max_active": int("$MAX_ACTIVE"),
    "jobs": {
        "prepare": "$PREPARE_JOB",
        "full": "$FULL_JOB",
        "official": "$OFFICIAL_JOB",
        "audit": "$AUDIT_JOB",
    },
}
temporary = path.with_name(f".{path.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
