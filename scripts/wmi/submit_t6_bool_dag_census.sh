#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_T6_REMOTE_PARENT:-}"
REMOTE_BRANCH="${EUF_VIPER_T6_REMOTE_BRANCH:-research-t6-theory-dag}"
MANIFEST="$ROOT/campaigns/t6-theory-dag-hard10-v1.json"

cd "$ROOT"
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state must be clean before WMI submission" >&2
  exit 2
fi
BRANCH="$(git branch --show-current)"
if [ "$BRANCH" != "$REMOTE_BRANCH" ]; then
  echo "T6 submission requires branch $REMOTE_BRANCH, got $BRANCH" >&2
  exit 2
fi
REVISION="$(git rev-parse HEAD)"
PUBLISHED_REVISION="$(git rev-parse "origin/$REMOTE_BRANCH")"
if [ "$REVISION" != "$PUBLISHED_REVISION" ]; then
  echo "HEAD $REVISION is not published as origin/$REMOTE_BRANCH $PUBLISHED_REVISION" >&2
  exit 2
fi
if [ ! -s "$MANIFEST" ]; then
  echo "missing frozen manifest: $MANIFEST" >&2
  exit 2
fi
MANIFEST_SHA256="$(shasum -a 256 "$MANIFEST" | awk '{print $1}')"

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
REMOTE_CORPUS_ROOT="${EUF_VIPER_T6_REMOTE_CORPUS_ROOT:-$REMOTE_HOME/euf-viper/benchmarks/smtlib-2025/QF_UF}"
SHORT_REVISION="$(git rev-parse --short=12 HEAD)"
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION-t6-theory-dag"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; if [ ! -d '$REMOTE_WORK/.git' ]; then git clone --quiet https://github.com/nasqret/euf-viper.git '$REMOTE_WORK'; fi; git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'; test -d '$REMOTE_CORPUS_ROOT'"

SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && mkdir -p results && sbatch --parsable --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256='$MANIFEST_SHA256',EUF_VIPER_T6_CORPUS_ROOT='$REMOTE_CORPUS_ROOT' scripts/wmi/euf_viper_t6_bool_dag_census.sbatch")"
JOB_ID="${SUBMISSION%%;*}"
case "$JOB_ID" in
  *[!0-9]*|'') echo "invalid T6 census job id: $SUBMISSION" >&2; exit 2 ;;
esac

mkdir -p results
python3 - "$ROOT/results/t6-bool-dag-census-submission-$JOB_ID.json" <<PY
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "schema": "euf-viper.t6-theory-dag-wmi-submission.v1",
    "state": "submitted",
    "analysis_kind": "source_only_structural_projection",
    "revision": "$REVISION",
    "branch": "$REMOTE_BRANCH",
    "remote_host": "$REMOTE_HOST",
    "remote_worktree": "$REMOTE_WORK",
    "remote_corpus_root": "$REMOTE_CORPUS_ROOT",
    "manifest_sha256": "$MANIFEST_SHA256",
    "expected_sources": 10,
    "job_id": "$JOB_ID",
}
temporary = path.with_name(f".{path.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
