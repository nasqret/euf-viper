#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
BASE_PREPARE_JOB_ID="${1:-${EUF_VIPER_BASE_PREPARE_JOB_ID:-}}"
BASE_AUDIT_JOB_ID="${2:-${EUF_VIPER_BASE_AUDIT_JOB_ID:-}}"
SHARDS="${EUF_VIPER_CONTINUATION_SHARDS:-64}"
MAX_ACTIVE="${EUF_VIPER_CONTINUATION_MAX_ACTIVE:-16}"
BOOTSTRAP_REPLICATES="${EUF_VIPER_CONTINUATION_BOOTSTRAP_REPLICATES:-10000}"
WALL_TIME_60="${EUF_VIPER_CONTINUATION_WALL_TIME_60:-04:00:00}"
WALL_TIME_1200="${EUF_VIPER_CONTINUATION_WALL_TIME_1200:-24:00:00}"

positive_integer() {
  case "$2" in
    ''|0|0*|*[!0-9]*)
      echo "$1 must be a positive base-10 integer" >&2
      exit 2
      ;;
  esac
}

positive_integer "base prepare job id" "$BASE_PREPARE_JOB_ID"
positive_integer "base audit job id" "$BASE_AUDIT_JOB_ID"
positive_integer "configured shard count" "$SHARDS"
positive_integer "maximum active shard count" "$MAX_ACTIVE"
positive_integer "bootstrap replicate count" "$BOOTSTRAP_REPLICATES"

case "$REMOTE_PARENT" in
  *[!A-Za-z0-9_./-]*)
    echo "remote campaign root contains unsupported shell characters" >&2
    exit 2
    ;;
esac

cd "$ROOT"
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state must be clean before WMI submission" >&2
  exit 2
fi
SUBMITTER_REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
REVISION="${EUF_VIPER_CONTINUATION_REVISION:-$SUBMITTER_REVISION}"
case "$REVISION" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) echo "campaign revision must be a full lowercase Git object id" >&2; exit 2 ;;
esac
git cat-file -e "$REVISION^{commit}"
PUBLISHED_LINE="$(git ls-remote --exit-code origin refs/heads/main)"
case "$PUBLISHED_LINE" in
  *$'\n'*) echo "origin/main resolved to multiple revisions" >&2; exit 2 ;;
esac
PUBLISHED_REVISION="${PUBLISHED_LINE%%$'\t'*}"
case "$PUBLISHED_REVISION" in
  ''|*[!0-9a-f]*) echo "origin/main did not resolve to a lowercase Git object id" >&2; exit 2 ;;
esac
if [ "$SUBMITTER_REVISION" != "$PUBLISHED_REVISION" ]; then
  echo "submitter HEAD $SUBMITTER_REVISION is not published as origin/main $PUBLISHED_REVISION" >&2
  exit 2
fi
if ! git merge-base --is-ancestor "$REVISION" "$PUBLISHED_REVISION"; then
  echo "campaign revision $REVISION is not an ancestor of published origin/main $PUBLISHED_REVISION" >&2
  exit 2
fi

if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
case "$REMOTE_PARENT" in
  /*) ;;
  *) echo "remote campaign root must be absolute" >&2; exit 2 ;;
esac

SHORT_REVISION="${REVISION:0:12}"
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION"
printf -v Q_REMOTE_PARENT '%q' "$REMOTE_PARENT"
printf -v Q_REMOTE_WORK '%q' "$REMOTE_WORK"
printf -v Q_REVISION '%q' "$REVISION"

ssh "$REMOTE_HOST" "set -euo pipefail
mkdir -p $Q_REMOTE_PARENT
if [ ! -d $Q_REMOTE_WORK/.git ]; then
  git clone --quiet https://github.com/nasqret/euf-viper.git $Q_REMOTE_WORK
fi
git -C $Q_REMOTE_WORK fetch --quiet origin $Q_REVISION
git -C $Q_REMOTE_WORK checkout --quiet --detach $Q_REVISION
test \"\$(git -C $Q_REMOTE_WORK rev-parse HEAD)\" = $Q_REVISION
test -z \"\$(git -C $Q_REMOTE_WORK status --porcelain=v1 --untracked-files=no)\"
mkdir -p $Q_REMOTE_WORK/results"

DISPATCH_SUBMISSION="$(ssh "$REMOTE_HOST" "cd $Q_REMOTE_WORK && sbatch --parsable --kill-on-invalid-dep=yes \
  --dependency=afterok:$BASE_AUDIT_JOB_ID \
  --export=ALL,EUF_VIPER_EXPECTED_REVISION=$REVISION,EUF_VIPER_BASE_PREPARE_JOB_ID=$BASE_PREPARE_JOB_ID,EUF_VIPER_BASE_AUDIT_JOB_ID=$BASE_AUDIT_JOB_ID,EUF_VIPER_CONTINUATION_TARGET_BUDGET=60,EUF_VIPER_CONTINUATION_SHARDS=$SHARDS,EUF_VIPER_CONTINUATION_MAX_ACTIVE=$MAX_ACTIVE,EUF_VIPER_CONTINUATION_BOOTSTRAP_REPLICATES=$BOOTSTRAP_REPLICATES,EUF_VIPER_CONTINUATION_WALL_TIME_60=$WALL_TIME_60,EUF_VIPER_CONTINUATION_WALL_TIME_1200=$WALL_TIME_1200 \
  scripts/wmi/euf_viper_continuation_dispatch.sbatch")"
DISPATCH_JOB_ID="${DISPATCH_SUBMISSION%%;*}"
positive_integer "initial continuation dispatcher job id" "$DISPATCH_JOB_ID"

mkdir -p "$ROOT/results"
RECEIPT="$ROOT/results/locked-continuation-submission-$DISPATCH_JOB_ID.json"
python3 - \
  "$RECEIPT" "$REVISION" "$REMOTE_HOST" "$REMOTE_WORK" \
  "$SUBMITTER_REVISION" \
  "$BASE_PREPARE_JOB_ID" "$BASE_AUDIT_JOB_ID" "$DISPATCH_JOB_ID" \
  "$SHARDS" "$MAX_ACTIVE" "$BOOTSTRAP_REPLICATES" \
  "$WALL_TIME_60" "$WALL_TIME_1200" <<'PY'
import json
import os
import sys
from pathlib import Path

(
    output_raw, revision, remote_host, remote_worktree, submitter_revision, base_prepare,
    base_audit, dispatcher, shards, max_active, bootstrap_replicates,
    wall_time_60, wall_time_1200,
) = sys.argv[1:]
payload = {
    "schema_version": 1,
    "status": "submitted",
    "revision": revision,
    "submitter_revision": submitter_revision,
    "remote_host": remote_host,
    "remote_worktree": remote_worktree,
    "base_prepare_job_id": int(base_prepare),
    "base_audit_job_id": int(base_audit),
    "chain_id": int(dispatcher),
    "initial_dispatcher_job_id": int(dispatcher),
    "configured_shards": int(shards),
    "max_active": int(max_active),
    "bootstrap_replicates": int(bootstrap_replicates),
    "wall_time": {"60": wall_time_60, "1200": wall_time_1200},
    "dependency": f"afterok:{base_audit}",
}
output = Path(output_raw)
if output.exists() or output.is_symlink():
    raise SystemExit(f"refuse to replace local submission receipt {output}")
temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
temporary.replace(output)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
