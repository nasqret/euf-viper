#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_TYPED_PARSER_CAMPAIGN_PARENT:-}"
PUBLISHED_REF="${EUF_VIPER_TYPED_PARSER_PUBLISHED_REF:-origin/research-typed-stream-parity}"
DEPENDENCY="${EUF_VIPER_TYPED_PARSER_DEPENDENCY:-}"
EXPECTED_SOURCES="${EUF_VIPER_TYPED_PARSER_EXPECTED_SOURCES:-7503}"
SHARDS="${EUF_VIPER_TYPED_PARSER_SHARDS:-128}"
MAX_PARALLEL="${EUF_VIPER_TYPED_PARSER_MAX_PARALLEL:-32}"
TIMEOUT_SECONDS="${EUF_VIPER_TYPED_PARSER_TIMEOUT_SECONDS:-60}"

if [ -n "$DEPENDENCY" ]; then
  case "$DEPENDENCY" in *[!0-9]*) echo "dependency must be numeric" >&2; exit 2 ;; esac
fi
for value in "$EXPECTED_SOURCES" "$SHARDS" "$MAX_PARALLEL" "$TIMEOUT_SECONDS"; do
  case "$value" in
    ''|0|0*|*[!0-9]*) echo "campaign integers must be canonical and positive" >&2; exit 2 ;;
  esac
done
if [ "$MAX_PARALLEL" -gt "$SHARDS" ]; then
  echo "max parallelism cannot exceed shard count" >&2
  exit 2
fi

cd "$ROOT"
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
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-parser-parity-campaigns"
fi
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION"
CAMPAIGN_TAG="${EUF_VIPER_TYPED_PARSER_CAMPAIGN_TAG:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
case "$CAMPAIGN_TAG" in
  *[!A-Za-z0-9._-]*|'') echo "campaign tag contains unsafe characters" >&2; exit 2 ;;
esac
CAMPAIGN_ROOT="$REMOTE_WORK/results/typed-parser-parity-$CAMPAIGN_TAG"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; if [ ! -d '$REMOTE_WORK/.git' ]; then git clone --quiet https://github.com/nasqret/euf-viper.git '$REMOTE_WORK'; fi; git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'"
ssh "$REMOTE_HOST" "test ! -e '$CAMPAIGN_ROOT'"

PREPARE_ARGS=(--parsable)
if [ -n "$DEPENDENCY" ]; then
  PREPARE_ARGS+=(--dependency="afterok:$DEPENDENCY")
fi
PREPARE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && mkdir -p results && sbatch ${PREPARE_ARGS[*]} --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_TYPED_PARSER_ROOT='$CAMPAIGN_ROOT',EUF_VIPER_TYPED_PARSER_EXPECTED_SOURCES='$EXPECTED_SOURCES',EUF_VIPER_TYPED_PARSER_SHARDS='$SHARDS',EUF_VIPER_TYPED_PARSER_TIMEOUT_SECONDS='$TIMEOUT_SECONDS' scripts/wmi/euf_viper_typed_parser_parity_prepare.sbatch")"
PREPARE_JOB="${PREPARE_SUBMISSION%%;*}"
case "$PREPARE_JOB" in *[!0-9]*|'') echo "invalid prepare job id: $PREPARE_SUBMISSION" >&2; exit 2 ;; esac

LAST_SHARD="$((SHARDS - 1))"
ARRAY_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --dependency=afterok:$PREPARE_JOB --array=0-$LAST_SHARD%$MAX_PARALLEL --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_TYPED_PARSER_ROOT='$CAMPAIGN_ROOT' scripts/wmi/euf_viper_typed_parser_parity_array.sbatch")"
ARRAY_JOB="${ARRAY_SUBMISSION%%;*}"
case "$ARRAY_JOB" in *[!0-9]*|'') echo "invalid array job id: $ARRAY_SUBMISSION" >&2; exit 2 ;; esac

AUDIT_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --dependency=afterok:$ARRAY_JOB --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_TYPED_PARSER_ROOT='$CAMPAIGN_ROOT',EUF_VIPER_TYPED_PARSER_EXPECTED_SOURCES='$EXPECTED_SOURCES' scripts/wmi/euf_viper_typed_parser_parity_audit.sbatch")"
AUDIT_JOB="${AUDIT_SUBMISSION%%;*}"
case "$AUDIT_JOB" in *[!0-9]*|'') echo "invalid audit job id: $AUDIT_SUBMISSION" >&2; exit 2 ;; esac

mkdir -p results
python3 - "$ROOT/results/typed-parser-parity-submission-$PREPARE_JOB.json" <<PY
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "schema": "euf-viper.typed-parser-parity-submission.v1",
    "status": "submitted",
    "revision": "$REVISION",
    "published_ref": "$PUBLISHED_REF",
    "remote_host": "$REMOTE_HOST",
    "remote_worktree": "$REMOTE_WORK",
    "campaign_root": "$CAMPAIGN_ROOT",
    "dependency": "$DEPENDENCY" or None,
    "expected_sources": int("$EXPECTED_SOURCES"),
    "shards": int("$SHARDS"),
    "max_parallel": int("$MAX_PARALLEL"),
    "timeout_seconds": int("$TIMEOUT_SECONDS"),
    "prepare_job": "$PREPARE_JOB",
    "array_job": "$ARRAY_JOB",
    "audit_job": "$AUDIT_JOB",
}
temporary = path.with_name(f".{path.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
