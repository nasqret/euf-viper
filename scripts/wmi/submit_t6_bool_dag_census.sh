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
REMOTE_CARGO="${EUF_VIPER_CARGO_REMOTE_PATH:-$REMOTE_HOME/.cargo/bin/cargo}"
case "$REMOTE_CARGO" in
  /*) ;;
  *) echo "remote cargo path must be absolute" >&2; exit 2 ;;
esac
case "$REMOTE_CARGO" in
  *[!A-Za-z0-9_./-]*) echo "remote cargo path contains unsafe characters" >&2; exit 2 ;;
esac
if ! REMOTE_CARGO_RESOLVED="$(ssh "$REMOTE_HOST" "test -f '$REMOTE_CARGO' && test -x '$REMOTE_CARGO' && readlink -f -- '$REMOTE_CARGO'")"; then
  echo "remote cargo is missing, not executable, or unresolvable: $REMOTE_CARGO" >&2
  exit 2
fi
case "$REMOTE_CARGO_RESOLVED" in
  /*) ;;
  *) echo "resolved remote cargo path must be absolute" >&2; exit 2 ;;
esac
case "$REMOTE_CARGO_RESOLVED" in
  *[!A-Za-z0-9_./-]*) echo "resolved remote cargo path contains unsafe characters" >&2; exit 2 ;;
esac
if ! REMOTE_CARGO_SHA256="$(ssh "$REMOTE_HOST" "test -f '$REMOTE_CARGO_RESOLVED' && test -x '$REMOTE_CARGO_RESOLVED' && sha256sum '$REMOTE_CARGO_RESOLVED' | awk '{print \$1}'")"; then
  echo "failed to hash resolved remote cargo: $REMOTE_CARGO_RESOLVED" >&2
  exit 2
fi
if [ "${#REMOTE_CARGO_SHA256}" -ne 64 ]; then
  echo "failed to pin remote cargo SHA-256 at $REMOTE_CARGO_RESOLVED" >&2
  exit 2
fi
case "$REMOTE_CARGO_SHA256" in
  *[!0-9a-f]*) echo "remote cargo SHA-256 is malformed" >&2; exit 2 ;;
esac
if ! REMOTE_CARGO_VERSION="$(ssh "$REMOTE_HOST" "'$REMOTE_CARGO' --version")"; then
  echo "failed to read remote cargo version through $REMOTE_CARGO" >&2
  exit 2
fi
if [[ ! "$REMOTE_CARGO_VERSION" =~ ^cargo\ [0-9]+\.[0-9]+\.[0-9]+\ \([0-9a-f]+\ [0-9]{4}-[0-9]{2}-[0-9]{2}\)$ ]]; then
  echo "remote cargo version is malformed: $REMOTE_CARGO_VERSION" >&2
  exit 2
fi
REMOTE_CORPUS_ROOT="${EUF_VIPER_T6_REMOTE_CORPUS_ROOT:-$REMOTE_HOME/euf-viper/benchmarks/smtlib-2025/QF_UF}"
SHORT_REVISION="$(git rev-parse --short=12 HEAD)"
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION-t6-theory-dag"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; if [ ! -d '$REMOTE_WORK/.git' ]; then git clone --quiet https://github.com/nasqret/euf-viper.git '$REMOTE_WORK'; fi; git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'; test -d '$REMOTE_CORPUS_ROOT'"

SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && mkdir -p results && sbatch --parsable --export=ALL,EUF_VIPER_EXPECTED_REVISION='$REVISION',EUF_VIPER_CARGO='$REMOTE_CARGO',EUF_VIPER_CARGO_RESOLVED='$REMOTE_CARGO_RESOLVED',EUF_VIPER_CARGO_SHA256='$REMOTE_CARGO_SHA256',EUF_VIPER_CARGO_VERSION='$REMOTE_CARGO_VERSION',EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256='$MANIFEST_SHA256',EUF_VIPER_T6_CORPUS_ROOT='$REMOTE_CORPUS_ROOT' scripts/wmi/euf_viper_t6_bool_dag_census.sbatch")"
JOB_ID="${SUBMISSION%%;*}"
case "$JOB_ID" in
  *[!0-9]*|'') echo "invalid T6 census job id: $SUBMISSION" >&2; exit 2 ;;
esac

mkdir -p results
CAMPAIGN_ROOT="$REMOTE_WORK/results/t6-bool-dag-census-$JOB_ID"
python3 - "$ROOT/results/t6-bool-dag-census-submission-$JOB_ID.json" \
  "$REVISION" "$REMOTE_BRANCH" "$REMOTE_HOST" "$REMOTE_WORK" \
  "$REMOTE_CORPUS_ROOT" "$MANIFEST_SHA256" "$REMOTE_CARGO" \
  "$REMOTE_CARGO_RESOLVED" "$REMOTE_CARGO_SHA256" "$REMOTE_CARGO_VERSION" \
  "$CAMPAIGN_ROOT" "$JOB_ID" <<'PY'
import json
import sys
from pathlib import Path

(
    output,
    revision,
    branch,
    remote_host,
    remote_worktree,
    remote_corpus_root,
    manifest_sha256,
    cargo_configured,
    cargo_resolved,
    cargo_sha256,
    cargo_version,
    campaign_root,
    job_id,
) = sys.argv[1:]
path = Path(output)
payload = {
    "schema": "euf-viper.t6-theory-dag-wmi-submission.v1",
    "state": "submitted",
    "analysis_kind": "source_only_structural_projection",
    "revision": revision,
    "branch": branch,
    "remote_host": remote_host,
    "remote_worktree": remote_worktree,
    "remote_corpus_root": remote_corpus_root,
    "campaign_root": campaign_root,
    "manifest_sha256": manifest_sha256,
    "cargo": {
        "configured_path": cargo_configured,
        "resolved_path": cargo_resolved,
        "sha256": cargo_sha256,
        "version": cargo_version,
    },
    "gate_scope": "historical_58efe9d_developmental_8_of_10",
    "current_confirmation_required": True,
    "implementation_or_promotion_eligible": False,
    "expected_sources": 10,
    "job_id": int(job_id),
}
temporary = path.with_name(f".{path.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
