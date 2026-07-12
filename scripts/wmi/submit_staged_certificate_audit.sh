#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
ANALYSIS="${EUF_VIPER_CERT_STAGED_ANALYSIS:?set the remote staged analysis path}"
STAGE_AUDITS="${EUF_VIPER_CERT_STAGE_AUDITS:?set colon-separated remote stage audits}"
OUTPUT="${EUF_VIPER_CERT_STAGED_OUTPUT:?set the remote staged certificate audit output}"
DEPENDENCY_JOBS="${EUF_VIPER_CERT_DEPENDENCY_JOBS:?set colon-separated certificate audit job IDs}"

die() { echo "$*" >&2; exit 2; }
safe_path_list() { [[ "$1" =~ ^[A-Za-z0-9_./:-]+$ ]]; }
safe_path_list "$ANALYSIS" || die "analysis path contains unsafe characters"
safe_path_list "$STAGE_AUDITS" || die "stage audit paths contain unsafe characters"
safe_path_list "$OUTPUT" || die "output path contains unsafe characters"
[[ "$DEPENDENCY_JOBS" =~ ^[1-9][0-9]*(:[1-9][0-9]*)*$ ]] || die "dependency jobs are invalid"
case "$ANALYSIS:$OUTPUT" in /*:/*) ;; *) die "analysis and output paths must be absolute" ;; esac
IFS=: read -r -a AUDITS <<< "$STAGE_AUDITS"
for AUDIT in "${AUDITS[@]}"; do case "$AUDIT" in /*) ;; *) die "stage audit paths must be absolute" ;; esac; done

cd "$ROOT"
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  die "tracked repository state must be clean before staged certificate submission"
fi
REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
PUBLISHED="$(git ls-remote --exit-code origin refs/heads/main)"
PUBLISHED_REVISION="${PUBLISHED%%$'\t'*}"
if [ "$REVISION" != "$PUBLISHED_REVISION" ]; then
  die "HEAD is not the published origin/main revision"
fi
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
case "$REMOTE_PARENT" in /*) ;; *) die "remote campaign root must be absolute" ;; esac
REMOTE_WORK="$REMOTE_PARENT/$(git rev-parse --short=12 HEAD)"

ssh "$REMOTE_HOST" "set -euo pipefail; test -d '$REMOTE_WORK/.git'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'; test -s '$ANALYSIS'"
SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --dependency='afterok:$DEPENDENCY_JOBS' --export='ALL,EUF_VIPER_CERT_EXPECTED_REVISION=$REVISION,EUF_VIPER_CERT_STAGED_ANALYSIS=$ANALYSIS,EUF_VIPER_CERT_STAGE_AUDITS=$STAGE_AUDITS,EUF_VIPER_CERT_STAGED_OUTPUT=$OUTPUT' scripts/wmi/euf_viper_certificate_staged_audit.sbatch")"
JOB_ID="${SUBMISSION%%;*}"
case "$JOB_ID" in ''|0|0*|*[!0-9]*) die "invalid staged certificate audit job id: $SUBMISSION" ;; esac

mkdir -p results/certificate-shadow-submissions
RECEIPT="results/certificate-shadow-submissions/staged-$JOB_ID.json"
python3 - "$RECEIPT" "$REVISION" "$REMOTE_HOST" "$REMOTE_WORK" "$ANALYSIS" "$STAGE_AUDITS" "$OUTPUT" "$DEPENDENCY_JOBS" "$JOB_ID" <<'PY'
import json
import os
import sys
from pathlib import Path

output, revision, host, worktree, analysis, audits, result, dependencies, job = sys.argv[1:]
payload = {
    "schema_version": 1,
    "status": "submitted",
    "scope": "staged_physical_origin_certificate_union",
    "revision": revision,
    "remote_host": host,
    "remote_worktree": worktree,
    "analysis": analysis,
    "stage_audits": audits.split(":"),
    "output": result,
    "dependency_jobs": [int(value) for value in dependencies.split(":")],
    "job_id": int(job),
}
path = Path(output)
if path.exists() or path.is_symlink():
    raise SystemExit(f"refuse to replace receipt {path}")
temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="ascii")
temporary.replace(path)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
