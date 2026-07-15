#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_T6_REMOTE_PARENT:-}"
REMOTE_BRANCH="${EUF_VIPER_T6_REMOTE_BRANCH:-research-t6-theory-dag}"
MANIFEST="$ROOT/campaigns/t6-theory-dag-p0-qg12-v1.json"
TOOLCHAIN_CONTRACT="$ROOT/campaigns/t6-wmi-rust-toolchain-1.96.0-v1.json"
HISTORICAL_DISPOSITION="$ROOT/campaigns/t6-wmi-job-146075-disposition-v1.json"
EXPECTED_MANIFEST_SHA256="33a9f0016570dc07dc4c9aed2f575633eb5a2ee10d21177c97a4e86b65507c78"
EXPECTED_TOOLCHAIN_CONTRACT_SHA256="db825fa64cf03e20d07842d063638ecdf7193a1eba4966be5d9e5f7e5c108baa"
EXPECTED_HISTORICAL_DISPOSITION_SHA256="b22f3bfdb10d2a379d5777e206eacd1e85453ee69c7380d8b68d995bda3fcbda"
HISTORICAL_HARD10_JOB_ID=146075

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

MANIFEST_SHA256="$(shasum -a 256 "$MANIFEST" | awk '{print $1}')"
if [ "$MANIFEST_SHA256" != "$EXPECTED_MANIFEST_SHA256" ]; then
  echo "manifest hash mismatch: expected $EXPECTED_MANIFEST_SHA256, got $MANIFEST_SHA256" >&2
  exit 2
fi
TOOLCHAIN_CONTRACT_SHA256="$(shasum -a 256 "$TOOLCHAIN_CONTRACT" | awk '{print $1}')"
if [ "$TOOLCHAIN_CONTRACT_SHA256" != "$EXPECTED_TOOLCHAIN_CONTRACT_SHA256" ]; then
  echo "toolchain contract hash mismatch" >&2
  exit 2
fi
HISTORICAL_DISPOSITION_SHA256="$(shasum -a 256 "$HISTORICAL_DISPOSITION" | awk '{print $1}')"
if [ "$HISTORICAL_DISPOSITION_SHA256" != "$EXPECTED_HISTORICAL_DISPOSITION_SHA256" ]; then
  echo "historical job $HISTORICAL_HARD10_JOB_ID disposition hash mismatch" >&2
  exit 2
fi

# This exits before any SSH while external 1.96.0 provisioning is unavailable or unreviewed.
PYTHONDONTWRITEBYTECODE=1 python3 scripts/bench/validate_t6_wmi_toolchain.py require-ready

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
REMOTE_CORPUS_ROOT="${EUF_VIPER_T6_REMOTE_CORPUS_ROOT:-$REMOTE_HOME/euf-viper/benchmarks/smtlib-2025/QF_UF}"
SHORT_REVISION="$(git rev-parse --short=12 HEAD)"
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION-t6-theory-dag"
REMOTE_TOOLCHAIN_ATTESTATION="$REMOTE_WORK/results/t6-toolchain-preflight-$SHORT_REVISION.json"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; if [ ! -d '$REMOTE_WORK/.git' ]; then git clone --quiet https://github.com/nasqret/euf-viper.git '$REMOTE_WORK'; fi; git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'; test -d '$REMOTE_CORPUS_ROOT'; mkdir -p '$REMOTE_WORK/results'; cd '$REMOTE_WORK'; PYTHONDONTWRITEBYTECODE=1 python3 scripts/bench/validate_t6_wmi_toolchain.py inspect-host --repo-root '$REMOTE_WORK' --output '$REMOTE_TOOLCHAIN_ATTESTATION'"

SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --export=NONE scripts/wmi/euf_viper_t6_bool_dag_census.sbatch '$REVISION' '$REMOTE_CORPUS_ROOT'")"
JOB_ID="${SUBMISSION%%;*}"
case "$JOB_ID" in
  *[!0-9]*|'') echo "invalid T6 census job id: $SUBMISSION" >&2; exit 2 ;;
esac
if [ "$JOB_ID" -eq "$HISTORICAL_HARD10_JOB_ID" ]; then
  echo "scheduler returned historical hard10 job id $HISTORICAL_HARD10_JOB_ID" >&2
  exit 2
fi

mkdir -p results
CAMPAIGN_ROOT="$REMOTE_WORK/results/t6-bool-dag-census-$JOB_ID"
python3 - "$ROOT/results/t6-bool-dag-census-submission-$JOB_ID.json" \
  "$REVISION" "$REMOTE_BRANCH" "$REMOTE_HOST" "$REMOTE_WORK" \
  "$REMOTE_CORPUS_ROOT" "$MANIFEST_SHA256" "$TOOLCHAIN_CONTRACT_SHA256" \
  "$REMOTE_TOOLCHAIN_ATTESTATION" "$HISTORICAL_DISPOSITION_SHA256" \
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
    toolchain_contract_sha256,
    remote_toolchain_attestation,
    historical_disposition_sha256,
    campaign_root,
    job_id,
) = sys.argv[1:]
path = Path(output)
payload = {
    "schema": "euf-viper.t6-theory-dag-wmi-submission.v3",
    "state": "submitted",
    "analysis_kind": "source_only_structural_projection",
    "revision": revision,
    "branch": branch,
    "remote_host": remote_host,
    "remote_worktree": remote_worktree,
    "remote_corpus_root": remote_corpus_root,
    "campaign_root": campaign_root,
    "manifest_sha256": manifest_sha256,
    "toolchain": {
        "contract_sha256": toolchain_contract_sha256,
        "provisioning": "external_only_no_rustup_mutation",
        "independent_verification": "required",
        "remote_preflight_attestation": remote_toolchain_attestation,
        "version": "1.96.0",
    },
    "historical_job_146075": {
        "classification": "historical_hard10",
        "automatic_cancellation_allowed": False,
        "disposition_sha256": historical_disposition_sha256,
    },
    "slurm_export": "NONE",
    "gate_scope": "current_p0_qg7_derived_10_of_12",
    "required_qualifying_sources": 10,
    "population_status": "accepted",
    "projection_status": "not_executed",
    "implementation_or_promotion_eligible": False,
    "expected_sources": 12,
    "job_id": int(job_id),
}
temporary = path.with_name(f".{path.name}.tmp")
temporary.write_text(
    json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n",
    encoding="ascii",
)
temporary.replace(path)
print(json.dumps(payload, allow_nan=False, indent=2, sort_keys=True))
PY
