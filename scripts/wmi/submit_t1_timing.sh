#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
PUBLISHED_REF="${EUF_VIPER_T1_PUBLISHED_REF:-origin/research-typed-parser-timing}"
REMOTE_PARENT="${EUF_VIPER_T1_REMOTE_PARENT:-}"
PARTITION="${EUF_VIPER_T1_PARTITION:-cpu_idle}"
DEPENDENCY="${EUF_VIPER_T1_DEPENDENCY:-}"
SHARDS=128
MAX_PARALLEL=32

cd "$ROOT"
source scripts/wmi/t1_timing_common.sh
case "$PUBLISHED_REF" in
  origin/*) PUBLISHED_BRANCH="${PUBLISHED_REF#origin/}" ;;
  *) echo "published ref must name an origin branch" >&2; exit 2 ;;
esac
case "$PUBLISHED_BRANCH" in
  ''|*[!A-Za-z0-9._/-]*|*..*|-*) echo "published branch is unsafe" >&2; exit 2 ;;
esac
case "$REMOTE_HOST" in
  ''|*[!A-Za-z0-9._@-]*) echo "remote host is unsafe" >&2; exit 2 ;;
esac
case "$PARTITION" in
  ''|*[!A-Za-z0-9_-]*) echo "partition is unsafe" >&2; exit 2 ;;
esac
if [ -n "$DEPENDENCY" ]; then
  case "$DEPENDENCY" in *[!0-9]*) echo "dependency must be numeric" >&2; exit 2 ;; esac
fi

REVISION="$(git rev-parse --verify HEAD^{commit})"
t1_verify_checkout "$REVISION" "$PUBLISHED_REF"
SHORT_REVISION="$(git rev-parse --short=12 "$REVISION")"
CONTRACT_SHA256="$(sha256sum campaigns/t1-typed-parser-timing-v1.json | awk '{print $1}')"

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
case "$REMOTE_HOME" in
  /*) ;;
  *) echo "remote HOME is not absolute" >&2; exit 2 ;;
esac
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-t1-timing-campaigns"
fi
case "$REMOTE_PARENT" in
  /*) ;;
  *) echo "remote campaign parent must be absolute" >&2; exit 2 ;;
esac
case "$REMOTE_PARENT" in
  *[!A-Za-z0-9_./-]*) echo "remote campaign parent is unsafe" >&2; exit 2 ;;
esac

remote_tool_identity() {
  local requested="$1"
  local label="$2"
  local canonical digest version
  case "$requested" in
    /*) ;;
    *) echo "$label path must be absolute" >&2; return 2 ;;
  esac
  case "$requested" in
    *[!A-Za-z0-9_./-]*) echo "$label path is unsafe" >&2; return 2 ;;
  esac
  canonical="$(ssh "$REMOTE_HOST" "readlink -f -- '$requested'")" || {
    echo "cannot canonicalize remote $label" >&2
    return 2
  }
  digest="$(ssh "$REMOTE_HOST" "test -f '$canonical' && test -x '$canonical' && test ! -L '$canonical' && sha256sum '$canonical' | awk '{print \$1}'")" || {
    echo "remote $label is unavailable" >&2
    return 2
  }
  t1_require_sha256 "$digest" "remote $label SHA-256" || return
  version="$(ssh "$REMOTE_HOST" "'$canonical' --version 2>&1")" || {
    echo "remote $label --version failed" >&2
    return 2
  }
  case "$version" in
    ''|*$'\n'*|*$'\r'*|*[!A-Za-z0-9._+\ \(\)/:-]*)
      echo "remote $label version is unsafe: $version" >&2
      return 2
      ;;
  esac
  printf '%s\t%s\t%s\n' "$canonical" "$digest" "$version"
}

IFS=$'\t' read -r REMOTE_PYTHON REMOTE_PYTHON_SHA256 REMOTE_PYTHON_VERSION < <(
  remote_tool_identity "${EUF_VIPER_PYTHON_REMOTE_PATH:-/usr/bin/python3}" Python
)
if [ -n "${EUF_VIPER_CARGO_REMOTE_PATH:-}" ]; then
  REQUESTED_REMOTE_CARGO="$EUF_VIPER_CARGO_REMOTE_PATH"
else
  REQUESTED_REMOTE_CARGO="$(ssh "$REMOTE_HOST" "'$REMOTE_HOME/.cargo/bin/rustup' which cargo")"
fi
if [ -n "${EUF_VIPER_RUSTC_REMOTE_PATH:-}" ]; then
  REQUESTED_REMOTE_RUSTC="$EUF_VIPER_RUSTC_REMOTE_PATH"
else
  REQUESTED_REMOTE_RUSTC="$(ssh "$REMOTE_HOST" "'$REMOTE_HOME/.cargo/bin/rustup' which rustc")"
fi
IFS=$'\t' read -r REMOTE_CARGO REMOTE_CARGO_SHA256 REMOTE_CARGO_VERSION < <(
  remote_tool_identity "$REQUESTED_REMOTE_CARGO" Cargo
)
IFS=$'\t' read -r REMOTE_RUSTC REMOTE_RUSTC_SHA256 REMOTE_RUSTC_VERSION < <(
  remote_tool_identity "$REQUESTED_REMOTE_RUSTC" Rustc
)

CAMPAIGN_TAG="${EUF_VIPER_T1_CAMPAIGN_TAG:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
case "$CAMPAIGN_TAG" in
  ''|*[!A-Za-z0-9._-]*) echo "campaign tag is unsafe" >&2; exit 2 ;;
esac
REMOTE_RUN="$REMOTE_PARENT/$CAMPAIGN_TAG-$SHORT_REVISION"
REMOTE_WORK="$REMOTE_RUN/repo"
CAMPAIGN_ROOT="$REMOTE_RUN/artifacts"
REMOTE_LOGS="$REMOTE_RUN/logs"
CHECKOUT_RECEIPT="$REMOTE_RUN/checkout-receipt.json"
REMOTE_MANIFEST="$REMOTE_HOME/euf-viper/benchmarks/smtlib-2025/qf_uf_manifest.jsonl"

ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REMOTE_PARENT'; test ! -e '$REMOTE_RUN'; mkdir '$REMOTE_RUN'; git clone --quiet https://github.com/nasqret/euf-viper.git '$REMOTE_WORK'; git -C '$REMOTE_WORK' fetch --quiet origin '+refs/heads/$PUBLISHED_BRANCH:refs/remotes/origin/$PUBLISHED_BRANCH'; test \"\$(git -C '$REMOTE_WORK' rev-parse 'origin/$PUBLISHED_BRANCH^{commit}')\" = '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'; mkdir '$REMOTE_LOGS'; test -s '$REMOTE_MANIFEST'; test \"\$(sha256sum '$REMOTE_WORK/campaigns/t1-typed-parser-timing-v1.json' | awk '{print \$1}')\" = '$CONTRACT_SHA256'; '$REMOTE_PYTHON' -I -B '$REMOTE_WORK/scripts/wmi/t1_timing_checkout_receipt.py' --repository '$REMOTE_WORK' --revision '$REVISION' --published-ref '$PUBLISHED_REF' --output '$CHECKOUT_RECEIPT'"
MANIFEST_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_MANIFEST' | awk '{print \$1}'")"
CHECKOUT_RECEIPT_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$CHECKOUT_RECEIPT' | awk '{print \$1}'")"
t1_require_sha256 "$MANIFEST_SHA256" "remote manifest SHA-256"
t1_require_sha256 "$CHECKOUT_RECEIPT_SHA256" "checkout receipt SHA-256"

common_environment="EUF_VIPER_EXPECTED_REVISION='$REVISION' EUF_VIPER_T1_PUBLISHED_REF='$PUBLISHED_REF' EUF_VIPER_T1_EXPECTED_CONTRACT_SHA256='$CONTRACT_SHA256' EUF_VIPER_T1_EXPECTED_MANIFEST_SHA256='$MANIFEST_SHA256' EUF_VIPER_T1_EXPECTED_CHECKOUT_RECEIPT_SHA256='$CHECKOUT_RECEIPT_SHA256' EUF_VIPER_PYTHON='$REMOTE_PYTHON' EUF_VIPER_PYTHON_SHA256='$REMOTE_PYTHON_SHA256' EUF_VIPER_PYTHON_VERSION='$REMOTE_PYTHON_VERSION' EUF_VIPER_CARGO='$REMOTE_CARGO' EUF_VIPER_CARGO_SHA256='$REMOTE_CARGO_SHA256' EUF_VIPER_CARGO_VERSION='$REMOTE_CARGO_VERSION' EUF_VIPER_RUSTC='$REMOTE_RUSTC' EUF_VIPER_RUSTC_SHA256='$REMOTE_RUSTC_SHA256' EUF_VIPER_RUSTC_VERSION='$REMOTE_RUSTC_VERSION'"

prepare_dependency=""
if [ -n "$DEPENDENCY" ]; then
  prepare_dependency="--dependency=afterok:$DEPENDENCY"
fi
PREPARE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && env -i HOME='$REMOTE_HOME' PATH=/usr/bin:/bin $common_environment sbatch --parsable --partition='$PARTITION' $prepare_dependency --output='$REMOTE_LOGS/prepare-%j.out' --error='$REMOTE_LOGS/prepare-%j.err' --export=ALL scripts/wmi/euf_viper_t1_timing_prepare.sbatch")"
PREPARE_JOB="${PREPARE_SUBMISSION%%;*}"
case "$PREPARE_JOB" in ''|*[!0-9]*) echo "invalid prepare job id: $PREPARE_SUBMISSION" >&2; exit 2 ;; esac

LAST_SHARD="$((SHARDS - 1))"
ARRAY_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && env -i HOME='$REMOTE_HOME' PATH=/usr/bin:/bin $common_environment sbatch --parsable --partition='$PARTITION' --dependency=afterok:$PREPARE_JOB --array=0-$LAST_SHARD%$MAX_PARALLEL --output='$REMOTE_LOGS/array-%A_%a.out' --error='$REMOTE_LOGS/array-%A_%a.err' --export=ALL scripts/wmi/euf_viper_t1_timing_array.sbatch")"
ARRAY_JOB="${ARRAY_SUBMISSION%%;*}"
case "$ARRAY_JOB" in ''|*[!0-9]*) echo "invalid array job id: $ARRAY_SUBMISSION" >&2; exit 2 ;; esac

AUDIT_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && env -i HOME='$REMOTE_HOME' PATH=/usr/bin:/bin $common_environment sbatch --parsable --partition='$PARTITION' --dependency=afterok:$ARRAY_JOB --output='$REMOTE_LOGS/audit-%j.out' --error='$REMOTE_LOGS/audit-%j.err' --export=ALL scripts/wmi/euf_viper_t1_timing_audit.sbatch")"
AUDIT_JOB="${AUDIT_SUBMISSION%%;*}"
case "$AUDIT_JOB" in ''|*[!0-9]*) echo "invalid audit job id: $AUDIT_SUBMISSION" >&2; exit 2 ;; esac

mkdir -p results
RECEIPT="results/t1-typed-parser-timing-submission-$PREPARE_JOB.json"
[ ! -e "$RECEIPT" ] || { echo "refusing to replace receipt: $RECEIPT" >&2; exit 2; }
TEMPORARY="$RECEIPT.tmp.$$"
trap 'rm -f "$TEMPORARY"' EXIT
ssh "$REMOTE_HOST" "'$REMOTE_PYTHON' -" > "$TEMPORARY" <<PY
import json
payload = {
    "array_job": "$ARRAY_JOB",
    "audit_job": "$AUDIT_JOB",
    "campaign_root": "$CAMPAIGN_ROOT",
    "contract_sha256": "$CONTRACT_SHA256",
    "manifest_sha256": "$MANIFEST_SHA256",
    "checkout_receipt_sha256": "$CHECKOUT_RECEIPT_SHA256",
    "dependency": "$DEPENDENCY" or None,
    "max_parallel": $MAX_PARALLEL,
    "partition": "$PARTITION",
    "prepare_job": "$PREPARE_JOB",
    "published_ref": "$PUBLISHED_REF",
    "remote_host": "$REMOTE_HOST",
    "remote_worktree": "$REMOTE_WORK",
    "remote_run": "$REMOTE_RUN",
    "revision": "$REVISION",
    "schema": "euf-viper.typed-parser-timing-submission.v1",
    "shards": $SHARDS,
    "status": "submitted",
    "tools": {
        "cargo": {"path": "$REMOTE_CARGO", "sha256": "$REMOTE_CARGO_SHA256", "version": "$REMOTE_CARGO_VERSION"},
        "python": {"path": "$REMOTE_PYTHON", "sha256": "$REMOTE_PYTHON_SHA256", "version": "$REMOTE_PYTHON_VERSION"},
        "rustc": {"path": "$REMOTE_RUSTC", "sha256": "$REMOTE_RUSTC_SHA256", "version": "$REMOTE_RUSTC_VERSION"},
    },
}
print(json.dumps(payload, allow_nan=False, indent=2, sort_keys=True))
PY
ln "$TEMPORARY" "$RECEIPT"
rm -f "$TEMPORARY"
trap - EXIT
cat "$RECEIPT"
