#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
PUBLISHED_REF="${EUF_VIPER_T1_PUBLISHED_REF:-origin/research-typed-parser-timing}"
REMOTE_PARENT="${EUF_VIPER_T1_REMOTE_PARENT:-}"
PARTITION="cpu_idle"
NODELIST="c1n1"
DEPENDENCY="${EUF_VIPER_T1_DEPENDENCY:-}"
SHARDS=128
MAX_PARALLEL=32
WARMUP_ROUNDS=1
MEASURED_ROUNDS=5
TIMEOUT_SECONDS=2
MANIFEST_SHA256="32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
PARITY_RECEIPT_SHA256="c0c9c1879c9ac2da524c69f07affa991626c326ac0837f8f8066fde708d8482c"

cd "$ROOT"
source scripts/wmi/t1_timing_common.sh
unset EUF_VIPER_T1_PARTITION EUF_VIPER_T1_NODELIST
unset EUF_VIPER_T1_TIMING_CONTRACT EUF_VIPER_T1_TIMING_MANIFEST
unset EUF_VIPER_T1_TIMING_ACCEPTED_PARITY_RECEIPT EUF_VIPER_SHARED_CORPUS
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
if [ -n "$DEPENDENCY" ]; then
  case "$DEPENDENCY" in *[!0-9]*) echo "dependency must be numeric" >&2; exit 2 ;; esac
fi

REVISION="$(t1_git rev-parse --verify HEAD^{commit})"
t1_verify_checkout "$REVISION" "$PUBLISHED_REF"
SHORT_REVISION="$(t1_git rev-parse --short=12 "$REVISION")"
CONTRACT_SHA256="$(sha256sum campaigns/t1-typed-parser-timing-v1.json | awk '{print $1}')"
ACCEPTED_PARITY_RECEIPT="$ROOT/results/wmi/typed-parser-parity-146510/receipt.json"
t1_verify_bound_file "$ACCEPTED_PARITY_RECEIPT" "$PARITY_RECEIPT_SHA256" "accepted parity receipt"
python3 -I -B scripts/bench/typed_parser_timing.py verify-evidence \
  --contract campaigns/t1-typed-parser-timing-v1.json \
  --accepted-parity-receipt "$ACCEPTED_PARITY_RECEIPT" \
  --expected-contract-sha256 "$CONTRACT_SHA256" \
  --expected-shards "$SHARDS" \
  --expected-max-parallel "$MAX_PARALLEL" \
  --expected-warmup-rounds "$WARMUP_ROUNDS" \
  --expected-measured-rounds "$MEASURED_ROUNDS" \
  --expected-timeout-seconds "$TIMEOUT_SECONDS" >/dev/null

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
  version="$(ssh "$REMOTE_HOST" "'$canonical' --version 2>&1" | sed -n '1p')" || {
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
  remote_tool_identity /usr/bin/python3 Python
)
REQUESTED_REMOTE_CARGO="$(ssh "$REMOTE_HOST" "'$REMOTE_HOME/.cargo/bin/rustup' which cargo")"
REQUESTED_REMOTE_RUSTC="$(ssh "$REMOTE_HOST" "'$REMOTE_HOME/.cargo/bin/rustup' which rustc")"
IFS=$'\t' read -r REMOTE_CARGO REMOTE_CARGO_SHA256 REMOTE_CARGO_VERSION < <(
  remote_tool_identity "$REQUESTED_REMOTE_CARGO" Cargo
)
IFS=$'\t' read -r REMOTE_RUSTC REMOTE_RUSTC_SHA256 REMOTE_RUSTC_VERSION < <(
  remote_tool_identity "$REQUESTED_REMOTE_RUSTC" Rustc
)
IFS=$'\t' read -r REMOTE_CC REMOTE_CC_SHA256 REMOTE_CC_VERSION < <(
  remote_tool_identity /usr/bin/cc CC
)
IFS=$'\t' read -r REMOTE_LD REMOTE_LD_SHA256 REMOTE_LD_VERSION < <(
  remote_tool_identity /usr/bin/ld LD
)
IFS=$'\t' read -r REMOTE_AR REMOTE_AR_SHA256 REMOTE_AR_VERSION < <(
  remote_tool_identity /usr/bin/ar AR
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
REMOTE_PARITY_RECEIPT="$REMOTE_WORK/results/wmi/typed-parser-parity-146510/receipt.json"

ssh "$REMOTE_HOST" "set -euo pipefail; umask 077; mkdir -p '$REMOTE_PARENT'; test ! -e '$REMOTE_RUN'; mkdir '$REMOTE_RUN'; git clone --quiet https://github.com/nasqret/euf-viper.git '$REMOTE_WORK'; git -C '$REMOTE_WORK' fetch --quiet origin '+refs/heads/$PUBLISHED_BRANCH:refs/remotes/origin/$PUBLISHED_BRANCH'; test \"\$(git -C '$REMOTE_WORK' rev-parse 'origin/$PUBLISHED_BRANCH^{commit}')\" = '$REVISION'; git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'; test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'; mkdir '$REMOTE_LOGS'; test -s '$REMOTE_MANIFEST'; test \"\$(sha256sum '$REMOTE_WORK/campaigns/t1-typed-parser-timing-v1.json' | awk '{print \$1}')\" = '$CONTRACT_SHA256'; test \"\$(sha256sum '$REMOTE_MANIFEST' | awk '{print \$1}')\" = '$MANIFEST_SHA256'; test \"\$(sha256sum '$REMOTE_PARITY_RECEIPT' | awk '{print \$1}')\" = '$PARITY_RECEIPT_SHA256'; '$REMOTE_PYTHON' -I -B '$REMOTE_WORK/scripts/bench/typed_parser_timing.py' verify-corpus --manifest '$REMOTE_MANIFEST' --source-root '$REMOTE_HOME/euf-viper' --contract '$REMOTE_WORK/campaigns/t1-typed-parser-timing-v1.json' --accepted-parity-receipt '$REMOTE_PARITY_RECEIPT' --expected-accepted-parity-receipt-sha256 '$PARITY_RECEIPT_SHA256' --expected-contract-sha256 '$CONTRACT_SHA256' >/dev/null; '$REMOTE_PYTHON' -I -B '$REMOTE_WORK/scripts/wmi/t1_timing_checkout_receipt.py' --repository '$REMOTE_WORK' --revision '$REVISION' --published-ref '$PUBLISHED_REF' --output '$CHECKOUT_RECEIPT'"
CHECKOUT_RECEIPT_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$CHECKOUT_RECEIPT' | awk '{print \$1}'")"
t1_require_sha256 "$MANIFEST_SHA256" "remote manifest SHA-256"
t1_require_sha256 "$CHECKOUT_RECEIPT_SHA256" "checkout receipt SHA-256"

common_environment="EUF_VIPER_EXPECTED_REVISION='$REVISION' EUF_VIPER_T1_PUBLISHED_REF='$PUBLISHED_REF' EUF_VIPER_T1_EXPECTED_CONTRACT_SHA256='$CONTRACT_SHA256' EUF_VIPER_T1_EXPECTED_MANIFEST_SHA256='$MANIFEST_SHA256' EUF_VIPER_T1_EXPECTED_CHECKOUT_RECEIPT_SHA256='$CHECKOUT_RECEIPT_SHA256' EUF_VIPER_T1_EXPECTED_PARITY_RECEIPT_SHA256='$PARITY_RECEIPT_SHA256' EUF_VIPER_PYTHON='$REMOTE_PYTHON' EUF_VIPER_PYTHON_SHA256='$REMOTE_PYTHON_SHA256' EUF_VIPER_PYTHON_VERSION='$REMOTE_PYTHON_VERSION' EUF_VIPER_CARGO='$REMOTE_CARGO' EUF_VIPER_CARGO_SHA256='$REMOTE_CARGO_SHA256' EUF_VIPER_CARGO_VERSION='$REMOTE_CARGO_VERSION' EUF_VIPER_RUSTC='$REMOTE_RUSTC' EUF_VIPER_RUSTC_SHA256='$REMOTE_RUSTC_SHA256' EUF_VIPER_RUSTC_VERSION='$REMOTE_RUSTC_VERSION' EUF_VIPER_CC='$REMOTE_CC' EUF_VIPER_CC_SHA256='$REMOTE_CC_SHA256' EUF_VIPER_CC_VERSION='$REMOTE_CC_VERSION' EUF_VIPER_LD='$REMOTE_LD' EUF_VIPER_LD_SHA256='$REMOTE_LD_SHA256' EUF_VIPER_LD_VERSION='$REMOTE_LD_VERSION' EUF_VIPER_AR='$REMOTE_AR' EUF_VIPER_AR_SHA256='$REMOTE_AR_SHA256' EUF_VIPER_AR_VERSION='$REMOTE_AR_VERSION'"

prepare_dependency=""
if [ -n "$DEPENDENCY" ]; then
  prepare_dependency="--dependency=afterok:$DEPENDENCY"
fi
PREPARE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && env -i HOME='$REMOTE_HOME' PATH=/usr/bin:/bin $common_environment sbatch --parsable --partition='$PARTITION' --nodelist='$NODELIST' --hint=nomultithread --threads-per-core=1 --cpu-bind=cores --mem-bind=local $prepare_dependency --output='$REMOTE_LOGS/prepare-%j.out' --error='$REMOTE_LOGS/prepare-%j.err' --export=ALL scripts/wmi/euf_viper_t1_timing_prepare.sbatch")"
PREPARE_JOB="${PREPARE_SUBMISSION%%;*}"
case "$PREPARE_JOB" in ''|*[!0-9]*) echo "invalid prepare job id: $PREPARE_SUBMISSION" >&2; exit 2 ;; esac

LAST_SHARD="$((SHARDS - 1))"
ARRAY_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && env -i HOME='$REMOTE_HOME' PATH=/usr/bin:/bin $common_environment sbatch --parsable --partition='$PARTITION' --nodelist='$NODELIST' --hint=nomultithread --threads-per-core=1 --cpu-bind=cores --mem-bind=local --dependency=afterok:$PREPARE_JOB --array=0-$LAST_SHARD%$MAX_PARALLEL --output='$REMOTE_LOGS/array-%A_%a.out' --error='$REMOTE_LOGS/array-%A_%a.err' --export=ALL scripts/wmi/euf_viper_t1_timing_array.sbatch")"
ARRAY_JOB="${ARRAY_SUBMISSION%%;*}"
case "$ARRAY_JOB" in ''|*[!0-9]*) echo "invalid array job id: $ARRAY_SUBMISSION" >&2; exit 2 ;; esac

AUDIT_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && env -i HOME='$REMOTE_HOME' PATH=/usr/bin:/bin $common_environment sbatch --parsable --partition='$PARTITION' --nodelist='$NODELIST' --hint=nomultithread --threads-per-core=1 --cpu-bind=cores --mem-bind=local --dependency=afterok:$ARRAY_JOB --output='$REMOTE_LOGS/audit-%j.out' --error='$REMOTE_LOGS/audit-%j.err' --export=ALL scripts/wmi/euf_viper_t1_timing_audit.sbatch")"
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
    "accepted_parity_receipt_sha256": "$PARITY_RECEIPT_SHA256",
    "checkout_receipt_sha256": "$CHECKOUT_RECEIPT_SHA256",
    "dependency": "$DEPENDENCY" or None,
    "max_parallel": $MAX_PARALLEL,
    "partition": "$PARTITION",
    "nodelist": "$NODELIST",
    "promotion_eligibility": "research-only-first-campaign",
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
        "ar": {"path": "$REMOTE_AR", "sha256": "$REMOTE_AR_SHA256", "version": "$REMOTE_AR_VERSION"},
        "cargo": {"path": "$REMOTE_CARGO", "sha256": "$REMOTE_CARGO_SHA256", "version": "$REMOTE_CARGO_VERSION"},
        "cc": {"path": "$REMOTE_CC", "sha256": "$REMOTE_CC_SHA256", "version": "$REMOTE_CC_VERSION"},
        "ld": {"path": "$REMOTE_LD", "sha256": "$REMOTE_LD_SHA256", "version": "$REMOTE_LD_VERSION"},
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
