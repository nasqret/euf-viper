#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=euf_viper_kissat4_paired_common.sh
source "$ROOT/scripts/wmi/euf_viper_kissat4_paired_common.sh"

DRY_RUN=0
case "${1:-}" in
  '') ;;
  --dry-run) DRY_RUN=1 ;;
  *) printf 'usage: %s [--dry-run]\n' "$0" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { printf 'usage: %s [--dry-run]\n' "$0" >&2; exit 2; }

REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_REPOSITORY="${EUF_VIPER_KISSAT4_REMOTE_REPOSITORY:-https://github.com/nasqret/euf-viper.git}"
REMOTE_BRANCH="${EUF_VIPER_KISSAT4_REMOTE_BRANCH:-research-modern-kissat}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
VALIDATION_ROOT="${EUF_VIPER_KISSAT4_VALIDATION_ROOT:-$KISSAT4_DEFAULT_VALIDATION_ROOT}"
SHARDS="${EUF_VIPER_KISSAT4_SHARDS:-64}"
MAX_ACTIVE="${EUF_VIPER_KISSAT4_MAX_ACTIVE:-16}"
TIMEOUT="${EUF_VIPER_KISSAT4_TIMEOUT:-2}"
REPEATS="${EUF_VIPER_KISSAT4_REPEATS:-3}"
WARMUPS="${EUF_VIPER_KISSAT4_WARMUPS:-1}"
SAMPLE_LIMIT="${EUF_VIPER_KISSAT4_SAMPLE_LIMIT:-64}"
SAMPLE_SEED="${EUF_VIPER_KISSAT4_SAMPLE_SEED:-144945}"
SAMPLE_MIN_PAIRED="${EUF_VIPER_KISSAT4_SAMPLE_MIN_PAIRED:-20}"
SAMPLE_MIN_SPEEDUP="${EUF_VIPER_KISSAT4_SAMPLE_MIN_SPEEDUP:-0.95}"
BROAD_MIN_PAIRED="${EUF_VIPER_KISSAT4_BROAD_MIN_PAIRED:-100}"
BROAD_MIN_SPEEDUP="${EUF_VIPER_KISSAT4_BROAD_MIN_SPEEDUP:-1.0}"
BROAD_MAX_P_VALUE="${EUF_VIPER_KISSAT4_BROAD_MAX_P_VALUE:-0.05}"
BROAD_ITERATIONS="${EUF_VIPER_KISSAT4_BROAD_ITERATIONS:-10000}"
EXTERNAL_DEPENDENCY="${EUF_VIPER_KISSAT4_DEPENDENCY:-}"
kissat4_require_safe_remote_value REMOTE_HOST "$REMOTE_HOST"
case "$REMOTE_HOST" in -*) kissat4_die "REMOTE_HOST cannot begin with '-'" ;; esac

for pair in \
  "SHARDS:$SHARDS" \
  "MAX_ACTIVE:$MAX_ACTIVE" \
  "TIMEOUT:$TIMEOUT" \
  "REPEATS:$REPEATS" \
  "SAMPLE_LIMIT:$SAMPLE_LIMIT" \
  "SAMPLE_MIN_PAIRED:$SAMPLE_MIN_PAIRED" \
  "BROAD_MIN_PAIRED:$BROAD_MIN_PAIRED" \
  "BROAD_ITERATIONS:$BROAD_ITERATIONS"
do
  kissat4_require_positive_int "${pair%%:*}" "${pair#*:}"
done
kissat4_require_nonnegative_int WARMUPS "$WARMUPS"
kissat4_require_nonnegative_int SAMPLE_SEED "$SAMPLE_SEED"
kissat4_require_positive_decimal SAMPLE_MIN_SPEEDUP "$SAMPLE_MIN_SPEEDUP"
kissat4_require_positive_decimal BROAD_MIN_SPEEDUP "$BROAD_MIN_SPEEDUP"
kissat4_require_probability BROAD_MAX_P_VALUE "$BROAD_MAX_P_VALUE"
if [ -n "$EXTERNAL_DEPENDENCY" ]; then
  kissat4_require_positive_int EUF_VIPER_KISSAT4_DEPENDENCY "$EXTERNAL_DEPENDENCY"
fi
[ "$MAX_ACTIVE" -le "$SHARDS" ] || kissat4_die "MAX_ACTIVE cannot exceed SHARDS"
[ "$SAMPLE_MIN_PAIRED" -le "$SAMPLE_LIMIT" ] || \
  kissat4_die "SAMPLE_MIN_PAIRED cannot exceed SAMPLE_LIMIT"

REVISION="$(git rev-parse HEAD)"
kissat4_check_repository "$REVISION"
SCRIPT_BUNDLE_SHA256="$(kissat4_script_bundle_sha256)"
PUBLISHED_REVISION="$(git ls-remote --exit-code origin "refs/heads/$REMOTE_BRANCH" | awk 'NR == 1 {print $1}')"
[ "$PUBLISHED_REVISION" = "$REVISION" ] || \
  kissat4_die "HEAD $REVISION is not published at origin/$REMOTE_BRANCH ($PUBLISHED_REVISION)"
SHORT_REVISION="$(git rev-parse --short=12 HEAD)"

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
REMOTE_WORK="$REMOTE_PARENT/$SHORT_REVISION-kissat4-paired"
SHARED_CORPUS="${EUF_VIPER_KISSAT4_SHARED_CORPUS:-$REMOTE_HOME/euf-viper/benchmarks/smtlib-2025}"
REMOTE_MANIFEST="$SHARED_CORPUS/qf_uf_manifest.jsonl"
for pair in \
  "REMOTE_HOST:$REMOTE_HOST" \
  "REMOTE_REPOSITORY:$REMOTE_REPOSITORY" \
  "REMOTE_BRANCH:$REMOTE_BRANCH" \
  "REMOTE_HOME:$REMOTE_HOME" \
  "REMOTE_PARENT:$REMOTE_PARENT" \
  "REMOTE_WORK:$REMOTE_WORK" \
  "SHARED_CORPUS:$SHARED_CORPUS" \
  "REMOTE_MANIFEST:$REMOTE_MANIFEST" \
  "VALIDATION_ROOT:$VALIDATION_ROOT"
do
  kissat4_require_safe_remote_value "${pair%%:*}" "${pair#*:}"
done

ssh "$REMOTE_HOST" "set -euo pipefail
mkdir -p '$REMOTE_PARENT'
if [ ! -d '$REMOTE_WORK/.git' ]; then
  git clone --quiet --branch '$REMOTE_BRANCH' '$REMOTE_REPOSITORY' '$REMOTE_WORK'
fi
git -C '$REMOTE_WORK' fetch --quiet origin '$REMOTE_BRANCH'
git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'
test \"\$(git -C '$REMOTE_WORK' rev-parse HEAD)\" = '$REVISION'
test -s '$REMOTE_MANIFEST'
mkdir -p '$REMOTE_WORK/benchmarks'
if [ -L '$REMOTE_WORK/benchmarks/smtlib-2025' ]; then
  test \"\$(readlink -f '$REMOTE_WORK/benchmarks/smtlib-2025')\" = \"\$(readlink -f '$SHARED_CORPUS')\"
elif [ -e '$REMOTE_WORK/benchmarks/smtlib-2025' ]; then
  echo 'unexpected non-symlink benchmarks/smtlib-2025' >&2
  exit 2
else
  ln -s '$SHARED_CORPUS' '$REMOTE_WORK/benchmarks/smtlib-2025'
fi
cd '$REMOTE_WORK'
source scripts/wmi/euf_viper_kissat4_paired_common.sh
kissat4_check_repository '$REVISION'
kissat4_check_script_bundle '$SCRIPT_BUNDLE_SHA256'
kissat4_check_binaries '$VALIDATION_ROOT'"

MANIFEST_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_MANIFEST' | awk '{print \$1}'")"
MANIFEST_ROWS="$(ssh "$REMOTE_HOST" "awk 'NF {count++} END {print count + 0}' '$REMOTE_MANIFEST'")"
kissat4_require_positive_int MANIFEST_ROWS "$MANIFEST_ROWS"
[ "$SHARDS" -le "$MANIFEST_ROWS" ] || kissat4_die "SHARDS exceeds manifest rows"
[ "$SAMPLE_LIMIT" -le "$MANIFEST_ROWS" ] || kissat4_die "SAMPLE_LIMIT exceeds manifest rows"

mkdir -p results
PLAN_PATH="$ROOT/results/kissat4-paired-plan-$SHORT_REVISION.json"

if [ "$DRY_RUN" = 1 ]; then
  SAMPLE_JOB=""
  BROAD_JOB=""
  MERGE_JOB=""
  SUBMISSION_STATUS="validated_plan"
else
  COMMON_EXPORTS="HOME=$REMOTE_HOME,EUF_VIPER_KISSAT4_EXPECTED_REVISION=$REVISION,EUF_VIPER_KISSAT4_SCRIPT_BUNDLE_SHA256=$SCRIPT_BUNDLE_SHA256,EUF_VIPER_KISSAT4_VALIDATION_ROOT=$VALIDATION_ROOT,EUF_VIPER_KISSAT4_MANIFEST=$REMOTE_MANIFEST,EUF_VIPER_KISSAT4_MANIFEST_SHA256=$MANIFEST_SHA256,EUF_VIPER_KISSAT4_TIMEOUT=$TIMEOUT,EUF_VIPER_KISSAT4_REPEATS=$REPEATS,EUF_VIPER_KISSAT4_WARMUPS=$WARMUPS"
  SAMPLE_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_KISSAT4_STAGE=sample,EUF_VIPER_KISSAT4_SAMPLE_LIMIT=$SAMPLE_LIMIT,EUF_VIPER_KISSAT4_SAMPLE_SEED=$SAMPLE_SEED,EUF_VIPER_KISSAT4_SAMPLE_MIN_PAIRED=$SAMPLE_MIN_PAIRED,EUF_VIPER_KISSAT4_SAMPLE_MIN_SPEEDUP=$SAMPLE_MIN_SPEEDUP"
  SAMPLE_DEPENDENCY=""
  if [ -n "$EXTERNAL_DEPENDENCY" ]; then
    SAMPLE_DEPENDENCY="--dependency=afterok:$EXTERNAL_DEPENDENCY"
  fi
  SAMPLE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && mkdir -p results && sbatch --parsable --kill-on-invalid-dep=yes $SAMPLE_DEPENDENCY --job-name=euf-k4-sample --output=results/kissat4-paired-sample-%j.out --error=results/kissat4-paired-sample-%j.err --export='$SAMPLE_EXPORTS' scripts/wmi/euf_viper_kissat4_paired.sbatch")"
  SAMPLE_JOB="${SAMPLE_SUBMISSION%%;*}"
  case "$SAMPLE_JOB" in ''|*[!0-9]*) kissat4_die "invalid sample job id: $SAMPLE_SUBMISSION" ;; esac

  abort_partial_chain() {
    ssh "$REMOTE_HOST" "scancel '$SAMPLE_JOB' ${BROAD_JOB:+'$BROAD_JOB'} ${MERGE_JOB:+'$MERGE_JOB'}" >/dev/null 2>&1 || true
  }
  BROAD_JOB=""
  MERGE_JOB=""
  trap abort_partial_chain ERR INT TERM

  BROAD_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_KISSAT4_STAGE=broad,EUF_VIPER_KISSAT4_RUN_ID=$SAMPLE_JOB,EUF_VIPER_KISSAT4_SHARDS=$SHARDS"
  BROAD_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --dependency=afterok:'$SAMPLE_JOB' --array=0-$((SHARDS - 1))%'$MAX_ACTIVE' --job-name=euf-k4-broad --output=results/kissat4-paired-broad-%A_%a.out --error=results/kissat4-paired-broad-%A_%a.err --export='$BROAD_EXPORTS' scripts/wmi/euf_viper_kissat4_paired.sbatch")"
  BROAD_JOB="${BROAD_SUBMISSION%%;*}"
  case "$BROAD_JOB" in ''|*[!0-9]*) kissat4_die "invalid broad job id: $BROAD_SUBMISSION" ;; esac

  MERGE_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_KISSAT4_RUN_ID=$SAMPLE_JOB,EUF_VIPER_KISSAT4_SHARDS=$SHARDS,EUF_VIPER_KISSAT4_BROAD_MIN_PAIRED=$BROAD_MIN_PAIRED,EUF_VIPER_KISSAT4_BROAD_MIN_SPEEDUP=$BROAD_MIN_SPEEDUP,EUF_VIPER_KISSAT4_BROAD_MAX_P_VALUE=$BROAD_MAX_P_VALUE,EUF_VIPER_KISSAT4_BROAD_ITERATIONS=$BROAD_ITERATIONS"
  MERGE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --dependency=afterok:'$BROAD_JOB' --job-name=euf-k4-merge --export='$MERGE_EXPORTS' scripts/wmi/euf_viper_kissat4_paired_merge.sbatch")"
  MERGE_JOB="${MERGE_SUBMISSION%%;*}"
  case "$MERGE_JOB" in ''|*[!0-9]*) kissat4_die "invalid merge job id: $MERGE_SUBMISSION" ;; esac
  SUBMISSION_STATUS="submitted"
  PLAN_PATH="$ROOT/results/kissat4-paired-submission-$SAMPLE_JOB.json"
fi

export KISSAT4_SUBMISSION_STATUS="$SUBMISSION_STATUS"
export KISSAT4_SUBMISSION_REVISION="$REVISION"
export KISSAT4_SUBMISSION_REMOTE_HOST="$REMOTE_HOST"
export KISSAT4_SUBMISSION_REMOTE_WORK="$REMOTE_WORK"
export KISSAT4_SUBMISSION_REMOTE_BRANCH="$REMOTE_BRANCH"
export KISSAT4_SUBMISSION_VALIDATION_ROOT="$VALIDATION_ROOT"
export KISSAT4_SUBMISSION_MANIFEST="$REMOTE_MANIFEST"
export KISSAT4_SUBMISSION_MANIFEST_SHA256="$MANIFEST_SHA256"
export KISSAT4_SUBMISSION_MANIFEST_ROWS="$MANIFEST_ROWS"
export KISSAT4_SUBMISSION_SCRIPT_BUNDLE="$SCRIPT_BUNDLE_SHA256"
export KISSAT4_SUBMISSION_SHARDS="$SHARDS"
export KISSAT4_SUBMISSION_MAX_ACTIVE="$MAX_ACTIVE"
export KISSAT4_SUBMISSION_TIMEOUT="$TIMEOUT"
export KISSAT4_SUBMISSION_REPEATS="$REPEATS"
export KISSAT4_SUBMISSION_WARMUPS="$WARMUPS"
export KISSAT4_SUBMISSION_SAMPLE_LIMIT="$SAMPLE_LIMIT"
export KISSAT4_SUBMISSION_SAMPLE_SEED="$SAMPLE_SEED"
export KISSAT4_SUBMISSION_SAMPLE_MIN_PAIRED="$SAMPLE_MIN_PAIRED"
export KISSAT4_SUBMISSION_SAMPLE_MIN_SPEEDUP="$SAMPLE_MIN_SPEEDUP"
export KISSAT4_SUBMISSION_BROAD_MIN_PAIRED="$BROAD_MIN_PAIRED"
export KISSAT4_SUBMISSION_BROAD_MIN_SPEEDUP="$BROAD_MIN_SPEEDUP"
export KISSAT4_SUBMISSION_BROAD_MAX_P_VALUE="$BROAD_MAX_P_VALUE"
export KISSAT4_SUBMISSION_BROAD_ITERATIONS="$BROAD_ITERATIONS"
export KISSAT4_SUBMISSION_EXTERNAL_DEPENDENCY="$EXTERNAL_DEPENDENCY"
export KISSAT4_SUBMISSION_SAMPLE_JOB="$SAMPLE_JOB"
export KISSAT4_SUBMISSION_BROAD_JOB="$BROAD_JOB"
export KISSAT4_SUBMISSION_MERGE_JOB="$MERGE_JOB"
export KISSAT4_SUBMISSION_RUNTIME_ENV="$(printf '%s\n' "${KISSAT4_RUNTIME_SETTINGS[@]}")"
export KISSAT4_SUBMISSION_UNSET_ENV="$(printf '%s\n' "${KISSAT4_EXPLICITLY_UNSET[@]}")"

python3 - "$PLAN_PATH" "${KISSAT4_CAMPAIGN_SCRIPTS[@]}" <<'PY_SUBMISSION'
import hashlib
import json
import os
import sys
from pathlib import Path


def optional_int(name: str) -> int | None:
    value = os.environ[name]
    return int(value) if value else None


out = Path(sys.argv[1])
scripts = [Path(path) for path in sys.argv[2:]]
sample_job = optional_int("KISSAT4_SUBMISSION_SAMPLE_JOB")
run_root = (
    f"{os.environ['KISSAT4_SUBMISSION_REMOTE_WORK']}/results/kissat4-paired-{sample_job}"
    if sample_job is not None
    else None
)
payload = {
    "schema_version": 1,
    "campaign": "kissat-sc2021-vs-kissat-4.0.4",
    "status": os.environ["KISSAT4_SUBMISSION_STATUS"],
    "revision": os.environ["KISSAT4_SUBMISSION_REVISION"],
    "remote": {
        "host": os.environ["KISSAT4_SUBMISSION_REMOTE_HOST"],
        "worktree": os.environ["KISSAT4_SUBMISSION_REMOTE_WORK"],
        "branch": os.environ["KISSAT4_SUBMISSION_REMOTE_BRANCH"],
    },
    "validation": {
        "job_id": 144945,
        "revision": "d7c14dac90615717b06e063274c42296a46e01a3",
        "root": os.environ["KISSAT4_SUBMISSION_VALIDATION_ROOT"],
        "binaries": {
            "euf-viper-kissat-sc2021": "d7321602b8cc86683ccb41e90bea7b843a5059caad62d1eba347bb3e69c70362",
            "euf-viper-kissat-4.0.4": "ecbcfebb1f39c725c1d0266442c7dcc80083b8347e3b77d90bfb5646bd4ea6b6",
        },
    },
    "manifest": {
        "path": os.environ["KISSAT4_SUBMISSION_MANIFEST"],
        "sha256": os.environ["KISSAT4_SUBMISSION_MANIFEST_SHA256"],
        "instances": int(os.environ["KISSAT4_SUBMISSION_MANIFEST_ROWS"]),
    },
    "scripts": {
        "bundle_sha256": os.environ["KISSAT4_SUBMISSION_SCRIPT_BUNDLE"],
        "files": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in scripts
        },
    },
    "solver_environment": {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in os.environ["KISSAT4_SUBMISSION_RUNTIME_ENV"].splitlines()
    },
    "explicitly_unset_solver_environment": os.environ[
        "KISSAT4_SUBMISSION_UNSET_ENV"
    ].splitlines(),
    "parameters": {
        "shards": int(os.environ["KISSAT4_SUBMISSION_SHARDS"]),
        "max_active": int(os.environ["KISSAT4_SUBMISSION_MAX_ACTIVE"]),
        "timeout_s": int(os.environ["KISSAT4_SUBMISSION_TIMEOUT"]),
        "repeats": int(os.environ["KISSAT4_SUBMISSION_REPEATS"]),
        "warmups": int(os.environ["KISSAT4_SUBMISSION_WARMUPS"]),
        "sample_limit": int(os.environ["KISSAT4_SUBMISSION_SAMPLE_LIMIT"]),
        "sample_seed": int(os.environ["KISSAT4_SUBMISSION_SAMPLE_SEED"]),
        "sample_min_paired": int(os.environ["KISSAT4_SUBMISSION_SAMPLE_MIN_PAIRED"]),
        "sample_min_speedup": float(os.environ["KISSAT4_SUBMISSION_SAMPLE_MIN_SPEEDUP"]),
        "broad_min_paired": int(os.environ["KISSAT4_SUBMISSION_BROAD_MIN_PAIRED"]),
        "broad_min_speedup": float(os.environ["KISSAT4_SUBMISSION_BROAD_MIN_SPEEDUP"]),
        "broad_max_p_value": float(os.environ["KISSAT4_SUBMISSION_BROAD_MAX_P_VALUE"]),
        "broad_iterations": int(os.environ["KISSAT4_SUBMISSION_BROAD_ITERATIONS"]),
    },
    "jobs": {
        "sample": sample_job,
        "broad": optional_int("KISSAT4_SUBMISSION_BROAD_JOB"),
        "merge": optional_int("KISSAT4_SUBMISSION_MERGE_JOB"),
        "external_dependency": optional_int("KISSAT4_SUBMISSION_EXTERNAL_DEPENDENCY"),
        "dependency": "external afterok -> sample afterok -> broad array afterok -> merge",
    },
    "outputs": {
        "run_root": run_root,
        "sample_result": f"{run_root}/sample/result.json" if run_root else None,
        "broad_result": f"{run_root}/broad/merge/result.json" if run_root else None,
        "submission": str(out.resolve()),
    },
}
out.parent.mkdir(parents=True, exist_ok=True)
temporary = out.with_name(f".{out.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(out)
print(json.dumps(payload, indent=2, sort_keys=True))
PY_SUBMISSION

if [ "$DRY_RUN" = 0 ]; then
  ssh "$REMOTE_HOST" "mkdir -p '$REMOTE_WORK/results/kissat4-paired-$SAMPLE_JOB'"
  scp "$PLAN_PATH" "$REMOTE_HOST:$REMOTE_WORK/results/kissat4-paired-$SAMPLE_JOB/submission.json"
  trap - ERR INT TERM
fi
