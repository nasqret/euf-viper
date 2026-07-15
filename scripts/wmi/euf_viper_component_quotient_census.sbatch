#!/bin/bash
#SBATCH --job-name=euf-cqram-census
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=64G
#SBATCH --time=08:00:00
#SBATCH --output=results/component-quotient-census-%j.out
#SBATCH --error=results/component-quotient-census-%j.err

set -euo pipefail

reject_hostile_environment() {
  local entry name
  while IFS= read -r entry; do
    name="${entry%%=*}"
    case "$name" in
      BASH_ENV|CDPATH|ENV|GIT_*|PYTHON*|CARGO_*|RUST*|LD_*|DYLD_*|BASH_FUNC_*)
        echo "hostile ambient environment is forbidden: $name" >&2
        exit 2
        ;;
    esac
  done < <(/usr/bin/env)
}

# This is the first operation.  sbatch exports only the fixed allowlist below.
reject_hostile_environment
export PATH=/usr/bin:/bin
export LANG=C
export LC_ALL=C
export TZ=UTC

trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

JOB_ID="${SLURM_JOB_ID:-}"
EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:-}"
ATTEMPT_ID="${EUF_VIPER_COMPONENT_QUOTIENT_ATTEMPT_ID:-}"
SUBMISSION_NONCE="${EUF_VIPER_COMPONENT_QUOTIENT_SUBMISSION_NONCE:-}"
NAMESPACE_ID="${EUF_VIPER_COMPONENT_QUOTIENT_NAMESPACE_ID:-}"
NAMESPACE_DEVICE="${EUF_VIPER_COMPONENT_QUOTIENT_NAMESPACE_DEVICE:-}"
NAMESPACE_INODE="${EUF_VIPER_COMPONENT_QUOTIENT_NAMESPACE_INODE:-}"
RESULTS_DEVICE="${EUF_VIPER_COMPONENT_QUOTIENT_RESULTS_DEVICE:-}"
RESULTS_INODE="${EUF_VIPER_COMPONENT_QUOTIENT_RESULTS_INODE:-}"
MANIFEST_SHA256="${EUF_VIPER_COMPONENT_QUOTIENT_MANIFEST_SHA256:-}"
PYTHON_REALPATH="${EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_REALPATH:-}"
PYTHON_VERSION="${EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_VERSION:-}"
PYTHON_SHA256="${EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_SHA256:-}"
SHARED_CORPUS="${EUF_VIPER_COMPONENT_QUOTIENT_SHARED_CORPUS:-}"

if [ "$(uname -s)" != Linux ]; then
  echo "component quotient census requires real Linux O_TMPFILE/linkat" >&2
  exit 2
fi
if [[ ! "$JOB_ID" =~ ^[1-9][0-9]*$ ]]; then
  echo "SLURM_JOB_ID must be a positive integer" >&2
  exit 2
fi
if [[ ! "$EXPECTED_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected revision must be a full lowercase Git SHA-1" >&2
  exit 2
fi
if [[ ! "$ATTEMPT_ID" =~ ^[A-Za-z0-9_.-]{6,128}$ ]]; then
  echo "submission attempt id is malformed" >&2
  exit 2
fi
for digest in "$SUBMISSION_NONCE" "$NAMESPACE_ID" "$MANIFEST_SHA256" "$PYTHON_SHA256"; do
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "a required SHA-256/nonce binding is malformed" >&2
    exit 2
  fi
done
for identity in "$NAMESPACE_DEVICE" "$NAMESPACE_INODE" "$RESULTS_DEVICE" "$RESULTS_INODE"; do
  if [[ ! "$identity" =~ ^[1-9][0-9]*$ ]]; then
    echo "a required directory identity is malformed" >&2
    exit 2
  fi
done
if [[ "$PYTHON_REALPATH" != /* ]] || [ ! -x "$PYTHON_REALPATH" ]; then
  echo "pinned Python executable must be an absolute executable path" >&2
  exit 2
fi
if [ -z "$PYTHON_VERSION" ] || [[ "$SHARED_CORPUS" != /* ]]; then
  echo "pinned Python version or shared corpus path is malformed" >&2
  exit 2
fi

SUBMIT_DIR="$(readlink -f -- "${SLURM_SUBMIT_DIR:-$PWD}")"
RESULTS="$SUBMIT_DIR/results"
if [ ! -d "$RESULTS" ]; then
  echo "bound result directory must preexist" >&2
  exit 2
fi
read -r ACTUAL_NAMESPACE_DEVICE ACTUAL_NAMESPACE_INODE < <(stat -c '%d %i' -- "$SUBMIT_DIR")
read -r ACTUAL_RESULTS_DEVICE ACTUAL_RESULTS_INODE < <(stat -c '%d %i' -- "$RESULTS")
if [ "$ACTUAL_NAMESPACE_DEVICE:$ACTUAL_NAMESPACE_INODE" != "$NAMESPACE_DEVICE:$NAMESPACE_INODE" ] || \
   [ "$ACTUAL_RESULTS_DEVICE:$ACTUAL_RESULTS_INODE" != "$RESULTS_DEVICE:$RESULTS_INODE" ]; then
  echo "submission namespace identity changed before job entry" >&2
  exit 2
fi
cd "$SUBMIT_DIR"

clean_git() {
  env -i \
    PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    GIT_PAGER=cat \
    git "$@"
}

clean_python() {
  env -i \
    PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 RAYON_NUM_THREADS=1 \
    "$PYTHON_REALPATH" -I -B -S "$@"
}

clean_guard() {
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    scripts/wmi/check_component_quotient_checkout.sh "$EXPECTED_REVISION"
}

verify_python_identity() {
  local phase="$1"
  local actual_realpath actual_reported_realpath actual_version actual_sha256
  actual_realpath="$(readlink -f -- "$PYTHON_REALPATH")"
  if [ "$actual_realpath" != "$PYTHON_REALPATH" ]; then
    echo "$phase Python realpath drift" >&2
    exit 2
  fi
  actual_sha256="$(sha256sum -- "$PYTHON_REALPATH")"
  actual_sha256="${actual_sha256%% *}"
  if [ "$actual_sha256" != "$PYTHON_SHA256" ]; then
    echo "$phase Python SHA-256 drift" >&2
    exit 2
  fi
  actual_reported_realpath="$(clean_python -c 'import os, sys; print(os.path.realpath(sys.executable))')"
  actual_version="$(clean_python -c 'import platform; print(platform.python_version())')"
  if [ "$actual_reported_realpath" != "$PYTHON_REALPATH" ] || [ "$actual_version" != "$PYTHON_VERSION" ]; then
    echo "$phase Python identity drift" >&2
    exit 2
  fi
}

verify_runtime_identity() {
  local phase="$1"
  clean_guard
  verify_python_identity "$phase"
}

clean_guard
ACTUAL_REVISION="$(clean_git -C "$PWD" rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "sanitized Git revision drift" >&2
  exit 2
fi

if [ ! -e "$PWD/benchmarks/smtlib-2025" ] && [ -s "$SHARED_CORPUS/qf_uf_manifest.jsonl" ]; then
  ln -s -- "$SHARED_CORPUS" "$PWD/benchmarks/smtlib-2025"
fi
MANIFEST="$PWD/benchmarks/smtcomp-2025/qf_uf_manifest.jsonl"
LOCK="$PWD/campaigns/component-quotient-ram-census-v1.json"
if [ ! -s "$MANIFEST" ] || [ ! -s "$LOCK" ]; then
  echo "fixed manifest or campaign lock is absent" >&2
  exit 2
fi
ACTUAL_MANIFEST_SHA256="$(sha256sum -- "$MANIFEST")"
ACTUAL_MANIFEST_SHA256="${ACTUAL_MANIFEST_SHA256%% *}"
if [ "$ACTUAL_MANIFEST_SHA256" != "$MANIFEST_SHA256" ]; then
  echo "manifest digest differs from the submission receipt" >&2
  exit 2
fi
if [ "$MANIFEST_SHA256" != ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6 ]; then
  echo "manifest digest differs from the fixed revision blob" >&2
  exit 2
fi

STAGE="$(mktemp -d "$RESULTS/.component-quotient-census-${JOB_ID}.${SUBMISSION_NONCE}.XXXXXXXX")"
FINAL_BUNDLE="$RESULTS/component-quotient-census-${JOB_ID}-attempt-${ATTEMPT_ID}.tar"
CURRENT_MARKER="$RESULTS/component-quotient-census-${JOB_ID}.current"

verify_runtime_identity analyzer
clean_python scripts/bench/census_component_quotient_ram.py \
  "$MANIFEST" \
  --repository-root "$PWD" \
  --lock "$LOCK" \
  --records-out "$STAGE/records.jsonl" \
  --aggregate-out "$STAGE/aggregate.json" \
  --targets-out "$STAGE/targets.jsonl" \
  > "$STAGE/run.txt"

verify_runtime_identity verifier
clean_python scripts/bench/verify_component_quotient_ram_bundle.py \
  "$MANIFEST" \
  --repository-root "$PWD" \
  --lock "$LOCK" \
  --records "$STAGE/records.jsonl" \
  --aggregate "$STAGE/aggregate.json" \
  --targets "$STAGE/targets.jsonl" \
  --expected-manifest-sha256 "$MANIFEST_SHA256" \
  --receipt-out "$STAGE/verification.json" \
  --require-validity \
  > "$STAGE/verification.txt"

verify_runtime_identity finalizer
# exec makes the descriptor-bound marker publication the job's final operation.
exec env -i \
  PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
  OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 RAYON_NUM_THREADS=1 \
  "$PYTHON_REALPATH" -I -B -S scripts/bench/finalize_component_quotient_ram_metadata.py \
  --final-bundle "$FINAL_BUNDLE" \
  --current-marker "$CURRENT_MARKER" \
  --attempt-id "$ATTEMPT_ID" \
  --submission-nonce "$SUBMISSION_NONCE" \
  --namespace-root "$SUBMIT_DIR" \
  --namespace-id "$NAMESPACE_ID" \
  --namespace-device "$NAMESPACE_DEVICE" \
  --namespace-inode "$NAMESPACE_INODE" \
  --results-device "$RESULTS_DEVICE" \
  --results-inode "$RESULTS_INODE" \
  --repository-root "$PWD" \
  --manifest "$MANIFEST" \
  --expected-manifest-sha256 "$MANIFEST_SHA256" \
  --lock "$LOCK" \
  --records "$STAGE/records.jsonl" \
  --aggregate "$STAGE/aggregate.json" \
  --targets "$STAGE/targets.jsonl" \
  --verification "$STAGE/verification.json" \
  --run-log "$STAGE/run.txt" \
  --verification-log "$STAGE/verification.txt" \
  --revision "$EXPECTED_REVISION" \
  --job-id "$JOB_ID" \
  --python-realpath "$PYTHON_REALPATH" \
  --python-version "$PYTHON_VERSION" \
  --python-sha256 "$PYTHON_SHA256"
