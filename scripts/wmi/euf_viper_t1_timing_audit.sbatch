#!/usr/bin/env bash
#SBATCH --job-name=euf-t1-audit
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=01:00:00
#SBATCH --output=results/t1-timing-audit-%j.out
#SBATCH --error=results/t1-timing-audit-%j.err

set -euo pipefail

[ "$#" -eq 9 ] || { echo "expected exact root/ref/receipt arguments" >&2; exit 2; }
EXPECTED_WRAPPER_SHA256="$9"
if [ "${EUF_VIPER_T1_WRAPPER_BOUND:-}" != "$EXPECTED_WRAPPER_SHA256" ]; then
  exec 30<"${BASH_SOURCE[0]}"
  [ "$(/usr/bin/sha256sum /proc/self/fd/30 | /usr/bin/awk '{print $1}')" = "$EXPECTED_WRAPPER_SHA256" ] || {
    echo "spooled audit wrapper hash mismatch" >&2
    exit 2
  }
  /usr/bin/python3 -I -B -c 'import os; os.lseek(30, 0, os.SEEK_SET)'
  export EUF_VIPER_T1_WRAPPER_BOUND="$EXPECTED_WRAPPER_SHA256"
  exec /bin/bash /proc/self/fd/30 "$@"
fi
unset EUF_VIPER_T1_WRAPPER_BOUND
/usr/bin/python3 -I -B -c 'import os; os.lseek(30, 0, os.SEEK_SET)'
[ "$(/usr/bin/sha256sum /proc/self/fd/30 | /usr/bin/awk '{print $1}')" = "$EXPECTED_WRAPPER_SHA256" ] || {
  echo "retained audit wrapper hash mismatch" >&2
  exit 2
}
T1_JOB_ROOT="$1"
EXPECTED_REVISION="$2"
PUBLISHED_REF="$3"
SUBMISSION_MODE="$4"
EXPECTED_CONTRACT_SHA256="$5"
EXPECTED_MANIFEST_SHA256="$6"
EXPECTED_RECEIPT_SHA256="$7"
SUBMISSION_RECEIPT="$8"
case "$T1_JOB_ROOT" in /*) ;; *) echo "T1 execution root must be absolute" >&2; exit 2 ;; esac
[ "${#EXPECTED_REVISION}" -eq 40 ] || { echo "T1 revision length is invalid" >&2; exit 2; }
case "$EXPECTED_REVISION" in *[!0-9a-f]*) echo "T1 revision is malformed" >&2; exit 2 ;; esac
case "$PUBLISHED_REF" in origin/*) ;; *) echo "T1 published ref must be an origin ref" >&2; exit 2 ;; esac
[ "$SUBMISSION_MODE" = full ] || { echo "the complete T1 audit is full-mode only" >&2; exit 2; }
T1_JOB_ROOT="$(/usr/bin/readlink -f -- "$T1_JOB_ROOT")"
[ "$T1_JOB_ROOT" = "$(/usr/bin/pwd -P)" ] || {
  echo "Slurm did not enter the submitted immutable execution root" >&2
  exit 2
}
t1_bootstrap_git() {
  env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    /usr/bin/git -C "$T1_JOB_ROOT" "$@"
}
[ "$(t1_bootstrap_git rev-parse --verify HEAD^{commit})" = "$EXPECTED_REVISION" ] || {
  echo "T1 execution root HEAD mismatch" >&2
  exit 2
}
[ "$(t1_bootstrap_git rev-parse --verify "$PUBLISHED_REF^{commit}")" = "$EXPECTED_REVISION" ] || {
  echo "T1 execution root published-ref mismatch" >&2
  exit 2
}
COMMON_RELATIVE="scripts/wmi/t1_timing_common.sh"
COMMON_PATH="$T1_JOB_ROOT/$COMMON_RELATIVE"
COMMON_ENTRY="$(t1_bootstrap_git ls-tree "$EXPECTED_REVISION" -- "$COMMON_RELATIVE")"
[ "${COMMON_ENTRY%% *}" = 100755 ] || { echo "T1 common helper mode mismatch" >&2; exit 2; }
COMMON_BLOB="$(printf '%s\n' "$COMMON_ENTRY" | /usr/bin/awk '{print $3}')"
exec 18<"$COMMON_PATH"
[ "$(t1_bootstrap_git hash-object --no-filters -- /proc/self/fd/18)" = "$COMMON_BLOB" ] || {
  echo "T1 common helper blob mismatch" >&2
  exit 2
}
source /proc/self/fd/18
exec 18<&-
t1_reject_ambient_influence
EXPECTED_JOB_PREFIX="euf-t1-audit-"
case "${SLURM_JOB_NAME:-}" in
  "$EXPECTED_JOB_PREFIX"*) EXPECTED_SUBMISSION_RECEIPT_SHA256="${SLURM_JOB_NAME#"$EXPECTED_JOB_PREFIX"}" ;;
  *) echo "audit job name does not bind a submission receipt" >&2; exit 2 ;;
esac
t1_require_sha256 "$EXPECTED_SUBMISSION_RECEIPT_SHA256" "submission receipt SHA-256"
exec 6<"$SUBMISSION_RECEIPT"
[ "$(sha256sum /proc/self/fd/6 | awk '{print $1}')" = "$EXPECTED_SUBMISSION_RECEIPT_SHA256" ] || {
  echo "opened submission receipt hash mismatch" >&2
  exit 2
}
cd "$T1_JOB_ROOT"
export LANG=C LC_ALL=C TZ=UTC OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
export EUF_VIPER_BACKEND=auto
unset EUF_VIPER_PROFILE

CAMPAIGN_ROOT="$(dirname "$T1_JOB_ROOT")/artifacts"
HARNESS="$T1_JOB_ROOT/scripts/bench/typed_parser_timing.py"

t1_verify_checkout "$EXPECTED_REVISION" "$PUBLISHED_REF"
t1_verify_pinned_tool Python EUF_VIPER_PYTHON EUF_VIPER_PYTHON_SHA256 EUF_VIPER_PYTHON_VERSION
t1_verify_pinned_tool Cargo EUF_VIPER_CARGO EUF_VIPER_CARGO_SHA256 EUF_VIPER_CARGO_VERSION
t1_verify_pinned_tool Rustc EUF_VIPER_RUSTC EUF_VIPER_RUSTC_SHA256 EUF_VIPER_RUSTC_VERSION
t1_verify_pinned_tool CC EUF_VIPER_CC EUF_VIPER_CC_SHA256 EUF_VIPER_CC_VERSION
t1_verify_pinned_tool LD EUF_VIPER_LD EUF_VIPER_LD_SHA256 EUF_VIPER_LD_VERSION
t1_verify_pinned_tool AR EUF_VIPER_AR EUF_VIPER_AR_SHA256 EUF_VIPER_AR_VERSION
HARNESS_ENTRY="$(t1_git ls-tree "$EXPECTED_REVISION" -- scripts/bench/typed_parser_timing.py)"
[ "${HARNESS_ENTRY%% *}" = 100755 ] || { echo "timing harness mode mismatch" >&2; exit 2; }
HARNESS_BLOB="$(printf '%s\n' "$HARNESS_ENTRY" | awk '{print $3}')"
exec 18<"$HARNESS" 19<"$EUF_VIPER_PYTHON"
[ "$(t1_git hash-object --no-filters -- /proc/self/fd/18)" = "$HARNESS_BLOB" ] || {
  echo "opened timing harness differs from the immutable revision" >&2
  exit 2
}
[ "$(sha256sum /proc/self/fd/19 | awk '{print $1}')" = "$EUF_VIPER_PYTHON_SHA256" ] || {
  echo "opened Python descriptor hash mismatch" >&2
  exit 2
}
/proc/self/fd/19 -I -B /proc/self/fd/18 verify-submission-receipt \
  --submission-receipt "$SUBMISSION_RECEIPT" --submission-receipt-fd 6 \
  --expected-submission-receipt-sha256 "$EXPECTED_SUBMISSION_RECEIPT_SHA256" \
  --revision "$EXPECTED_REVISION" --submission-mode full --role audit \
  --expected-wrapper-sha256 "$EXPECTED_WRAPPER_SHA256" >/dev/null
/proc/self/fd/19 -I -B /proc/self/fd/18 audit \
  --root "$CAMPAIGN_ROOT" \
  --revision "$EXPECTED_REVISION" \
  --expected-checkout-receipt-sha256 "$EXPECTED_RECEIPT_SHA256" \
  --expected-contract-sha256 "$EXPECTED_CONTRACT_SHA256" \
  --expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" \
  --submission-receipt "$SUBMISSION_RECEIPT" \
  --submission-receipt-fd 6 \
  --expected-submission-receipt-sha256 "$EXPECTED_SUBMISSION_RECEIPT_SHA256" \
  --submission-mode full \
  --expected-wrapper-sha256 "$EXPECTED_WRAPPER_SHA256"

printf 't1_timing_audit=%s\n' "$CAMPAIGN_ROOT/audit.json"
