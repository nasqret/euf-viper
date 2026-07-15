#!/usr/bin/env bash
set -euo pipefail

# Re-enter through retained bytes before any campaign logic. The initial pathname
# invocation performs only this immutable-revision bootstrap.
if [ -z "${EUF_VIPER_T1_LOCAL_SUBMIT_BOUND:-}" ]; then
  INITIAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  INITIAL_REVISION="$(env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    git -C "$INITIAL_ROOT" rev-parse --verify HEAD^{commit})"
  ENTRY="$(env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    git -C "$INITIAL_ROOT" ls-tree "$INITIAL_REVISION" -- scripts/wmi/submit_t1_timing.sh)"
  [ "${ENTRY%% *}" = 100755 ] || { echo "T1 submit helper mode mismatch" >&2; exit 2; }
  BLOB="$(printf '%s\n' "$ENTRY" | awk '{print $3}')"
  exec 30<"${BASH_SOURCE[0]}"
  DESCRIPTOR=/dev/fd/30
  [ -d /proc/self/fd ] && DESCRIPTOR=/proc/self/fd/30
  [ "$(env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    git -C "$INITIAL_ROOT" hash-object --no-filters -- "$DESCRIPTOR")" = "$BLOB" ] || {
    echo "opened T1 submit helper differs from the immutable revision" >&2
    exit 2
  }
  env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B -c \
    'import os; os.lseek(30, 0, os.SEEK_SET)'
  export EUF_VIPER_T1_LOCAL_SUBMIT_BOUND="$INITIAL_ROOT:$INITIAL_REVISION:$BLOB"
  exec /bin/bash "$DESCRIPTOR" "$@"
fi

IFS=: read -r ROOT BOOTSTRAP_REVISION SUBMIT_BLOB <<<"$EUF_VIPER_T1_LOCAL_SUBMIT_BOUND"
unset EUF_VIPER_T1_LOCAL_SUBMIT_BOUND
case "$ROOT" in /*) ;; *) echo "bound T1 root is not absolute" >&2; exit 2 ;; esac
if [ -d /proc/self/fd ]; then
  SELF_DESCRIPTOR=/proc/self/fd/30
else
  SELF_DESCRIPTOR=/dev/fd/30
fi
env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B -c \
  'import os; os.lseek(30, 0, os.SEEK_SET)'
[ "$(env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  git -C "$ROOT" hash-object --no-filters -- "$SELF_DESCRIPTOR")" = "$SUBMIT_BLOB" ] || {
  echo "retained T1 submit helper hash mismatch" >&2
  exit 2
}

REMOTE_HOST="wmicluster"
PUBLISHED_REF="origin/research-typed-parser-timing"
MODE=""
DEPENDENCY=""
SHARDS=128
MAX_PARALLEL=1
WARMUP_ROUNDS=1
MEASURED_ROUNDS=5
TIMEOUT_SECONDS=2
MANIFEST_SHA256="32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
PARITY_RECEIPT_SHA256="c0c9c1879c9ac2da524c69f07affa991626c326ac0837f8f8066fde708d8482c"

cd "$ROOT"
COMMON_RELATIVE="scripts/wmi/t1_timing_common.sh"
COMMON_ENTRY="$(env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  git -C "$ROOT" ls-tree "$BOOTSTRAP_REVISION" -- "$COMMON_RELATIVE")"
[ "${COMMON_ENTRY%% *}" = 100755 ] || { echo "T1 common helper mode mismatch" >&2; exit 2; }
COMMON_BLOB="$(printf '%s\n' "$COMMON_ENTRY" | awk '{print $3}')"
exec 18<"$ROOT/$COMMON_RELATIVE"
if [ -d /proc/self/fd ]; then COMMON_DESCRIPTOR=/proc/self/fd/18; else COMMON_DESCRIPTOR=/dev/fd/18; fi
[ "$(env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  git -C "$ROOT" hash-object --no-filters -- "$COMMON_DESCRIPTOR")" = "$COMMON_BLOB" ] || {
  echo "T1 common helper blob mismatch" >&2
  exit 2
}
env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B -c \
  'import os; os.lseek(18, 0, os.SEEK_SET)'
source "$COMMON_DESCRIPTOR"
exec 18<&-
t1_reject_forbidden_euf_viper_environment

usage() {
  echo "usage: $0 (--canary | --full) [--dependency JOB_ID]" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --canary|--full)
      [ -z "$MODE" ] || usage
      MODE="${1#--}"
      shift
      ;;
    --dependency)
      [ -z "$DEPENDENCY" ] && [ "$#" -ge 2 ] || usage
      DEPENDENCY="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
[ -n "$MODE" ] || usage
case "$DEPENDENCY" in ''|[1-9][0-9]*) ;; *) echo "dependency must be a canonical job id" >&2; exit 2 ;; esac
case "$PUBLISHED_REF" in origin/*) PUBLISHED_BRANCH="${PUBLISHED_REF#origin/}" ;; *) exit 2 ;; esac
case "$PUBLISHED_BRANCH" in ''|*[!A-Za-z0-9._/-]*|*..*) echo "published branch is unsafe" >&2; exit 2 ;; esac
case "$REMOTE_HOST" in ''|*[!A-Za-z0-9._@-]*) echo "remote host is unsafe" >&2; exit 2 ;; esac

REVISION="$(t1_git rev-parse --verify HEAD^{commit})"
[ "$REVISION" = "$BOOTSTRAP_REVISION" ] || {
  echo "T1 checkout changed after binding the submit helper" >&2
  exit 2
}
t1_verify_checkout "$REVISION" "$PUBLISHED_REF"
CONTRACT_SHA256="$(sha256sum campaigns/t1-typed-parser-timing-v1.json | awk '{print $1}')"
ACCEPTED_PARITY_RECEIPT="$ROOT/results/wmi/typed-parser-parity-146510/receipt.json"
t1_verify_bound_file "$ACCEPTED_PARITY_RECEIPT" "$PARITY_RECEIPT_SHA256" "accepted parity receipt"

HARNESS_RELATIVE="scripts/bench/typed_parser_timing.py"
HARNESS_ENTRY="$(t1_git ls-tree "$REVISION" -- "$HARNESS_RELATIVE")"
[ "${HARNESS_ENTRY%% *}" = 100755 ] || { echo "timing harness mode mismatch" >&2; exit 2; }
HARNESS_BLOB="$(printf '%s\n' "$HARNESS_ENTRY" | awk '{print $3}')"
exec 17<"$ROOT/$HARNESS_RELATIVE"
if [ -d /proc/self/fd ]; then HARNESS_DESCRIPTOR=/proc/self/fd/17; else HARNESS_DESCRIPTOR=/dev/fd/17; fi
[ "$(t1_git hash-object --no-filters -- "$HARNESS_DESCRIPTOR")" = "$HARNESS_BLOB" ] || {
  echo "opened timing harness differs from the immutable revision" >&2
  exit 2
}
local_harness() {
  env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B -c \
    'import os; os.lseek(17, 0, os.SEEK_SET)'
  /usr/bin/python3 -I -B "$HARNESS_DESCRIPTOR" "$@"
}
local_harness verify-evidence \
  --contract campaigns/t1-typed-parser-timing-v1.json \
  --accepted-parity-receipt "$ACCEPTED_PARITY_RECEIPT" \
  --expected-contract-sha256 "$CONTRACT_SHA256" \
  --expected-shards "$SHARDS" \
  --expected-max-parallel "$MAX_PARALLEL" \
  --expected-warmup-rounds "$WARMUP_ROUNDS" \
  --expected-measured-rounds "$MEASURED_ROUNDS" \
  --expected-timeout-seconds "$TIMEOUT_SECONDS" >/dev/null

REMOTE_HELPER_RELATIVE="scripts/wmi/t1_timing_remote_submit.py"
REMOTE_HELPER_ENTRY="$(t1_git ls-tree "$REVISION" -- "$REMOTE_HELPER_RELATIVE")"
[ "${REMOTE_HELPER_ENTRY%% *}" = 100755 ] || { echo "remote transaction helper mode mismatch" >&2; exit 2; }
REMOTE_HELPER_BLOB="$(printf '%s\n' "$REMOTE_HELPER_ENTRY" | awk '{print $3}')"
exec 19<"$ROOT/$REMOTE_HELPER_RELATIVE"
if [ -d /proc/self/fd ]; then REMOTE_HELPER_DESCRIPTOR=/proc/self/fd/19; else REMOTE_HELPER_DESCRIPTOR=/dev/fd/19; fi
[ "$(t1_git hash-object --no-filters -- "$REMOTE_HELPER_DESCRIPTOR")" = "$REMOTE_HELPER_BLOB" ] || {
  echo "opened remote transaction helper differs from the immutable revision" >&2
  exit 2
}

remote_helper() {
  env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B -c \
    'import os; os.lseek(19, 0, os.SEEK_SET)'
  ssh "$REMOTE_HOST" /usr/bin/python3 -I -B - "$@" < "$REMOTE_HELPER_DESCRIPTOR"
}

mkdir -p results
TEMPORARY="results/.t1-submission-receipt.$$.tmp"
[ ! -e "$TEMPORARY" ] || { echo "temporary receipt already exists" >&2; exit 2; }
STAGED=0
REMOTE_RECEIPT=""
RECEIPT_SHA256=""
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [ "$STAGED" -eq 1 ] && [ -n "$REMOTE_RECEIPT" ] && [ -n "$RECEIPT_SHA256" ]; then
    remote_helper cancel --receipt "$REMOTE_RECEIPT" \
      --receipt-sha256 "$RECEIPT_SHA256" >/dev/null 2>&1 || true
  fi
  rm -f "$TEMPORARY"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

STAGE_ARGUMENTS=(
  stage
  --revision "$REVISION"
  --published-ref "$PUBLISHED_REF"
  --published-branch "$PUBLISHED_BRANCH"
  --mode "$MODE"
  --contract-sha256 "$CONTRACT_SHA256"
  --manifest-sha256 "$MANIFEST_SHA256"
  --parity-receipt-sha256 "$PARITY_RECEIPT_SHA256"
)
if [ -n "$DEPENDENCY" ]; then
  STAGE_ARGUMENTS+=(--dependency "$DEPENDENCY")
fi
remote_helper "${STAGE_ARGUMENTS[@]}" > "$TEMPORARY"
[ -s "$TEMPORARY" ] || { echo "remote stage emitted no receipt" >&2; exit 2; }
exec 16<"$TEMPORARY"
if [ -d /proc/self/fd ]; then RECEIPT_DESCRIPTOR=/proc/self/fd/16; else RECEIPT_DESCRIPTOR=/dev/fd/16; fi
RECEIPT_SHA256="$(sha256sum "$RECEIPT_DESCRIPTOR" | awk '{print $1}')"
t1_require_sha256 "$RECEIPT_SHA256" "staged receipt SHA-256"
REMOTE_RECEIPT="$(/usr/bin/python3 -I -B -c '
import json,os
content=os.pread(16, os.fstat(16).st_size, 0)
print(json.loads(content.decode("ascii"))["receipt_path"])
')"
case "$REMOTE_RECEIPT" in /*) ;; *) echo "remote receipt path is not absolute" >&2; exit 2 ;; esac
case "$REMOTE_RECEIPT" in *[!A-Za-z0-9_./-]*) echo "remote receipt path is unsafe" >&2; exit 2 ;; esac
STAGED=1
SUMMARY="$(local_harness verify-submission-receipt-file \
  --submission-receipt "$TEMPORARY" \
  --submission-receipt-fd 16 \
  --expected-submission-receipt-sha256 "$RECEIPT_SHA256" \
  --revision "$REVISION" --submission-mode "$MODE")"
PREPARE_JOB="$(printf '%s\n' "$SUMMARY" | /usr/bin/python3 -I -B -c \
  'import json,sys; print(json.load(sys.stdin)["prepare_job"])')"
SUMMARY_RECEIPT="$(printf '%s\n' "$SUMMARY" | /usr/bin/python3 -I -B -c \
  'import json,sys; print(json.load(sys.stdin)["receipt_path"])')"
case "$PREPARE_JOB" in [1-9][0-9]*) ;; *) echo "staged prepare job is malformed" >&2; exit 2 ;; esac
[ "$SUMMARY_RECEIPT" = "$REMOTE_RECEIPT" ] || { echo "receipt path validation drifted" >&2; exit 2; }

RECEIPT="results/t1-typed-parser-timing-submission-$PREPARE_JOB.json"
[ ! -e "$RECEIPT" ] || { echo "refusing to replace receipt: $RECEIPT" >&2; exit 2; }
/usr/bin/python3 -I -B -c '
import os,sys
source,destination,directory=sys.argv[1:]
descriptor=16
identity=lambda value: (value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns)
try:
    os.fchmod(descriptor, 0o400)
    os.fsync(descriptor)
    opened=os.fstat(descriptor)
    if identity(os.lstat(source)) != identity(opened):
        raise RuntimeError("staged receipt pathname no longer names retained bytes")
    os.link(source, destination, follow_symlinks=False)
    if identity(os.lstat(destination)) != identity(opened):
        raise RuntimeError("published receipt is not the retained inode")
    directory_fd=os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(directory_fd)
    finally: os.close(directory_fd)
except BaseException:
    try: os.unlink(destination)
    except FileNotFoundError: pass
    raise
' "$TEMPORARY" "$RECEIPT" "$(dirname "$RECEIPT")"

remote_helper release --receipt "$REMOTE_RECEIPT" \
  --receipt-sha256 "$RECEIPT_SHA256" >/dev/null
STAGED=0
exec 16<&-
rm -f "$TEMPORARY"
trap - EXIT HUP INT TERM
cat "$RECEIPT"
