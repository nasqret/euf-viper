#!/usr/bin/env bash
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

reject_hostile_environment
export PATH=/usr/bin:/bin
export LANG=C
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
DEPENDENCY="${EUF_VIPER_COMPONENT_QUOTIENT_DEPENDENCY:-}"
PUBLISHED_REF="${EUF_VIPER_COMPONENT_QUOTIENT_PUBLISHED_REF:-origin/main}"
REMOTE_PYTHON_REQUEST="${EUF_VIPER_COMPONENT_QUOTIENT_REMOTE_PYTHON:-python3}"
REMOTE_SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-}"

if [[ ! "$REMOTE_HOST" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
  echo "remote host is malformed" >&2
  exit 2
fi
if [ -n "$DEPENDENCY" ] && [[ ! "$DEPENDENCY" =~ ^[1-9][0-9]*$ ]]; then
  echo "dependency must be a positive SLURM job id" >&2
  exit 2
fi
if [[ ! "$PUBLISHED_REF" =~ ^[A-Za-z0-9_./-]+$ ]]; then
  echo "published ref is malformed" >&2
  exit 2
fi
case "$REMOTE_PYTHON_REQUEST" in
  ''|*[!A-Za-z0-9_./+-]*)
    echo "remote Python request contains unsupported characters" >&2
    exit 2
    ;;
  */*)
    if [[ "$REMOTE_PYTHON_REQUEST" != /* ]]; then
      echo "remote Python path must be absolute" >&2
      exit 2
    fi
    ;;
esac

safe_local_git() {
  env -i \
    PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    GIT_PAGER=cat \
    git -C "$ROOT" "$@"
}

REVISION="$(safe_local_git rev-parse HEAD)"
env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
  bash -c 'cd "$1" && scripts/wmi/check_component_quotient_checkout.sh "$2"' \
  bash "$ROOT" "$REVISION"
PUBLISHED_REVISION="$(safe_local_git rev-parse "$PUBLISHED_REF")"
if [ "$REVISION" != "$PUBLISHED_REVISION" ]; then
  echo "HEAD $REVISION is not published as $PUBLISHED_REF $PUBLISHED_REVISION" >&2
  exit 2
fi
SHORT_REVISION="${REVISION:0:12}"

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
if [[ "$REMOTE_HOME" != /* ]] || [[ ! "$REMOTE_HOME" =~ ^[A-Za-z0-9_./+-]+$ ]]; then
  echo "remote HOME response is malformed" >&2
  exit 2
fi
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
if [ -z "$REMOTE_SHARED_CORPUS" ]; then
  REMOTE_SHARED_CORPUS="$REMOTE_HOME/euf-viper/benchmarks/smtlib-2025"
fi
for remote_path in "$REMOTE_PARENT" "$REMOTE_SHARED_CORPUS"; do
  if [[ "$remote_path" != /* ]] || [[ ! "$remote_path" =~ ^[A-Za-z0-9_./+-]+$ ]]; then
    echo "remote path is not an absolute supported path: $remote_path" >&2
    exit 2
  fi
done

REMOTE_WORK="$(
  ssh "$REMOTE_HOST" bash -s -- "$REMOTE_PARENT" "$SHORT_REVISION" <<'REMOTE_CREATE_ATTEMPT'
set -euo pipefail
while IFS= read -r entry; do
  name="${entry%%=*}"
  case "$name" in
    BASH_ENV|CDPATH|ENV|GIT_*|PYTHON*|CARGO_*|RUST*|LD_*|DYLD_*|BASH_FUNC_*)
      echo "hostile remote environment is forbidden: $name" >&2
      exit 2
      ;;
  esac
done < <(/usr/bin/env)
export PATH=/usr/bin:/bin
parent="$1"
short_revision="$2"
mkdir -p -- "$parent"
physical_parent="$(cd -- "$parent" && pwd -P)"
if [ "$physical_parent" != "$parent" ]; then
  echo "remote campaign parent must be a canonical physical path" >&2
  exit 2
fi
umask 077
attempt="$(mktemp -d "$parent/component-quotient-${short_revision}-attempt.XXXXXXXX")"
cd -- "$attempt"
pwd -P
REMOTE_CREATE_ATTEMPT
)"
case "$REMOTE_WORK" in
  "$REMOTE_PARENT/component-quotient-$SHORT_REVISION-attempt."*) ;;
  *)
    echo "remote attempt directory response is malformed: $REMOTE_WORK" >&2
    exit 2
    ;;
esac
REMOTE_ATTEMPT_ID="${REMOTE_WORK##*/}"
if [[ ! "$REMOTE_ATTEMPT_ID" =~ ^component-quotient-[0-9a-f]{12}-attempt\.[A-Za-z0-9]{8}$ ]]; then
  echo "remote attempt id is malformed: $REMOTE_ATTEMPT_ID" >&2
  exit 2
fi

ssh "$REMOTE_HOST" bash -s -- "$REMOTE_WORK" "$REVISION" <<'REMOTE_PREPARE_ATTEMPT'
set -euo pipefail
while IFS= read -r entry; do
  name="${entry%%=*}"
  case "$name" in
    BASH_ENV|CDPATH|ENV|GIT_*|PYTHON*|CARGO_*|RUST*|LD_*|DYLD_*|BASH_FUNC_*)
      echo "hostile remote environment is forbidden: $name" >&2
      exit 2
      ;;
  esac
done < <(/usr/bin/env)
export PATH=/usr/bin:/bin
work="$1"
revision="$2"
if [ ! -d "$work" ] || [ -e "$work/.git" ] || \
   [ -n "$(find "$work" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  echo "remote attempt directory is absent or no longer empty" >&2
  exit 2
fi
env -i \
  PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  git clone --quiet https://github.com/nasqret/euf-viper.git "$work"
env -i \
  PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  git -C "$work" fetch --quiet origin "$revision"
env -i \
  PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  git -C "$work" checkout --quiet --detach "$revision"
cd "$work"
env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
  scripts/wmi/check_component_quotient_checkout.sh "$revision"
REMOTE_PREPARE_ATTEMPT

REMOTE_BINDINGS_RAW="$(
  ssh "$REMOTE_HOST" bash -s -- \
    "$REMOTE_WORK" "$REMOTE_SHARED_CORPUS" "$REMOTE_PYTHON_REQUEST" <<'REMOTE_BINDINGS'
set -euo pipefail
while IFS= read -r entry; do
  name="${entry%%=*}"
  case "$name" in
    BASH_ENV|CDPATH|ENV|GIT_*|PYTHON*|CARGO_*|RUST*|LD_*|DYLD_*|BASH_FUNC_*)
      echo "hostile remote environment is forbidden: $name" >&2
      exit 2
      ;;
  esac
done < <(/usr/bin/env)
export PATH=/usr/bin:/bin
work="$1"
shared_corpus="$2"
requested_python="$3"
cd "$work"
if [ "$(pwd -P)" != "$work" ]; then
  echo "remote attempt namespace is not a canonical physical path" >&2
  exit 2
fi
mkdir results
if [ ! -e benchmarks/smtlib-2025 ]; then
  if [ ! -s "$shared_corpus/qf_uf_manifest.jsonl" ]; then
    echo "shared QF_UF corpus manifest is absent" >&2
    exit 2
  fi
  ln -s -- "$shared_corpus" benchmarks/smtlib-2025
fi
manifest="$work/benchmarks/smtcomp-2025/qf_uf_manifest.jsonl"
if [ ! -s "$manifest" ]; then
  echo "fixed QF_UF manifest is absent" >&2
  exit 2
fi
submission_nonce="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
read -r namespace_device namespace_inode < <(stat -c '%d %i' -- "$work")
read -r results_device results_inode < <(stat -c '%d %i' -- "$work/results")
namespace_id="$(
  printf '%s\0%s\0%s\0%s\0%s\0%s\0' \
    "$work" "$namespace_device" "$namespace_inode" \
    "$results_device" "$results_inode" "$submission_nonce" | sha256sum
)"
namespace_id="${namespace_id%% *}"
manifest_sha256="$(sha256sum -- "$manifest")"
manifest_sha256="${manifest_sha256%% *}"
if [[ "$requested_python" == */* ]]; then
  python_candidate="$requested_python"
else
  python_candidate="$(command -v -- "$requested_python")"
fi
python_realpath="$(readlink -f -- "$python_candidate")"
if [[ "$python_realpath" != /* ]] || [ ! -x "$python_realpath" ]; then
  echo "resolved remote Python is not an absolute executable" >&2
  exit 2
fi
reported_realpath="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C \
    "$python_realpath" -I -B -S -c 'import os, sys; print(os.path.realpath(sys.executable))'
)"
python_version="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C \
    "$python_realpath" -I -B -S -c 'import platform; print(platform.python_version())'
)"
python_sha256="$(sha256sum -- "$python_realpath")"
python_sha256="${python_sha256%% *}"
if [ "$reported_realpath" != "$python_realpath" ]; then
  echo "remote Python sys.executable does not match its realpath" >&2
  exit 2
fi
printf '%s\n' \
  "$submission_nonce" "$namespace_id" \
  "$namespace_device" "$namespace_inode" \
  "$results_device" "$results_inode" \
  "$manifest_sha256" "$python_realpath" "$python_version" "$python_sha256"
REMOTE_BINDINGS
)"
REMOTE_BINDINGS=()
while IFS= read -r field; do
  REMOTE_BINDINGS+=("$field")
done <<< "$REMOTE_BINDINGS_RAW"
if [ "${#REMOTE_BINDINGS[@]}" -ne 10 ]; then
  echo "remote identity response is malformed" >&2
  exit 2
fi
SUBMISSION_NONCE="${REMOTE_BINDINGS[0]}"
NAMESPACE_ID="${REMOTE_BINDINGS[1]}"
NAMESPACE_DEVICE="${REMOTE_BINDINGS[2]}"
NAMESPACE_INODE="${REMOTE_BINDINGS[3]}"
RESULTS_DEVICE="${REMOTE_BINDINGS[4]}"
RESULTS_INODE="${REMOTE_BINDINGS[5]}"
MANIFEST_SHA256="${REMOTE_BINDINGS[6]}"
REMOTE_PYTHON_REALPATH="${REMOTE_BINDINGS[7]}"
REMOTE_PYTHON_VERSION="${REMOTE_BINDINGS[8]}"
REMOTE_PYTHON_SHA256="${REMOTE_BINDINGS[9]}"
for digest in "$SUBMISSION_NONCE" "$NAMESPACE_ID" "$MANIFEST_SHA256" "$REMOTE_PYTHON_SHA256"; do
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "remote digest/nonce binding is malformed" >&2
    exit 2
  fi
done
if [ "$MANIFEST_SHA256" != ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6 ]; then
  echo "remote manifest differs from the fixed revision blob" >&2
  exit 2
fi
for identity in "$NAMESPACE_DEVICE" "$NAMESPACE_INODE" "$RESULTS_DEVICE" "$RESULTS_INODE"; do
  if [[ ! "$identity" =~ ^[1-9][0-9]*$ ]]; then
    echo "remote inode identity is malformed" >&2
    exit 2
  fi
done
if [[ "$REMOTE_PYTHON_REALPATH" != /* ]] || \
   [[ ! "$REMOTE_PYTHON_REALPATH" =~ ^[A-Za-z0-9_./+-]+$ ]] || \
   [[ ! "$REMOTE_PYTHON_VERSION" =~ ^[A-Za-z0-9_.+-]+$ ]]; then
  echo "remote Python identity is malformed" >&2
  exit 2
fi

SUBMISSION_RAW="$(
  ssh "$REMOTE_HOST" bash -s -- \
    "$REMOTE_WORK" "$DEPENDENCY" "$REVISION" "$PUBLISHED_REF" "$REMOTE_HOST" \
    "$REMOTE_ATTEMPT_ID" "$SUBMISSION_NONCE" "$NAMESPACE_ID" \
    "$NAMESPACE_DEVICE" "$NAMESPACE_INODE" "$RESULTS_DEVICE" "$RESULTS_INODE" \
    "$MANIFEST_SHA256" "$REMOTE_SHARED_CORPUS" \
    "$REMOTE_PYTHON_REALPATH" "$REMOTE_PYTHON_VERSION" "$REMOTE_PYTHON_SHA256" \
    <<'REMOTE_SUBMIT_ATTEMPT'
set -euo pipefail
while IFS= read -r entry; do
  name="${entry%%=*}"
  case "$name" in
    BASH_ENV|CDPATH|ENV|GIT_*|PYTHON*|CARGO_*|RUST*|LD_*|DYLD_*|BASH_FUNC_*)
      echo "hostile remote environment is forbidden: $name" >&2
      exit 2
      ;;
  esac
done < <(/usr/bin/env)
export PATH=/usr/bin:/bin
work="$1"
dependency="$2"
revision="$3"
published_ref="$4"
remote_host="$5"
attempt_id="$6"
submission_nonce="$7"
namespace_id="$8"
namespace_device="$9"
namespace_inode="${10}"
results_device="${11}"
results_inode="${12}"
manifest_sha256="${13}"
shared_corpus="${14}"
python_realpath="${15}"
python_version="${16}"
python_sha256="${17}"
args=(--parsable --hold)
if [ -n "$dependency" ]; then
  args+=(--dependency="afterok:$dependency")
fi
cd "$work"
export_list="EUF_VIPER_EXPECTED_REVISION=$revision"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_ATTEMPT_ID=$attempt_id"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_SUBMISSION_NONCE=$submission_nonce"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_NAMESPACE_ID=$namespace_id"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_NAMESPACE_DEVICE=$namespace_device"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_NAMESPACE_INODE=$namespace_inode"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_RESULTS_DEVICE=$results_device"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_RESULTS_INODE=$results_inode"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_MANIFEST_SHA256=$manifest_sha256"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_SHARED_CORPUS=$shared_corpus"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_REALPATH=$python_realpath"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_VERSION=$python_version"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_SHA256=$python_sha256"
submission="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    sbatch "${args[@]}" --export="$export_list" \
    scripts/wmi/euf_viper_component_quotient_census.sbatch
)"
job_id="${submission%%;*}"
if [[ ! "$job_id" =~ ^[1-9][0-9]*$ ]]; then
  echo "invalid census job id: $submission" >&2
  exit 2
fi
pending_path="$work/results/component-quotient-census-submission-${attempt_id}-${job_id}.json"
payload="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    "$python_realpath" -I -B -S - \
    "$pending_path" "$revision" "$published_ref" "$remote_host" "$work" \
    "$attempt_id" "$submission_nonce" "$namespace_id" \
    "$namespace_device" "$namespace_inode" "$results_device" "$results_inode" \
    "$manifest_sha256" "$dependency" "$job_id" \
    "$python_realpath" "$python_version" "$python_sha256" <<'PY'
import hashlib
import json
import os
import sys

(
    path,
    revision,
    published_ref,
    remote_host,
    namespace_path,
    attempt_id,
    submission_nonce,
    namespace_id,
    namespace_device,
    namespace_inode,
    results_device,
    results_inode,
    manifest_sha256,
    dependency,
    job_id,
    python_realpath,
    python_version,
    python_sha256,
) = sys.argv[1:]
job = int(job_id)
value = {
    "schema": "euf-viper.component-quotient-ram-wmi-submission.v5",
    "status": "submitted_pending_nondecisive",
    "decisive": False,
    "authoritative": False,
    "revision": revision,
    "published_ref": published_ref,
    "remote_host": remote_host,
    "remote_namespace": {
        "id": namespace_id,
        "path": namespace_path,
        "device": int(namespace_device),
        "inode": int(namespace_inode),
        "results_path": f"{namespace_path}/results",
        "results_device": int(results_device),
        "results_inode": int(results_inode),
    },
    "attempt_id": attempt_id,
    "submission_nonce": submission_nonce,
    "dependency": int(dependency) if dependency else None,
    "job_id": job,
    "expected_marker_name": f"component-quotient-census-{job}.current",
    "contract": {
        "expected_sources": 7503,
        "lock_sha256": "1b313a912e2de8e202aeb2f9b3f50033ffdc65687940565d7a8f192b6ff5bf82",
        "manifest_sha256": manifest_sha256,
        "portable_source_set_sha256": "d8997c621fbd58034e55bef1e6636ea0f0a28bc63bb6391be39e9195c6f44653",
    },
    "python": {
        "realpath": python_realpath,
        "version": python_version,
        "sha256": python_sha256,
    },
}
canonical = lambda item: (json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
value["receipt_sha256"] = hashlib.sha256(canonical(value)).hexdigest()
data = canonical(value)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
try:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("pending receipt write made no progress")
        offset += written
    os.fsync(descriptor)
    os.fchmod(descriptor, 0o444)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
sys.stdout.buffer.write(data)
PY
)"
env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
  scontrol --quiet release "$job_id"
printf '%s\n%s\n' "$job_id" "$payload"
REMOTE_SUBMIT_ATTEMPT
)"

JOB_ID="${SUBMISSION_RAW%%$'\n'*}"
PENDING_JSON="${SUBMISSION_RAW#*$'\n'}"
if [[ ! "$JOB_ID" =~ ^[1-9][0-9]*$ ]] || [ -z "$PENDING_JSON" ] || \
   [[ "$PENDING_JSON" == *$'\n'* ]]; then
  echo "remote submission/receipt response is malformed" >&2
  exit 2
fi

mkdir -p "$ROOT/results"
RECEIPT_PATH="$ROOT/results/component-quotient-census-submission-${REMOTE_ATTEMPT_ID}-${JOB_ID}.json"
if ! LOCAL_PYTHON="$(command -v python3)"; then
  echo "local Python is required to persist the pending receipt" >&2
  exit 2
fi
LOCAL_PYTHON="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    "$LOCAL_PYTHON" -I -B -S -c \
    'import os, sys; print(os.path.realpath(sys.executable))'
)"
if [[ "$LOCAL_PYTHON" != /* ]] || [ ! -x "$LOCAL_PYTHON" ]; then
  echo "local Python realpath is not an absolute executable" >&2
  exit 2
fi
env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
  "$LOCAL_PYTHON" -I -B -S -c '
import os, sys
path, text = sys.argv[1:]
data = (text + "\n").encode("ascii")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
try:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("local pending receipt write made no progress")
        offset += written
    os.fsync(fd)
    os.fchmod(fd, 0o444)
    os.fsync(fd)
finally:
    os.close(fd)
directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
' "$RECEIPT_PATH" "$PENDING_JSON"

printf '%s\n' "$PENDING_JSON"
printf 'job_id=%s remote_pending_receipt=%s local_pending_receipt=%s\n' \
  "$JOB_ID" \
  "$REMOTE_WORK/results/component-quotient-census-submission-${REMOTE_ATTEMPT_ID}-${JOB_ID}.json" \
  "$RECEIPT_PATH"
