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
manifest="$work/benchmarks/smtlib-2025/qf_uf_manifest.jsonl"
if [ ! -s "$manifest" ]; then
  echo "external 7,503-row QF_UF manifest is absent" >&2
  exit 2
fi
if [ "$(readlink -f -- "$manifest")" != \
     "$(readlink -f -- "$shared_corpus/qf_uf_manifest.jsonl")" ]; then
  echo "selected T5 manifest is not the bound external smtlib-2025 manifest" >&2
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
manifest_rows="$(wc -l < "$manifest")"
manifest_rows="${manifest_rows//[[:space:]]/}"
if [ "$manifest_sha256" != 32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4 ] || \
   [ "$manifest_rows" = 3521 ] || [ "$manifest_rows" != 7503 ]; then
  echo "external T5 manifest SHA/cardinality binding failed" >&2
  exit 2
fi
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
slurm_cluster="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    scontrol show config | awk '$1 == "ClusterName" && $2 == "=" { print $3 }'
)"
job_user="$(id -un)"
if [[ ! "$slurm_cluster" =~ ^[A-Za-z0-9_.-]+$ ]] || \
   [[ ! "$job_user" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "remote Slurm cluster/user identity is malformed" >&2
  exit 2
fi
printf '%s\n' \
  "$submission_nonce" "$namespace_id" \
  "$namespace_device" "$namespace_inode" \
  "$results_device" "$results_inode" \
  "$manifest_sha256" "$python_realpath" "$python_version" "$python_sha256" \
  "$slurm_cluster" "$job_user"
REMOTE_BINDINGS
)"
REMOTE_BINDINGS=()
while IFS= read -r field; do
  REMOTE_BINDINGS+=("$field")
done <<< "$REMOTE_BINDINGS_RAW"
if [ "${#REMOTE_BINDINGS[@]}" -ne 12 ]; then
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
REMOTE_SLURM_CLUSTER="${REMOTE_BINDINGS[10]}"
REMOTE_JOB_USER="${REMOTE_BINDINGS[11]}"
for digest in "$SUBMISSION_NONCE" "$NAMESPACE_ID" "$MANIFEST_SHA256" "$REMOTE_PYTHON_SHA256"; do
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "remote digest/nonce binding is malformed" >&2
    exit 2
  fi
done
if [ "$MANIFEST_SHA256" != 32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4 ]; then
  echo "remote manifest differs from the fixed external T5 campaign" >&2
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
   [[ ! "$REMOTE_PYTHON_VERSION" =~ ^[A-Za-z0-9_.+-]+$ ]] || \
   [[ ! "$REMOTE_SLURM_CLUSTER" =~ ^[A-Za-z0-9_.-]+$ ]] || \
   [[ ! "$REMOTE_JOB_USER" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "remote Python/Slurm identity is malformed" >&2
  exit 2
fi
LOCAL_JOB_NAME="euf-cqram-${NAMESPACE_ID:0:20}"
if [[ ! "$LOCAL_JOB_NAME" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "per-attempt Slurm job name is malformed" >&2
  exit 2
fi

LOCAL_JOB_ID=""
LOCAL_SLURM_CLUSTER="$REMOTE_SLURM_CLUSTER"
LOCAL_HELD_RECEIPT_SHA256=""
LOCAL_SUBMISSION_ACTIVE=0
LOCAL_RELEASED=0

cancel_local_held_job() {
  local status="$?"
  trap - EXIT HUP INT TERM
  if [ "$LOCAL_SUBMISSION_ACTIVE" -eq 1 ] && [ "$LOCAL_RELEASED" -eq 0 ]; then
    if ! ssh "$REMOTE_HOST" bash -s -- \
      "$REMOTE_WORK" "$REMOTE_ATTEMPT_ID" \
      "$LOCAL_JOB_ID" "$LOCAL_SLURM_CLUSTER" \
      "$LOCAL_JOB_NAME" "$REMOTE_JOB_USER" \
      "$REMOTE_PYTHON_REALPATH" "$REMOTE_PYTHON_SHA256" \
      "$LOCAL_HELD_RECEIPT_SHA256" <<'REMOTE_CANCEL_LOCAL_HANDOFF'
set -euo pipefail
export PATH=/usr/bin:/bin
work="$1"
attempt_id="$2"
job_id="$3"
cluster="$4"
job_name="$5"
job_user="$6"
python_realpath="$7"
python_sha256="$8"
held_receipt_sha256="$9"
if [[ ! "$cluster" =~ ^[A-Za-z0-9_.-]+$ ]] || \
   [[ ! "$job_name" =~ ^[A-Za-z0-9_.-]+$ ]] || \
   [[ ! "$job_user" =~ ^[A-Za-z0-9_.-]+$ ]] || \
   [[ "$work" != /* ]] || [[ "$python_realpath" != /* ]] || \
   [[ ! "$python_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "held census fallback identity is malformed" >&2
  exit 2
fi
if [[ ! "$job_id" =~ ^[1-9][0-9]*$ ]]; then
  queue="$(
    env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
      squeue --clusters="$cluster" --noheader --user="$job_user" \
        --name="$job_name" --format='%A'
  )"
  candidates=()
  while IFS= read -r candidate; do
    candidate="${candidate//[[:space:]]/}"
    [ -z "$candidate" ] && continue
    [[ "$candidate" =~ ^[1-9][0-9]*$ ]] || {
      echo "held census fallback query returned a malformed job id" >&2
      exit 2
    }
    candidates+=("$candidate")
  done <<< "$queue"
  if [ "${#candidates[@]}" -ne 1 ]; then
    echo "held census fallback query returned zero or ambiguous jobs" >&2
    exit 2
  fi
  job_id="${candidates[0]}"
fi
held_path="$work/results/component-quotient-census-held-${attempt_id}.json"
if [ ! -s "$held_path" ]; then
  if ! env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    "$python_realpath" -I -B -S "$work/scripts/bench/t5_held_scheduler.py" capture \
      --job-id "$job_id" --cluster "$cluster" --job-name "$job_name" \
      --user "$job_user" --workdir "$work" --output "$held_path" >/dev/null; then
    [ -s "$held_path" ] || {
      echo "cannot persist held scheduler ownership for cancellation" >&2
      exit 2
    }
  fi
fi
digest_args=()
if [ -n "$held_receipt_sha256" ]; then
  [[ "$held_receipt_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "held census receipt digest is malformed" >&2
    exit 2
  }
  digest_args=(--expected-receipt-sha256 "$held_receipt_sha256")
fi
observed_python_sha256="$(sha256sum -- "$python_realpath")"
observed_python_sha256="${observed_python_sha256%% *}"
if [ "$observed_python_sha256" != "$python_sha256" ]; then
  echo "held census Python identity drift" >&2
  exit 2
fi
env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
  "$python_realpath" -I -B -S "$work/scripts/bench/t5_held_scheduler.py" operate \
    --receipt "$held_path" "${digest_args[@]}" --expected-job-id "$job_id" \
    --expected-cluster "$cluster" --expected-job-name "$job_name" \
    --expected-user "$job_user" --expected-workdir "$work" --action cancel
REMOTE_CANCEL_LOCAL_HANDOFF
    then
      echo "failed to cancel census during local receipt handoff" >&2
    fi
  fi
  exit "$status"
}

LOCAL_SUBMISSION_ACTIVE=1
trap cancel_local_held_job EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

SUBMISSION_RAW="$(
  ssh "$REMOTE_HOST" bash -s -- \
    "$REMOTE_WORK" "$DEPENDENCY" "$REVISION" "$PUBLISHED_REF" "$REMOTE_HOST" \
    "$REMOTE_ATTEMPT_ID" "$SUBMISSION_NONCE" "$NAMESPACE_ID" \
    "$NAMESPACE_DEVICE" "$NAMESPACE_INODE" "$RESULTS_DEVICE" "$RESULTS_INODE" \
    "$MANIFEST_SHA256" "$REMOTE_SHARED_CORPUS" \
    "$REMOTE_PYTHON_REALPATH" "$REMOTE_PYTHON_VERSION" "$REMOTE_PYTHON_SHA256" \
    "$REMOTE_SLURM_CLUSTER" "$REMOTE_JOB_USER" "$LOCAL_JOB_NAME" \
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
expected_cluster="${18}"
expected_user="${19}"
job_name="${20}"
job_user="$(id -un)"
cluster="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    scontrol show config | awk '$1 == "ClusterName" && $2 == "=" { print $3 }'
)"
if [[ ! "$cluster" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "Slurm ClusterName is malformed: $cluster" >&2
  exit 2
fi
if [ "$cluster" != "$expected_cluster" ] || [ "$job_user" != "$expected_user" ] || \
   [[ ! "$job_name" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "Slurm cluster/user/job-name binding drifted before submission" >&2
  exit 2
fi
args=(--parsable --hold --job-name="$job_name")
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
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_SLURM_CLUSTER=$cluster"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_JOB_NAME=$job_name"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_JOB_USER=$job_user"
export_list+=",EUF_VIPER_COMPONENT_QUOTIENT_WORKDIR=$work"
submission=""
job_id=""
held_path="$work/results/component-quotient-census-held-${attempt_id}.json"
remote_handoff_complete=0
cancel_held_job() {
  local status="$?"
  local cancel_job="$job_id"
  local cancel_cluster="$cluster"
  trap - EXIT
  if [[ ! "$cancel_job" =~ ^[1-9][0-9]*$ ]] && \
     [[ "$submission" =~ ^([1-9][0-9]*)\;([A-Za-z0-9_.-]+)$ ]]; then
    cancel_job="${BASH_REMATCH[1]}"
    cancel_cluster="${BASH_REMATCH[2]}"
  fi
  if [ "$remote_handoff_complete" -eq 0 ] && \
     [[ "$cancel_job" =~ ^[1-9][0-9]*$ ]] && \
     [[ "$cancel_cluster" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    if [ ! -s "$held_path" ]; then
      env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
        "$python_realpath" -I -B -S scripts/bench/t5_held_scheduler.py capture \
          --job-id "$cancel_job" --cluster "$cancel_cluster" \
          --job-name "$job_name" --user "$job_user" --workdir "$work" \
          --output "$held_path" >/dev/null || true
    fi
    if ! env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
      "$python_realpath" -I -B -S scripts/bench/t5_held_scheduler.py operate \
        --receipt "$held_path" --expected-job-id "$cancel_job" \
        --expected-cluster "$cancel_cluster" --expected-job-name "$job_name" \
        --expected-user "$job_user" --expected-workdir "$work" --action cancel; then
      echo "failed to cancel held job $cancel_job on cluster $cancel_cluster" >&2
    fi
  fi
  exit "$status"
}
trap cancel_held_job EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
submission="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    sbatch "${args[@]}" --export="$export_list" \
    scripts/wmi/euf_viper_component_quotient_census.sbatch
)"
if [[ ! "$submission" =~ ^([1-9][0-9]*)\;([A-Za-z0-9_.-]+)$ ]]; then
  echo "invalid full census job/cluster identity: $submission" >&2
  exit 2
fi
job_id="${BASH_REMATCH[1]}"
submitted_cluster="${BASH_REMATCH[2]}"
if [ "$submitted_cluster" != "$cluster" ]; then
  echo "sbatch --parsable cluster differs from Slurm ClusterName" >&2
  exit 2
fi
held_payload="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    "$python_realpath" -I -B -S scripts/bench/t5_held_scheduler.py capture \
      --job-id "$job_id" --cluster "$cluster" --job-name "$job_name" \
      --user "$job_user" --workdir "$work" --output "$held_path"
)"
if [ -z "$held_payload" ] || [[ "$held_payload" == *$'\n'* ]]; then
  echo "held scheduler receipt response is malformed" >&2
  exit 2
fi
pending_path="$work/results/component-quotient-census-submission-${attempt_id}-${job_id}.json"
payload="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    "$python_realpath" -I -B -S - \
    "$pending_path" "$revision" "$published_ref" "$remote_host" "$work" \
    "$attempt_id" "$submission_nonce" "$namespace_id" \
    "$namespace_device" "$namespace_inode" "$results_device" "$results_inode" \
    "$manifest_sha256" "$dependency" "$job_id" "$submission" "$cluster" \
    "$job_name" "$job_user" "$held_payload" \
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
    sbatch_parsable,
    cluster,
    job_name,
    job_user,
    held_payload,
    python_realpath,
    python_version,
    python_sha256,
) = sys.argv[1:]
job = int(job_id)
held = json.loads(held_payload)
held_canonical = canonical = lambda item: (json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
if held_canonical(held) != (held_payload + "\n").encode("ascii"):
    raise ValueError("held scheduler receipt is not canonical JSON")
value = {
    "schema": "euf-viper.component-quotient-ram-wmi-submission.v7",
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
    "scheduler_submission": {
        "sbatch_parsable": sbatch_parsable,
        "job_id": job,
        "cluster": cluster,
        "job_name": job_name,
        "user": job_user,
        "workdir": namespace_path,
    },
    "scheduler_held": held,
    "expected_marker_name": f"component-quotient-census-{job}.current",
    "contract": {
        "expected_sources": 7503,
        "manifest_relative_path": "benchmarks/smtlib-2025/qf_uf_manifest.jsonl",
        "lock_sha256": "7958892d3bf45abbf7d40f31b75c5cdf07a6aec13c66442278685b0ad4eddc24",
        "manifest_sha256": manifest_sha256,
        "portable_source_set_sha256": "d8997c621fbd58034e55bef1e6636ea0f0a28bc63bb6391be39e9195c6f44653",
    },
    "python": {
        "realpath": python_realpath,
        "version": python_version,
        "sha256": python_sha256,
    },
}
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
held_receipt_sha256="$(
  printf '%s\n' "$held_payload" | \
    "$python_realpath" -I -B -S -c \
      'import json,sys; value=json.load(sys.stdin); print(value["receipt_sha256"])'
)"
if [[ ! "$held_receipt_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "held scheduler receipt digest response is malformed" >&2
  exit 2
fi
printf '%s\n%s\n%s\n' "$submission" "$held_receipt_sha256" "$payload"
remote_handoff_complete=1
trap - EXIT HUP INT TERM
REMOTE_SUBMIT_ATTEMPT
)"

SBATCH_PARSABLE="${SUBMISSION_RAW%%$'\n'*}"
SUBMISSION_REMAINDER="${SUBMISSION_RAW#*$'\n'}"
HELD_RECEIPT_SHA256="${SUBMISSION_REMAINDER%%$'\n'*}"
PENDING_JSON="${SUBMISSION_REMAINDER#*$'\n'}"
if [[ ! "$SBATCH_PARSABLE" =~ ^([1-9][0-9]*)\;([A-Za-z0-9_.-]+)$ ]] || \
   [[ ! "$HELD_RECEIPT_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
   [ -z "$PENDING_JSON" ] || \
   [[ "$PENDING_JSON" == *$'\n'* ]]; then
  echo "remote submission/receipt response is malformed" >&2
  exit 2
fi
JOB_ID="${BASH_REMATCH[1]}"
SLURM_CLUSTER="${BASH_REMATCH[2]}"
if [ "$SLURM_CLUSTER" != "$REMOTE_SLURM_CLUSTER" ]; then
  echo "returned census cluster differs from the prebound Slurm cluster" >&2
  exit 2
fi
LOCAL_JOB_ID="$JOB_ID"
LOCAL_SLURM_CLUSTER="$SLURM_CLUSTER"
LOCAL_HELD_RECEIPT_SHA256="$HELD_RECEIPT_SHA256"

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
if ! SSH_BIN="$(command -v ssh)" || [[ "$SSH_BIN" != /* ]] || [ ! -x "$SSH_BIN" ]; then
  echo "an absolute local SSH executable is required for held-job handoff" >&2
  exit 2
fi
HANDOFF_JSON="$(
  printf '%s\n' "$PENDING_JSON" | \
    env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
      "$LOCAL_PYTHON" -I -B -S scripts/bench/t5_submission_receipt.py \
        --receipt "$RECEIPT_PATH" \
        --revision "$REVISION" \
        --published-ref "$PUBLISHED_REF" \
        --remote-host "$REMOTE_HOST" \
        --namespace-path "$REMOTE_WORK" \
        --namespace-id "$NAMESPACE_ID" \
        --namespace-device "$NAMESPACE_DEVICE" \
        --namespace-inode "$NAMESPACE_INODE" \
        --results-device "$RESULTS_DEVICE" \
        --results-inode "$RESULTS_INODE" \
        --attempt-id "$REMOTE_ATTEMPT_ID" \
        --submission-nonce "$SUBMISSION_NONCE" \
        --dependency "$DEPENDENCY" \
        --job-id "$JOB_ID" \
        --cluster "$SLURM_CLUSTER" \
        --job-name "$LOCAL_JOB_NAME" \
        --job-user "$REMOTE_JOB_USER" \
        --held-receipt-sha256 "$HELD_RECEIPT_SHA256" \
        --python-realpath "$REMOTE_PYTHON_REALPATH" \
        --python-version "$REMOTE_PYTHON_VERSION" \
        --python-sha256 "$REMOTE_PYTHON_SHA256" \
        --ssh "$SSH_BIN"
)"
LOCAL_RELEASED=1
LOCAL_SUBMISSION_ACTIVE=0
trap - EXIT HUP INT TERM

printf '%s\n' "$PENDING_JSON"
printf '%s\n' "$HANDOFF_JSON"
printf 'sbatch_parsable=%s job_id=%s cluster=%s remote_pending_receipt=%s local_pending_receipt=%s\n' \
  "$SBATCH_PARSABLE" "$JOB_ID" "$SLURM_CLUSTER" \
  "$REMOTE_WORK/results/component-quotient-census-submission-${REMOTE_ATTEMPT_ID}-${JOB_ID}.json" \
  "$RECEIPT_PATH"
