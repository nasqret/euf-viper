#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---dry-run}"
if [ "$MODE" != "--dry-run" ] && [ "$MODE" != "--submit" ]; then
  echo "usage: $0 [--dry-run|--submit]" >&2
  exit 2
fi

while IFS= read -r entry; do
  name="${entry%%=*}"
  case "$name" in
    BASH_ENV|CDPATH|ENV|GIT_*|PYTHON*|CARGO_*|RUST*|LD_*|DYLD_*|BASH_FUNC_*)
      echo "hostile canary submission environment is forbidden: $name" >&2
      exit 2
      ;;
  esac
done < <(/usr/bin/env)

export PATH=/usr/bin:/bin
export LANG=C
export LC_ALL=C
export TZ=UTC
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
SCRIPT="scripts/wmi/euf_viper_t5_environment_canary.sbatch"

if [ "$MODE" = "--dry-run" ]; then
  printf '%s\n' \
    'mode=dry-run' \
    'resources=00:02:00,256MiB,1cpu,1task,no-array' \
    'scope=non-corpus-environment-only' \
    "command=sbatch --parsable --export=<revision,python,user> $SCRIPT" \
    'post_job=validate_t5_environment_canary.sh JOB_ID;CLUSTER CANARY RECEIPT'
  exit 0
fi

if [ "$(uname -s)" != Linux ]; then
  echo "canary submission must run in the intended Linux checkout" >&2
  exit 2
fi
cd "$ROOT"
mkdir -p results
PYTHON="$(command -v python3)"
PYTHON="$(readlink -f -- "$PYTHON")"
REVISION="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    git -C "$ROOT" rev-parse HEAD
)"
USER_NAME="$(id -un)"
CLUSTER="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    scontrol show config | awk '$1 == "ClusterName" && $2 == "=" { print $3 }'
)"
if [[ ! "$REVISION" =~ ^[0-9a-f]{40}$ ]] || \
   [[ "$PYTHON" != /* ]] || [ ! -x "$PYTHON" ] || \
   [[ ! "$USER_NAME" =~ ^[A-Za-z0-9_.-]+$ ]] || \
   [[ ! "$CLUSTER" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "canary submission binding is malformed" >&2
  exit 2
fi
EXPORTS="EUF_VIPER_T5_CANARY_REVISION=$REVISION"
EXPORTS+=",EUF_VIPER_T5_CANARY_PYTHON=$PYTHON"
EXPORTS+=",EUF_VIPER_T5_CANARY_USER=$USER_NAME"
SUBMISSION="$(
  env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
    sbatch --parsable --export="$EXPORTS" "$SCRIPT"
)"
if [[ ! "$SUBMISSION" =~ ^([1-9][0-9]*)\;([A-Za-z0-9_.-]+)$ ]] || \
   [ "${BASH_REMATCH[2]}" != "$CLUSTER" ]; then
  echo "canary sbatch job;cluster response is malformed: $SUBMISSION" >&2
  exit 2
fi
JOB_ID="${BASH_REMATCH[1]}"
printf 'sbatch_parsable=%s canary=%s validation_command=%q\n' \
  "$SUBMISSION" \
  "$ROOT/results/t5-environment-canary-${JOB_ID}.json" \
  "scripts/wmi/validate_t5_environment_canary.sh '$SUBMISSION' '$ROOT/results/t5-environment-canary-${JOB_ID}.json' '$ROOT/results/t5-environment-canary-validation-${JOB_ID}.json'"
