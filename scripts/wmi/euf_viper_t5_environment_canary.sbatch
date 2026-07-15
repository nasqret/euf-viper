#!/bin/bash
#SBATCH --job-name=euf-t5-env-canary
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=256M
#SBATCH --time=00:02:00
#SBATCH --output=results/t5-environment-canary-%j.out
#SBATCH --error=results/t5-environment-canary-%j.err

set -euo pipefail

while IFS= read -r entry; do
  name="${entry%%=*}"
  case "$name" in
    BASH_ENV|CDPATH|ENV|GIT_*|PYTHON*|CARGO_*|RUST*|LD_*|DYLD_*|BASH_FUNC_*)
      echo "hostile canary environment is forbidden: $name" >&2
      exit 2
      ;;
  esac
done < <(/usr/bin/env)

export PATH=/usr/bin:/bin
export LANG=C
export LC_ALL=C
export TZ=UTC

EXPECTED_REVISION="${EUF_VIPER_T5_CANARY_REVISION:-}"
PYTHON_REALPATH="${EUF_VIPER_T5_CANARY_PYTHON:-}"
JOB_USER="${EUF_VIPER_T5_CANARY_USER:-}"
SUBMIT_DIR="$(readlink -f -- "${SLURM_SUBMIT_DIR:-}")"

if [[ ! "$EXPECTED_REVISION" =~ ^[0-9a-f]{40}$ ]] || \
   [[ "$PYTHON_REALPATH" != /* ]] || [ ! -x "$PYTHON_REALPATH" ] || \
   [[ ! "$JOB_USER" =~ ^[A-Za-z0-9_.-]+$ ]] || \
   [[ ! "${SLURM_JOB_ID:-}" =~ ^[1-9][0-9]*$ ]] || \
   [[ ! "${SLURM_CLUSTER_NAME:-}" =~ ^[A-Za-z0-9_.-]+$ ]] || \
   [ "${SLURM_JOB_NAME:-}" != "euf-t5-env-canary" ] || \
   [[ "$SUBMIT_DIR" != /* ]]; then
  echo "canary submission identity is malformed" >&2
  exit 2
fi
if [ ! -d "$SUBMIT_DIR/results" ]; then
  echo "canary result directory is absent" >&2
  exit 2
fi

cd "$SUBMIT_DIR"
exec env -i \
  PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
  SLURM_JOB_ID="$SLURM_JOB_ID" \
  SLURM_CLUSTER_NAME="$SLURM_CLUSTER_NAME" \
  SLURM_JOB_NAME="$SLURM_JOB_NAME" \
  SLURM_JOB_USER="$JOB_USER" \
  SLURM_SUBMIT_DIR="$SUBMIT_DIR" \
  "$PYTHON_REALPATH" -I -B -S scripts/bench/t5_environment_canary.py emit \
    --repository-root "$SUBMIT_DIR" \
    --output-directory "$SUBMIT_DIR/results" \
    --expected-revision "$EXPECTED_REVISION"
