#!/usr/bin/env bash
set -euo pipefail

SBATCH_PARSABLE="${1:?usage: $0 JOB_ID;CLUSTER CANARY RECEIPT}"
CANARY="${2:?usage: $0 JOB_ID;CLUSTER CANARY RECEIPT}"
RECEIPT="${3:?usage: $0 JOB_ID;CLUSTER CANARY RECEIPT}"
if [[ ! "$SBATCH_PARSABLE" =~ ^[1-9][0-9]*\;[A-Za-z0-9_.-]+$ ]] || \
   [[ "$CANARY" != /* ]] || [[ "$RECEIPT" != /* ]]; then
  echo "canary validation arguments are malformed" >&2
  exit 2
fi

export PATH=/usr/bin:/bin
export LANG=C
export LC_ALL=C
export TZ=UTC
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
PYTHON="$(readlink -f -- "$(command -v python3)")"
cd "$ROOT"
exec env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \
  "$PYTHON" -I -B -S scripts/bench/t5_environment_canary.py validate \
    --canary "$CANARY" \
    --sbatch-parsable "$SBATCH_PARSABLE" \
    --receipt-out "$RECEIPT"
