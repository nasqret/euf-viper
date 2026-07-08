#!/usr/bin/env bash
set -euo pipefail

REMOTE="${EUF_VIPER_REMOTE:-wmicluster:~/euf-viper}"
LOCAL_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CASES="${EUF_VIPER_CASES:-40}"
SIZE="${EUF_VIPER_SIZE:-20000}"

cd "$LOCAL_ROOT"
mkdir -p results
rsync -az --delete \
  --exclude target \
  --exclude .git \
  --exclude results \
  --exclude docs/book/_build \
  ./ "$REMOTE/"

ssh wmicluster "cd ~/euf-viper && mkdir -p results && sbatch --export=ALL,EUF_VIPER_CASES=$CASES,EUF_VIPER_SIZE=$SIZE scripts/wmi/euf_viper_bench.sbatch"
