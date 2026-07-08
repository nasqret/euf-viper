#!/usr/bin/env bash
set -euo pipefail

REMOTE="${EUF_VIPER_REMOTE:-wmicluster:~/euf-viper}"
LOCAL_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIMIT="${EUF_VIPER_CORPUS_LIMIT:-40}"
TIMEOUT="${EUF_VIPER_CORPUS_TIMEOUT:-10}"
SEED="${EUF_VIPER_CORPUS_SEED:-euf-viper-qf-uf-wmi-20260708}"

cd "$LOCAL_ROOT"
mkdir -p results
rsync -az --delete \
  --exclude target \
  --exclude .git \
  --exclude results \
  --exclude docs/book/_build \
  --exclude benchmarks/smtlib-2025 \
  --exclude third_party/solvers \
  ./ "$REMOTE/"

ssh wmicluster "cd ~/euf-viper && mkdir -p results && sbatch --export=ALL,EUF_VIPER_CORPUS_LIMIT=$LIMIT,EUF_VIPER_CORPUS_TIMEOUT=$TIMEOUT,EUF_VIPER_CORPUS_SEED=$SEED scripts/wmi/euf_viper_corpus.sbatch"
