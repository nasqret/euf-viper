#!/usr/bin/env bash
set -euo pipefail

REMOTE="${EUF_VIPER_REMOTE:-wmicluster:~/euf-viper}"
LOCAL_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIMIT="${EUF_VIPER_CORPUS_LIMIT:-40}"
TIMEOUT="${EUF_VIPER_CORPUS_TIMEOUT:-10}"
SEED="${EUF_VIPER_CORPUS_SEED:-euf-viper-qf-uf-wmi-20260708}"
JOBS="${EUF_VIPER_CORPUS_JOBS:-8}"
AXIOM_ORDER="${EUF_VIPER_AXIOM_ORDER:-lex}"
AXIOM_SEED="${EUF_VIPER_AXIOM_SEED:-11400714819323198485}"
PATH_REGEX="${EUF_VIPER_CORPUS_PATH_REGEX:-}"

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

EXPORTS="ALL,EUF_VIPER_CORPUS_LIMIT=$LIMIT,EUF_VIPER_CORPUS_TIMEOUT=$TIMEOUT,EUF_VIPER_CORPUS_SEED=$SEED,EUF_VIPER_CORPUS_JOBS=$JOBS,EUF_VIPER_AXIOM_ORDER=$AXIOM_ORDER,EUF_VIPER_AXIOM_SEED=$AXIOM_SEED"
if [ -n "$PATH_REGEX" ]; then
  EXPORTS="$EXPORTS,EUF_VIPER_CORPUS_PATH_REGEX=$PATH_REGEX"
fi

ssh wmicluster "cd ~/euf-viper && mkdir -p results && sbatch --export='$EXPORTS' scripts/wmi/euf_viper_corpus.sbatch"
