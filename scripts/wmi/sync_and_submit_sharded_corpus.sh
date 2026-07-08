#!/usr/bin/env bash
set -euo pipefail

REMOTE="${EUF_VIPER_REMOTE:-wmicluster:~/euf-viper}"
LOCAL_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SHARDS="${EUF_VIPER_CORPUS_SHARDS:-64}"
MAX_ACTIVE="${EUF_VIPER_CORPUS_MAX_ACTIVE:-4}"
TIMEOUT="${EUF_VIPER_CORPUS_TIMEOUT:-60}"
JOBS="${EUF_VIPER_CORPUS_JOBS:-8}"
WALL_TIME="${EUF_VIPER_CORPUS_WALL_TIME:-04:00:00}"
AXIOM_ORDER="${EUF_VIPER_AXIOM_ORDER:-native}"
AXIOM_SEED="${EUF_VIPER_AXIOM_SEED:-11400714819323198485}"
LIMIT="${EUF_VIPER_CORPUS_LIMIT:-0}"
SEED="${EUF_VIPER_CORPUS_SEED:-euf-viper-qf-uf-wmi-20260708}"

cd "$LOCAL_ROOT"
if ! git diff --quiet || ! git diff --cached --quiet || \
  [ -n "$(git ls-files --others --exclude-standard)" ]; then
  echo "refusing sharded campaign from a dirty worktree" >&2
  exit 1
fi
REVISION="$(git rev-parse HEAD)"

for value in "$SHARDS" "$MAX_ACTIVE" "$JOBS"; do
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "shards, max-active, and jobs must be positive integers" >&2
    exit 1
  fi
done
if ! [[ "$LIMIT" =~ ^[0-9]+$ ]]; then
  echo "limit must be a non-negative integer" >&2
  exit 1
fi
if ! [[ "$TIMEOUT" =~ ^[0-9]+([.][0-9]+)?$ ]] || \
  [[ "$TIMEOUT" =~ ^0+([.]0+)?$ ]]; then
  echo "timeout must be a positive number of seconds" >&2
  exit 1
fi
if ! [[ "$WALL_TIME" =~ ^[0-9]{1,2}:[0-9]{2}:[0-9]{2}$ ]]; then
  echo "wall-time must use HH:MM:SS" >&2
  exit 1
fi
if ! [[ "$SEED" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "sample seed may contain only letters, digits, dot, underscore, and dash" >&2
  exit 1
fi
case "$AXIOM_ORDER" in
  lex | native | hash) ;;
  *)
    echo "axiom order must be lex, native, or hash" >&2
    exit 1
    ;;
esac
if ! [[ "$AXIOM_SEED" =~ ^[0-9]+$ ]]; then
  echo "axiom seed must be a non-negative integer" >&2
  exit 1
fi
if [ "$MAX_ACTIVE" -gt "$SHARDS" ]; then
  echo "max-active cannot exceed shards" >&2
  exit 1
fi

rsync -az --delete \
  --exclude target \
  --exclude .git \
  --exclude results \
  --exclude docs/book/_build \
  --exclude benchmarks/smtlib-2025 \
  --exclude third_party/solvers \
  ./ "$REMOTE/"

PREP_JOB="$(ssh wmicluster \
  "cd ~/euf-viper && mkdir -p results && sbatch --parsable --export=ALL,EUF_VIPER_GIT_REVISION=$REVISION,EUF_VIPER_CORPUS_LIMIT=$LIMIT,EUF_VIPER_CORPUS_SEED=$SEED scripts/wmi/euf_viper_prepare.sbatch")"
RUN_ID="${PREP_JOB%%;*}"
ARRAY_END="$((SHARDS - 1))"
ARRAY_JOB="$(ssh wmicluster \
  "cd ~/euf-viper && sbatch --parsable --dependency=afterok:$RUN_ID --array=0-${ARRAY_END}%${MAX_ACTIVE} --time=$WALL_TIME --export=ALL,EUF_VIPER_RUN_ID=$RUN_ID,EUF_VIPER_CORPUS_SHARDS=$SHARDS,EUF_VIPER_CORPUS_TIMEOUT=$TIMEOUT,EUF_VIPER_CORPUS_JOBS=$JOBS,EUF_VIPER_AXIOM_ORDER=$AXIOM_ORDER,EUF_VIPER_AXIOM_SEED=$AXIOM_SEED scripts/wmi/euf_viper_corpus_shard.sbatch")"
ARRAY_ID="${ARRAY_JOB%%;*}"
MERGE_JOB="$(ssh wmicluster \
  "cd ~/euf-viper && sbatch --parsable --dependency=afterok:$ARRAY_ID --export=ALL,EUF_VIPER_RUN_ID=$RUN_ID,EUF_VIPER_CORPUS_SHARDS=$SHARDS,EUF_VIPER_CORPUS_TIMEOUT=$TIMEOUT scripts/wmi/euf_viper_merge_shards.sbatch")"
MERGE_ID="${MERGE_JOB%%;*}"

METADATA="$(printf \
  '{"run_id":"%s","revision":"%s","prepare_job":"%s","array_job":"%s","merge_job":"%s","instances_limit":%s,"sample_seed":"%s","shards":%s,"max_active":%s,"timeout_s":%s,"jobs_per_shard":%s,"wall_time":"%s","axiom_order":"%s"}' \
  "$RUN_ID" "$REVISION" "$RUN_ID" "$ARRAY_ID" "$MERGE_ID" "$LIMIT" "$SEED" "$SHARDS" \
  "$MAX_ACTIVE" "$TIMEOUT" "$JOBS" "$WALL_TIME" "$AXIOM_ORDER")"
printf '%s\n' "$METADATA" | ssh wmicluster \
  "cat > ~/euf-viper/results/qf-uf-campaign-${RUN_ID}.json"

printf 'run_id=%s prepare_job=%s array_job=%s merge_job=%s revision=%s\n' \
  "$RUN_ID" "$RUN_ID" "$ARRAY_ID" "$MERGE_ID" "$REVISION"
