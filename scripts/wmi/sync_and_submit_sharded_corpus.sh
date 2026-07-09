#!/usr/bin/env bash
set -euo pipefail

REMOTE="${EUF_VIPER_REMOTE:-wmicluster:~/euf-viper}"
REMOTE_HOST="${REMOTE%%:*}"
REMOTE_ROOT="${REMOTE#*:}"
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
RESUME_RUN_ID="${EUF_VIPER_CORPUS_RESUME_RUN_ID:-}"
RETRY_SOLVERS="${EUF_VIPER_CORPUS_RETRY_SOLVERS:-}"
if [ "${EUF_VIPER_CORPUS_RETRY_RESULTS+x}" = x ]; then
  RETRY_RESULTS="$EUF_VIPER_CORPUS_RETRY_RESULTS"
else
  RETRY_RESULTS="timeout"
fi
SKIP_BUILD="${EUF_VIPER_CORPUS_SKIP_BUILD:-0}"
EXPECTED_BINARY_SHA256="${EUF_VIPER_EXPECTED_BINARY_SHA256:-}"

cd "$LOCAL_ROOT"
if [ "$REMOTE_HOST" = "$REMOTE" ] || \
  ! [[ "$REMOTE_HOST" =~ ^[A-Za-z0-9._-]+$ ]] || \
  ! [[ "$REMOTE_ROOT" =~ ^~?/[A-Za-z0-9._/-]+$ ]]; then
  echo "remote must use HOST:PATH with a shell-safe absolute or home-relative path" >&2
  exit 1
fi
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
if [ -n "$RESUME_RUN_ID" ] && ! [[ "$RESUME_RUN_ID" =~ ^[1-9][0-9]*$ ]]; then
  echo "resume run id must be a positive integer" >&2
  exit 1
fi
if [ -n "$RETRY_SOLVERS" ] && \
  ! [[ "$RETRY_SOLVERS" =~ ^(euf-viper|z3|cvc5|yices2)(,(euf-viper|z3|cvc5|yices2))*$ ]]; then
  echo "retry solvers must be a comma-separated solver list" >&2
  exit 1
fi
if [ -n "$RETRY_RESULTS" ] && \
  ! [[ "$RETRY_RESULTS" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]]; then
  echo "retry results must be a comma-separated shell-safe result list" >&2
  exit 1
fi
if ! [[ "$SKIP_BUILD" =~ ^[01]$ ]]; then
  echo "skip-build must be 0 or 1" >&2
  exit 1
fi
if [ "$SKIP_BUILD" = 1 ] && [ -z "$EXPECTED_BINARY_SHA256" ]; then
  echo "skip-build requires EUF_VIPER_EXPECTED_BINARY_SHA256" >&2
  exit 1
fi
if [ -n "$EXPECTED_BINARY_SHA256" ] && \
  ! [[ "$EXPECTED_BINARY_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "expected binary SHA-256 must be 64 lowercase hexadecimal digits" >&2
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
  ./ "$REMOTE_HOST:$REMOTE_ROOT/"

PREP_JOB="$(ssh "$REMOTE_HOST" \
  "cd $REMOTE_ROOT && mkdir -p results && EUF_VIPER_CORPUS_RETRY_RESULTS=$RETRY_RESULTS sbatch --parsable --export=ALL,EUF_VIPER_GIT_REVISION=$REVISION,EUF_VIPER_CORPUS_LIMIT=$LIMIT,EUF_VIPER_CORPUS_SEED=$SEED,EUF_VIPER_CORPUS_SKIP_BUILD=$SKIP_BUILD,EUF_VIPER_EXPECTED_BINARY_SHA256=$EXPECTED_BINARY_SHA256,EUF_VIPER_CORPUS_RETRY_RESULTS scripts/wmi/euf_viper_prepare.sbatch")"
RUN_ID="${PREP_JOB%%;*}"
ARRAY_END="$((SHARDS - 1))"
ARRAY_JOB="$(ssh "$REMOTE_HOST" \
  "cd $REMOTE_ROOT && EUF_VIPER_CORPUS_RETRY_SOLVERS=$RETRY_SOLVERS EUF_VIPER_CORPUS_RETRY_RESULTS=$RETRY_RESULTS sbatch --parsable --dependency=afterok:$RUN_ID --array=0-${ARRAY_END}%${MAX_ACTIVE} --time=$WALL_TIME --export=ALL,EUF_VIPER_RUN_ID=$RUN_ID,EUF_VIPER_CORPUS_SHARDS=$SHARDS,EUF_VIPER_CORPUS_TIMEOUT=$TIMEOUT,EUF_VIPER_CORPUS_JOBS=$JOBS,EUF_VIPER_AXIOM_ORDER=$AXIOM_ORDER,EUF_VIPER_AXIOM_SEED=$AXIOM_SEED,EUF_VIPER_CORPUS_RESUME_RUN_ID=$RESUME_RUN_ID,EUF_VIPER_CORPUS_RETRY_SOLVERS,EUF_VIPER_CORPUS_RETRY_RESULTS scripts/wmi/euf_viper_corpus_shard.sbatch")"
ARRAY_ID="${ARRAY_JOB%%;*}"
MERGE_JOB="$(ssh "$REMOTE_HOST" \
  "cd $REMOTE_ROOT && EUF_VIPER_CORPUS_RETRY_SOLVERS=$RETRY_SOLVERS EUF_VIPER_CORPUS_RETRY_RESULTS=$RETRY_RESULTS sbatch --parsable --dependency=afterok:$ARRAY_ID --export=ALL,EUF_VIPER_RUN_ID=$RUN_ID,EUF_VIPER_CORPUS_SHARDS=$SHARDS,EUF_VIPER_CORPUS_TIMEOUT=$TIMEOUT,EUF_VIPER_CORPUS_RESUME_RUN_ID=$RESUME_RUN_ID,EUF_VIPER_CORPUS_RETRY_SOLVERS,EUF_VIPER_CORPUS_RETRY_RESULTS scripts/wmi/euf_viper_merge_shards.sbatch")"
MERGE_ID="${MERGE_JOB%%;*}"

METADATA="$(printf \
  '{"run_id":"%s","revision":"%s","remote_root":"%s","prepare_job":"%s","array_job":"%s","merge_job":"%s","instances_limit":%s,"sample_seed":"%s","shards":%s,"max_active":%s,"timeout_s":%s,"jobs_per_shard":%s,"wall_time":"%s","axiom_order":"%s","resume_run_id":"%s","retry_solvers":"%s","retry_results":"%s","skip_build":%s,"expected_binary_sha256":"%s"}' \
  "$RUN_ID" "$REVISION" "$REMOTE_ROOT" "$RUN_ID" "$ARRAY_ID" "$MERGE_ID" "$LIMIT" "$SEED" "$SHARDS" \
  "$MAX_ACTIVE" "$TIMEOUT" "$JOBS" "$WALL_TIME" "$AXIOM_ORDER" "$RESUME_RUN_ID" "$RETRY_SOLVERS" \
  "$RETRY_RESULTS" "$SKIP_BUILD" "$EXPECTED_BINARY_SHA256")"
printf '%s\n' "$METADATA" | ssh "$REMOTE_HOST" \
  "cat > $REMOTE_ROOT/results/qf-uf-campaign-${RUN_ID}.json"

printf 'run_id=%s prepare_job=%s array_job=%s merge_job=%s revision=%s remote=%s:%s\n' \
  "$RUN_ID" "$RUN_ID" "$ARRAY_ID" "$MERGE_ID" "$REVISION" \
  "$REMOTE_HOST" "$REMOTE_ROOT"
