#!/usr/bin/env bash
#SBATCH --job-name=euf-p0-shard
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=10G
#SBATCH --time=02:00:00
#SBATCH --output=results/p0-shard-%A_%a.out
#SBATCH --error=results/p0-shard-%A_%a.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export LANG=C
export LC_ALL=C
export TZ=UTC

PREPARE_JOB_ID="${EUF_VIPER_PREPARE_JOB_ID:?set EUF_VIPER_PREPARE_JOB_ID}"
CORPUS_KIND="${EUF_VIPER_CORPUS_KIND:?set EUF_VIPER_CORPUS_KIND}"
EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
case "$CORPUS_KIND" in
  full|official) ;;
  *) echo "EUF_VIPER_CORPUS_KIND must be full or official" >&2; exit 2 ;;
esac

if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in shard job" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty in shard job" >&2
  exit 2
fi

RUN_ROOT="$PWD/results/p0-${PREPARE_JOB_ID}"
INDEX="$(printf '%04d' "$SLURM_ARRAY_TASK_ID")"
PREPARED_LOCK="$RUN_ROOT/locks/$CORPUS_KIND/lock-$INDEX.json"
BOUND_LOCK="$RUN_ROOT/locks/$CORPUS_KIND/bound-$INDEX.json"

python3 scripts/bench/bind_campaign_cpu.py "$PREPARED_LOCK" \
  --out "$BOUND_LOCK" \
  > "$RUN_ROOT/locks/$CORPUS_KIND/binding-$INDEX.json"
python3 scripts/bench/run_locked_campaign.py "$BOUND_LOCK"
