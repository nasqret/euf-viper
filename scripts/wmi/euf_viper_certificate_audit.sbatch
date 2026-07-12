#!/usr/bin/env bash
#SBATCH --job-name=euf-cert-audit
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=12G
#SBATCH --time=04:00:00
#SBATCH --output=results/certificate-audit-%j.out
#SBATCH --error=results/certificate-audit-%j.err

set -euo pipefail
umask 077

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1

EXPECTED_REVISION="${EUF_VIPER_CERT_EXPECTED_REVISION:?set EUF_VIPER_CERT_EXPECTED_REVISION}"
RUN_ROOT="${EUF_VIPER_CERT_RUN_ROOT:?set EUF_VIPER_CERT_RUN_ROOT}"
PARENT_LOCK="${EUF_VIPER_CERT_BASE_PARENT_LOCK:?set EUF_VIPER_CERT_BASE_PARENT_LOCK}"
SHARD_LOCK_DIR="${EUF_VIPER_CERT_BASE_SHARD_LOCK_DIR:?set EUF_VIPER_CERT_BASE_SHARD_LOCK_DIR}"
SHARD_RESULTS_ROOT="${EUF_VIPER_CERT_BASE_SHARD_RESULTS_ROOT:?set EUF_VIPER_CERT_BASE_SHARD_RESULTS_ROOT}"
SHARDS="${EUF_VIPER_CERT_SHARDS:?set EUF_VIPER_CERT_SHARDS}"
CHECKER="${EUF_VIPER_CERT_CHECKER:?set EUF_VIPER_CERT_CHECKER}"
CHECKER_SHA256="${EUF_VIPER_CERT_CHECKER_SHA256:?set EUF_VIPER_CERT_CHECKER_SHA256}"
DRAT_TRIM="${EUF_VIPER_CERT_DRAT_TRIM:?set EUF_VIPER_CERT_DRAT_TRIM}"
DRAT_TRIM_SHA256="${EUF_VIPER_CERT_DRAT_TRIM_SHA256:?set EUF_VIPER_CERT_DRAT_TRIM_SHA256}"
CORPUS_ROOT="${EUF_VIPER_CERT_CORPUS_ROOT:-}"
TIMEOUT_S="${EUF_VIPER_CERT_TIMEOUT_S:-60}"
CHECKER_TIMEOUT_S="${EUF_VIPER_CERT_CHECKER_TIMEOUT_S:-60}"
TIMEOUT_GRACE_S="${EUF_VIPER_CERT_TIMEOUT_GRACE_S:-0.25}"
STAGE_LABEL="${EUF_VIPER_CERT_STAGE_LABEL:-base-2s}"

case "$SHARDS" in
  ''|0|0*|*[!0-9]*)
    echo "EUF_VIPER_CERT_SHARDS must be a canonical positive integer" >&2
    exit 2
    ;;
esac
case "$STAGE_LABEL" in ''|*[!A-Za-z0-9._-]*) echo "invalid certificate stage label" >&2; exit 2 ;; esac
if [ "${SLURM_CPUS_PER_TASK:-1}" != 1 ]; then
  echo "certificate audit requires exactly one allocated core" >&2
  exit 2
fi
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in certificate audit" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "repository must be completely clean in certificate audit" >&2
  exit 2
fi
test -s "$RUN_ROOT/prepare.json"

ACTUAL_CHECKER_SHA256="$(sha256sum "$CHECKER" | awk '{print $1}')"
ACTUAL_DRAT_TRIM_SHA256="$(sha256sum "$DRAT_TRIM" | awk '{print $1}')"
if [ "$ACTUAL_CHECKER_SHA256" != "$CHECKER_SHA256" ]; then
  echo "certificate checker SHA-256 drift before global audit" >&2
  exit 2
fi
if [ "$ACTUAL_DRAT_TRIM_SHA256" != "$DRAT_TRIM_SHA256" ]; then
  echo "drat-trim SHA-256 drift before global audit" >&2
  exit 2
fi

COMMAND=(
  python3 scripts/cert/audit_shadow_campaign.py
  --parent-lock "$PARENT_LOCK"
  --shard-lock-dir "$SHARD_LOCK_DIR"
  --shard-results-root "$SHARD_RESULTS_ROOT"
  --shadow-output-root "$RUN_ROOT/shards"
  --checker "$CHECKER"
  --drat-trim "$DRAT_TRIM"
  --timeout "$TIMEOUT_S"
  --checker-timeout "$CHECKER_TIMEOUT_S"
  --timeout-grace "$TIMEOUT_GRACE_S"
  --out "$RUN_ROOT/$STAGE_LABEL-audit.json"
)
if [ -n "$CORPUS_ROOT" ]; then
  COMMAND+=(--corpus-root "$CORPUS_ROOT")
fi

"${COMMAND[@]}"
