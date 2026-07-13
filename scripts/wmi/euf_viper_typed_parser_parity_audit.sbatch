#!/usr/bin/env bash
#SBATCH --job-name=euf-parser-audit
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=00:30:00
#SBATCH --output=results/typed-parser-audit-%j.out
#SBATCH --error=results/typed-parser-audit-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export LANG=C
export LC_ALL=C
export TZ=UTC
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
unset EUF_VIPER_PROFILE

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
CAMPAIGN_ROOT="${EUF_VIPER_TYPED_PARSER_ROOT:?set EUF_VIPER_TYPED_PARSER_ROOT}"
EXPECTED_SOURCES="${EUF_VIPER_TYPED_PARSER_EXPECTED_SOURCES:-7503}"
case "$EXPECTED_SOURCES" in
  ''|0|0*|*[!0-9]*) echo "expected source count must be canonical and positive" >&2; exit 2 ;;
esac

ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi

python3 scripts/bench/typed_parser_parity.py audit \
  --root "$CAMPAIGN_ROOT" \
  --revision "$EXPECTED_REVISION" \
  --expected-sources "$EXPECTED_SOURCES"

printf 'typed_parser_audit=%s\n' "$CAMPAIGN_ROOT/audit.json"
