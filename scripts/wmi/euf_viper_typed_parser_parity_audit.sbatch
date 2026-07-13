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

PYTHON="${EUF_VIPER_PYTHON:?set EUF_VIPER_PYTHON}"
EXPECTED_PYTHON_SHA256="${EUF_VIPER_PYTHON_SHA256:?set EUF_VIPER_PYTHON_SHA256}"
EXPECTED_PYTHON_VERSION="${EUF_VIPER_PYTHON_VERSION:?set EUF_VIPER_PYTHON_VERSION}"
case "$PYTHON" in
  /*) ;;
  *) echo "EUF_VIPER_PYTHON must be an absolute path: $PYTHON" >&2; exit 127 ;;
esac
if [ ! -f "$PYTHON" ] || [ ! -x "$PYTHON" ]; then
  echo "pinned python is not an executable file: $PYTHON" >&2
  exit 127
fi
if [ "${#EXPECTED_PYTHON_SHA256}" -ne 64 ]; then
  echo "EUF_VIPER_PYTHON_SHA256 must be a lowercase SHA-256" >&2
  exit 2
fi
case "$EXPECTED_PYTHON_SHA256" in
  *[!0-9a-f]*) echo "EUF_VIPER_PYTHON_SHA256 must be a lowercase SHA-256" >&2; exit 2 ;;
esac
ACTUAL_PYTHON_SHA256="$(sha256sum "$PYTHON" | awk '{print $1}')"
if [ "$ACTUAL_PYTHON_SHA256" != "$EXPECTED_PYTHON_SHA256" ]; then
  echo "python hash mismatch: expected $EXPECTED_PYTHON_SHA256, got $ACTUAL_PYTHON_SHA256" >&2
  exit 2
fi
ACTUAL_PYTHON_VERSION="$("$PYTHON" --version 2>&1)"
if [ "$ACTUAL_PYTHON_VERSION" != "$EXPECTED_PYTHON_VERSION" ]; then
  echo "python version mismatch: expected $EXPECTED_PYTHON_VERSION, got $ACTUAL_PYTHON_VERSION" >&2
  exit 2
fi

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

"$PYTHON" scripts/bench/typed_parser_parity.py audit \
  --root "$CAMPAIGN_ROOT" \
  --revision "$EXPECTED_REVISION" \
  --expected-sources "$EXPECTED_SOURCES"

printf 'typed_parser_audit=%s\n' "$CAMPAIGN_ROOT/audit.json"
