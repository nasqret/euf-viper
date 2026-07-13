#!/usr/bin/env bash
#SBATCH --job-name=euf-cqram-census
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=64G
#SBATCH --time=08:00:00
#SBATCH --output=results/component-quotient-census-%j.out
#SBATCH --error=results/component-quotient-census-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1
export PYTHONHASHSEED=0

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
EXPECTED_SOURCES="${EUF_VIPER_COMPONENT_QUOTIENT_EXPECTED_SOURCES:-7503}"
PYTHON_REALPATH="${EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_REALPATH:?set EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_REALPATH}"
PYTHON_VERSION="${EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_VERSION:?set EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_VERSION}"
PYTHON_SHA256="${EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_SHA256:?set EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_SHA256}"
if [ "$EXPECTED_SOURCES" != 7503 ]; then
  echo "component quotient census requires exactly 7503 sources" >&2
  exit 2
fi
if [[ "$PYTHON_REALPATH" != /* ]] || [ ! -x "$PYTHON_REALPATH" ]; then
  echo "pinned Python executable must be an absolute executable path" >&2
  exit 2
fi
if [[ ! "$PYTHON_SHA256" =~ ^[0-9a-f]{64}$ ]] || [ -z "$PYTHON_VERSION" ]; then
  echo "pinned Python version or SHA-256 is malformed" >&2
  exit 2
fi

verify_python_identity() {
  local phase="$1"
  local actual_realpath actual_reported_realpath actual_version actual_sha256
  actual_realpath="$(readlink -f -- "$PYTHON_REALPATH")"
  if [ "$actual_realpath" != "$PYTHON_REALPATH" ]; then
    echo "$phase Python realpath drift: expected $PYTHON_REALPATH, got $actual_realpath" >&2
    exit 2
  fi
  actual_sha256="$(sha256sum -- "$PYTHON_REALPATH")"
  actual_sha256="${actual_sha256%% *}"
  if [ "$actual_sha256" != "$PYTHON_SHA256" ]; then
    echo "$phase Python SHA-256 drift: expected $PYTHON_SHA256, got $actual_sha256" >&2
    exit 2
  fi
  actual_reported_realpath="$("$PYTHON_REALPATH" -c 'import os, sys; print(os.path.realpath(sys.executable))')"
  if [ "$actual_reported_realpath" != "$PYTHON_REALPATH" ]; then
    echo "$phase Python sys.executable drift: expected $PYTHON_REALPATH, got $actual_reported_realpath" >&2
    exit 2
  fi
  actual_version="$("$PYTHON_REALPATH" -c 'import platform; print(platform.python_version())')"
  if [ "$actual_version" != "$PYTHON_VERSION" ]; then
    echo "$phase Python version drift: expected $PYTHON_VERSION, got $actual_version" >&2
    exit 2
  fi
}

ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi

SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-$HOME/euf-viper/benchmarks/smtlib-2025}"
if [ ! -e "$PWD/benchmarks/smtlib-2025" ] && \
   [ -s "$SHARED_CORPUS/qf_uf_manifest.jsonl" ]; then
  ln -s "$SHARED_CORPUS" "$PWD/benchmarks/smtlib-2025"
fi
MANIFEST="${EUF_VIPER_COMPONENT_QUOTIENT_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl}"
LOCK="$PWD/campaigns/component-quotient-ram-census-v1.json"
if [ ! -s "$MANIFEST" ]; then
  echo "missing nonempty census manifest: $MANIFEST" >&2
  exit 2
fi
if [ ! -s "$LOCK" ]; then
  echo "missing component quotient campaign lock: $LOCK" >&2
  exit 2
fi

OUT="$PWD/results/component-quotient-census-${SLURM_JOB_ID}"
mkdir -p "$OUT"
verify_python_identity analyzer
"$PYTHON_REALPATH" scripts/bench/census_component_quotient_ram.py \
  "$MANIFEST" \
  --repository-root "$PWD" \
  --lock "$LOCK" \
  --records-out "$OUT/records.jsonl" \
  --aggregate-out "$OUT/aggregate.json" \
  --targets-out "$OUT/targets.jsonl" \
  > "$OUT/run.txt"

verify_python_identity verifier
"$PYTHON_REALPATH" scripts/bench/verify_component_quotient_ram_bundle.py \
  "$MANIFEST" \
  --repository-root "$PWD" \
  --lock "$LOCK" \
  --records "$OUT/records.jsonl" \
  --aggregate "$OUT/aggregate.json" \
  --targets "$OUT/targets.jsonl" \
  --receipt-out "$OUT/verification.json" \
  --require-validity \
  > "$OUT/verification.txt"

verify_python_identity metadata
"$PYTHON_REALPATH" scripts/bench/finalize_component_quotient_ram_metadata.py \
  --metadata-out "$OUT/metadata.json" \
  --repository-root "$PWD" \
  --manifest "$MANIFEST" \
  --lock "$LOCK" \
  --records "$OUT/records.jsonl" \
  --aggregate "$OUT/aggregate.json" \
  --targets "$OUT/targets.jsonl" \
  --verification "$OUT/verification.json" \
  --run-log "$OUT/run.txt" \
  --verification-log "$OUT/verification.txt" \
  --expected-sources "$EXPECTED_SOURCES" \
  --revision "$EXPECTED_REVISION" \
  --job-id "$SLURM_JOB_ID" \
  --python-realpath "$PYTHON_REALPATH" \
  --python-version "$PYTHON_VERSION" \
  --python-sha256 "$PYTHON_SHA256"

printf 'census_root=%s\n' "$OUT"
printf 'revision=%s\n' "$ACTUAL_REVISION"
