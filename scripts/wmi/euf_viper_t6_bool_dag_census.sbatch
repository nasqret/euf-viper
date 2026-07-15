#!/bin/bash
#SBATCH --job-name=euf-t6-dag-census
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=32G
#SBATCH --time=02:00:00
#SBATCH --output=results/t6-bool-dag-census-%j.out
#SBATCH --error=results/t6-bool-dag-census-%j.err

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 EXPECTED_REVISION CORPUS_ROOT" >&2
  exit 2
fi
EXPECTED_REVISION="$1"
CORPUS_ROOT="$2"
case "$EXPECTED_REVISION" in
  *[!0-9a-f]*|'') echo "expected revision must be lowercase hexadecimal" >&2; exit 2 ;;
esac
if [ "${#EXPECTED_REVISION}" -ne 40 ]; then
  echo "expected revision must contain exactly 40 hexadecimal digits" >&2
  exit 2
fi
case "$CORPUS_ROOT" in
  /*) ;;
  *) echo "corpus root must be absolute" >&2; exit 2 ;;
esac

export PATH="/usr/local/bin:/usr/bin:/bin"
export PYTHONDONTWRITEBYTECODE=1
cd "${SLURM_SUBMIT_DIR:?SLURM_SUBMIT_DIR is required}"

EXPECTED_MANIFEST_SHA256="33a9f0016570dc07dc4c9aed2f575633eb5a2ee10d21177c97a4e86b65507c78"
EXPECTED_TOOLCHAIN_CONTRACT_SHA256="db825fa64cf03e20d07842d063638ecdf7193a1eba4966be5d9e5f7e5c108baa"
EXPECTED_HISTORICAL_DISPOSITION_SHA256="b22f3bfdb10d2a379d5777e206eacd1e85453ee69c7380d8b68d995bda3fcbda"
MANIFEST="$PWD/campaigns/t6-theory-dag-p0-qg12-v1.json"
TOOLCHAIN_CONTRACT="$PWD/campaigns/t6-wmi-rust-toolchain-1.96.0-v1.json"
HISTORICAL_DISPOSITION="$PWD/campaigns/t6-wmi-job-146075-disposition-v1.json"

ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi
if [ ! -d "$CORPUS_ROOT" ]; then
  echo "missing T6 corpus root: $CORPUS_ROOT" >&2
  exit 2
fi
if [ "$(sha256sum "$MANIFEST" | awk '{print $1}')" != "$EXPECTED_MANIFEST_SHA256" ]; then
  echo "frozen T6 manifest artifact hash mismatch" >&2
  exit 2
fi
if [ "$(sha256sum "$TOOLCHAIN_CONTRACT" | awk '{print $1}')" != "$EXPECTED_TOOLCHAIN_CONTRACT_SHA256" ]; then
  echo "T6 WMI toolchain contract artifact hash mismatch" >&2
  exit 2
fi
if [ "$(sha256sum "$HISTORICAL_DISPOSITION" | awk '{print $1}')" != "$EXPECTED_HISTORICAL_DISPOSITION_SHA256" ]; then
  echo "historical job 146075 disposition artifact hash mismatch" >&2
  exit 2
fi

python3 scripts/bench/validate_t6_wmi_toolchain.py require-ready

if [ -z "${SLURM_JOB_ID:-}" ]; then
  echo "SLURM_JOB_ID is required" >&2
  exit 2
fi
case "${SLURM_TMPDIR:-}" in
  /*) ;;
  *) echo "an absolute SLURM_TMPDIR is required for the private attempt" >&2; exit 2 ;;
esac
if [ ! -d "$SLURM_TMPDIR" ]; then
  echo "SLURM_TMPDIR does not exist: $SLURM_TMPDIR" >&2
  exit 2
fi

OUT="$PWD/results/t6-bool-dag-census-${SLURM_JOB_ID}"
ATTEMPT_ROOT="$SLURM_TMPDIR/euf-viper-t6-${SLURM_JOB_ID}"
if [ -e "$ATTEMPT_ROOT" ]; then
  echo "attempt-private root already exists: $ATTEMPT_ROOT" >&2
  exit 2
fi
mkdir -p "$OUT"

python3 scripts/bench/validate_t6_wmi_toolchain.py run-census \
  --repo-root "$PWD" \
  --attempt-root "$ATTEMPT_ROOT" \
  --manifest "$MANIFEST" \
  --corpus-root "$CORPUS_ROOT" \
  --output "$OUT/report.json" \
  --revision "$EXPECTED_REVISION" \
  --run-log "$OUT/run.txt" \
  --attestation "$OUT/toolchain-attestation.json"

python3 scripts/bench/validate_t6_census_report.py \
  --report "$OUT/report.json" \
  --manifest "$MANIFEST" \
  --corpus-root "$CORPUS_ROOT" \
  --metadata "$OUT/metadata.json" \
  --run-log "$OUT/run.txt" \
  --toolchain-attestation "$OUT/toolchain-attestation.json" \
  --historical-job-disposition "$HISTORICAL_DISPOSITION" \
  --expected-revision "$EXPECTED_REVISION" \
  --job-id "$SLURM_JOB_ID"

printf 'census_root=%s\n' "$OUT"
printf 'revision=%s\n' "$ACTUAL_REVISION"
printf 'report_sha256=%s\n' "$(sha256sum "$OUT/report.json" | awk '{print $1}')"
