#!/usr/bin/env bash
#SBATCH --job-name=euf-t8-lineage
#SBATCH --partition=cpu_idle
#SBATCH --array=0-63
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=02:00:00
#SBATCH --output=results/t8-lineage-%A_%a.out
#SBATCH --error=results/t8-lineage-%A_%a.err

set -euo pipefail

: "${T8_LINEAGE_REPO:?set T8_LINEAGE_REPO to the clean repository checkout}"
: "${T8_LINEAGE_REVISION:?set T8_LINEAGE_REVISION to the exact 40-hex commit}"
: "${T8_LINEAGE_BINARY:?set T8_LINEAGE_BINARY to the prepared lineage-feature binary}"
: "${T8_LINEAGE_BINARY_SHA256:?set T8_LINEAGE_BINARY_SHA256 to the prepared binary hash}"
: "${T8_LINEAGE_MANIFEST:?set T8_LINEAGE_MANIFEST to the frozen 7,503-row manifest}"
: "${T8_LINEAGE_PYTHON:?set T8_LINEAGE_PYTHON to the canonical Python executable}"
: "${T8_LINEAGE_PYTHON_SHA256:?set T8_LINEAGE_PYTHON_SHA256 to the Python hash}"
: "${T8_LINEAGE_PYTHON_VERSION:?set T8_LINEAGE_PYTHON_VERSION to the exact version line}"
: "${T8_LINEAGE_SOURCE_ROOT:?set T8_LINEAGE_SOURCE_ROOT to the extracted QF_UF root}"
: "${SLURM_ARRAY_JOB_ID:?this script must run as a SLURM array job}"
: "${SLURM_ARRAY_TASK_ID:?this script must run as a SLURM array task}"

cd "${T8_LINEAGE_REPO}"

test "$(git rev-parse HEAD)" = "${T8_LINEAGE_REVISION}"
test -z "$(git status --porcelain --untracked-files=all)"
test "$(readlink -f -- "${T8_LINEAGE_PYTHON}")" = "${T8_LINEAGE_PYTHON}"
test "$(sha256sum "${T8_LINEAGE_PYTHON}" | awk '{print $1}')" = "${T8_LINEAGE_PYTHON_SHA256}"
test "$("${T8_LINEAGE_PYTHON}" --version 2>&1)" = "${T8_LINEAGE_PYTHON_VERSION}"

export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export RAYON_NUM_THREADS=1
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
unset EUF_VIPER_PROFILE || true

contract="campaigns/t8-assertion-lineage-census-v1.json"
result_root="results/t8-lineage-${SLURM_ARRAY_JOB_ID}"
mkdir -p "${result_root}/records"

"${T8_LINEAGE_PYTHON}" scripts/bench/validate_t8_lineage_contract.py \
  --contract "${contract}" \
  --root "${T8_LINEAGE_REPO}"

"${T8_LINEAGE_PYTHON}" scripts/bench/assertion_lineage_census.py run-shard \
  --binary "${T8_LINEAGE_BINARY}" \
  --binary-sha256 "${T8_LINEAGE_BINARY_SHA256}" \
  --contract "${contract}" \
  --manifest "${T8_LINEAGE_MANIFEST}" \
  --out "${result_root}/records/shard-${SLURM_ARRAY_TASK_ID}.jsonl" \
  --python-sha256 "${T8_LINEAGE_PYTHON_SHA256}" \
  --python-version "${T8_LINEAGE_PYTHON_VERSION}" \
  --revision "${T8_LINEAGE_REVISION}" \
  --root "${T8_LINEAGE_REPO}" \
  --shard-count 64 \
  --shard-index "${SLURM_ARRAY_TASK_ID}" \
  --source-root "${T8_LINEAGE_SOURCE_ROOT}"
