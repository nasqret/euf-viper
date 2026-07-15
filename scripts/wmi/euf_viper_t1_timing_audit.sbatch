#!/usr/bin/env bash
#SBATCH --job-name=euf-t1-audit
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=01:00:00
#SBATCH --output=results/t1-timing-audit-%j.out
#SBATCH --error=results/t1-timing-audit-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
source scripts/wmi/t1_timing_common.sh
t1_reject_ambient_influence
export LANG=C LC_ALL=C TZ=UTC OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
export EUF_VIPER_BACKEND=auto
unset EUF_VIPER_PROFILE

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
PUBLISHED_REF="${EUF_VIPER_T1_PUBLISHED_REF:?set EUF_VIPER_T1_PUBLISHED_REF}"
EXPECTED_CONTRACT_SHA256="${EUF_VIPER_T1_EXPECTED_CONTRACT_SHA256:?set expected contract hash}"
EXPECTED_MANIFEST_SHA256="${EUF_VIPER_T1_EXPECTED_MANIFEST_SHA256:?set expected manifest hash}"
EXPECTED_RECEIPT_SHA256="${EUF_VIPER_T1_EXPECTED_CHECKOUT_RECEIPT_SHA256:?set expected checkout receipt hash}"
CAMPAIGN_ROOT="$(dirname "$PWD")/artifacts"
HARNESS="$PWD/scripts/bench/typed_parser_timing.py"

t1_verify_checkout "$EXPECTED_REVISION" "$PUBLISHED_REF"
t1_verify_pinned_tool Python EUF_VIPER_PYTHON EUF_VIPER_PYTHON_SHA256 EUF_VIPER_PYTHON_VERSION
t1_verify_pinned_tool Cargo EUF_VIPER_CARGO EUF_VIPER_CARGO_SHA256 EUF_VIPER_CARGO_VERSION
t1_verify_pinned_tool Rustc EUF_VIPER_RUSTC EUF_VIPER_RUSTC_SHA256 EUF_VIPER_RUSTC_VERSION
t1_verify_pinned_tool CC EUF_VIPER_CC EUF_VIPER_CC_SHA256 EUF_VIPER_CC_VERSION
t1_verify_pinned_tool LD EUF_VIPER_LD EUF_VIPER_LD_SHA256 EUF_VIPER_LD_VERSION
t1_verify_pinned_tool AR EUF_VIPER_AR EUF_VIPER_AR_SHA256 EUF_VIPER_AR_VERSION
"$EUF_VIPER_PYTHON" -I -B "$HARNESS" audit \
  --root "$CAMPAIGN_ROOT" \
  --revision "$EXPECTED_REVISION" \
  --expected-checkout-receipt-sha256 "$EXPECTED_RECEIPT_SHA256" \
  --expected-contract-sha256 "$EXPECTED_CONTRACT_SHA256" \
  --expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256"

printf 't1_timing_audit=%s\n' "$CAMPAIGN_ROOT/audit.json"
