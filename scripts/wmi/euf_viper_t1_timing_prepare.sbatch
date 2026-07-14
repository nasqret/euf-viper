#!/usr/bin/env bash
#SBATCH --job-name=euf-t1-prepare
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=00:45:00
#SBATCH --output=results/t1-timing-prepare-%j.out
#SBATCH --error=results/t1-timing-prepare-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
source scripts/wmi/t1_timing_common.sh
t1_reject_ambient_influence
export LANG=C LC_ALL=C TZ=UTC OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export CARGO_BUILD_JOBS=1
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
unset EUF_VIPER_PROFILE

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
PUBLISHED_REF="${EUF_VIPER_T1_PUBLISHED_REF:?set EUF_VIPER_T1_PUBLISHED_REF}"
EXPECTED_CONTRACT_SHA256="${EUF_VIPER_T1_EXPECTED_CONTRACT_SHA256:?set expected contract hash}"
EXPECTED_MANIFEST_SHA256="${EUF_VIPER_T1_EXPECTED_MANIFEST_SHA256:?set expected manifest hash}"
EXPECTED_RECEIPT_SHA256="${EUF_VIPER_T1_EXPECTED_CHECKOUT_RECEIPT_SHA256:?set expected checkout receipt hash}"
RUN_ROOT="$(dirname "$PWD")"
CAMPAIGN_ROOT="$RUN_ROOT/artifacts"
CONTRACT="$PWD/campaigns/t1-typed-parser-timing-v1.json"
MANIFEST="$HOME/euf-viper/benchmarks/smtlib-2025/qf_uf_manifest.jsonl"
SOURCE_ROOT="$HOME/euf-viper"
CHECKOUT_RECEIPT="$RUN_ROOT/checkout-receipt.json"
export CARGO_TARGET_DIR="$RUN_ROOT/target"
export CARGO_HOME="$RUN_ROOT/cargo-home"

t1_verify_checkout "$EXPECTED_REVISION" "$PUBLISHED_REF"
t1_verify_pinned_tool Python EUF_VIPER_PYTHON EUF_VIPER_PYTHON_SHA256 EUF_VIPER_PYTHON_VERSION
t1_verify_pinned_tool Cargo EUF_VIPER_CARGO EUF_VIPER_CARGO_SHA256 EUF_VIPER_CARGO_VERSION
t1_verify_pinned_tool Rustc EUF_VIPER_RUSTC EUF_VIPER_RUSTC_SHA256 EUF_VIPER_RUSTC_VERSION
[ -s "$MANIFEST" ] || { echo "missing nonempty T1 manifest: $MANIFEST" >&2; exit 2; }
[ -f "$CONTRACT" ] || { echo "missing T1 contract: $CONTRACT" >&2; exit 2; }
[ ! -e "$CAMPAIGN_ROOT" ] || { echo "campaign root already exists: $CAMPAIGN_ROOT" >&2; exit 2; }
t1_verify_bound_file "$CONTRACT" "$EXPECTED_CONTRACT_SHA256" contract
t1_verify_bound_file "$MANIFEST" "$EXPECTED_MANIFEST_SHA256" manifest
t1_verify_bound_file "$CHECKOUT_RECEIPT" "$EXPECTED_RECEIPT_SHA256" "checkout receipt"
[ ! -e "$CARGO_TARGET_DIR" ] || { echo "fresh target already exists: $CARGO_TARGET_DIR" >&2; exit 2; }
[ ! -e "$CARGO_HOME" ] || { echo "fresh Cargo home already exists: $CARGO_HOME" >&2; exit 2; }
mkdir -m 700 "$CARGO_HOME"

env -i \
  HOME="$HOME" \
  PATH=/usr/bin:/bin \
  CARGO_HOME="$CARGO_HOME" \
  CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  CARGO_BUILD_JOBS=1 \
  RUSTC="$EUF_VIPER_RUSTC" \
  "$EUF_VIPER_CARGO" build --release --locked
BINARY="$CARGO_TARGET_DIR/release/euf-viper"
[ -f "$BINARY" ] && [ -x "$BINARY" ] || { echo "release binary is missing" >&2; exit 2; }
"$EUF_VIPER_PYTHON" -I -B scripts/bench/typed_parser_timing.py prepare \
  --manifest "$MANIFEST" \
  --repository-root "$PWD" \
  --source-root "$SOURCE_ROOT" \
  --binary "$BINARY" \
  --preflight-source tests/fixtures/parser_parity/bool_data_mixed_sorts.smt2 \
  --contract "$CONTRACT" \
  --revision "$EXPECTED_REVISION" \
  --checkout-receipt "$CHECKOUT_RECEIPT" \
  --expected-checkout-receipt-sha256 "$EXPECTED_RECEIPT_SHA256" \
  --expected-contract-sha256 "$EXPECTED_CONTRACT_SHA256" \
  --expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" \
  --output-root "$CAMPAIGN_ROOT"

printf 't1_timing_campaign_root=%s\nrevision=%s\n' "$CAMPAIGN_ROOT" "$EXPECTED_REVISION"
