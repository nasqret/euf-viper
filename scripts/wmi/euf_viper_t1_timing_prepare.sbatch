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
export LANG=C LC_ALL=C TZ=UTC OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export CARGO_BUILD_JOBS=1
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
unset EUF_VIPER_PROFILE

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
PUBLISHED_REF="${EUF_VIPER_T1_PUBLISHED_REF:?set EUF_VIPER_T1_PUBLISHED_REF}"
CAMPAIGN_ROOT="${EUF_VIPER_T1_TIMING_ROOT:?set EUF_VIPER_T1_TIMING_ROOT}"
CONTRACT="${EUF_VIPER_T1_TIMING_CONTRACT:-$PWD/campaigns/t1-typed-parser-timing-v1.json}"

t1_verify_checkout "$EXPECTED_REVISION" "$PUBLISHED_REF"
t1_verify_pinned_tool Python EUF_VIPER_PYTHON EUF_VIPER_PYTHON_SHA256 EUF_VIPER_PYTHON_VERSION
t1_verify_pinned_tool Cargo EUF_VIPER_CARGO EUF_VIPER_CARGO_SHA256 EUF_VIPER_CARGO_VERSION
t1_verify_pinned_tool Rustc EUF_VIPER_RUSTC EUF_VIPER_RUSTC_SHA256 EUF_VIPER_RUSTC_VERSION

SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-$HOME/euf-viper/benchmarks/smtlib-2025}"
if [ ! -e "$PWD/benchmarks/smtlib-2025" ] && [ -s "$SHARED_CORPUS/qf_uf_manifest.jsonl" ]; then
  ln -s "$SHARED_CORPUS" "$PWD/benchmarks/smtlib-2025"
fi
MANIFEST="${EUF_VIPER_T1_TIMING_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl}"
[ -s "$MANIFEST" ] || { echo "missing nonempty T1 manifest: $MANIFEST" >&2; exit 2; }
[ -f "$CONTRACT" ] || { echo "missing T1 contract: $CONTRACT" >&2; exit 2; }
[ ! -e "$CAMPAIGN_ROOT" ] || { echo "campaign root already exists: $CAMPAIGN_ROOT" >&2; exit 2; }

RUSTC="$EUF_VIPER_RUSTC" "$EUF_VIPER_CARGO" build --release --locked
BINARY="$PWD/target/release/euf-viper"
[ -f "$BINARY" ] && [ -x "$BINARY" ] || { echo "release binary is missing" >&2; exit 2; }
"$EUF_VIPER_PYTHON" scripts/bench/typed_parser_timing.py prepare \
  --manifest "$MANIFEST" \
  --repository-root "$PWD" \
  --binary "$BINARY" \
  --preflight-source tests/fixtures/parser_parity/bool_data_mixed_sorts.smt2 \
  --contract "$CONTRACT" \
  --revision "$EXPECTED_REVISION" \
  --output-root "$CAMPAIGN_ROOT"

printf 't1_timing_campaign_root=%s\nrevision=%s\n' "$CAMPAIGN_ROOT" "$EXPECTED_REVISION"
