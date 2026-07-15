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
umask 077
export LANG=C LC_ALL=C TZ=UTC OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export CARGO_BUILD_JOBS=1
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
export EUF_VIPER_BACKEND=auto
unset EUF_VIPER_PROFILE

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
PUBLISHED_REF="${EUF_VIPER_T1_PUBLISHED_REF:?set EUF_VIPER_T1_PUBLISHED_REF}"
EXPECTED_CONTRACT_SHA256="${EUF_VIPER_T1_EXPECTED_CONTRACT_SHA256:?set expected contract hash}"
EXPECTED_MANIFEST_SHA256="${EUF_VIPER_T1_EXPECTED_MANIFEST_SHA256:?set expected manifest hash}"
EXPECTED_RECEIPT_SHA256="${EUF_VIPER_T1_EXPECTED_CHECKOUT_RECEIPT_SHA256:?set expected checkout receipt hash}"
EXPECTED_PARITY_RECEIPT_SHA256="${EUF_VIPER_T1_EXPECTED_PARITY_RECEIPT_SHA256:?set accepted parity receipt hash}"
CONTROL_REPO="$PWD"
RUN_ROOT="$(dirname "$PWD")"
CAMPAIGN_ROOT="$RUN_ROOT/artifacts"
SOURCE_SNAPSHOT="$RUN_ROOT/source"
CONTRACT="$CONTROL_REPO/campaigns/t1-typed-parser-timing-v1.json"
MANIFEST="$HOME/euf-viper/benchmarks/smtlib-2025/qf_uf_manifest.jsonl"
SOURCE_ROOT="$HOME/euf-viper"
CHECKOUT_RECEIPT="$RUN_ROOT/checkout-receipt.json"
PARITY_RECEIPT="$CONTROL_REPO/results/wmi/typed-parser-parity-146510/receipt.json"
BUILD_GUARD="$SOURCE_SNAPSHOT/scripts/wmi/t1_timing_build_guard.py"
HARNESS="$CONTROL_REPO/scripts/bench/typed_parser_timing.py"
BUILD_RECEIPT="$RUN_ROOT/build-receipt.json"
PRE_INVENTORY="$RUN_ROOT/pre-build-inventory.json"
POST_INVENTORY="$RUN_ROOT/post-build-inventory.json"
MONITOR_READY="$RUN_ROOT/mutation-monitor-ready.json"
MONITOR_STOP="$RUN_ROOT/mutation-monitor.stop"
MONITOR_EVENTS="$RUN_ROOT/mutation-events.jsonl"
MONITOR_RECEIPT="$RUN_ROOT/mutation-monitor-receipt.json"
export CARGO_TARGET_DIR="$RUN_ROOT/target"
export CARGO_HOME="$RUN_ROOT/build-cargo-home"
FETCH_CARGO_HOME="$RUN_ROOT/fetch-cargo-home"
BUILD_HOME="$RUN_ROOT/build-home"
DEPENDENCY_ROOT="$RUN_ROOT/dependencies"
VENDOR_DIR="$DEPENDENCY_ROOT/vendor"
VENDOR_CONFIG="$DEPENDENCY_ROOT/cargo-vendor-config.toml"
DEPENDENCY_PRE_INVENTORY="$RUN_ROOT/pre-build-dependency-inventory.json"
DEPENDENCY_POST_INVENTORY="$RUN_ROOT/post-build-dependency-inventory.json"
DEPENDENCY_MONITOR_READY="$RUN_ROOT/dependency-mutation-monitor-ready.json"
DEPENDENCY_MONITOR_STOP="$RUN_ROOT/dependency-mutation-monitor.stop"
DEPENDENCY_MONITOR_EVENTS="$RUN_ROOT/dependency-mutation-events.jsonl"
DEPENDENCY_MONITOR_RECEIPT="$RUN_ROOT/dependency-mutation-monitor-receipt.json"

t1_verify_checkout "$EXPECTED_REVISION" "$PUBLISHED_REF"
t1_verify_pinned_tool Python EUF_VIPER_PYTHON EUF_VIPER_PYTHON_SHA256 EUF_VIPER_PYTHON_VERSION
t1_verify_pinned_tool Cargo EUF_VIPER_CARGO EUF_VIPER_CARGO_SHA256 EUF_VIPER_CARGO_VERSION
t1_verify_pinned_tool Rustc EUF_VIPER_RUSTC EUF_VIPER_RUSTC_SHA256 EUF_VIPER_RUSTC_VERSION
t1_verify_pinned_tool CC EUF_VIPER_CC EUF_VIPER_CC_SHA256 EUF_VIPER_CC_VERSION
t1_verify_pinned_tool LD EUF_VIPER_LD EUF_VIPER_LD_SHA256 EUF_VIPER_LD_VERSION
t1_verify_pinned_tool AR EUF_VIPER_AR EUF_VIPER_AR_SHA256 EUF_VIPER_AR_VERSION
[ -s "$MANIFEST" ] || { echo "missing nonempty T1 manifest: $MANIFEST" >&2; exit 2; }
[ ! -e "$CAMPAIGN_ROOT" ] || { echo "campaign root already exists: $CAMPAIGN_ROOT" >&2; exit 2; }
t1_verify_bound_file "$MANIFEST" "$EXPECTED_MANIFEST_SHA256" manifest
t1_verify_bound_file "$CHECKOUT_RECEIPT" "$EXPECTED_RECEIPT_SHA256" "checkout receipt"
[ ! -e "$SOURCE_SNAPSHOT" ] || { echo "fresh source snapshot already exists: $SOURCE_SNAPSHOT" >&2; exit 2; }
[ ! -e "$CARGO_TARGET_DIR" ] || { echo "fresh target already exists: $CARGO_TARGET_DIR" >&2; exit 2; }
[ ! -e "$CARGO_HOME" ] || { echo "fresh Cargo home already exists: $CARGO_HOME" >&2; exit 2; }
[ ! -e "$FETCH_CARGO_HOME" ] || { echo "fresh fetch Cargo home already exists: $FETCH_CARGO_HOME" >&2; exit 2; }
[ ! -e "$BUILD_HOME" ] || { echo "fresh build home already exists: $BUILD_HOME" >&2; exit 2; }
[ ! -e "$DEPENDENCY_ROOT" ] || { echo "fresh dependency root already exists: $DEPENDENCY_ROOT" >&2; exit 2; }
mkdir -m 700 "$SOURCE_SNAPSHOT" "$CARGO_HOME" "$FETCH_CARGO_HOME" "$BUILD_HOME" "$DEPENDENCY_ROOT"
t1_git archive --format=tar "$EXPECTED_REVISION" | \
  env -i PATH=/usr/bin:/bin /usr/bin/tar -xf - -C "$SOURCE_SNAPSHOT"
t1_verify_bound_file "$CONTRACT" "$EXPECTED_CONTRACT_SHA256" contract
t1_verify_bound_file "$PARITY_RECEIPT" "$EXPECTED_PARITY_RECEIPT_SHA256" "accepted parity receipt"
[ ! -e /.cargo/config ] && [ ! -e /.cargo/config.toml ] || {
  echo "root Cargo configuration can influence the guarded build" >&2
  exit 2
}

MONITOR_PID=""
DEPENDENCY_MONITOR_PID=""
stop_monitor() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$DEPENDENCY_MONITOR_PID" ]; then
    [ -e "$DEPENDENCY_MONITOR_STOP" ] || : > "$DEPENDENCY_MONITOR_STOP"
    wait "$DEPENDENCY_MONITOR_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "$MONITOR_PID" ]; then
    [ -e "$MONITOR_STOP" ] || : > "$MONITOR_STOP"
    wait "$MONITOR_PID" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap stop_monitor EXIT HUP INT TERM
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" monitor \
  --snapshot "$SOURCE_SNAPSHOT" \
  --ready "$MONITOR_READY" \
  --stop "$MONITOR_STOP" \
  --events "$MONITOR_EVENTS" \
  --receipt "$MONITOR_RECEIPT" &
MONITOR_PID=$!
for _ in $(seq 1 400); do
  [ -s "$MONITOR_READY" ] && break
  kill -0 "$MONITOR_PID" 2>/dev/null || { echo "mutation monitor exited before ready" >&2; exit 2; }
  sleep 0.05
done
[ -s "$MONITOR_READY" ] || { echo "mutation monitor did not become ready" >&2; exit 2; }

"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" inventory \
  --repository "$CONTROL_REPO" \
  --revision "$EXPECTED_REVISION" \
  --snapshot "$SOURCE_SNAPSHOT" \
  --output "$PRE_INVENTORY"

cd /
env -i \
  HOME="$BUILD_HOME" \
  PATH=/usr/bin:/bin \
  CARGO_HOME="$FETCH_CARGO_HOME" \
  CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  CARGO_BUILD_JOBS=1 \
  CARGO_INCREMENTAL=0 \
  RUSTC="$EUF_VIPER_RUSTC" \
  CC="$EUF_VIPER_CC" \
  LD="$EUF_VIPER_LD" \
  AR="$EUF_VIPER_AR" \
  "$EUF_VIPER_CARGO" vendor \
    --manifest-path "$SOURCE_SNAPSHOT/Cargo.toml" \
    --locked --versioned-dirs "$VENDOR_DIR" > "$VENDOR_CONFIG"
[ -s "$VENDOR_CONFIG" ] || { echo "Cargo did not emit a vendor configuration" >&2; exit 2; }
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" monitor \
  --snapshot "$DEPENDENCY_ROOT" \
  --ready "$DEPENDENCY_MONITOR_READY" \
  --stop "$DEPENDENCY_MONITOR_STOP" \
  --events "$DEPENDENCY_MONITOR_EVENTS" \
  --receipt "$DEPENDENCY_MONITOR_RECEIPT" &
DEPENDENCY_MONITOR_PID=$!
for _ in $(seq 1 400); do
  [ -s "$DEPENDENCY_MONITOR_READY" ] && break
  kill -0 "$DEPENDENCY_MONITOR_PID" 2>/dev/null || {
    echo "dependency mutation monitor exited before ready" >&2
    exit 2
  }
  sleep 0.05
done
[ -s "$DEPENDENCY_MONITOR_READY" ] || {
  echo "dependency mutation monitor did not become ready" >&2
  exit 2
}
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" inventory-tree \
  --root "$DEPENDENCY_ROOT" \
  --output "$DEPENDENCY_PRE_INVENTORY"

set +e
env -i \
  HOME="$BUILD_HOME" \
  PATH=/usr/bin:/bin \
  CARGO_HOME="$CARGO_HOME" \
  CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  CARGO_BUILD_JOBS=1 \
  CARGO_INCREMENTAL=0 \
  CARGO_NET_OFFLINE=true \
  RUSTC="$EUF_VIPER_RUSTC" \
  CC="$EUF_VIPER_CC" \
  LD="$EUF_VIPER_LD" \
  AR="$EUF_VIPER_AR" \
  RUSTFLAGS="-C linker=$EUF_VIPER_CC -C link-arg=-fuse-ld=bfd" \
  "$EUF_VIPER_CARGO" build \
    --manifest-path "$SOURCE_SNAPSHOT/Cargo.toml" \
    --release --locked --offline \
    --config "source.crates-io.replace-with='vendored-sources'" \
    --config "source.vendored-sources.directory='$VENDOR_DIR'"
BUILD_STATUS=$?
set -e
cd "$CONTROL_REPO"
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" inventory \
  --repository "$CONTROL_REPO" \
  --revision "$EXPECTED_REVISION" \
  --snapshot "$SOURCE_SNAPSHOT" \
  --output "$POST_INVENTORY"
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" inventory-tree \
  --root "$DEPENDENCY_ROOT" \
  --output "$DEPENDENCY_POST_INVENTORY"
: > "$MONITOR_STOP"
: > "$DEPENDENCY_MONITOR_STOP"
set +e
wait "$MONITOR_PID"
MONITOR_STATUS=$?
wait "$DEPENDENCY_MONITOR_PID"
DEPENDENCY_MONITOR_STATUS=$?
set -e
MONITOR_PID=""
DEPENDENCY_MONITOR_PID=""
trap - EXIT HUP INT TERM
[ "$BUILD_STATUS" -eq 0 ] || { echo "locked release build failed: $BUILD_STATUS" >&2; exit "$BUILD_STATUS"; }
[ "$MONITOR_STATUS" -eq 0 ] || { echo "source mutation monitor rejected build: $MONITOR_STATUS" >&2; exit "$MONITOR_STATUS"; }
[ "$DEPENDENCY_MONITOR_STATUS" -eq 0 ] || {
  echo "dependency mutation monitor rejected build: $DEPENDENCY_MONITOR_STATUS" >&2
  exit "$DEPENDENCY_MONITOR_STATUS"
}

BINARY="$CARGO_TARGET_DIR/release/euf-viper"
[ -f "$BINARY" ] && [ -x "$BINARY" ] || { echo "release binary is missing" >&2; exit 2; }
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" receipt \
  --revision "$EXPECTED_REVISION" \
  --pre-inventory "$PRE_INVENTORY" \
  --post-inventory "$POST_INVENTORY" \
  --monitor-receipt "$MONITOR_RECEIPT" \
  --dependency-pre-inventory "$DEPENDENCY_PRE_INVENTORY" \
  --dependency-post-inventory "$DEPENDENCY_POST_INVENTORY" \
  --dependency-monitor-receipt "$DEPENDENCY_MONITOR_RECEIPT" \
  --binary "$BINARY" \
  --cargo-home "$CARGO_HOME" \
  --fetch-cargo-home "$FETCH_CARGO_HOME" \
  --target-dir "$CARGO_TARGET_DIR" \
  --vendor-dir "$VENDOR_DIR" \
  --output "$BUILD_RECEIPT"

cd "$CONTROL_REPO"
"$EUF_VIPER_PYTHON" -I -B "$HARNESS" prepare \
  --manifest "$MANIFEST" \
  --repository-root "$CONTROL_REPO" \
  --source-root "$SOURCE_ROOT" \
  --binary "$BINARY" \
  --preflight-source "$CONTROL_REPO/tests/fixtures/parser_parity/bool_data_mixed_sorts.smt2" \
  --contract "$CONTRACT" \
  --revision "$EXPECTED_REVISION" \
  --checkout-receipt "$CHECKOUT_RECEIPT" \
  --accepted-parity-receipt "$PARITY_RECEIPT" \
  --expected-accepted-parity-receipt-sha256 "$EXPECTED_PARITY_RECEIPT_SHA256" \
  --build-receipt "$BUILD_RECEIPT" \
  --expected-checkout-receipt-sha256 "$EXPECTED_RECEIPT_SHA256" \
  --expected-contract-sha256 "$EXPECTED_CONTRACT_SHA256" \
  --expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" \
  --output-root "$CAMPAIGN_ROOT"

printf 't1_timing_campaign_root=%s\nrevision=%s\n' "$CAMPAIGN_ROOT" "$EXPECTED_REVISION"
