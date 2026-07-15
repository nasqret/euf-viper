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

[ "$#" -eq 8 ] || { echo "expected exact root/ref contract arguments" >&2; exit 2; }
T1_JOB_ROOT="$1"
EXPECTED_REVISION="$2"
PUBLISHED_REF="$3"
SUBMISSION_MODE="$4"
EXPECTED_CONTRACT_SHA256="$5"
EXPECTED_MANIFEST_SHA256="$6"
EXPECTED_RECEIPT_SHA256="$7"
EXPECTED_PARITY_RECEIPT_SHA256="$8"
case "$T1_JOB_ROOT" in /*) ;; *) echo "T1 execution root must be absolute" >&2; exit 2 ;; esac
[ "${#EXPECTED_REVISION}" -eq 40 ] || { echo "T1 revision length is invalid" >&2; exit 2; }
case "$EXPECTED_REVISION" in *[!0-9a-f]*) echo "T1 revision is malformed" >&2; exit 2 ;; esac
case "$PUBLISHED_REF" in origin/*) ;; *) echo "T1 published ref must be an origin ref" >&2; exit 2 ;; esac
case "$SUBMISSION_MODE" in canary|full) ;; *) echo "invalid T1 submission mode" >&2; exit 2 ;; esac
T1_JOB_ROOT="$(/usr/bin/readlink -f -- "$T1_JOB_ROOT")"
[ "$T1_JOB_ROOT" = "$(/usr/bin/pwd -P)" ] || {
  echo "Slurm did not enter the submitted immutable execution root" >&2
  exit 2
}
t1_bootstrap_git() {
  env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    /usr/bin/git -C "$T1_JOB_ROOT" "$@"
}
[ "$(t1_bootstrap_git rev-parse --verify HEAD^{commit})" = "$EXPECTED_REVISION" ] || {
  echo "T1 execution root HEAD mismatch" >&2
  exit 2
}
[ "$(t1_bootstrap_git rev-parse --verify "$PUBLISHED_REF^{commit}")" = "$EXPECTED_REVISION" ] || {
  echo "T1 execution root published-ref mismatch" >&2
  exit 2
}
COMMON_RELATIVE="scripts/wmi/t1_timing_common.sh"
COMMON_PATH="$T1_JOB_ROOT/$COMMON_RELATIVE"
COMMON_ENTRY="$(t1_bootstrap_git ls-tree "$EXPECTED_REVISION" -- "$COMMON_RELATIVE")"
[ "${COMMON_ENTRY%% *}" = 100755 ] || { echo "T1 common helper mode mismatch" >&2; exit 2; }
COMMON_BLOB="$(printf '%s\n' "$COMMON_ENTRY" | /usr/bin/awk '{print $3}')"
[ "$(t1_bootstrap_git hash-object --no-filters -- "$COMMON_PATH")" = "$COMMON_BLOB" ] || {
  echo "T1 common helper blob mismatch" >&2
  exit 2
}
source "$COMMON_PATH"
t1_reject_ambient_influence
cd "$T1_JOB_ROOT"
umask 077
export LANG=C LC_ALL=C TZ=UTC OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export CARGO_BUILD_JOBS=1
export EUF_VIPER_SCOPED_LET=auto
export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024
export EUF_VIPER_BACKEND=auto
unset EUF_VIPER_PROFILE

CONTROL_REPO="$T1_JOB_ROOT"
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
MONITOR_CONTROL="$RUN_ROOT/.mutation-monitor-control.$$"
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
DEPENDENCY_MONITOR_CONTROL="$RUN_ROOT/.dependency-mutation-monitor-control.$$"
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
MONITOR_CONTROL_OPEN=0
DEPENDENCY_MONITOR_CONTROL_OPEN=0
SOURCE_MONITOR_EVIDENCE_OPEN=0
DEPENDENCY_MONITOR_EVIDENCE_OPEN=0
INVENTORY_EVIDENCE_OPEN=0
BUILD_RECEIPT_OPEN=0
stop_monitor() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [ "$DEPENDENCY_MONITOR_CONTROL_OPEN" -eq 1 ]; then
    exec 9>&-
    DEPENDENCY_MONITOR_CONTROL_OPEN=0
  fi
  if [ -n "$DEPENDENCY_MONITOR_PID" ]; then
    wait "$DEPENDENCY_MONITOR_PID" >/dev/null 2>&1 || true
  fi
  if [ "$MONITOR_CONTROL_OPEN" -eq 1 ]; then
    exec 8>&-
    MONITOR_CONTROL_OPEN=0
  fi
  if [ -n "$MONITOR_PID" ]; then
    wait "$MONITOR_PID" >/dev/null 2>&1 || true
  fi
  if [ "$DEPENDENCY_MONITOR_EVIDENCE_OPEN" -eq 1 ]; then
    exec 10>&- 11>&- 12>&-
  fi
  if [ "$SOURCE_MONITOR_EVIDENCE_OPEN" -eq 1 ]; then
    exec 3>&- 4>&- 5>&-
  fi
  if [ "$INVENTORY_EVIDENCE_OPEN" -eq 1 ]; then
    exec 13>&- 14>&- 15>&- 16>&-
  fi
  if [ "$BUILD_RECEIPT_OPEN" -eq 1 ]; then
    exec 17>&-
  fi
  rm -f "$MONITOR_CONTROL" "$DEPENDENCY_MONITOR_CONTROL"
  exit "$status"
}
trap stop_monitor EXIT HUP INT TERM
(
  set -o noclobber
  : > "$MONITOR_READY"
  : > "$MONITOR_EVENTS"
  : > "$MONITOR_RECEIPT"
)
chmod 600 "$MONITOR_READY" "$MONITOR_EVENTS" "$MONITOR_RECEIPT"
exec 3<>"$MONITOR_READY" 4<>"$MONITOR_EVENTS" 5<>"$MONITOR_RECEIPT"
SOURCE_MONITOR_EVIDENCE_OPEN=1
mkfifo -m 600 "$MONITOR_CONTROL"
exec 8<>"$MONITOR_CONTROL"
MONITOR_CONTROL_OPEN=1
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" monitor \
  --snapshot "$SOURCE_SNAPSHOT" \
  --ready "$MONITOR_READY" \
  --ready-fd 3 \
  --control-fd 0 \
  --events "$MONITOR_EVENTS" \
  --events-fd 4 \
  --receipt "$MONITOR_RECEIPT" \
  --receipt-fd 5 < "$MONITOR_CONTROL" 8>&- &
MONITOR_PID=$!
rm -f "$MONITOR_CONTROL"
for ((attempt = 0; attempt < 400; attempt++)); do
  [ -s "$MONITOR_READY" ] && break
  kill -0 "$MONITOR_PID" 2>/dev/null || { echo "mutation monitor exited before ready" >&2; exit 2; }
  sleep 0.05
done
[ -s "$MONITOR_READY" ] || { echo "mutation monitor did not become ready" >&2; exit 2; }

"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" inventory \
  --repository "$CONTROL_REPO" \
  --revision "$EXPECTED_REVISION" \
  --snapshot "$SOURCE_SNAPSHOT" \
  --output "$PRE_INVENTORY" 3>&- 4>&- 5>&- 8>&-
exec 13<"$PRE_INVENTORY"

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
    --locked --versioned-dirs "$VENDOR_DIR" > "$VENDOR_CONFIG" \
    3>&- 4>&- 5>&- 8>&- 13>&-
[ -s "$VENDOR_CONFIG" ] || { echo "Cargo did not emit a vendor configuration" >&2; exit 2; }
(
  set -o noclobber
  : > "$DEPENDENCY_MONITOR_READY"
  : > "$DEPENDENCY_MONITOR_EVENTS"
  : > "$DEPENDENCY_MONITOR_RECEIPT"
)
chmod 600 \
  "$DEPENDENCY_MONITOR_READY" \
  "$DEPENDENCY_MONITOR_EVENTS" \
  "$DEPENDENCY_MONITOR_RECEIPT"
exec 10<>"$DEPENDENCY_MONITOR_READY" \
  11<>"$DEPENDENCY_MONITOR_EVENTS" \
  12<>"$DEPENDENCY_MONITOR_RECEIPT"
DEPENDENCY_MONITOR_EVIDENCE_OPEN=1
mkfifo -m 600 "$DEPENDENCY_MONITOR_CONTROL"
exec 9<>"$DEPENDENCY_MONITOR_CONTROL"
DEPENDENCY_MONITOR_CONTROL_OPEN=1
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" monitor \
  --snapshot "$DEPENDENCY_ROOT" \
  --ready "$DEPENDENCY_MONITOR_READY" \
  --ready-fd 10 \
  --control-fd 0 \
  --events "$DEPENDENCY_MONITOR_EVENTS" \
  --events-fd 11 \
  --receipt "$DEPENDENCY_MONITOR_RECEIPT" \
  --receipt-fd 12 \
  < "$DEPENDENCY_MONITOR_CONTROL" 3>&- 4>&- 5>&- 8>&- 9>&- &
DEPENDENCY_MONITOR_PID=$!
rm -f "$DEPENDENCY_MONITOR_CONTROL"
for ((attempt = 0; attempt < 400; attempt++)); do
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
  --output "$DEPENDENCY_PRE_INVENTORY" \
  3>&- 4>&- 5>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&-
exec 15<"$DEPENDENCY_PRE_INVENTORY"

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
    --config "source.vendored-sources.directory='$VENDOR_DIR'" \
    3>&- 4>&- 5>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- 15>&- &
BUILD_PID=$!
(
  exec 3>&- 4>&- 5>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- 15>&-
  monitor_is_live() {
    local state
    kill -0 "$1" 2>/dev/null || return 1
    state="$(/usr/bin/ps -o stat= -p "$1" 2>/dev/null)" || return 1
    case "$state" in ''|Z*) return 1 ;; esac
  }
  while kill -0 "$BUILD_PID" 2>/dev/null; do
    if ! monitor_is_live "$MONITOR_PID" || ! monitor_is_live "$DEPENDENCY_MONITOR_PID"; then
      kill "$BUILD_PID" 2>/dev/null || true
      echo "mutation monitor lost liveness during compilation" >&2
      exit 70
    fi
    sleep 0.05
  done
) &
WATCHDOG_PID=$!
set +e
wait "$BUILD_PID"
BUILD_STATUS=$?
wait "$WATCHDOG_PID"
WATCHDOG_STATUS=$?
set -e
[ "$WATCHDOG_STATUS" -eq 0 ] || {
  echo "release build monitor watchdog failed: $WATCHDOG_STATUS" >&2
  exit 2
}
kill -0 "$MONITOR_PID" 2>/dev/null || { echo "source monitor exited during build" >&2; exit 2; }
kill -0 "$DEPENDENCY_MONITOR_PID" 2>/dev/null || {
  echo "dependency monitor exited during build" >&2
  exit 2
}
BINARY="$CARGO_TARGET_DIR/release/euf-viper"
[ -f "$BINARY" ] && [ -x "$BINARY" ] && [ ! -L "$BINARY" ] || {
  echo "release binary is missing, linked, or nonexecutable" >&2
  exit 2
}
[ "$(readlink -f -- "$BINARY")" = "$BINARY" ] || {
  echo "release binary path is not canonical" >&2
  exit 2
}
exec 7<"$BINARY"
cd "$CONTROL_REPO"
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" inventory \
  --repository "$CONTROL_REPO" \
  --revision "$EXPECTED_REVISION" \
  --snapshot "$SOURCE_SNAPSHOT" \
  --output "$POST_INVENTORY" \
  3>&- 4>&- 5>&- 7>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- 15>&-
exec 14<"$POST_INVENTORY"
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" inventory-tree \
  --root "$DEPENDENCY_ROOT" \
  --output "$DEPENDENCY_POST_INVENTORY" \
  3>&- 4>&- 5>&- 7>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- 14>&- 15>&-
exec 16<"$DEPENDENCY_POST_INVENTORY"
INVENTORY_EVIDENCE_OPEN=1
exec 9>&-
DEPENDENCY_MONITOR_CONTROL_OPEN=0
set +e
wait "$DEPENDENCY_MONITOR_PID"
DEPENDENCY_MONITOR_STATUS=$?
exec 8>&-
MONITOR_CONTROL_OPEN=0
wait "$MONITOR_PID"
MONITOR_STATUS=$?
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

(
  set -o noclobber
  : > "$BUILD_RECEIPT"
)
chmod 600 "$BUILD_RECEIPT"
exec 17<>"$BUILD_RECEIPT"
BUILD_RECEIPT_OPEN=1
"$EUF_VIPER_PYTHON" -I -B "$BUILD_GUARD" receipt \
  --revision "$EXPECTED_REVISION" \
  --pre-inventory "$PRE_INVENTORY" \
  --pre-inventory-fd 13 \
  --post-inventory "$POST_INVENTORY" \
  --post-inventory-fd 14 \
  --monitor-receipt "$MONITOR_RECEIPT" \
  --monitor-receipt-fd 5 \
  --monitor-events "$MONITOR_EVENTS" \
  --monitor-events-fd 4 \
  --dependency-pre-inventory "$DEPENDENCY_PRE_INVENTORY" \
  --dependency-pre-inventory-fd 15 \
  --dependency-post-inventory "$DEPENDENCY_POST_INVENTORY" \
  --dependency-post-inventory-fd 16 \
  --dependency-monitor-receipt "$DEPENDENCY_MONITOR_RECEIPT" \
  --dependency-monitor-receipt-fd 12 \
  --dependency-monitor-events "$DEPENDENCY_MONITOR_EVENTS" \
  --dependency-monitor-events-fd 11 \
  --binary "$BINARY" \
  --binary-fd 7 \
  --cargo-home "$CARGO_HOME" \
  --fetch-cargo-home "$FETCH_CARGO_HOME" \
  --target-dir "$CARGO_TARGET_DIR" \
  --vendor-dir "$VENDOR_DIR" \
  --output "$BUILD_RECEIPT" \
  --output-fd 17 3>&- 10>&-

cd "$CONTROL_REPO"
"$EUF_VIPER_PYTHON" -I -B "$HARNESS" prepare \
  --manifest "$MANIFEST" \
  --repository-root "$CONTROL_REPO" \
  --source-root "$SOURCE_ROOT" \
  --binary "$BINARY" \
  --binary-fd 7 \
  --preflight-source "$CONTROL_REPO/tests/fixtures/parser_parity/bool_data_mixed_sorts.smt2" \
  --contract "$CONTRACT" \
  --revision "$EXPECTED_REVISION" \
  --checkout-receipt "$CHECKOUT_RECEIPT" \
  --accepted-parity-receipt "$PARITY_RECEIPT" \
  --expected-accepted-parity-receipt-sha256 "$EXPECTED_PARITY_RECEIPT_SHA256" \
  --build-receipt "$BUILD_RECEIPT" \
  --build-receipt-fd 17 \
  --expected-checkout-receipt-sha256 "$EXPECTED_RECEIPT_SHA256" \
  --expected-contract-sha256 "$EXPECTED_CONTRACT_SHA256" \
  --expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" \
  --output-root "$CAMPAIGN_ROOT" \
  3>&- 4>&- 5>&- 10>&- 11>&- 12>&- 13>&- 14>&- 15>&- 16>&-

printf 't1_timing_campaign_root=%s\nrevision=%s\n' "$CAMPAIGN_ROOT" "$EXPECTED_REVISION"
