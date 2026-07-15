#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CI_ROOT="${T1_CI_ROOT:?set T1_CI_ROOT to a fresh hosted-Linux directory}"
REVISION="$(git -C "$ROOT" rev-parse --verify HEAD^{commit})"
SOURCE="$CI_ROOT/source"
export CARGO_HOME="$CI_ROOT/cargo-home"
export CARGO_TARGET_DIR="$CI_ROOT/target"
FETCH_CARGO_HOME="$CI_ROOT/fetch-cargo-home"
BUILD_HOME="$CI_ROOT/build-home"
DEPENDENCY_ROOT="$CI_ROOT/dependencies"
VENDOR_DIR="$DEPENDENCY_ROOT/vendor"
VENDOR_CONFIG="$DEPENDENCY_ROOT/cargo-vendor-config.toml"
GUARD="$SOURCE/scripts/wmi/t1_timing_build_guard.py"
HARNESS="$SOURCE/scripts/bench/typed_parser_timing.py"
PRE="$CI_ROOT/pre-build-inventory.json"
POST="$CI_ROOT/post-build-inventory.json"
READY="$CI_ROOT/mutation-monitor-ready.json"
CONTROL="$CI_ROOT/.mutation-monitor-control.$$"
EVENTS="$CI_ROOT/mutation-events.jsonl"
MONITOR_RECEIPT="$CI_ROOT/mutation-monitor-receipt.json"
BUILD_RECEIPT="$CI_ROOT/build-receipt.json"
DEPENDENCY_PRE="$CI_ROOT/pre-build-dependency-inventory.json"
DEPENDENCY_POST="$CI_ROOT/post-build-dependency-inventory.json"
DEPENDENCY_READY="$CI_ROOT/dependency-mutation-monitor-ready.json"
DEPENDENCY_CONTROL="$CI_ROOT/.dependency-mutation-monitor-control.$$"
DEPENDENCY_EVENTS="$CI_ROOT/dependency-mutation-events.jsonl"
DEPENDENCY_MONITOR_RECEIPT="$CI_ROOT/dependency-mutation-monitor-receipt.json"

[ "$(uname -s)" = Linux ] || { echo "T1 release integration requires Linux" >&2; exit 2; }
[ ! -e "$CI_ROOT" ] || { echo "T1 CI root must be fresh: $CI_ROOT" >&2; exit 2; }
umask 077
mkdir -m 700 -p \
  "$CI_ROOT" "$SOURCE" "$CARGO_HOME" "$CARGO_TARGET_DIR" \
  "$FETCH_CARGO_HOME" "$BUILD_HOME" "$DEPENDENCY_ROOT"
env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  git -C "$ROOT" archive --format=tar "$REVISION" | \
  env -i PATH=/usr/bin:/bin /usr/bin/tar -xf - -C "$SOURCE"
[ ! -e /.cargo/config ] && [ ! -e /.cargo/config.toml ] || {
  echo "root Cargo configuration can influence the guarded build" >&2
  exit 2
}

tool_identity() {
  local name="$1"
  local requested="$2"
  local upper path digest output version
  upper="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
  path="$(readlink -f -- "$requested")"
  [ -f "$path" ] && [ -x "$path" ] && [ ! -L "$path" ]
  digest="$(sha256sum "$path" | awk '{print $1}')"
  output="$("$path" --version 2>&1)"
  version="${output%%$'\n'*}"
  printf -v "EUF_VIPER_${upper}" '%s' "$path"
  printf -v "EUF_VIPER_${upper}_SHA256" '%s' "$digest"
  printf -v "EUF_VIPER_${upper}_VERSION" '%s' "$version"
  export "EUF_VIPER_${upper}" "EUF_VIPER_${upper}_SHA256" "EUF_VIPER_${upper}_VERSION"
}

tool_identity python "$(command -v python3)"
tool_identity cargo "$(rustup which cargo)"
tool_identity rustc "$(rustup which rustc)"
tool_identity cc /usr/bin/cc
tool_identity ld /usr/bin/ld
tool_identity ar /usr/bin/ar

exec 18<"$GUARD" 19<"$HARNESS" 20<"$EUF_VIPER_PYTHON"
[ "$(git -C "$ROOT" hash-object --no-filters -- /proc/self/fd/18)" = \
  "$(git -C "$ROOT" rev-parse "$REVISION:scripts/wmi/t1_timing_build_guard.py")" ] || {
  echo "opened hosted build guard differs from the immutable revision" >&2
  exit 2
}
[ "$(git -C "$ROOT" hash-object --no-filters -- /proc/self/fd/19)" = \
  "$(git -C "$ROOT" rev-parse "$REVISION:scripts/bench/typed_parser_timing.py")" ] || {
  echo "opened hosted timing harness differs from the immutable revision" >&2
  exit 2
}
[ "$(sha256sum /proc/self/fd/20 | awk '{print $1}')" = "$EUF_VIPER_PYTHON_SHA256" ] || {
  echo "opened hosted Python descriptor hash mismatch" >&2
  exit 2
}
GUARD_EXEC=/proc/self/fd/18
HARNESS_EXEC=/proc/self/fd/19
PYTHON_EXEC=/proc/self/fd/20

MONITOR_PID=""
DEPENDENCY_MONITOR_PID=""
MONITOR_CONTROL_OPEN=0
DEPENDENCY_MONITOR_CONTROL_OPEN=0
SOURCE_MONITOR_EVIDENCE_OPEN=0
DEPENDENCY_MONITOR_EVIDENCE_OPEN=0
INVENTORY_EVIDENCE_OPEN=0
BUILD_RECEIPT_OPEN=0
EXECUTION_DESCRIPTORS_OPEN=1
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
  if [ "$EXECUTION_DESCRIPTORS_OPEN" -eq 1 ]; then
    exec 18<&- 19<&- 20<&-
  fi
  rm -f "$CONTROL" "$DEPENDENCY_CONTROL"
  exit "$status"
}
trap stop_monitor EXIT HUP INT TERM
(
  set -o noclobber
  : > "$READY"
  : > "$EVENTS"
  : > "$MONITOR_RECEIPT"
)
chmod 600 "$READY" "$EVENTS" "$MONITOR_RECEIPT"
exec 3<>"$READY" 4<>"$EVENTS" 5<>"$MONITOR_RECEIPT"
SOURCE_MONITOR_EVIDENCE_OPEN=1
mkfifo -m 600 "$CONTROL"
exec 8<>"$CONTROL"
MONITOR_CONTROL_OPEN=1
"$PYTHON_EXEC" -I -B "$GUARD_EXEC" monitor \
  --snapshot "$SOURCE" --ready "$READY" --ready-fd 3 --control-fd 0 \
  --events "$EVENTS" --events-fd 4 \
  --receipt "$MONITOR_RECEIPT" --receipt-fd 5 < "$CONTROL" 8>&- &
MONITOR_PID=$!
rm -f "$CONTROL"
READY_VALID=0
for ((attempt = 0; attempt < 400; attempt++)); do
  if [ -s "$READY" ] && \
    "$PYTHON_EXEC" -I -B "$GUARD_EXEC" verify-ready \
      --ready "$READY" --ready-fd 3 --expected-snapshot "$SOURCE" \
      --expected-monitor-pid "$MONITOR_PID" --expected-parent-pid "$$" \
      >/dev/null 2>&1; then
    READY_VALID=1
    break
  fi
  kill -0 "$MONITOR_PID" 2>/dev/null || { echo "mutation monitor exited before ready" >&2; exit 2; }
  sleep 0.05
done
[ "$READY_VALID" -eq 1 ] || { echo "mutation monitor did not publish valid readiness" >&2; exit 2; }

"$PYTHON_EXEC" -I -B "$GUARD_EXEC" inventory \
  --repository "$ROOT" --revision "$REVISION" --snapshot "$SOURCE" --output "$PRE" \
  3>&- 4>&- 5>&- 8>&-
exec 13<"$PRE"
cd /
env -i \
  HOME="$BUILD_HOME" PATH=/usr/bin:/bin \
  CARGO_HOME="$FETCH_CARGO_HOME" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  RUSTC="$EUF_VIPER_RUSTC" CC="$EUF_VIPER_CC" LD="$EUF_VIPER_LD" AR="$EUF_VIPER_AR" \
  "$EUF_VIPER_CARGO" vendor \
    --manifest-path "$SOURCE/Cargo.toml" \
    --locked --versioned-dirs "$VENDOR_DIR" > "$VENDOR_CONFIG" \
    3>&- 4>&- 5>&- 8>&- 13>&- 18>&- 19>&- 20>&-
[ -s "$VENDOR_CONFIG" ] || { echo "Cargo did not emit a vendor configuration" >&2; exit 2; }
(
  set -o noclobber
  : > "$DEPENDENCY_READY"
  : > "$DEPENDENCY_EVENTS"
  : > "$DEPENDENCY_MONITOR_RECEIPT"
)
chmod 600 "$DEPENDENCY_READY" "$DEPENDENCY_EVENTS" "$DEPENDENCY_MONITOR_RECEIPT"
exec 10<>"$DEPENDENCY_READY" 11<>"$DEPENDENCY_EVENTS" \
  12<>"$DEPENDENCY_MONITOR_RECEIPT"
DEPENDENCY_MONITOR_EVIDENCE_OPEN=1
mkfifo -m 600 "$DEPENDENCY_CONTROL"
exec 9<>"$DEPENDENCY_CONTROL"
DEPENDENCY_MONITOR_CONTROL_OPEN=1
"$PYTHON_EXEC" -I -B "$GUARD_EXEC" monitor \
  --snapshot "$DEPENDENCY_ROOT" --ready "$DEPENDENCY_READY" --ready-fd 10 \
  --control-fd 0 --events "$DEPENDENCY_EVENTS" --events-fd 11 \
  --receipt "$DEPENDENCY_MONITOR_RECEIPT" --receipt-fd 12 \
  < "$DEPENDENCY_CONTROL" 3>&- 4>&- 5>&- 8>&- 9>&- &
DEPENDENCY_MONITOR_PID=$!
rm -f "$DEPENDENCY_CONTROL"
DEPENDENCY_READY_VALID=0
for ((attempt = 0; attempt < 400; attempt++)); do
  if [ -s "$DEPENDENCY_READY" ] && \
    "$PYTHON_EXEC" -I -B "$GUARD_EXEC" verify-ready \
      --ready "$DEPENDENCY_READY" --ready-fd 10 \
      --expected-snapshot "$DEPENDENCY_ROOT" \
      --expected-monitor-pid "$DEPENDENCY_MONITOR_PID" --expected-parent-pid "$$" \
      >/dev/null 2>&1; then
    DEPENDENCY_READY_VALID=1
    break
  fi
  kill -0 "$DEPENDENCY_MONITOR_PID" 2>/dev/null || {
    echo "dependency mutation monitor exited before ready" >&2
    exit 2
  }
  sleep 0.05
done
[ "$DEPENDENCY_READY_VALID" -eq 1 ] || {
  echo "dependency mutation monitor did not publish valid readiness" >&2
  exit 2
}
"$PYTHON_EXEC" -I -B "$GUARD_EXEC" inventory-tree \
  --root "$DEPENDENCY_ROOT" --output "$DEPENDENCY_PRE" \
  3>&- 4>&- 5>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&-
exec 15<"$DEPENDENCY_PRE"
env -i \
  HOME="$BUILD_HOME" PATH=/usr/bin:/bin \
  CARGO_HOME="$CARGO_HOME" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  RUSTC="$EUF_VIPER_RUSTC" CC="$EUF_VIPER_CC" LD="$EUF_VIPER_LD" AR="$EUF_VIPER_AR" \
  RUSTFLAGS="-C linker=$EUF_VIPER_CC -C link-arg=-fuse-ld=bfd -C target-feature=+crt-static" \
  "$EUF_VIPER_CARGO" build \
    --manifest-path "$SOURCE/Cargo.toml" \
    --release --locked --offline \
    --config "source.crates-io.replace-with='vendored-sources'" \
    --config "source.vendored-sources.directory='$VENDOR_DIR'" \
    3>&- 4>&- 5>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- 15>&- \
    18>&- 19>&- 20>&- &
BUILD_PID=$!
(
  exec 3>&- 4>&- 5>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- 15>&- 18>&- 19>&- 20>&-
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
[ "$BUILD_STATUS" -eq 0 ] || { echo "hosted locked release build failed: $BUILD_STATUS" >&2; exit "$BUILD_STATUS"; }
[ "$WATCHDOG_STATUS" -eq 0 ] || { echo "hosted monitor watchdog failed" >&2; exit 2; }
kill -0 "$MONITOR_PID" 2>/dev/null || { echo "source monitor exited during build" >&2; exit 2; }
kill -0 "$DEPENDENCY_MONITOR_PID" 2>/dev/null || {
  echo "dependency monitor exited during build" >&2
  exit 2
}
BINARY="$CARGO_TARGET_DIR/release/euf-viper"
[ -f "$BINARY" ] && [ -x "$BINARY" ] && [ ! -L "$BINARY" ] || {
  echo "hosted release binary is missing, linked, or nonexecutable" >&2
  exit 2
}
[ "$(readlink -f -- "$BINARY")" = "$BINARY" ] || {
  echo "hosted release binary path is not canonical" >&2
  exit 2
}
exec 7<"$BINARY"
cd "$ROOT"
"$PYTHON_EXEC" -I -B "$GUARD_EXEC" inventory \
  --repository "$ROOT" --revision "$REVISION" --snapshot "$SOURCE" --output "$POST" \
  3>&- 4>&- 5>&- 7>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- 15>&-
exec 14<"$POST"
"$PYTHON_EXEC" -I -B "$GUARD_EXEC" inventory-tree \
  --root "$DEPENDENCY_ROOT" --output "$DEPENDENCY_POST" \
  3>&- 4>&- 5>&- 7>&- 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- 14>&- 15>&-
exec 16<"$DEPENDENCY_POST"
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
[ "$MONITOR_STATUS" -eq 0 ] || { echo "mutation monitor rejected hosted build" >&2; exit "$MONITOR_STATUS"; }
[ "$DEPENDENCY_MONITOR_STATUS" -eq 0 ] || {
  echo "dependency mutation monitor rejected hosted build" >&2
  exit "$DEPENDENCY_MONITOR_STATUS"
}

(
  set -o noclobber
  : > "$BUILD_RECEIPT"
)
chmod 600 "$BUILD_RECEIPT"
exec 17<>"$BUILD_RECEIPT"
BUILD_RECEIPT_OPEN=1
"$PYTHON_EXEC" -I -B "$GUARD_EXEC" receipt \
  --revision "$REVISION" --pre-inventory "$PRE" --post-inventory "$POST" \
  --pre-inventory-fd 13 --post-inventory-fd 14 \
  --monitor-receipt "$MONITOR_RECEIPT" --monitor-receipt-fd 5 \
  --monitor-ready "$READY" --monitor-ready-fd 3 \
  --monitor-events "$EVENTS" --monitor-events-fd 4 \
  --dependency-pre-inventory "$DEPENDENCY_PRE" --dependency-pre-inventory-fd 15 \
  --dependency-post-inventory "$DEPENDENCY_POST" --dependency-post-inventory-fd 16 \
  --dependency-monitor-receipt "$DEPENDENCY_MONITOR_RECEIPT" \
  --dependency-monitor-receipt-fd 12 \
  --dependency-monitor-ready "$DEPENDENCY_READY" \
  --dependency-monitor-ready-fd 10 \
  --dependency-monitor-events "$DEPENDENCY_EVENTS" \
  --dependency-monitor-events-fd 11 \
  --binary "$BINARY" --binary-fd 7 --cargo-home "$CARGO_HOME" \
  --fetch-cargo-home "$FETCH_CARGO_HOME" --target-dir "$CARGO_TARGET_DIR" \
  --vendor-dir "$VENDOR_DIR" --output "$BUILD_RECEIPT" --output-fd 17
"$PYTHON_EXEC" -I -B "$HARNESS_EXEC" \
  verify-build-receipt --build-receipt "$BUILD_RECEIPT" --build-receipt-fd 17 \
  --binary "$BINARY" --binary-fd 7 --revision "$REVISION" >/dev/null \
  3>&- 4>&- 5>&- 10>&- 11>&- 12>&- 13>&- 14>&- 15>&- 16>&-

cd "$SOURCE"
EUF_VIPER_T1_REAL_BINARY="$BINARY" EUF_VIPER_T1_REAL_BINARY_FD=7 \
  "$PYTHON_EXEC" -I -B -m unittest \
  tests.test_typed_parser_timing.RealReleaseIntegrationTests \
  3>&- 4>&- 5>&- 10>&- 11>&- 12>&- 13>&- 14>&- 15>&- 16>&- 17>&-

exec 18<&- 19<&- 20<&-
EXECUTION_DESCRIPTORS_OPEN=0
