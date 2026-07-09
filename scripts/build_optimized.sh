#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
case "$HOST" in
  x86_64-*) DEFAULT_TARGET_CPU="x86-64-v3" ;;
  *) DEFAULT_TARGET_CPU="native" ;;
esac
TARGET_CPU="${EUF_VIPER_TARGET_CPU:-$DEFAULT_TARGET_CPU}"
export RUSTFLAGS="${EUF_VIPER_RUSTFLAGS:--C target-cpu=$TARGET_CPU}"

cd "$ROOT"
printf 'host=%s\n' "$HOST"
printf 'target_cpu=%s\n' "$TARGET_CPU"
printf 'rustflags=%s\n' "$RUSTFLAGS"
rustc -Vv
cargo build --locked --release

BINARY="$ROOT/target/release/euf-viper"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$BINARY"
else
  shasum -a 256 "$BINARY"
fi
