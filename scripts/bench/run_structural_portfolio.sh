#!/usr/bin/env bash
set -euo pipefail

EUF_VIPER_BIN="${EUF_VIPER_BIN:?set EUF_VIPER_BIN}"
YICES_BIN="${YICES_BIN:?set YICES_BIN}"
if [ "${1:-}" = "solve" ]; then
  shift
fi
exec "$EUF_VIPER_BIN" portfolio --yices "$YICES_BIN" "$@"
