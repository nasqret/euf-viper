#!/usr/bin/env bash
set -euo pipefail

YICES_BIN="${YICES_BIN:?set YICES_BIN}"
if [ "${1:-}" = "solve" ]; then
  shift
fi
exec "$YICES_BIN" "$@"
