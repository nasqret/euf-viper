#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
if ! command -v jupyter-book >/dev/null 2>&1; then
  echo "jupyter-book not found; skipping HTML build" >&2
  exit 0
fi
jupyter-book build . -W -n --all
