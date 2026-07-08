#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="${1:-$ROOT/benchmarks/smtlib-2025}"
ARCHIVE="$DEST/QF_UF.tar.zst"
EXTRACT_DIR="$DEST/QF_UF"
URL="https://zenodo.org/api/records/16740866/files/QF_UF.tar.zst/content"
MD5_EXPECTED="e185bc80a80116bcfea116df190f87d2"

mkdir -p "$DEST"

if [ ! -f "$ARCHIVE" ]; then
  echo "download $URL"
  curl -L --fail --retry 3 --output "$ARCHIVE" "$URL"
fi

if command -v md5sum >/dev/null 2>&1; then
  MD5_ACTUAL="$(md5sum "$ARCHIVE" | awk '{print $1}')"
else
  MD5_ACTUAL="$(md5 -q "$ARCHIVE")"
fi

if [ "$MD5_ACTUAL" != "$MD5_EXPECTED" ]; then
  echo "checksum mismatch for $ARCHIVE" >&2
  echo "expected $MD5_EXPECTED" >&2
  echo "actual   $MD5_ACTUAL" >&2
  exit 1
fi

mkdir -p "$EXTRACT_DIR"
if ! find "$EXTRACT_DIR" -type f -name '*.smt2' -print -quit | grep -q .; then
  TMP_EXTRACT="$DEST/.extract-QF_UF"
  rm -rf "$TMP_EXTRACT"
  mkdir -p "$TMP_EXTRACT"
  zstd -dc "$ARCHIVE" | tar -xf - -C "$TMP_EXTRACT"
  FIRST_DIR="$(find "$TMP_EXTRACT" -mindepth 1 -maxdepth 1 -type d | head -1)"
  if [ -n "$FIRST_DIR" ]; then
    cp -R "$FIRST_DIR"/. "$EXTRACT_DIR"/
  else
    cp -R "$TMP_EXTRACT"/. "$EXTRACT_DIR"/
  fi
  rm -rf "$TMP_EXTRACT"
fi

python3 "$ROOT/scripts/bench/make_manifest.py" "$EXTRACT_DIR" \
  --logic QF_UF \
  --source-doi 10.5281/zenodo.16740866 \
  --source-url "$URL" \
  --archive-md5 "$MD5_EXPECTED" \
  --out "$DEST/qf_uf_manifest.jsonl"

echo "$DEST/qf_uf_manifest.jsonl"
