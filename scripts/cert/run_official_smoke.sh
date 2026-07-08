#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORPUS="${EUF_VIPER_QF_UF_CORPUS:-$ROOT/benchmarks/smtlib-2025/QF_UF/QF_UF}"
OUT="${EUF_VIPER_CERT_OUT:-$ROOT/results/cert-official-smoke}"
DRAT_TRIM="${DRAT_TRIM:-$(command -v drat-trim || true)}"

if [ -z "$DRAT_TRIM" ]; then
  echo "drat-trim is required; run scripts/cert/install_drat_trim.sh" >&2
  exit 127
fi

verify() {
  local name="$1"
  local source="$2"
  local prefix="$OUT/$name"
  if [ ! -f "$source" ]; then
    echo "missing official corpus input: $source" >&2
    exit 1
  fi
  "$ROOT/target/release/euf-viper" certify "$source" --out-prefix "$prefix"
  "$ROOT/scripts/cert/check_certificate.py" "$prefix.euf.json" \
    --drat-trim "$DRAT_TRIM"
}

cd "$ROOT"
mkdir -p "$OUT"
cargo build --release --features certificates
verify \
  rodin-3166111930664231918 \
  "$CORPUS/20170829-Rodin/smt3166111930664231918.smt2"
verify \
  typesafe-z3-1184163 \
  "$CORPUS/TypeSafe/z3.1184163.smt2"
