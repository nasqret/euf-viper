#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${EUF_VIPER_CERT_OUT:-$ROOT/results/cert-smoke}"
DRAT_TRIM="${DRAT_TRIM:-$(command -v drat-trim || true)}"

if [ -z "$DRAT_TRIM" ]; then
  echo "drat-trim is required; run scripts/cert/install_drat_trim.sh" >&2
  exit 127
fi

cd "$ROOT"
mkdir -p "$OUT"
cargo build --release --features certificates

for fixture in \
  tests/fixtures/basic_unsat.smt2 \
  tests/fixtures/eq_diamond_unsat.smt2 \
  tests/fixtures/predicate_congruence_unsat.smt2 \
  tests/fixtures/transitivity_unsat.smt2 \
  generated/synthetic/chain1000_unsat.smt2
do
  name="$(basename "$fixture" .smt2)"
  prefix="$OUT/$name"
  target/release/euf-viper certify "$fixture" --out-prefix "$prefix"
  scripts/cert/check_certificate.py "$prefix.euf.json" \
    --drat-trim "$DRAT_TRIM"
done

if target/release/euf-viper certify generated/synthetic/chain1000_sat.smt2 \
  --out-prefix "$OUT/chain1000_sat"
then
  echo "certificate generator accepted a SAT fixture" >&2
  exit 1
fi
