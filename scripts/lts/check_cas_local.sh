#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="/opt/magma/V2.28-3:$PATH"

if command -v sage >/dev/null 2>&1; then
  sage artifacts/sage/euf_quotient.sage
else
  echo "skip sage: not found"
fi

if command -v Singular >/dev/null 2>&1; then
  Singular -q artifacts/singular/euf_quotient.sing
elif command -v singular >/dev/null 2>&1; then
  singular -q artifacts/singular/euf_quotient.sing
else
  echo "skip singular: not found"
fi

if command -v julia >/dev/null 2>&1; then
  julia --project=@. artifacts/oscar/euf_quotient.jl
else
  echo "skip julia/oscar: not found"
fi

if command -v magma >/dev/null 2>&1; then
  magma -n artifacts/magma/euf_quotient.m
else
  echo "skip magma: not found"
fi
