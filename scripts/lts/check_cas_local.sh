#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="/opt/magma/V2.28-3:$PATH"

if command -v sage >/dev/null 2>&1; then
  SAGE_RUN_HOME="${EUF_VIPER_SAGE_HOME:-${TMPDIR:-/tmp}/euf-viper-sage-${UID:-0}}"
  mkdir -p "$SAGE_RUN_HOME"
  HOME="$SAGE_RUN_HOME" SAGE_HOME="$SAGE_RUN_HOME" \
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
  JULIA_RUN_HOME="${EUF_VIPER_JULIA_HOME:-${TMPDIR:-/tmp}/euf-viper-julia-${UID:-0}}"
  JULIA_PACKAGE_DEPOT="${EUF_VIPER_JULIA_PACKAGE_DEPOT:-$HOME/.julia}"
  JULIA_BIN="${EUF_VIPER_JULIA_BIN:-}"
  if [ -z "$JULIA_BIN" ]; then
    for candidate in \
      "$HOME"/.julia/juliaup/julia-*/Julia-*.app/Contents/Resources/julia/bin/julia
    do
      if [ -x "$candidate" ]; then
        JULIA_BIN="$candidate"
      fi
    done
  fi
  if [ -z "$JULIA_BIN" ]; then
    JULIA_BIN="$(command -v julia)"
  fi
  mkdir -p "$JULIA_RUN_HOME/depot"
  HOME="$JULIA_RUN_HOME" \
    JULIA_DEPOT_PATH="$JULIA_RUN_HOME/depot:$JULIA_PACKAGE_DEPOT" \
    "$JULIA_BIN" --project=@. artifacts/oscar/euf_quotient.jl
else
  echo "skip julia/oscar: not found"
fi

if command -v magma >/dev/null 2>&1; then
  magma -n artifacts/magma/euf_quotient.m
else
  echo "skip magma: not found"
fi
