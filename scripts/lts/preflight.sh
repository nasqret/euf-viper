#!/usr/bin/env bash
set -euo pipefail

HOST="${EUF_VIPER_LTS_HOST:-bnaskrecki@lts-faculty.wmi.amu.edu.pl}"
ssh "$HOST" 'export PATH="/opt/magma/V2.28-3:$HOME/.cargo/bin:$PATH"; printf "host=%s\n" "$(hostname)"; for t in magma sage Singular singular julia z3 cargo rustc; do printf "%-10s" "$t"; command -v "$t" || true; done'
