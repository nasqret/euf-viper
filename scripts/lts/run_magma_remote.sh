#!/usr/bin/env bash
set -euo pipefail

HOST="${EUF_VIPER_LTS_HOST:-bnaskrecki@lts-faculty.wmi.amu.edu.pl}"
REMOTE_DIR="${EUF_VIPER_LTS_DIR:-/tmp/${USER:-bnaskrecki}/euf-viper-cas}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

ssh "$HOST" "mkdir -p $REMOTE_DIR/artifacts/magma"
rsync -az "$ROOT/artifacts/magma/euf_quotient.m" "$HOST:$REMOTE_DIR/artifacts/magma/euf_quotient.m"
ssh "$HOST" "export PATH=/opt/magma/V2.28-3:\$PATH; cd $REMOTE_DIR && magma -n artifacts/magma/euf_quotient.m"
