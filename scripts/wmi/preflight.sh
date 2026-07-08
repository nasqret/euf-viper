#!/usr/bin/env bash
set -euo pipefail

SKILL_DIR="${CODEX_HOME:-$HOME/.codex}/skills/wmi-alphageometry-slurm"
bash "$SKILL_DIR/scripts/cluster_status.sh" --full
ssh wmicluster 'export PATH="$HOME/.cargo/bin:$PATH"; printf "remote=%s\n" "$(hostname)"; command -v cargo || true; command -v rustc || true; command -v z3 || true; squeue -u "$USER" -o "%.18i %.9T %.24j %.10M %.10l %.30R"'
