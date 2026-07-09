#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-single
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=00:05:00
#SBATCH --output=results/euf-viper-single-%j.out
#SBATCH --error=results/euf-viper-single-%j.err

set -uo pipefail

BINARY="${EUF_VIPER_SINGLE_BIN:?set EUF_VIPER_SINGLE_BIN}"
INPUT="${EUF_VIPER_SINGLE_INPUT:?set EUF_VIPER_SINGLE_INPUT}"
TIMEOUT="${EUF_VIPER_SINGLE_TIMEOUT:-120}"

/usr/bin/time -v timeout --signal=KILL "${TIMEOUT}s" "$BINARY" solve "$INPUT"
status=$?
printf 'solver_exit=%s\n' "$status"
exit 0
