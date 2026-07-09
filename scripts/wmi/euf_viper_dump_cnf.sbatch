#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-dump-cnf
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=00:15:00
#SBATCH --output=results/euf-viper-dump-cnf-%j.out
#SBATCH --error=results/euf-viper-dump-cnf-%j.err

set -euo pipefail

ROOT="${SLURM_SUBMIT_DIR:-$PWD}"
BINARY="${EUF_VIPER_DUMP_BIN:?set EUF_VIPER_DUMP_BIN}"
INPUT="${EUF_VIPER_DUMP_INPUT:?set EUF_VIPER_DUMP_INPUT}"
OUTPUT="${EUF_VIPER_DUMP_OUTPUT:?set EUF_VIPER_DUMP_OUTPUT}"

"$BINARY" dump-eager-cnf "$INPUT" --out "$OUTPUT"
sha256sum "$OUTPUT"
