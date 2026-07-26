#!/bin/bash -l
#SBATCH --job-name=euf-viper-audit
#SBATCH --account=plgccaiautore2026-cpu
#SBATCH --partition=plgrid
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --hint=nomultithread
#SBATCH --mem=10G
#SBATCH --time=02:00:00

set -euo pipefail

ORCHESTRATION_CHECKOUT="${EUF_VIPER_HELIOS_ORCHESTRATION_CHECKOUT:?set orchestration checkout}"
module --force purge
module load GCCcore/14.3.0 Rust/1.88.0
export LANG=C LC_ALL=C TZ=UTC PYTHONDONTWRITEBYTECODE=1

srun \
  --nodes=1 \
  --ntasks=1 \
  --cpus-per-task=1 \
  --cpu-bind=cores \
  --exclusive \
  /bin/bash -l "$ORCHESTRATION_CHECKOUT/scripts/helios/run_campaign_finalize.sh"
