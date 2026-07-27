#!/bin/bash -l
#SBATCH --job-name=euf-viper-qg7-stage
#SBATCH --account=plgccaiautore2026-cpu
#SBATCH --partition=plgrid
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --hint=nomultithread
#SBATCH --mem=4G
#SBATCH --time=00:20:00

set -euo pipefail

EXPERIMENT_ROOT="${EUF_VIPER_MATRIX_ROOT:?set matrix root}"
TASK_SCRIPT="$EXPERIMENT_ROOT/run_staged_qg7_matrix_task.sh"

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || die "requires exactly one CPU per task"
[[ "${SLURM_ARRAY_TASK_ID:-}" =~ ^[0-9]+$ ]] || die "requires an array task ID"
[ -f "$TASK_SCRIPT" ] && [ ! -L "$TASK_SCRIPT" ] || die "matrix task script is missing"

module --force purge
module load GCCcore/14.3.0 Rust/1.88.0
export LANG=C
export LC_ALL=C
export TZ=UTC
export PYTHONDONTWRITEBYTECODE=1

srun \
  --nodes=1 \
  --ntasks=1 \
  --cpus-per-task=1 \
  --cpu-bind=cores \
  --exclusive \
  /bin/bash -l "$TASK_SCRIPT"
