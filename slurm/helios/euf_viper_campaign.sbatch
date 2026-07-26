#!/bin/bash -l
#SBATCH --job-name=euf-viper-cpu
#SBATCH --account=plgccaiautore2026-cpu
#SBATCH --partition=plgrid
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --hint=nomultithread
#SBATCH --mem=10G
#SBATCH --time=06:00:00

set -euo pipefail

ORCHESTRATION_CHECKOUT="${EUF_VIPER_HELIOS_ORCHESTRATION_CHECKOUT:?set orchestration checkout}"
SOLVER_CHECKOUT="${EUF_VIPER_HELIOS_SOLVER_CHECKOUT:?set solver checkout}"
RUN_ROOT="${EUF_VIPER_HELIOS_RUN_ROOT:?set run root}"
RUN_ID="${EUF_VIPER_HELIOS_RUN_ID:?set run ID}"
EXPECTED_ORCHESTRATION_REVISION="${EUF_VIPER_HELIOS_ORCHESTRATION_REVISION:?set orchestration revision}"
EXPECTED_SOLVER_REVISION="${EUF_VIPER_HELIOS_SOLVER_REVISION:?set solver revision}"
EXPECTED_ACCOUNT="${EUF_VIPER_HELIOS_ACCOUNT:-plgccaiautore2026-cpu}"
EXPECTED_PARTITION="${EUF_VIPER_HELIOS_PARTITION:-plgrid}"
EXPECTED_TOOLCHAIN_SHA256="${EUF_VIPER_HELIOS_TOOLCHAIN_SHA256:?set toolchain hash}"
EXPECTED_ARGV_SHA256="${EUF_VIPER_HELIOS_CANDIDATE_ARGV_SHA256:?set candidate argv hash}"
EXPECTED_COMPARATOR_BUNDLE_RECEIPT_SHA256="${EUF_VIPER_HELIOS_COMPARATOR_BUNDLE_RECEIPT_SHA256:?set comparator bundle hash}"

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

hash_or_dash() {
  if [ -f "$1" ]; then
    sha256sum "$1" | awk '{print $1}'
  else
    printf '%s' '-'
  fi
}

field_or_dash() {
  local path="$1"
  local key="$2"
  local value
  if [ -f "$path" ]; then
    value="$(awk -F '\t' -v key="$key" '$1 == key {print $2}' "$path")"
    printf '%s' "${value:--}"
  else
    printf '%s' '-'
  fi
}

tool_hash_or_dash() {
  local path="$1"
  local name="$2"
  local value
  if [ -f "$path" ]; then
    value="$(awk -F '\t' -v name="$name" '$2 == name {print $4}' "$path")"
    printf '%s' "${value:--}"
  else
    printf '%s' '-'
  fi
}

write_receipt() {
  local task_status="$1"
  local status=failed
  local finished_at toolchain cpu_model candidate_sha256 solver_config_sha256
  local taxonomy_sha256 taxonomy_split_sha256 promotion_eligible
  local rust_module_sha256 gcc_module_sha256 cargo_sha256 rustc_sha256
  local python_sha256 resource_wrapper_sha256 receipt temporary_receipt
  local -a header values

  [ "$task_status" -eq 0 ] && status=complete
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  toolchain="$RUN_ROOT/toolchain.tsv"
  rust_module_sha256="$(tool_hash_or_dash "$toolchain" Rust/1.88.0)"
  gcc_module_sha256="$(tool_hash_or_dash "$toolchain" GCCcore/14.3.0)"
  cargo_sha256="$(tool_hash_or_dash "$toolchain" cargo)"
  rustc_sha256="$(tool_hash_or_dash "$toolchain" rustc)"
  python_sha256="$(tool_hash_or_dash "$toolchain" python3)"
  resource_wrapper_sha256="$(hash_or_dash "$ORCHESTRATION_CHECKOUT/scripts/helios/run_with_resources.py")"
  cpu_model="$(field_or_dash "$RUN_ROOT/compute.tsv" cpu_model)"
  candidate_sha256="$(field_or_dash "$RUN_ROOT/preparation.tsv" candidate_binary_sha256)"
  solver_config_sha256="$(field_or_dash "$RUN_ROOT/preparation.tsv" solver_config_sha256)"
  taxonomy_sha256="$(field_or_dash "$RUN_ROOT/preparation.tsv" taxonomy_sha256)"
  taxonomy_split_sha256="$(field_or_dash "$RUN_ROOT/preparation.tsv" taxonomy_split_sha256)"
  promotion_eligible="$(field_or_dash "$RUN_ROOT/preparation.tsv" promotion_eligible)"

  header=(
    schema_version status job_id run_id
    orchestration_revision solver_revision orchestration_checkout solver_checkout
    account partition cpu_model cpus_per_task cpu_bind started_at finished_at
    task_exit_code toolchain_sha256 rust_module_sha256 gcc_module_sha256
    cargo_sha256 rustc_sha256 python_sha256 resource_wrapper_sha256
    comparator_bundle_receipt_sha256 corpus_inventory_sha256 manifest_sha256 taxonomy_sha256
    taxonomy_split_sha256 promotion_eligible candidate_argv_json
    candidate_argv_sha256 candidate_binary_sha256 solver_config_sha256
    resource_capture_sha256
  )
  values=(
    1 "$status" "$SLURM_JOB_ID" "$RUN_ID"
    "$EXPECTED_ORCHESTRATION_REVISION" "$EXPECTED_SOLVER_REVISION"
    "$ORCHESTRATION_CHECKOUT" "$SOLVER_CHECKOUT"
    "$EXPECTED_ACCOUNT" "$EXPECTED_PARTITION" "$cpu_model" 1 cores
    "$STARTED_AT" "$finished_at" "$task_status"
    "$EXPECTED_TOOLCHAIN_SHA256" "$rust_module_sha256" "$gcc_module_sha256"
    "$cargo_sha256" "$rustc_sha256" "$python_sha256" "$resource_wrapper_sha256"
    "$EXPECTED_COMPARATOR_BUNDLE_RECEIPT_SHA256"
    "$EUF_VIPER_HELIOS_CORPUS_INVENTORY_SHA256"
    "$EUF_VIPER_HELIOS_MANIFEST_SHA256" "$taxonomy_sha256"
    "$taxonomy_split_sha256" "$promotion_eligible"
    '["{binary}","fabric-solve","--engine","quotient-portfolio","{instance}"]'
    "$EXPECTED_ARGV_SHA256" "$candidate_sha256" "$solver_config_sha256"
    "$(hash_or_dash "$RUN_ROOT/resource-usage.json")"
  )
  [ "${#header[@]}" -eq "${#values[@]}" ] || die "receipt field count drifted"

  receipt="$RUN_ROOT/receipt.tsv"
  temporary_receipt="$RUN_ROOT/.receipt.tsv.${SLURM_JOB_ID}"
  test ! -e "$receipt"
  {
    IFS=$'\t'
    printf '%s\n' "${header[*]}"
    printf '%s\n' "${values[*]}"
  } > "$temporary_receipt"
  chmod 0444 "$temporary_receipt"
  ln "$temporary_receipt" "$receipt"
  rm -f "$temporary_receipt"
}

[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || die "requires exactly one CPU per task"
[ "${SLURM_JOB_ACCOUNT:-$EXPECTED_ACCOUNT}" = "$EXPECTED_ACCOUNT" ] || \
  die "Slurm account drifted"
[ "${SLURM_JOB_PARTITION:-$EXPECTED_PARTITION}" = "$EXPECTED_PARTITION" ] || \
  die "Slurm partition drifted"
case "$RUN_ROOT" in
  /*) ;;
  *) die "run root must be absolute" ;;
esac
test ! -e "$RUN_ROOT" || die "immutable run root already exists: $RUN_ROOT"
mkdir "$RUN_ROOT"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TASK_STATUS=2
finalize() {
  local script_status="$?"
  trap - EXIT
  if [ ! -e "$RUN_ROOT/receipt.tsv" ]; then
    write_receipt "$TASK_STATUS" || true
  fi
  chmod -R a-w "$RUN_ROOT" || true
  return "$script_status"
}
trap finalize EXIT

module --force purge
module load GCCcore/14.3.0 Rust/1.88.0
export LANG=C
export LC_ALL=C
export TZ=UTC
export PYTHONDONTWRITEBYTECODE=1

set +e
srun \
  --nodes=1 \
  --ntasks=1 \
  --cpus-per-task=1 \
  --cpu-bind=cores \
  --exclusive \
  bash -l "$ORCHESTRATION_CHECKOUT/scripts/helios/run_campaign_task.sh"
TASK_STATUS="$?"
set -e
exit "$TASK_STATUS"
