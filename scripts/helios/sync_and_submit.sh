#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSH_TARGET="${EUF_VIPER_HELIOS_SSH_TARGET:-helios}"
ACCOUNT="${EUF_VIPER_HELIOS_ACCOUNT:-plgccaiautore2026-cpu}"
PARTITION="${EUF_VIPER_HELIOS_PARTITION:-plgrid}"
CORPUS_SOURCE="${EUF_VIPER_HELIOS_CORPUS_SOURCE:-/Users/airbartek/codex/z3/benchmarks}"
SPEC_RELATIVE="${EUF_VIPER_HELIOS_SPEC_RELATIVE:-campaigns/best-overall-qf-uf-2026-07.json}"
INSTANCE_ROOT_RELATIVE="${EUF_VIPER_HELIOS_INSTANCE_ROOT_RELATIVE:-smtlib-2025/QF_UF}"
MANIFEST_RELATIVE=""
RUN_ID="${EUF_VIPER_HELIOS_RUN_ID:-}"
BUDGET="${EUF_VIPER_HELIOS_BUDGET:-2}"
WALL_TIME="${EUF_VIPER_HELIOS_WALL_TIME:-06:00:00}"
MEMORY="${EUF_VIPER_HELIOS_MEMORY:-10G}"
MEMORY_BYTES="${EUF_VIPER_HELIOS_MEMORY_BYTES:-8589934592}"
MODE=test-only
SOLVER_REVISION=8368d21de96eec77f3bb5f6820c11d1363d3041b

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'USAGE'
usage: sync_and_submit.sh --manifest RELATIVE [--submit] [options]

Options:
  --test-only             validate with sbatch --test-only (default)
  --submit                test first, then submit one real CPU job
  --run-id ID             immutable run identifier
  --budget SECONDS        frozen campaign budget: 2, 60, or 1200
  --wall-time HH:MM:SS    Slurm wall time
  --memory SIZE           Slurm memory request, for example 10G
  --instance-root PATH    corpus-relative instance root

The command refuses a dirty local repository, stages the exact detached
revision with rsync, content-addresses and rebases the external corpus, pins
all compiler and solver executables, and defaults to scheduler validation.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest)
      [ "$#" -ge 2 ] || die "--manifest requires a relative path"
      MANIFEST_RELATIVE="$2"
      shift 2
      ;;
    --instance-root)
      [ "$#" -ge 2 ] || die "--instance-root requires a relative path"
      INSTANCE_ROOT_RELATIVE="$2"
      shift 2
      ;;
    --run-id)
      [ "$#" -ge 2 ] || die "--run-id requires an ID"
      [ -z "$RUN_ID" ] || die "run ID was specified twice"
      RUN_ID="$2"
      shift 2
      ;;
    --budget)
      [ "$#" -ge 2 ] || die "--budget requires seconds"
      BUDGET="$2"
      shift 2
      ;;
    --wall-time)
      [ "$#" -ge 2 ] || die "--wall-time requires HH:MM:SS"
      WALL_TIME="$2"
      shift 2
      ;;
    --memory)
      [ "$#" -ge 2 ] || die "--memory requires a size"
      MEMORY="$2"
      shift 2
      ;;
    --test-only)
      [ "$MODE" = test-only ] || die "--test-only conflicts with --submit"
      shift
      ;;
    --submit)
      [ "$MODE" = test-only ] || die "--submit was specified twice"
      MODE=submit
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[ -n "$MANIFEST_RELATIVE" ] || { usage >&2; die "--manifest is required"; }
case "$BUDGET" in
  2|60|1200) ;;
  *) die "budget must be 2, 60, or 1200 seconds" ;;
esac
[[ "$WALL_TIME" =~ ^[0-9][0-9]:[0-5][0-9]:[0-5][0-9]$ ]] || \
  die "wall time must use canonical HH:MM:SS"
[[ "$MEMORY" =~ ^[1-9][0-9]*[KMGT]$ ]] || die "memory must be a positive Slurm size"
[[ "$MEMORY_BYTES" =~ ^[1-9][0-9]*$ ]] || die "memory bytes must be positive"
for value in "$SSH_TARGET" "$ACCOUNT" "$PARTITION"; do
  [[ "$value" =~ ^[A-Za-z0-9_.@+-]+$ ]] || die "unsafe setting: $value"
done
for value in "$MANIFEST_RELATIVE" "$INSTANCE_ROOT_RELATIVE" "$SPEC_RELATIVE"; do
  [[ "$value" =~ ^[A-Za-z0-9_./+-]+$ ]] || die "unsafe relative path: $value"
  case "$value" in
    /*|*../*|../*|*/..) die "path must stay relative and canonical: $value" ;;
  esac
done
for program in git mktemp python3 rsync shasum ssh; do
  command -v "$program" >/dev/null || die "$program is required"
done

cd "$ROOT"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "repository must be completely clean before Helios sync"
ORCHESTRATION_REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
[[ "$ORCHESTRATION_REVISION" =~ ^[0-9a-f]{40}$ ]] || \
  die "HEAD is not a full lowercase revision"
[ "$(git rev-parse --verify "$SOLVER_REVISION^{commit}")" = "$SOLVER_REVISION" ] || \
  die "pinned solver revision is unavailable: $SOLVER_REVISION"
grep -Eq '^edition[[:space:]]*=[[:space:]]*"2024"[[:space:]]*$' Cargo.toml || \
  die "Cargo.toml must use edition 2024"
if [ -z "$RUN_ID" ]; then
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${ORCHESTRATION_REVISION:0:12}-8368d21"
fi
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "unsafe run ID"

TEMPORARY="$(mktemp -d "${TMPDIR:-/tmp}/euf-viper-helios.XXXXXX")"
cleanup() {
  rm -rf -- "$TEMPORARY"
}
trap cleanup EXIT HUP INT TERM

PREFLIGHT_REPORT="$TEMPORARY/preflight.tsv"
"$ROOT/scripts/helios/preflight.sh" > "$PREFLIGHT_REPORT"
REMOTE_ROOT="$(awk -F '\t' '$1 == "fact" && $2 == "remote_root" {print $3}' \
  "$PREFLIGHT_REPORT")"
TOOLCHAIN_SHA256="$(awk -F '\t' '$1 == "receipt" && $2 == "toolchain" {print $4}' \
  "$PREFLIGHT_REPORT")"
case "$REMOTE_ROOT" in
  /*) ;;
  *) die "preflight did not return an absolute remote root" ;;
esac
[[ "$TOOLCHAIN_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "invalid toolchain receipt hash"

ORCHESTRATION_CHECKOUT="$REMOTE_ROOT/orchestration-checkouts/$ORCHESTRATION_REVISION"
SOLVER_CHECKOUT="$REMOTE_ROOT/solver-checkouts/$SOLVER_REVISION"
RUN_ROOT="$REMOTE_ROOT/runs/$RUN_ID"
LOCAL_ORCHESTRATION_CHECKOUT="$TEMPORARY/orchestration-checkout"
LOCAL_SOLVER_CHECKOUT="$TEMPORARY/solver-checkout"
TOKEN="$(date -u +%Y%m%dT%H%M%SZ)-$$"

make_local_checkout() {
  local revision="$1"
  local checkout="$2"
  local profile="$3"
  git clone --quiet --filter=blob:none --no-checkout --no-local "$ROOT" "$checkout"
  git -C "$checkout" sparse-checkout init --cone
  case "$profile" in
    orchestration)
      git -C "$checkout" sparse-checkout set campaigns scripts slurm
      ;;
    solver)
      git -C "$checkout" sparse-checkout set src vendor
      ;;
    *)
      die "unknown sparse checkout profile: $profile"
      ;;
  esac
  git -C "$checkout" checkout --quiet --detach "$revision"
  [ "$(git -C "$checkout" rev-parse --verify 'HEAD^{commit}')" = "$revision" ]
  [ -z "$(git -C "$checkout" status --porcelain=v1 --untracked-files=all)" ]
}

stage_remote_checkout() {
  local local_checkout="$1"
  local checkout="$2"
  local revision="$3"
  local marker="$4"
  local incoming="$REMOTE_ROOT/incoming/checkout-$revision-$TOKEN"
  if ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "test -d '$checkout/.git'"; then
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
      "REMOTE_CHECKOUT='$checkout' EXPECTED_CHECKOUT_REVISION='$revision' MARKER='$marker' bash -l -s" <<'REMOTE'
set -euo pipefail
test "$(git -C "$REMOTE_CHECKOUT" rev-parse --verify 'HEAD^{commit}')" = "$EXPECTED_CHECKOUT_REVISION"
test -z "$(git -C "$REMOTE_CHECKOUT" status --porcelain=v1 --untracked-files=all)"
test -e "$REMOTE_CHECKOUT/$MARKER"
REMOTE
    return
  fi

  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "INCOMING='$incoming' REMOTE_CHECKOUT='$checkout' RUN_ROOT='$RUN_ROOT' bash -l -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$(dirname "$INCOMING")" "$(dirname "$REMOTE_CHECKOUT")" "$(dirname "$RUN_ROOT")"
test ! -e "$INCOMING"
test ! -e "$REMOTE_CHECKOUT"
mkdir "$INCOMING"
REMOTE
  rsync -az --delete -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
    "$local_checkout/" "$SSH_TARGET:$incoming/"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "INCOMING='$incoming' REMOTE_CHECKOUT='$checkout' EXPECTED_CHECKOUT_REVISION='$revision' MARKER='$marker' bash -l -s" <<'REMOTE'
set -euo pipefail
test "$(git -C "$INCOMING" rev-parse --verify 'HEAD^{commit}')" = "$EXPECTED_CHECKOUT_REVISION"
test -z "$(git -C "$INCOMING" status --porcelain=v1 --untracked-files=all)"
test -e "$INCOMING/$MARKER"
chmod -R a-w "$INCOMING"
test ! -e "$REMOTE_CHECKOUT"
mv "$INCOMING" "$REMOTE_CHECKOUT"
REMOTE
}

make_local_checkout \
  "$ORCHESTRATION_REVISION" "$LOCAL_ORCHESTRATION_CHECKOUT" orchestration
make_local_checkout "$SOLVER_REVISION" "$LOCAL_SOLVER_CHECKOUT" solver
stage_remote_checkout \
  "$LOCAL_ORCHESTRATION_CHECKOUT" \
  "$ORCHESTRATION_CHECKOUT" \
  "$ORCHESTRATION_REVISION" \
  scripts/helios/run_campaign_task.sh
stage_remote_checkout \
  "$LOCAL_SOLVER_CHECKOUT" \
  "$SOLVER_CHECKOUT" \
  "$SOLVER_REVISION" \
  Cargo.toml

CORPUS_REPORT="$TEMPORARY/corpus.tsv"
"$ROOT/scripts/helios/sync_corpus.sh" \
  --source-root "$CORPUS_SOURCE" \
  --manifest "$MANIFEST_RELATIVE" \
  --instance-root "$INSTANCE_ROOT_RELATIVE" \
  --preflight-report "$PREFLIGHT_REPORT" \
  > "$CORPUS_REPORT"
CORPUS_INVENTORY_SHA256="$(awk -F '\t' '$1 == "corpus_inventory_sha256" {print $2}' \
  "$CORPUS_REPORT")"
CORPUS_SNAPSHOT="$(awk -F '\t' '$1 == "remote_corpus_root" {print $2}' \
  "$CORPUS_REPORT")"
CORPUS_INVENTORY="$(awk -F '\t' '$1 == "remote_inventory" {print $2}' \
  "$CORPUS_REPORT")"
MANIFEST="$(awk -F '\t' '$1 == "remote_manifest" {print $2}' "$CORPUS_REPORT")"
MANIFEST_SHA256="$(awk -F '\t' '$1 == "remote_manifest_sha256" {print $2}' \
  "$CORPUS_REPORT")"
INSTANCE_ROOT="$(awk -F '\t' '$1 == "remote_instance_root" {print $2}' \
  "$CORPUS_REPORT")"
for digest in "$CORPUS_INVENTORY_SHA256" "$MANIFEST_SHA256"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "invalid corpus artifact hash"
done

BUNDLE_REQUESTED="${EUF_VIPER_HELIOS_COMPARATOR_BUNDLE:-$REMOTE_ROOT/tools/solvers}"
[[ "$BUNDLE_REQUESTED" =~ ^[A-Za-z0-9_./+-]+$ ]] || \
  die "unsafe comparator bundle path"
case "$BUNDLE_REQUESTED" in /*) ;; *) die "comparator bundle must be absolute" ;; esac
solver_report() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "BUNDLE_REQUESTED='$BUNDLE_REQUESTED' ORCHESTRATION_CHECKOUT='$ORCHESTRATION_CHECKOUT' bash -l -s" <<'REMOTE'
set -euo pipefail
bundle="$(readlink -f -- "$BUNDLE_REQUESTED")"
case "$bundle" in /*) ;; *) exit 2 ;; esac
python3 "$ORCHESTRATION_CHECKOUT/scripts/helios/verify_competitor_bundle.py" \
  --bundle-root "$bundle" \
  --receipt "$bundle/receipt.json" \
  --release-lock "$ORCHESTRATION_CHECKOUT/campaigns/solver-releases-2026-07.json" \
  --execute \
  --format tsv
REMOTE
}
SOLVER_REPORT="$(solver_report)"
solver_value() {
  printf '%s\n' "$SOLVER_REPORT" | awk -F '\t' -v label="$1" -v column="$2" \
    '$1 == "solver" && $2 == label {print $column}'
}
Z3_BIN="$(solver_value z3 2)"; Z3_SHA256="$(solver_value z3 3)"
CVC5_BIN="$(solver_value cvc5 2)"; CVC5_SHA256="$(solver_value cvc5 3)"
YICES_BIN="$(solver_value yices2 2)"; YICES_SHA256="$(solver_value yices2 3)"
OPENSMT_BIN="$(solver_value opensmt 2)"; OPENSMT_SHA256="$(solver_value opensmt 3)"
COMPARATOR_BUNDLE_ROOT="$(printf '%s\n' "$SOLVER_REPORT" | \
  awk -F '\t' '$1 == "bundle" && $2 == "bundle" {print $3}')"
COMPARATOR_BUNDLE_RECEIPT_SHA256="$(printf '%s\n' "$SOLVER_REPORT" | \
  awk -F '\t' '$1 == "bundle" && $2 == "bundle" {print $4}')"
Z3_LIBRARY_PATH="$(printf '%s\n' "$SOLVER_REPORT" | \
  awk -F '\t' '$1 == "environment" && $2 == "z3-library" {print $3}')"
for digest in "$Z3_SHA256" "$CVC5_SHA256" "$YICES_SHA256" "$OPENSMT_SHA256"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "invalid remote solver hash"
done
[[ "$COMPARATOR_BUNDLE_RECEIPT_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
  die "invalid comparator bundle receipt hash"
for value in "$COMPARATOR_BUNDLE_ROOT" "$Z3_LIBRARY_PATH"; do
  case "$value" in /*) ;; *) die "comparator bundle report is incomplete" ;; esac
done

CANDIDATE_ARGV_JSON='["{binary}","fabric-solve","--engine","quotient-portfolio","{instance}"]'
CANDIDATE_ARGV_SHA256="$(printf '%s\n' "$CANDIDATE_ARGV_JSON" | \
  shasum -a 256 | awk '{print $1}')"

ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "RUN_ROOT='$RUN_ROOT' REMOTE_ROOT='$REMOTE_ROOT' bash -l -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$REMOTE_ROOT/logs" "$(dirname "$RUN_ROOT")"
test ! -e "$RUN_ROOT"
REMOTE

remote_sbatch() {
  local sbatch_mode="$1"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "SBATCH_MODE='$sbatch_mode' ORCHESTRATION_CHECKOUT='$ORCHESTRATION_CHECKOUT' SOLVER_CHECKOUT='$SOLVER_CHECKOUT' RUN_ROOT='$RUN_ROOT' RUN_ID='$RUN_ID' ORCHESTRATION_REVISION='$ORCHESTRATION_REVISION' SOLVER_REVISION='$SOLVER_REVISION' ACCOUNT='$ACCOUNT' PARTITION='$PARTITION' WALL_TIME='$WALL_TIME' MEMORY='$MEMORY' MEMORY_BYTES='$MEMORY_BYTES' TOOLCHAIN_SHA256='$TOOLCHAIN_SHA256' CORPUS_INVENTORY_SHA256='$CORPUS_INVENTORY_SHA256' CORPUS_SNAPSHOT='$CORPUS_SNAPSHOT' CORPUS_INVENTORY='$CORPUS_INVENTORY' INSTANCE_ROOT='$INSTANCE_ROOT' MANIFEST='$MANIFEST' MANIFEST_SHA256='$MANIFEST_SHA256' SPEC_RELATIVE='$SPEC_RELATIVE' BUDGET='$BUDGET' COMPARATOR_BUNDLE_ROOT='$COMPARATOR_BUNDLE_ROOT' COMPARATOR_BUNDLE_RECEIPT_SHA256='$COMPARATOR_BUNDLE_RECEIPT_SHA256' Z3_LIBRARY_PATH='$Z3_LIBRARY_PATH' Z3_BIN='$Z3_BIN' Z3_SHA256='$Z3_SHA256' CVC5_BIN='$CVC5_BIN' CVC5_SHA256='$CVC5_SHA256' YICES_BIN='$YICES_BIN' YICES_SHA256='$YICES_SHA256' OPENSMT_BIN='$OPENSMT_BIN' OPENSMT_SHA256='$OPENSMT_SHA256' CANDIDATE_ARGV_SHA256='$CANDIDATE_ARGV_SHA256' REMOTE_ROOT='$REMOTE_ROOT' bash -l -s" <<'REMOTE'
set -euo pipefail
exports="EUF_VIPER_HELIOS_ORCHESTRATION_CHECKOUT=$ORCHESTRATION_CHECKOUT,EUF_VIPER_HELIOS_SOLVER_CHECKOUT=$SOLVER_CHECKOUT,EUF_VIPER_HELIOS_RUN_ROOT=$RUN_ROOT,EUF_VIPER_HELIOS_RUN_ID=$RUN_ID,EUF_VIPER_HELIOS_ORCHESTRATION_REVISION=$ORCHESTRATION_REVISION,EUF_VIPER_HELIOS_SOLVER_REVISION=$SOLVER_REVISION,EUF_VIPER_HELIOS_ACCOUNT=$ACCOUNT,EUF_VIPER_HELIOS_PARTITION=$PARTITION,EUF_VIPER_HELIOS_TOOLCHAIN_SHA256=$TOOLCHAIN_SHA256,EUF_VIPER_HELIOS_CORPUS_INVENTORY_SHA256=$CORPUS_INVENTORY_SHA256,EUF_VIPER_HELIOS_CORPUS_SNAPSHOT=$CORPUS_SNAPSHOT,EUF_VIPER_HELIOS_CORPUS_INVENTORY=$CORPUS_INVENTORY,EUF_VIPER_HELIOS_INSTANCE_ROOT=$INSTANCE_ROOT,EUF_VIPER_HELIOS_MANIFEST=$MANIFEST,EUF_VIPER_HELIOS_MANIFEST_SHA256=$MANIFEST_SHA256,EUF_VIPER_HELIOS_SPEC_RELATIVE=$SPEC_RELATIVE,EUF_VIPER_HELIOS_BUDGET=$BUDGET,EUF_VIPER_HELIOS_MEMORY_BYTES=$MEMORY_BYTES,EUF_VIPER_HELIOS_COMPARATOR_BUNDLE_ROOT=$COMPARATOR_BUNDLE_ROOT,EUF_VIPER_HELIOS_COMPARATOR_BUNDLE_RECEIPT_SHA256=$COMPARATOR_BUNDLE_RECEIPT_SHA256,EUF_VIPER_HELIOS_Z3_LIBRARY_PATH=$Z3_LIBRARY_PATH,EUF_VIPER_HELIOS_Z3=$Z3_BIN,EUF_VIPER_HELIOS_Z3_SHA256=$Z3_SHA256,EUF_VIPER_HELIOS_CVC5=$CVC5_BIN,EUF_VIPER_HELIOS_CVC5_SHA256=$CVC5_SHA256,EUF_VIPER_HELIOS_YICES=$YICES_BIN,EUF_VIPER_HELIOS_YICES_SHA256=$YICES_SHA256,EUF_VIPER_HELIOS_OPENSMT=$OPENSMT_BIN,EUF_VIPER_HELIOS_OPENSMT_SHA256=$OPENSMT_SHA256,EUF_VIPER_HELIOS_CANDIDATE_ARGV_SHA256=$CANDIDATE_ARGV_SHA256"
arguments=(
  --account="$ACCOUNT"
  --partition="$PARTITION"
  --nodes=1
  --ntasks=1
  --cpus-per-task=1
  --hint=nomultithread
  --mem="$MEMORY"
  --time="$WALL_TIME"
  --chdir="$REMOTE_ROOT"
  --output="$REMOTE_ROOT/logs/euf-viper-$RUN_ID-%j.out"
  --error="$REMOTE_ROOT/logs/euf-viper-$RUN_ID-%j.err"
  --export="$exports"
)
script="$ORCHESTRATION_CHECKOUT/slurm/helios/euf_viper_campaign.sbatch"
if [ "$SBATCH_MODE" = test-only ]; then
  sbatch --test-only "${arguments[@]}" "$script"
else
  sbatch --parsable "${arguments[@]}" "$script"
fi
REMOTE
}

TEST_ONLY_OUTPUT="$(remote_sbatch test-only)"
printf '%s\n' "$TEST_ONLY_OUTPUT"
if [ "$MODE" = test-only ]; then
  printf 'mode=test-only orchestration_revision=%s solver_revision=%s run_id=%s manifest_sha256=%s\n' \
    "$ORCHESTRATION_REVISION" "$SOLVER_REVISION" "$RUN_ID" "$MANIFEST_SHA256"
  exit 0
fi

RECEIPT_ROOT="${EUF_VIPER_HELIOS_RECEIPT_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/euf-viper/helios-submissions}"
mkdir -p "$RECEIPT_ROOT"
RECEIPT_DIRECTORY="$RECEIPT_ROOT/$RUN_ID"
mkdir "$RECEIPT_DIRECTORY" || die "submission receipt directory already exists"
if ! SBATCH_OUTPUT="$(remote_sbatch submit)"; then
  rmdir "$RECEIPT_DIRECTORY" || true
  die "real sbatch submission failed after test-only passed"
fi
JOB_ID="${SBATCH_OUTPUT%%;*}"
[[ "$JOB_ID" =~ ^[1-9][0-9]*$ ]] || die "sbatch returned an invalid job ID: $SBATCH_OUTPUT"

report_hash() {
  awk -F '\t' -v kind="$1" -v name="$2" \
    '$1 == kind && $2 == name {print $4}' "$PREFLIGHT_REPORT"
}
GCC_MODULE_SHA256="$(report_hash module GCCcore/14.3.0)"
RUST_MODULE_SHA256="$(report_hash module Rust/1.88.0)"
CARGO_SHA256="$(report_hash tool cargo)"
RUSTC_SHA256="$(report_hash tool rustc)"
PYTHON_SHA256="$(report_hash tool python3)"
RESOURCE_WRAPPER_SHA256="$(shasum -a 256 \
  "$ROOT/scripts/helios/run_with_resources.py" | awk '{print $1}')"

RECEIPT="$RECEIPT_DIRECTORY/submission.tsv"
TEMPORARY_RECEIPT="$RECEIPT_DIRECTORY/.submission.tsv.$$"
header=(
  schema_version status submitted_at job_id run_id orchestration_revision
  solver_revision ssh_target remote_orchestration_checkout
  remote_solver_checkout remote_run_root remote_run_receipt account partition
  cpus_per_task cpu_bind toolchain_sha256 gcc_module_sha256
  rust_module_sha256 cargo_sha256 rustc_sha256 python_sha256
  resource_wrapper_sha256 corpus_inventory_sha256 manifest_sha256
  comparator_bundle_receipt_sha256
  candidate_argv_json candidate_argv_sha256 z3_sha256 cvc5_sha256
  yices2_sha256 opensmt_sha256
)
values=(
  1 submitted "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$JOB_ID" "$RUN_ID"
  "$ORCHESTRATION_REVISION" "$SOLVER_REVISION" "$SSH_TARGET"
  "$ORCHESTRATION_CHECKOUT" "$SOLVER_CHECKOUT" "$RUN_ROOT"
  "$RUN_ROOT/receipt.tsv" "$ACCOUNT" "$PARTITION" 1 cores
  "$TOOLCHAIN_SHA256" "$GCC_MODULE_SHA256" "$RUST_MODULE_SHA256"
  "$CARGO_SHA256" "$RUSTC_SHA256" "$PYTHON_SHA256"
  "$RESOURCE_WRAPPER_SHA256" "$CORPUS_INVENTORY_SHA256" "$MANIFEST_SHA256"
  "$COMPARATOR_BUNDLE_RECEIPT_SHA256"
  "$CANDIDATE_ARGV_JSON" "$CANDIDATE_ARGV_SHA256" "$Z3_SHA256"
  "$CVC5_SHA256" "$YICES_SHA256" "$OPENSMT_SHA256"
)
[ "${#header[@]}" -eq "${#values[@]}" ] || die "receipt field count drifted"
{
  IFS=$'\t'
  printf '%s\n' "${header[*]}"
  printf '%s\n' "${values[*]}"
} > "$TEMPORARY_RECEIPT"
chmod 0444 "$TEMPORARY_RECEIPT"
ln "$TEMPORARY_RECEIPT" "$RECEIPT"
rm -f "$TEMPORARY_RECEIPT"
chmod 0555 "$RECEIPT_DIRECTORY"
printf 'submitted job=%s run=%s receipt=%s\n' "$JOB_ID" "$RUN_ROOT" "$RECEIPT"
