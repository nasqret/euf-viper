#!/usr/bin/env bash
set -euo pipefail

ORCHESTRATION_CHECKOUT="${EUF_VIPER_HELIOS_ORCHESTRATION_CHECKOUT:?set orchestration checkout}"
SOLVER_CHECKOUT="${EUF_VIPER_HELIOS_SOLVER_CHECKOUT:?set solver checkout}"
RUN_ROOT="${EUF_VIPER_HELIOS_RUN_ROOT:?set run root}"
EXPECTED_ORCHESTRATION_REVISION="${EUF_VIPER_HELIOS_ORCHESTRATION_REVISION:?set orchestration revision}"
EXPECTED_SOLVER_REVISION="${EUF_VIPER_HELIOS_SOLVER_REVISION:?set solver revision}"
EXPECTED_TOOLCHAIN_SHA256="${EUF_VIPER_HELIOS_TOOLCHAIN_SHA256:?set toolchain hash}"
EXPECTED_CORPUS_INVENTORY_SHA256="${EUF_VIPER_HELIOS_CORPUS_INVENTORY_SHA256:?set corpus inventory hash}"
CORPUS_SNAPSHOT="${EUF_VIPER_HELIOS_CORPUS_SNAPSHOT:?set corpus snapshot}"
CORPUS_INVENTORY="${EUF_VIPER_HELIOS_CORPUS_INVENTORY:?set corpus inventory}"
INSTANCE_ROOT="${EUF_VIPER_HELIOS_INSTANCE_ROOT:?set instance root}"
MANIFEST="${EUF_VIPER_HELIOS_MANIFEST:?set manifest}"
EXPECTED_MANIFEST_SHA256="${EUF_VIPER_HELIOS_MANIFEST_SHA256:?set manifest hash}"
COMPARATOR_BUNDLE_ROOT="${EUF_VIPER_HELIOS_COMPARATOR_BUNDLE_ROOT:?set comparator bundle}"
EXPECTED_COMPARATOR_BUNDLE_RECEIPT_SHA256="${EUF_VIPER_HELIOS_COMPARATOR_BUNDLE_RECEIPT_SHA256:?set comparator bundle hash}"
SPEC_RELATIVE="${EUF_VIPER_HELIOS_SPEC_RELATIVE:-campaigns/best-overall-qf-uf-2026-07.json}"
BUDGET="${EUF_VIPER_HELIOS_BUDGET:-2}"
MEMORY_BYTES="${EUF_VIPER_HELIOS_MEMORY_BYTES:-8589934592}"
EXPECTED_CPU_MODEL="${EUF_VIPER_HELIOS_CPU_MODEL:-AMD EPYC 9654}"
Z3_BIN="${EUF_VIPER_HELIOS_Z3:?set Z3 path}"
Z3_SHA256="${EUF_VIPER_HELIOS_Z3_SHA256:?set Z3 hash}"
Z3_LIBRARY_PATH="${EUF_VIPER_HELIOS_Z3_LIBRARY_PATH:?set Z3 library path}"
CVC5_BIN="${EUF_VIPER_HELIOS_CVC5:?set cvc5 path}"
CVC5_SHA256="${EUF_VIPER_HELIOS_CVC5_SHA256:?set cvc5 hash}"
YICES_BIN="${EUF_VIPER_HELIOS_YICES:?set Yices2 path}"
YICES_SHA256="${EUF_VIPER_HELIOS_YICES_SHA256:?set Yices2 hash}"
OPENSMT_BIN="${EUF_VIPER_HELIOS_OPENSMT:?set OpenSMT path}"
OPENSMT_SHA256="${EUF_VIPER_HELIOS_OPENSMT_SHA256:?set OpenSMT hash}"
EXPECTED_ARGV_SHA256="${EUF_VIPER_HELIOS_CANDIDATE_ARGV_SHA256:?set candidate argv hash}"
EXECUTION_MODE="${EUF_VIPER_HELIOS_EXECUTION_MODE:-single}"
SHARD_COUNT="${EUF_VIPER_HELIOS_SHARD_COUNT:-1}"
REMOTE_ROOT="${EUF_VIPER_HELIOS_REMOTE_ROOT:?set remote campaign root}"
CAMPAIGN_ROOT="${EUF_VIPER_HELIOS_CAMPAIGN_ROOT:-$RUN_ROOT}"

CANDIDATE_ARGV_JSON='["{binary}","fabric-solve","--engine","quotient-portfolio","{instance}"]'

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

check_hash() {
  local path="$1"
  local expected="$2"
  local label="$3"
  [ -f "$path" ] && [ ! -L "$path" ] || die "$label is not a regular file"
  actual="$(hash_file "$path")"
  [ "$actual" = "$expected" ] || \
    die "$label hash mismatch: expected $expected, got $actual"
}

verify_checkout() {
  local checkout="$1"
  local revision="$2"
  local label="$3"
  [ -d "$checkout/.git" ] || die "$label checkout lacks .git"
  [ "$(git -C "$checkout" rev-parse --verify 'HEAD^{commit}')" = "$revision" ] || \
    die "$label checkout revision drifted"
  [ -z "$(git -C "$checkout" status --porcelain=v1 --untracked-files=all)" ] || \
    die "$label checkout is not an exact clean revision"
}

[ "$(uname -m)" = x86_64 ] || die "compute task must be x86_64"
[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || die "campaign task requires one allocated CPU"
command -v module >/dev/null 2>&1 || die "Lmod module command is unavailable"
module --force purge
module load GCCcore/14.3.0 Rust/1.88.0
export LANG=C
export LC_ALL=C
export TZ=UTC
export PYTHONDONTWRITEBYTECODE=1
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
GCC_INTERNAL_INCLUDE="$(gcc -print-file-name=include)"
case "$GCC_INTERNAL_INCLUDE" in /*) ;; *) die "GCC returned a non-absolute include path" ;; esac
[ -f "$GCC_INTERNAL_INCLUDE/stdbool.h" ] || die "GCC stdbool.h is missing"
export BINDGEN_EXTRA_CLANG_ARGS="-isystem $GCC_INTERNAL_INCLUDE"

for forbidden in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS; do
  [ -z "${!forbidden:-}" ] || die "ambient build override is forbidden: $forbidden"
done

[[ "$EXPECTED_SOLVER_REVISION" =~ ^[0-9a-f]{40}$ ]] || \
  die "solver revision must be a full lowercase commit"
case "$EXECUTION_MODE" in
  single)
    [ "$SHARD_COUNT" = 1 ] || die "single mode requires one shard"
    ;;
  prepare-sharded)
    [[ "$SHARD_COUNT" =~ ^[1-9][0-9]*$ ]] && [ "$SHARD_COUNT" -ge 2 ] || \
      die "prepare-sharded mode requires at least two shards"
    case "$CAMPAIGN_ROOT" in
      "$REMOTE_ROOT/campaigns/"*) ;;
      *) die "sharded campaign root escaped its namespace" ;;
    esac
    [ ! -e "$CAMPAIGN_ROOT" ] || die "sharded campaign root already exists"
    ;;
  *) die "unsupported execution mode: $EXECUTION_MODE" ;;
esac
verify_checkout \
  "$ORCHESTRATION_CHECKOUT" "$EXPECTED_ORCHESTRATION_REVISION" orchestration
verify_checkout "$SOLVER_CHECKOUT" "$EXPECTED_SOLVER_REVISION" solver
grep -Eq '^edition[[:space:]]*=[[:space:]]*"2024"[[:space:]]*$' \
  "$SOLVER_CHECKOUT/Cargo.toml" || die "solver Cargo.toml must use edition 2024"

AFFINITY_COUNT="$(python3 - <<'PY'
import os
print(len(os.sched_getaffinity(0)))
PY
)"
[ "$AFFINITY_COUNT" = 1 ] || die "srun did not bind the task to exactly one CPU"
CPU_MODEL="$(LC_ALL=C lscpu | awk -F: '$1 ~ /^Model name/ {sub(/^[[:space:]]+/, "", $2); print $2}')"
case "$CPU_MODEL" in
  *"$EXPECTED_CPU_MODEL"*) ;;
  *) die "unexpected CPU model: $CPU_MODEL" ;;
esac
printf 'cpu_model\t%s\naffinity_cpus\t%s\n' "$CPU_MODEL" "$AFFINITY_COUNT" \
  > "$RUN_ROOT/compute.tsv"

TOOLCHAIN="$RUN_ROOT/toolchain.tsv"
"$ORCHESTRATION_CHECKOUT/scripts/helios/toolchain_receipt.sh" > "$TOOLCHAIN"
OBSERVED_TOOLCHAIN_SHA256="$(hash_file "$TOOLCHAIN")"
[ "$OBSERVED_TOOLCHAIN_SHA256" = "$EXPECTED_TOOLCHAIN_SHA256" ] || \
  die "compute toolchain differs from the login preflight receipt"
chmod 0444 "$TOOLCHAIN" "$RUN_ROOT/compute.tsv"

check_hash "$CORPUS_INVENTORY" "$EXPECTED_CORPUS_INVENTORY_SHA256" \
  "corpus inventory"
check_hash "$MANIFEST" "$EXPECTED_MANIFEST_SHA256" "rebased manifest"
python3 "$ORCHESTRATION_CHECKOUT/scripts/helios/corpus_snapshot.py" verify \
  --root "$CORPUS_SNAPSHOT" \
  --inventory "$CORPUS_INVENTORY" >/dev/null
[ -d "$INSTANCE_ROOT" ] || die "instance root is missing"

check_hash "$Z3_BIN" "$Z3_SHA256" "Z3"
check_hash "$CVC5_BIN" "$CVC5_SHA256" "cvc5"
check_hash "$YICES_BIN" "$YICES_SHA256" "Yices2"
check_hash "$OPENSMT_BIN" "$OPENSMT_SHA256" "OpenSMT"
check_hash \
  "$COMPARATOR_BUNDLE_ROOT/receipt.json" \
  "$EXPECTED_COMPARATOR_BUNDLE_RECEIPT_SHA256" \
  "comparator bundle receipt"
[ "$Z3_LIBRARY_PATH" = "$COMPARATOR_BUNDLE_ROOT/lib" ] || \
  die "Z3 library path escaped the comparator bundle"
python3 "$ORCHESTRATION_CHECKOUT/scripts/helios/verify_competitor_bundle.py" \
  --bundle-root "$COMPARATOR_BUNDLE_ROOT" \
  --receipt "$COMPARATOR_BUNDLE_ROOT/receipt.json" \
  --release-lock "$ORCHESTRATION_CHECKOUT/campaigns/solver-releases-2026-07.json" \
  --execute >/dev/null

printf '%s\n' "$CANDIDATE_ARGV_JSON" > "$RUN_ROOT/candidate-argv.json"
OBSERVED_ARGV_SHA256="$(hash_file "$RUN_ROOT/candidate-argv.json")"
[ "$OBSERVED_ARGV_SHA256" = "$EXPECTED_ARGV_SHA256" ] || \
  die "candidate argv receipt drifted"
chmod 0444 "$RUN_ROOT/candidate-argv.json"

TARGET_DIR="$RUN_ROOT/target"
mkdir "$TARGET_DIR"
cargo build \
  --locked \
  --release \
  --features fabric,finite-symmetry \
  --jobs 1 \
  --target-dir "$TARGET_DIR" \
  --manifest-path "$SOLVER_CHECKOUT/Cargo.toml" \
  > "$RUN_ROOT/cargo-build.out" \
  2> "$RUN_ROOT/cargo-build.err"
VIPER_BIN="$TARGET_DIR/release/euf-viper"
[ -x "$VIPER_BIN" ] || die "candidate binary was not built"
VIPER_SHA256="$(hash_file "$VIPER_BIN")"

read -r SMOKE_INSTANCE SMOKE_EXPECTED < <(python3 - "$MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

line = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()[0]
row = json.loads(line)
if row.get("status") not in {"sat", "unsat"}:
    raise SystemExit("first manifest row lacks a checked status")
print(f"{row['path']}\t{row['status']}")
PY
)

SOLVER_CONFIG="$RUN_ROOT/solver-config.json"
python3 "$ORCHESTRATION_CHECKOUT/scripts/bench/record_solver_config.py" \
  --campaign "$ORCHESTRATION_CHECKOUT/$SPEC_RELATIVE" \
  --viper "$VIPER_BIN" \
  --viper-version "0.1.0+$EXPECTED_SOLVER_REVISION.quotient-portfolio" \
  --viper-arg '{binary}' \
  --viper-arg fabric-solve \
  --viper-arg=--engine \
  --viper-arg quotient-portfolio \
  --viper-arg '{instance}' \
  --viper-configuration quotient-portfolio \
  --z3 "$Z3_BIN" \
  --z3-env "LD_LIBRARY_PATH=$Z3_LIBRARY_PATH" \
  --cvc5 "$CVC5_BIN" \
  --yices2 "$YICES_BIN" \
  --opensmt "$OPENSMT_BIN" \
  --smoke-instance "$SMOKE_INSTANCE" \
  --smoke-expected "$SMOKE_EXPECTED" \
  --out "$SOLVER_CONFIG" \
  > "$RUN_ROOT/solver-config-summary.json"

TAXONOMY="$RUN_ROOT/taxonomy.jsonl"
TAXONOMY_SPLIT="$RUN_ROOT/taxonomy-split.json"
TAXONOMY_CACHE_ROOT="$REMOTE_ROOT/taxonomy-cache"
python3 "$ORCHESTRATION_CHECKOUT/scripts/helios/materialize_taxonomy.py" \
  "$MANIFEST" \
  --repository-root "$ORCHESTRATION_CHECKOUT" \
  --builder "$ORCHESTRATION_CHECKOUT/scripts/bench/build_family_manifest.py" \
  --cache-root "$TAXONOMY_CACHE_ROOT" \
  --taxonomy-out "$TAXONOMY" \
  --split-out "$TAXONOMY_SPLIT" \
  > "$RUN_ROOT/taxonomy-summary.json"
chmod 0444 "$TAXONOMY" "$TAXONOMY_SPLIT"

LOCK="$RUN_ROOT/campaign-lock.json"
OUTPUT_DIRECTORY="$RUN_ROOT/output"
if [ "$EXECUTION_MODE" = prepare-sharded ]; then
  OUTPUT_DIRECTORY="$CAMPAIGN_ROOT/results"
fi
python3 "$ORCHESTRATION_CHECKOUT/scripts/helios/prepare_campaign_lock.py" \
  --spec "$ORCHESTRATION_CHECKOUT/$SPEC_RELATIVE" \
  --manifest "$MANIFEST" \
  --taxonomy "$TAXONOMY" \
  --solver-config "$SOLVER_CONFIG" \
  --repository "$ORCHESTRATION_CHECKOUT" \
  --corpus-root "$INSTANCE_ROOT" \
  --solver-revision "$EXPECTED_SOLVER_REVISION" \
  --orchestration-revision "$EXPECTED_ORCHESTRATION_REVISION" \
  --budget "$BUDGET" \
  --memory-bytes "$MEMORY_BYTES" \
  --output-directory "$OUTPUT_DIRECTORY" \
  --out "$LOCK" \
  > "$RUN_ROOT/lock-summary.json"

if [ "$EXECUTION_MODE" = prepare-sharded ]; then
  SHARD_LOCKS="$RUN_ROOT/shard-locks"
  SHARD_SUMMARY="$RUN_ROOT/shard-summary.json"
  python3 "$ORCHESTRATION_CHECKOUT/scripts/bench/shard_campaign_lock.py" \
    "$LOCK" \
    --count "$SHARD_COUNT" \
    --out-dir "$SHARD_LOCKS" \
    > "$SHARD_SUMMARY"
  printf 'execution_mode\t%s\nshard_count\t%s\ncampaign_root\t%s\norchestration_revision\t%s\nsolver_revision\t%s\npromotion_eligible\ttrue\ncomparator_bundle_receipt_sha256\t%s\ncandidate_binary_sha256\t%s\nsolver_config_sha256\t%s\ntaxonomy_sha256\t%s\ntaxonomy_split_sha256\t%s\ntaxonomy_cache_summary_sha256\t%s\nlock_file_sha256\t%s\nshard_summary_sha256\t%s\n' \
    "$EXECUTION_MODE" \
    "$SHARD_COUNT" \
    "$CAMPAIGN_ROOT" \
    "$EXPECTED_ORCHESTRATION_REVISION" \
    "$EXPECTED_SOLVER_REVISION" \
    "$EXPECTED_COMPARATOR_BUNDLE_RECEIPT_SHA256" \
    "$VIPER_SHA256" \
    "$(hash_file "$SOLVER_CONFIG")" \
    "$(hash_file "$TAXONOMY")" \
    "$(hash_file "$TAXONOMY_SPLIT")" \
    "$(hash_file "$RUN_ROOT/taxonomy-summary.json")" \
    "$(hash_file "$LOCK")" \
    "$(hash_file "$SHARD_SUMMARY")" \
    > "$RUN_ROOT/preparation.tsv"
  chmod 0444 \
    "$RUN_ROOT/preparation.tsv" \
    "$RUN_ROOT/solver-config.json" \
    "$RUN_ROOT/taxonomy.jsonl" \
    "$RUN_ROOT/taxonomy-split.json" \
    "$RUN_ROOT/campaign-lock.json" \
    "$RUN_ROOT/shard-summary.json" \
    "$RUN_ROOT"/shard-locks/lock-*.json
  exit 0
fi

BOUND_LOCK="$RUN_ROOT/bound-lock.json"
python3 "$ORCHESTRATION_CHECKOUT/scripts/bench/bind_campaign_cpu.py" "$LOCK" \
  --out "$BOUND_LOCK" \
  > "$RUN_ROOT/cpu-binding.json"

RESOURCE_CAPTURE="$RUN_ROOT/resource-usage.json"
set +e
python3 "$ORCHESTRATION_CHECKOUT/scripts/helios/run_with_resources.py" \
  --out "$RESOURCE_CAPTURE" -- \
  python3 "$ORCHESTRATION_CHECKOUT/scripts/bench/run_locked_campaign.py" "$BOUND_LOCK"
RUNNER_STATUS="$?"
set -e
[ -s "$RESOURCE_CAPTURE" ] || die "resource wrapper did not produce a record"

printf 'execution_mode\tsingle\nshard_count\t1\norchestration_revision\t%s\nsolver_revision\t%s\npromotion_eligible\ttrue\ncomparator_bundle_receipt_sha256\t%s\ncandidate_binary_sha256\t%s\nsolver_config_sha256\t%s\ntaxonomy_sha256\t%s\ntaxonomy_split_sha256\t%s\ntaxonomy_cache_summary_sha256\t%s\nlock_file_sha256\t%s\nbound_lock_file_sha256\t%s\n' \
  "$EXPECTED_ORCHESTRATION_REVISION" \
  "$EXPECTED_SOLVER_REVISION" \
  "$EXPECTED_COMPARATOR_BUNDLE_RECEIPT_SHA256" \
  "$VIPER_SHA256" \
  "$(hash_file "$SOLVER_CONFIG")" \
  "$(hash_file "$TAXONOMY")" \
  "$(hash_file "$TAXONOMY_SPLIT")" \
  "$(hash_file "$RUN_ROOT/taxonomy-summary.json")" \
  "$(hash_file "$LOCK")" \
  "$(hash_file "$BOUND_LOCK")" \
  > "$RUN_ROOT/preparation.tsv"
chmod 0444 \
  "$RUN_ROOT/preparation.tsv" \
  "$RUN_ROOT/solver-config.json" \
  "$RUN_ROOT/taxonomy.jsonl" \
  "$RUN_ROOT/taxonomy-split.json" \
  "$RUN_ROOT/campaign-lock.json" \
  "$RUN_ROOT/bound-lock.json" \
  "$RUN_ROOT/resource-usage.json"
exit "$RUNNER_STATUS"
