#!/usr/bin/env bash
#SBATCH --job-name=euf-pgo-holdout
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=18:00:00
#SBATCH --output=results/pgo-holdout-%j.out
#SBATCH --error=results/pgo-holdout-%j.err

set -euo pipefail

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

canonical_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

canonical_revision() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

canonical_file() {
  local configured="$1"
  local label="$2"
  local resolved

  case "$configured" in
    /*) ;;
    *) die "$label must be an absolute path: $configured" ;;
  esac
  [ ! -L "$configured" ] || die "$label must not be a symlink: $configured"
  [ -f "$configured" ] || die "$label is not a regular file: $configured"
  resolved="$(readlink -f -- "$configured")" || die "cannot resolve $label"
  [ "$resolved" = "$configured" ] || die "$label path is not canonical: $resolved"
}

canonical_directory() {
  local configured="$1"
  local label="$2"
  local resolved

  case "$configured" in
    /*) ;;
    *) die "$label must be an absolute path: $configured" ;;
  esac
  [ ! -L "$configured" ] || die "$label must not be a symlink: $configured"
  [ -d "$configured" ] || die "$label is not a directory: $configured"
  resolved="$(readlink -f -- "$configured")" || die "cannot resolve $label"
  [ "$resolved" = "$configured" ] || die "$label path is not canonical: $resolved"
}

check_file_hash() {
  local file="$1"
  local expected_hash="$2"
  local label="$3"
  local actual_hash

  canonical_file "$file" "$label"
  canonical_sha256 "$expected_hash" || die "$label expected hash is not canonical"
  actual_hash="$(sha256sum "$file" | awk '{print $1}')"
  [ "$actual_hash" = "$expected_hash" ] || \
    die "$label hash mismatch: expected $expected_hash, got $actual_hash"
}

check_tool() {
  check_file_hash "$1" "$2" "$3"
  [ -x "$1" ] || die "$3 is not executable: $1"
}

[ "${EUF_VIPER_PGO_HOLDOUT_ENABLE:-0}" = 1 ] || \
  die "PGO holdout campaign is default-off; set EUF_VIPER_PGO_HOLDOUT_ENABLE=1"

JOB_ID="${SLURM_JOB_ID:?run this wrapper under Slurm}"
ROOT="${SLURM_SUBMIT_DIR:?SLURM_SUBMIT_DIR is required}"
WORK_ROOT="${EUF_VIPER_PGO_WORK_ROOT:?set EUF_VIPER_PGO_WORK_ROOT}"
RUN_ROOT="${EUF_VIPER_PGO_RUN_ROOT:?set EUF_VIPER_PGO_RUN_ROOT}"
CORPUS_ROOT="${EUF_VIPER_PGO_CORPUS_ROOT:?set EUF_VIPER_PGO_CORPUS_ROOT}"
EXPECTED_REVISION="${EUF_VIPER_PGO_EXPECTED_REVISION:?set EUF_VIPER_PGO_EXPECTED_REVISION}"
CARGO_BIN="${EUF_VIPER_PGO_CARGO:?set EUF_VIPER_PGO_CARGO}"
CARGO_SHA256="${EUF_VIPER_PGO_CARGO_SHA256:?set EUF_VIPER_PGO_CARGO_SHA256}"
RUSTC_BIN="${EUF_VIPER_PGO_RUSTC:?set EUF_VIPER_PGO_RUSTC}"
RUSTC_SHA256="${EUF_VIPER_PGO_RUSTC_SHA256:?set EUF_VIPER_PGO_RUSTC_SHA256}"
LLVM_PROFDATA="${EUF_VIPER_PGO_LLVM_PROFDATA:?set EUF_VIPER_PGO_LLVM_PROFDATA}"
LLVM_PROFDATA_SHA256="${EUF_VIPER_PGO_LLVM_PROFDATA_SHA256:?set EUF_VIPER_PGO_LLVM_PROFDATA_SHA256}"
PYTHON_BIN="${EUF_VIPER_PGO_PYTHON:?set EUF_VIPER_PGO_PYTHON}"
PYTHON_SHA256="${EUF_VIPER_PGO_PYTHON_SHA256:?set EUF_VIPER_PGO_PYTHON_SHA256}"
Z3_BIN="${EUF_VIPER_PGO_Z3:?set EUF_VIPER_PGO_Z3}"
Z3_SHA256="${EUF_VIPER_PGO_Z3_SHA256:?set EUF_VIPER_PGO_Z3_SHA256}"
YICES_BIN="${EUF_VIPER_PGO_YICES:?set EUF_VIPER_PGO_YICES}"
YICES_SHA256="${EUF_VIPER_PGO_YICES_SHA256:?set EUF_VIPER_PGO_YICES_SHA256}"
CVC5_BIN="${EUF_VIPER_PGO_CVC5:?set EUF_VIPER_PGO_CVC5}"
CVC5_SHA256="${EUF_VIPER_PGO_CVC5_SHA256:?set EUF_VIPER_PGO_CVC5_SHA256}"
COMPETITOR_RECEIPT="${EUF_VIPER_PGO_COMPETITOR_RECEIPT:?set EUF_VIPER_PGO_COMPETITOR_RECEIPT}"
COMPETITOR_RECEIPT_SHA256="${EUF_VIPER_PGO_COMPETITOR_RECEIPT_SHA256:?set EUF_VIPER_PGO_COMPETITOR_RECEIPT_SHA256}"

OFFICIAL_MANIFEST_SHA256=ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6
OFFICIAL_ROWS=3521
TRAINING_ROWS=101
HOLDOUT_ROWS=302
MAX_TRAIN_PER_FAMILY=16
MAX_TRAIN_SOURCE_BYTES=2000000
TRAINING_TIMEOUT_S=60
HOLDOUT_TIMEOUT_S=2
VIPER_SOLVER_ENV=(
  EUF_VIPER_FABRIC_DISEQUALITY_PROPAGATION=0
  EUF_VIPER_FABRIC_PROPAGATION_BATCH_UPDATES=4
  EUF_VIPER_FABRIC_LAZY_REASONS=1
  EUF_VIPER_FABRIC_INDEXED_CLASS_MEMBERS=1
  EUF_VIPER_FABRIC_PAIR_FILTERED_IMPACT=1
  EUF_VIPER_FABRIC_DEMAND_FLUSH=1
  EUF_VIPER_FABRIC_NARROW_MERGE_FRONTIER=1
  EUF_VIPER_FABRIC_SPARSE_ROOT=0
  EUF_VIPER_FABRIC_CONSTRUCTION_VALIDATION=0
  EUF_VIPER_FABRIC_ALLOCATION_FREE_ASSIGNMENTS=0
)
PGO_SOLVER_ENV_ARGS=()
WILLIAMS_SOLVER_ENV_ARGS=()
for setting in "${VIPER_SOLVER_ENV[@]}"; do
  PGO_SOLVER_ENV_ARGS+=(--solver-env "$setting")
  WILLIAMS_SOLVER_ENV_ARGS+=(--arm-env "$setting")
done

canonical_revision "$EXPECTED_REVISION" || die "expected revision is not canonical"
[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || die "campaign requires exactly one allocated CPU"
case "$ROOT:$WORK_ROOT:$RUN_ROOT:$CORPUS_ROOT" in
  /*:/*:/*:/*) ;;
  *) die "submit, work, run, and corpus roots must be absolute" ;;
esac
for value in "$ROOT" "$WORK_ROOT" "$RUN_ROOT" "$CORPUS_ROOT"; do
  case "$value" in
    *'/../'*|*/..) die "root path contains parent traversal: $value" ;;
  esac
done

ROOT="$(readlink -f -- "$ROOT")" || die "cannot resolve submit directory"
canonical_directory "$WORK_ROOT" "work root"
canonical_directory "$CORPUS_ROOT" "corpus root"
case "$WORK_ROOT" in
  /work/*) ;;
  *) die "work root must be below /work" ;;
esac
case "$ROOT" in
  "$WORK_ROOT"/checkouts/*) ;;
  *) die "submit directory must be a pinned checkout below work root" ;;
esac
case "$RUN_ROOT" in
  "$WORK_ROOT"/runs/*) ;;
  *) die "run root must be below the work root runs directory" ;;
esac
case "$RUN_ROOT" in
  "$CORPUS_ROOT"|"$CORPUS_ROOT"/*) die "run root must be outside corpus root" ;;
esac

check_tool "$CARGO_BIN" "$CARGO_SHA256" "cargo"
check_tool "$RUSTC_BIN" "$RUSTC_SHA256" "rustc"
check_tool "$LLVM_PROFDATA" "$LLVM_PROFDATA_SHA256" "llvm-profdata"
check_tool "$PYTHON_BIN" "$PYTHON_SHA256" "python"
check_tool "$Z3_BIN" "$Z3_SHA256" "Z3"
check_tool "$YICES_BIN" "$YICES_SHA256" "Yices2"
check_tool "$CVC5_BIN" "$CVC5_SHA256" "cvc5"
check_file_hash "$COMPETITOR_RECEIPT" "$COMPETITOR_RECEIPT_SHA256" \
  "competitor bundle receipt"

cd "$ROOT"
[ "$(git rev-parse --show-toplevel)" = "$ROOT" ] || die "submit root is not repository root"
ACTUAL_REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
[ "$ACTUAL_REVISION" = "$EXPECTED_REVISION" ] || die "revision mismatch"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "pinned checkout must be completely clean"
grep -Fqx 'channel = "1.93.0"' rust-toolchain.toml || \
  die "rust-toolchain.toml does not pin Rust 1.93.0"

MANIFEST="$ROOT/benchmarks/smtcomp-2025/qf_uf_manifest.jsonl"
SPLITTER="$ROOT/scripts/bench/build_pgo_split.py"
PGO_BUILDER="$ROOT/scripts/bench/build_rust_pgo.py"
WILLIAMS_RUNNER="$ROOT/scripts/bench/compare_multiarm_williams.py"
PGO_ADJUDICATOR="$ROOT/scripts/bench/adjudicate_pgo_holdout.py"
for required in "$MANIFEST" "$SPLITTER" "$PGO_BUILDER" "$WILLIAMS_RUNNER" "$PGO_ADJUDICATOR"; do
  canonical_file "$required" "campaign input"
done
[ "$(sha256sum "$MANIFEST" | awk '{print $1}')" = "$OFFICIAL_MANIFEST_SHA256" ] || \
  die "official manifest hash mismatch"
[ "$(wc -l < "$MANIFEST" | tr -d ' ')" = "$OFFICIAL_ROWS" ] || \
  die "official manifest row count mismatch"

for key in $(env | cut -d= -f1); do
  case "$key" in
    RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_INCREMENTAL|CARGO_TARGET_DIR|LLVM_PROFILE_FILE|RUSTC|RUSTC_BOOTSTRAP|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_TARGET|CARGO_PROFILE_*)
      die "ambient build override is forbidden: $key"
      ;;
  esac
done

export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export RAYON_NUM_THREADS=1
export CARGO_BUILD_JOBS=1
export PYTHONDONTWRITEBYTECODE=1
umask 077

mkdir -p "$WORK_ROOT/runs"
mkdir "$RUN_ROOT" || die "fresh run root already exists: $RUN_ROOT"
ACTIVE_LOCK="$RUN_ROOT/.active"
mkdir "$ACTIVE_LOCK"
release_lock() {
  rmdir "$ACTIVE_LOCK" 2>/dev/null || true
}
trap release_lock EXIT

ARTIFACTS="$RUN_ROOT/artifacts"
mkdir "$ARTIFACTS"
TRAIN_MANIFEST="$ARTIFACTS/train.jsonl"
HOLDOUT_MANIFEST="$ARTIFACTS/holdout-goel.jsonl"
SPLIT_REPORT="$ARTIFACTS/split-report.json"

"$PYTHON_BIN" "$SPLITTER" "$MANIFEST" \
  --train-out "$TRAIN_MANIFEST" \
  --holdout-out "$HOLDOUT_MANIFEST" \
  --report-out "$SPLIT_REPORT" \
  --holdout-family 2018-Goel-hwbench \
  --max-train-per-family "$MAX_TRAIN_PER_FAMILY" \
  --max-train-source-bytes "$MAX_TRAIN_SOURCE_BYTES" \
  --rebase-root "$CORPUS_ROOT"

"$PYTHON_BIN" - "$SPLIT_REPORT" "$TRAINING_ROWS" "$HOLDOUT_ROWS" <<'PY_SPLIT'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
expected_training = int(sys.argv[2])
expected_holdout = int(sys.argv[3])
if report.get("schema_version") != "euf-viper.pgo-split.v1":
    raise SystemExit("split schema mismatch")
if report.get("family_disjoint") is not True:
    raise SystemExit("split is not family disjoint")
if report["counts"]["training"] != expected_training:
    raise SystemExit("training count mismatch")
if report["counts"]["holdout"] != expected_holdout:
    raise SystemExit("holdout count mismatch")
if report["families"]["holdout"] != ["2018-Goel-hwbench"]:
    raise SystemExit("holdout family mismatch")
if "2018-Goel-hwbench" in report["families"]["training"]:
    raise SystemExit("Goel leaked into PGO training")
PY_SPLIT

COMMIT_EPOCH="$(git show -s --format=%ct HEAD)"
STANDARD_TARGET="$ARTIFACTS/standard-target"
env \
  CARGO_TARGET_DIR="$STANDARD_TARGET" \
  CARGO_INCREMENTAL=0 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TERM_COLOR=never \
  RUSTC="$RUSTC_BIN" \
  SOURCE_DATE_EPOCH="$COMMIT_EPOCH" \
  "$CARGO_BIN" build \
    --manifest-path "$ROOT/Cargo.toml" \
    --release \
    --features fabric \
    --locked
STANDARD_BINARY="$ARTIFACTS/euf-viper-standard"
install -m 0755 "$STANDARD_TARGET/release/euf-viper" "$STANDARD_BINARY"

PGO_WORK="$ARTIFACTS/pgo-work"
PGO_BINARY="$ARTIFACTS/euf-viper-pgo"
PGO_REPORT="$ARTIFACTS/pgo-report.json"
"$PYTHON_BIN" "$PGO_BUILDER" "$TRAIN_MANIFEST" \
  --split-report "$SPLIT_REPORT" \
  --source-root "$CORPUS_ROOT" \
  --repository "$ROOT" \
  --output-root "$PGO_WORK" \
  --binary-out "$PGO_BINARY" \
  --report-out "$PGO_REPORT" \
  --cargo "$CARGO_BIN" \
  --rustc "$RUSTC_BIN" \
  --llvm-profdata "$LLVM_PROFDATA" \
  --training-repeats 1 \
  --solver-timeout "$TRAINING_TIMEOUT_S" \
  --build-timeout 3600 \
  "${PGO_SOLVER_ENV_ARGS[@]}" \
  --allow-unknown-training

RESULTS_CSV="$ARTIFACTS/goel-williams.csv"
RESULTS_SUMMARY="$ARTIFACTS/goel-williams.json"
EUF_VIPER_GIT_REVISION="$ACTUAL_REVISION" \
"$PYTHON_BIN" "$WILLIAMS_RUNNER" "$HOLDOUT_MANIFEST" \
  --arm viper-standard \
  --arm-arg "$STANDARD_BINARY" \
  --arm-arg fabric-solve \
  --arm-arg=--engine \
  --arm-arg cadical-up \
  --arm-arg '{input}' \
  "${WILLIAMS_SOLVER_ENV_ARGS[@]}" \
  --arm viper-pgo \
  --arm-arg "$PGO_BINARY" \
  --arm-arg fabric-solve \
  --arm-arg=--engine \
  --arm-arg cadical-up \
  --arm-arg '{input}' \
  "${WILLIAMS_SOLVER_ENV_ARGS[@]}" \
  --arm z3 \
  --arm-arg "$Z3_BIN" \
  --arm-arg=-smt2 \
  --arm-arg '{input}' \
  --arm yices2 \
  --arm-arg "$YICES_BIN" \
  --arm-arg '{input}' \
  --arm cvc5 \
  --arm-arg "$CVC5_BIN" \
  --arm-arg=--lang=smt2 \
  --arm-arg '{input}' \
  --blocks 1 \
  --timeout "$HOLDOUT_TIMEOUT_S" \
  --out "$RESULTS_CSV" \
  --summary "$RESULTS_SUMMARY"

PGO_DECISION="$ARTIFACTS/pgo-decision.json"
"$PYTHON_BIN" "$PGO_ADJUDICATOR" "$RESULTS_SUMMARY" \
  --expected-instances "$HOLDOUT_ROWS" \
  --out "$PGO_DECISION"

# Pin the complete execution closure again after the long-running timing block.
check_tool "$CARGO_BIN" "$CARGO_SHA256" "cargo"
check_tool "$RUSTC_BIN" "$RUSTC_SHA256" "rustc"
check_tool "$LLVM_PROFDATA" "$LLVM_PROFDATA_SHA256" "llvm-profdata"
check_tool "$PYTHON_BIN" "$PYTHON_SHA256" "python"
check_tool "$Z3_BIN" "$Z3_SHA256" "Z3"
check_tool "$YICES_BIN" "$YICES_SHA256" "Yices2"
check_tool "$CVC5_BIN" "$CVC5_SHA256" "cvc5"
check_file_hash "$COMPETITOR_RECEIPT" "$COMPETITOR_RECEIPT_SHA256" \
  "competitor bundle receipt"

CAMPAIGN_REPORT="$ARTIFACTS/campaign.json"
"$PYTHON_BIN" - \
  "$CAMPAIGN_REPORT" \
  "$ACTUAL_REVISION" \
  "$JOB_ID" \
  "$SPLIT_REPORT" \
  "$PGO_REPORT" \
  "$RESULTS_SUMMARY" \
  "$RESULTS_CSV" \
  "$PGO_DECISION" \
  "$STANDARD_BINARY" \
  "$PGO_BINARY" \
  "$Z3_BIN" \
  "$YICES_BIN" \
  "$CVC5_BIN" \
  "$CARGO_BIN" \
  "$RUSTC_BIN" \
  "$LLVM_PROFDATA" \
  "$PYTHON_BIN" \
  "$COMPETITOR_RECEIPT" <<'PY_CAMPAIGN'
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

(
    report_raw,
    revision,
    job_id,
    split_raw,
    pgo_raw,
    summary_raw,
    csv_raw,
    decision_raw,
    standard_raw,
    pgo_binary_raw,
    z3_raw,
    yices_raw,
    cvc5_raw,
    cargo_raw,
    rustc_raw,
    llvm_profdata_raw,
    python_raw,
    competitor_receipt_raw,
) = sys.argv[1:]


def artifact(path_raw: str) -> dict[str, object]:
    path = Path(path_raw)
    data = path.read_bytes()
    return {
        "bytes": len(data),
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


split = json.loads(Path(split_raw).read_text(encoding="ascii"))
pgo = json.loads(Path(pgo_raw).read_text(encoding="ascii"))
summary = json.loads(Path(summary_raw).read_text(encoding="utf-8"))
decision = json.loads(Path(decision_raw).read_text(encoding="ascii"))
expected_viper_environment = {
    "EUF_VIPER_FABRIC_ALLOCATION_FREE_ASSIGNMENTS": "0",
    "EUF_VIPER_FABRIC_CONSTRUCTION_VALIDATION": "0",
    "EUF_VIPER_FABRIC_DEMAND_FLUSH": "1",
    "EUF_VIPER_FABRIC_DISEQUALITY_PROPAGATION": "0",
    "EUF_VIPER_FABRIC_INDEXED_CLASS_MEMBERS": "1",
    "EUF_VIPER_FABRIC_LAZY_REASONS": "1",
    "EUF_VIPER_FABRIC_NARROW_MERGE_FRONTIER": "1",
    "EUF_VIPER_FABRIC_PAIR_FILTERED_IMPACT": "1",
    "EUF_VIPER_FABRIC_PROPAGATION_BATCH_UPDATES": "4",
    "EUF_VIPER_FABRIC_SPARSE_ROOT": "0",
}
if pgo.get("schema_version") != "euf-viper.rust-pgo.v1":
    raise SystemExit("PGO report schema mismatch")
if pgo["git"]["head"] != revision or not pgo["git"]["promotable"]:
    raise SystemExit("PGO artifact is not bound to the clean target revision")
if pgo["build_contract"]["solver_environment"] != expected_viper_environment:
    raise SystemExit("PGO training environment does not match the campaign contract")
for label, path_raw in (
    ("cargo", cargo_raw),
    ("rustc", rustc_raw),
    ("llvm_profdata", llvm_profdata_raw),
):
    if pgo["toolchain"][label]["sha256"] != artifact(path_raw)["sha256"]:
        raise SystemExit(f"PGO {label} hash does not match the campaign tool")
if summary.get("status") != "complete":
    raise SystemExit("Williams benchmark is incomplete")
if summary["accounting"]["wrong_answers"]:
    raise SystemExit("Williams benchmark contains wrong answers")
if summary["accounting"]["execution_errors"]:
    raise SystemExit("Williams benchmark contains execution errors")
for arm in ("viper-standard", "viper-pgo"):
    if summary["environment_overrides"][arm] != expected_viper_environment:
        raise SystemExit(f"{arm} environment does not match the campaign contract")
for arm in ("z3", "yices2", "cvc5"):
    if summary["environment_overrides"][arm]:
        raise SystemExit(f"unexpected environment overrides for {arm}")
summary_artifact = artifact(summary_raw)
if decision.get("schema_version") != "euf-viper.pgo-holdout-decision.v1":
    raise SystemExit("PGO decision schema mismatch")
if decision.get("status") != "complete":
    raise SystemExit("PGO decision is incomplete")
if decision.get("decision") not in {"promote", "reject"}:
    raise SystemExit("PGO decision is invalid")
if decision["input"]["summary_sha256"] != summary_artifact["sha256"]:
    raise SystemExit("PGO decision is not bound to the Williams summary")
if decision["input"]["expected_instances"] != 302:
    raise SystemExit("PGO decision instance contract mismatch")

payload = {
    "schema_version": "euf-viper.pgo-holdout-campaign.v1",
    "status": "complete",
    "completed_at": datetime.now(timezone.utc).isoformat(),
    "git_revision": revision,
    "slurm_job_id": int(job_id),
    "pgo_decision": decision["decision"],
    "contract": {
        "family_disjoint": True,
        "holdout_families": split["families"]["holdout"],
        "training_families": split["families"]["training"],
        "cold_process_timing": True,
        "williams_complete_blocks": 1,
        "viper_solver_environment": expected_viper_environment,
    },
    "artifacts": {
        "split_report": artifact(split_raw),
        "pgo_report": artifact(pgo_raw),
        "williams_summary": summary_artifact,
        "williams_csv": artifact(csv_raw),
        "pgo_decision": artifact(decision_raw),
        "standard_binary": artifact(standard_raw),
        "pgo_binary": artifact(pgo_binary_raw),
        "z3_binary": artifact(z3_raw),
        "yices2_binary": artifact(yices_raw),
        "cvc5_binary": artifact(cvc5_raw),
        "cargo_binary": artifact(cargo_raw),
        "rustc_binary": artifact(rustc_raw),
        "llvm_profdata_binary": artifact(llvm_profdata_raw),
        "python_binary": artifact(python_raw),
        "competitor_bundle_receipt": artifact(competitor_receipt_raw),
    },
}
data = (json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
report = Path(report_raw)
descriptor, temporary = tempfile.mkstemp(prefix=f".{report.name}.", dir=report.parent)
try:
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, report)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY_CAMPAIGN

printf 'complete campaign=%s revision=%s job=%s\n' \
  "$CAMPAIGN_REPORT" "$ACTUAL_REVISION" "$JOB_ID"
