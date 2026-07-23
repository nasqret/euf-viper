#!/usr/bin/env bash
#SBATCH --job-name=euf-fabric-diff
#SBATCH --partition=cpu_idle
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=12:00:00
#SBATCH --output=results/fabric-differential-%j.out
#SBATCH --error=results/fabric-differential-%j.err

set -euo pipefail

GENERATOR_VERSION=1
CAMPAIGN_SEED=7640891576956012809
FIRST_CASE=0
CASE_COUNT=1000000
LAST_CASE=999999
SMOKE_REVISION=51fc7d31a0e499fc9ffc4c30bf9227e6b8c0fdcc
SMOKE_MANIFEST_SHA256=84364115fb1b169f96d3e78885ecbf4609e0d935f5aff21aa1b89cddb5d3e291
SMOKE_ROWS=2
SMOKE_JOB_ID=169653

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

canonical_nonnegative_integer() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
}

canonical_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
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
  resolved="$(readlink -f -- "$configured")" || die "cannot resolve $label: $configured"
  [ "$resolved" = "$configured" ] || die "$label must be its canonical path: $resolved"
}

canonical_executable() {
  canonical_file "$1" "$2"
  [ -x "$1" ] || die "$2 is not executable: $1"
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
  resolved="$(readlink -f -- "$configured")" || die "cannot resolve $label: $configured"
  [ "$resolved" = "$configured" ] || die "$label must be its canonical path: $resolved"
}

reject_ambient_cargo_configuration() {
  local directory
  local candidate

  for candidate in "$EUF_VIPER_FABRIC_DIFF_CARGO_HOME/config" \
    "$EUF_VIPER_FABRIC_DIFF_CARGO_HOME/config.toml"; do
    [ ! -e "$candidate" ] && [ ! -L "$candidate" ] || \
      die "ambient Cargo configuration is forbidden: $candidate"
  done
  directory="$(dirname "$ROOT")"
  while :; do
    for candidate in "$directory/.cargo/config" "$directory/.cargo/config.toml"; do
      [ ! -e "$candidate" ] && [ ! -L "$candidate" ] || \
        die "ambient Cargo configuration is forbidden: $candidate"
    done
    [ "$directory" = / ] && break
    directory="$(dirname "$directory")"
  done
}

[ "${EUF_VIPER_FABRIC_DIFF_ENABLE:-0}" = 1 ] || \
  die "Fabric differential WMI gate is default-off"

JOB_ID="${SLURM_JOB_ID:?run this wrapper under Slurm}"
ROOT="${SLURM_SUBMIT_DIR:?SLURM_SUBMIT_DIR is required}"
EXPECTED_REVISION="${EUF_VIPER_FABRIC_DIFF_EXPECTED_REVISION:?set expected revision}"
WORK_ROOT="${EUF_VIPER_FABRIC_DIFF_WORK_ROOT:?set work root}"
RUN_ROOT="${EUF_VIPER_FABRIC_DIFF_RUN_ROOT:?set run root}"
REMOTE_LOGIN_HOME="${EUF_VIPER_FABRIC_DIFF_REMOTE_LOGIN_HOME:?set remote login home}"
CARGO="${EUF_VIPER_FABRIC_DIFF_CARGO:?set pinned cargo}"
EXPECTED_CARGO_SHA256="${EUF_VIPER_FABRIC_DIFF_CARGO_SHA256:?set cargo SHA-256}"
EXPECTED_CARGO_VERSION="${EUF_VIPER_FABRIC_DIFF_CARGO_VERSION:?set cargo version}"
RUSTC="${EUF_VIPER_FABRIC_DIFF_RUSTC:?set pinned rustc}"
EXPECTED_RUSTC_SHA256="${EUF_VIPER_FABRIC_DIFF_RUSTC_SHA256:?set rustc SHA-256}"
EXPECTED_RUSTC_VERSION="${EUF_VIPER_FABRIC_DIFF_RUSTC_VERSION:?set rustc version}"
PYTHON="${EUF_VIPER_FABRIC_DIFF_PYTHON:?set pinned python}"
EXPECTED_PYTHON_SHA256="${EUF_VIPER_FABRIC_DIFF_PYTHON_SHA256:?set python SHA-256}"
EXPECTED_PYTHON_VERSION="${EUF_VIPER_FABRIC_DIFF_PYTHON_VERSION:?set python version}"
EUF_VIPER_FABRIC_DIFF_CARGO_HOME="${EUF_VIPER_FABRIC_DIFF_CARGO_HOME:?set Cargo home}"
EXPECTED_BINARY="${EUF_VIPER_FABRIC_DIFF_EXPECTED_BINARY:?set preflight binary}"
EXPECTED_BINARY_SHA256="${EUF_VIPER_FABRIC_DIFF_EXPECTED_BINARY_SHA256:?set binary SHA-256}"
AUTHORIZATION_RECEIPT="${EUF_VIPER_FABRIC_DIFF_AUTHORIZATION_RECEIPT:?set authorization receipt}"
EXPECTED_AUTHORIZATION_SHA256="${EUF_VIPER_FABRIC_DIFF_AUTHORIZATION_SHA256:?set authorization SHA-256}"
SMOKE_AUDIT_RECEIPT="${EUF_VIPER_FABRIC_DIFF_SMOKE_AUDIT_RECEIPT:?set smoke audit receipt}"
EXPECTED_SMOKE_AUDIT_SHA256="${EUF_VIPER_FABRIC_DIFF_SMOKE_AUDIT_SHA256:?set smoke audit SHA-256}"
EXPECTED_JOB_SCRIPT_SHA256="${EUF_VIPER_FABRIC_DIFF_JOB_SCRIPT_SHA256:?set job script SHA-256}"
EXPECTED_CARGO_TOML_SHA256="${EUF_VIPER_FABRIC_DIFF_CARGO_TOML_SHA256:?set Cargo.toml SHA-256}"
EXPECTED_CARGO_LOCK_SHA256="${EUF_VIPER_FABRIC_DIFF_CARGO_LOCK_SHA256:?set Cargo.lock SHA-256}"
EXPECTED_RUST_TOOLCHAIN_SHA256="${EUF_VIPER_FABRIC_DIFF_RUST_TOOLCHAIN_SHA256:?set rust-toolchain SHA-256}"
BOUND_SEED="${EUF_VIPER_FABRIC_DIFF_SEED:?set campaign seed}"
BOUND_FIRST_CASE="${EUF_VIPER_FABRIC_DIFF_FIRST_CASE:?set first case}"
BOUND_CASE_COUNT="${EUF_VIPER_FABRIC_DIFF_CASE_COUNT:?set case count}"
BOUND_LAST_CASE="${EUF_VIPER_FABRIC_DIFF_LAST_CASE:?set last case}"

canonical_revision "$EXPECTED_REVISION" || die "expected revision must be 40 lowercase hex digits"
for value in \
  "$EXPECTED_CARGO_SHA256" \
  "$EXPECTED_RUSTC_SHA256" \
  "$EXPECTED_PYTHON_SHA256" \
  "$EXPECTED_BINARY_SHA256" \
  "$EXPECTED_AUTHORIZATION_SHA256" \
  "$EXPECTED_SMOKE_AUDIT_SHA256" \
  "$EXPECTED_JOB_SCRIPT_SHA256" \
  "$EXPECTED_CARGO_TOML_SHA256" \
  "$EXPECTED_CARGO_LOCK_SHA256" \
  "$EXPECTED_RUST_TOOLCHAIN_SHA256"; do
  canonical_sha256 "$value" || die "all bound hashes must be lowercase SHA-256 values"
done
canonical_nonnegative_integer "$BOUND_FIRST_CASE" || die "first case must be canonical"
canonical_positive_integer "$BOUND_CASE_COUNT" || die "case count must be canonical and positive"
canonical_nonnegative_integer "$BOUND_LAST_CASE" || die "last case must be canonical"
[ "$BOUND_SEED" = "$CAMPAIGN_SEED" ] || die "campaign seed differs from the frozen gate"
[ "$BOUND_FIRST_CASE" = "$FIRST_CASE" ] || die "first case differs from the frozen gate"
[ "$BOUND_CASE_COUNT" = "$CASE_COUNT" ] || die "case count differs from the frozen gate"
[ "$BOUND_LAST_CASE" = "$LAST_CASE" ] || die "last case differs from the frozen gate"

[ "${SLURM_CPUS_PER_TASK:-}" = 1 ] || die "Fabric differential requires one allocated CPU"
[ "${SLURM_NTASKS:-1}" = 1 ] || die "Fabric differential requires one Slurm task"
[ -z "${SLURM_ARRAY_TASK_ID:-}" ] || die "Fabric differential must not run as an array task"

for value in "$ROOT" "$WORK_ROOT" "$RUN_ROOT" "$REMOTE_LOGIN_HOME" \
  "$EUF_VIPER_FABRIC_DIFF_CARGO_HOME"; do
  case "$value" in
    /*) ;;
    *) die "all root paths must be absolute: $value" ;;
  esac
  case "$value" in
    *'/../'*|*/..) die "root paths must not contain parent traversal: $value" ;;
  esac
done

canonical_directory "$WORK_ROOT" "Fabric differential work root"
canonical_directory "$RUN_ROOT" "Fabric differential run root"
canonical_directory "$REMOTE_LOGIN_HOME" "remote login home"
canonical_directory "$EUF_VIPER_FABRIC_DIFF_CARGO_HOME" "Fabric differential Cargo home"
ROOT="$(readlink -f -- "$ROOT")" || die "cannot resolve Slurm submit directory"
case "$WORK_ROOT" in
  /work/*) ;;
  *) die "Fabric differential work root must be below absolute /work" ;;
esac
case "$RUN_ROOT:$EUF_VIPER_FABRIC_DIFF_CARGO_HOME" in
  "$WORK_ROOT"/runs/*:"$WORK_ROOT"/cargo-home) ;;
  *) die "run artifacts and Cargo cache must stay below the /work campaign root" ;;
esac
case "$ROOT" in
  "$WORK_ROOT"/checkouts/"$EXPECTED_REVISION") ;;
  *) die "Slurm submit directory is not the exact-revision /work checkout" ;;
esac
for value in "$WORK_ROOT" "$RUN_ROOT" "$ROOT" "$EUF_VIPER_FABRIC_DIFF_CARGO_HOME"; do
  case "$value" in
    "$REMOTE_LOGIN_HOME"|"$REMOTE_LOGIN_HOME"/*)
      die "Fabric differential artifacts and build cache must stay outside remote HOME"
      ;;
  esac
done

canonical_executable "$CARGO" "pinned cargo"
canonical_executable "$RUSTC" "pinned rustc"
canonical_executable "$PYTHON" "pinned python"
canonical_executable "$EXPECTED_BINARY" "submit-time preflight binary"
canonical_file "$AUTHORIZATION_RECEIPT" "Fabric differential authorization receipt"
canonical_file "$SMOKE_AUDIT_RECEIPT" "audited Fabric smoke receipt"
case "$EXPECTED_BINARY:$AUTHORIZATION_RECEIPT:$SMOKE_AUDIT_RECEIPT" in
  "$RUN_ROOT"/inputs/euf-viper.preflight:"$RUN_ROOT"/inputs/authorization.json:"$RUN_ROOT"/inputs/audited-smoke.json) ;;
  *) die "binary and authorization inputs must use the exact run-root input paths" ;;
esac

ACTUAL_CARGO_SHA256="$(sha256sum "$CARGO" | awk '{print $1}')"
ACTUAL_RUSTC_SHA256="$(sha256sum "$RUSTC" | awk '{print $1}')"
ACTUAL_PYTHON_SHA256="$(sha256sum "$PYTHON" | awk '{print $1}')"
ACTUAL_BINARY_SHA256="$(sha256sum "$EXPECTED_BINARY" | awk '{print $1}')"
ACTUAL_AUTHORIZATION_SHA256="$(sha256sum "$AUTHORIZATION_RECEIPT" | awk '{print $1}')"
ACTUAL_SMOKE_AUDIT_SHA256="$(sha256sum "$SMOKE_AUDIT_RECEIPT" | awk '{print $1}')"
[ "$ACTUAL_CARGO_SHA256" = "$EXPECTED_CARGO_SHA256" ] || die "cargo hash mismatch"
[ "$ACTUAL_RUSTC_SHA256" = "$EXPECTED_RUSTC_SHA256" ] || die "rustc hash mismatch"
[ "$ACTUAL_PYTHON_SHA256" = "$EXPECTED_PYTHON_SHA256" ] || die "python hash mismatch"
[ "$ACTUAL_BINARY_SHA256" = "$EXPECTED_BINARY_SHA256" ] || die "preflight binary hash mismatch"
[ "$ACTUAL_AUTHORIZATION_SHA256" = "$EXPECTED_AUTHORIZATION_SHA256" ] || \
  die "authorization receipt hash mismatch"
[ "$ACTUAL_SMOKE_AUDIT_SHA256" = "$EXPECTED_SMOKE_AUDIT_SHA256" ] || \
  die "audited smoke receipt hash mismatch"

ACTUAL_CARGO_VERSION="$("$CARGO" --version)"
ACTUAL_RUSTC_VERSION="$("$RUSTC" --version)"
ACTUAL_PYTHON_VERSION="$("$PYTHON" --version 2>&1)"
[ "$ACTUAL_CARGO_VERSION" = "$EXPECTED_CARGO_VERSION" ] || die "cargo version mismatch"
[ "$ACTUAL_RUSTC_VERSION" = "$EXPECTED_RUSTC_VERSION" ] || die "rustc version mismatch"
[ "$ACTUAL_PYTHON_VERSION" = "$EXPECTED_PYTHON_VERSION" ] || die "python version mismatch"
case "$ACTUAL_CARGO_VERSION" in
  'cargo 1.93.0 '*) ;;
  *) die "Fabric differential requires cargo 1.93.0" ;;
esac
case "$ACTUAL_RUSTC_VERSION" in
  'rustc 1.93.0 '*) ;;
  *) die "Fabric differential requires rustc 1.93.0" ;;
esac
case "$ACTUAL_PYTHON_VERSION" in
  'Python 3.'*) ;;
  *) die "Fabric differential metadata requires Python 3" ;;
esac

cd "$ROOT"
[ "$(git rev-parse --show-toplevel)" = "$ROOT" ] || die "submit directory is not the repository root"
ACTUAL_REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
[ "$ACTUAL_REVISION" = "$EXPECTED_REVISION" ] || \
  die "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "exact-revision Fabric differential checkout must be completely clean"
ACTUAL_TREE="$(git rev-parse --verify 'HEAD^{tree}')"
canonical_revision "$ACTUAL_TREE" || die "Git tree identity is malformed"
grep -Fqx 'channel = "1.93.0"' rust-toolchain.toml || \
  die "rust-toolchain.toml does not pin Rust 1.93.0"

JOB_SCRIPT="$ROOT/scripts/wmi/euf_viper_fabric_differential.sbatch"
canonical_file "$ROOT/Cargo.toml" "Cargo.toml"
canonical_file "$ROOT/Cargo.lock" "Cargo.lock"
canonical_file "$ROOT/rust-toolchain.toml" "rust-toolchain.toml"
canonical_file "$JOB_SCRIPT" "Fabric differential job script"
[ "$(sha256sum "$JOB_SCRIPT" | awk '{print $1}')" = "$EXPECTED_JOB_SCRIPT_SHA256" ] || \
  die "job script hash mismatch"
[ "$(sha256sum Cargo.toml | awk '{print $1}')" = "$EXPECTED_CARGO_TOML_SHA256" ] || \
  die "Cargo.toml hash mismatch"
[ "$(sha256sum Cargo.lock | awk '{print $1}')" = "$EXPECTED_CARGO_LOCK_SHA256" ] || \
  die "Cargo.lock hash mismatch"
[ "$(sha256sum rust-toolchain.toml | awk '{print $1}')" = "$EXPECTED_RUST_TOOLCHAIN_SHA256" ] || \
  die "rust-toolchain.toml hash mismatch"
reject_ambient_cargo_configuration

"$PYTHON" - \
  "$AUTHORIZATION_RECEIPT" \
  "$SMOKE_AUDIT_RECEIPT" \
  "$EXPECTED_AUTHORIZATION_SHA256" \
  "$EXPECTED_SMOKE_AUDIT_SHA256" \
  "$EXPECTED_REVISION" \
  "$CAMPAIGN_SEED" \
  "$FIRST_CASE" \
  "$CASE_COUNT" \
  "$LAST_CASE" \
  "$SMOKE_REVISION" \
  "$SMOKE_MANIFEST_SHA256" \
  "$SMOKE_ROWS" \
  "$SMOKE_JOB_ID" <<'PY_VALIDATE_AUTHORIZATION'
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    authorization_raw,
    audit_raw,
    expected_authorization_hash,
    expected_audit_hash,
    target_revision,
    seed_raw,
    first_raw,
    count_raw,
    last_raw,
    smoke_revision,
    smoke_manifest_hash,
    smoke_rows_raw,
    smoke_job_raw,
) = sys.argv[1:]


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load(path_raw: str, expected_hash: str, label: str) -> dict[str, object]:
    path = Path(path_raw)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise SystemExit(f"{label} changed after shell snapshot")
    try:
        text = raw.decode("ascii", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid {label}: {error}") from error
    if type(value) is not dict:
        raise SystemExit(f"{label} must be a JSON object")
    return value


def fields(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise SystemExit(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise SystemExit(
            f"{label} fields differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def exact(actual: object, expected: object, label: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise SystemExit(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SystemExit(f"{label} must be a lowercase SHA-256")
    return value


def timestamp(value: object, label: str) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise SystemExit(f"{label} must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SystemExit(f"{label} is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise SystemExit(f"{label} must be UTC")
    return value


seed = int(seed_raw)
first = int(first_raw)
count = int(count_raw)
last = int(last_raw)
smoke_rows = int(smoke_rows_raw)
smoke_job = int(smoke_job_raw)
authorization = load(
    authorization_raw, expected_authorization_hash, "authorization receipt"
)
audit = load(audit_raw, expected_audit_hash, "smoke audit receipt")

fields(
    authorization,
    {
        "schema",
        "status",
        "decision",
        "authorization_id",
        "authorized_by",
        "authorized_at",
        "target",
        "audited_smoke",
    },
    "authorization receipt",
)
exact(
    authorization["schema"],
    "euf-viper.fabric-differential-authorization.v1",
    "authorization schema",
)
exact(authorization["status"], "authorized", "authorization status")
exact(
    authorization["decision"],
    "submit_one_wmi_fabric_differential",
    "authorization decision",
)
for name in ("authorization_id", "authorized_by"):
    value = authorization[name]
    if type(value) is not str or not value or any(ord(character) < 0x20 for character in value):
        raise SystemExit(f"authorization {name} must be a nonempty printable string")
timestamp(authorization["authorized_at"], "authorization timestamp")

target = fields(
    authorization["target"],
    {
        "revision",
        "generator_version",
        "seed",
        "first_case",
        "case_count",
        "last_case",
        "cpus_per_task",
        "command",
    },
    "authorization target",
)
exact(target["revision"], target_revision, "authorized target revision")
exact(target["generator_version"], 1, "authorized generator version")
exact(target["seed"], seed, "authorized seed")
exact(target["first_case"], first, "authorized first case")
exact(target["case_count"], count, "authorized case count")
exact(target["last_case"], last, "authorized last case")
exact(target["cpus_per_task"], 1, "authorized CPU count")
exact(
    target["command"],
    [
        "euf-viper",
        "fabric-differential",
        "--cases",
        str(count),
        "--first",
        str(first),
        "--seed",
        str(seed),
    ],
    "authorized command",
)

audited_smoke = fields(
    authorization["audited_smoke"],
    {
        "receipt_path",
        "receipt_sha256",
        "revision",
        "manifest_sha256",
        "rows",
        "job_id",
    },
    "authorization audited_smoke",
)
if type(audited_smoke["receipt_path"]) is not str or not audited_smoke[
    "receipt_path"
].startswith("/"):
    raise SystemExit("authorized smoke receipt path must be absolute")
exact(
    sha256(audited_smoke["receipt_sha256"], "authorized smoke receipt hash"),
    expected_audit_hash,
    "authorized smoke receipt hash",
)
exact(audited_smoke["revision"], smoke_revision, "authorized smoke revision")
exact(
    audited_smoke["manifest_sha256"],
    smoke_manifest_hash,
    "authorized smoke manifest",
)
exact(audited_smoke["rows"], smoke_rows, "authorized smoke rows")
exact(audited_smoke["job_id"], smoke_job, "authorized smoke job")

fields(
    audit,
    {
        "schema",
        "status",
        "scope",
        "revision",
        "corpus_mode",
        "job_id",
        "operator_expectations",
        "manifest",
        "bindings",
        "counts",
        "inputs",
        "audited_at",
    },
    "smoke audit receipt",
)
exact(audit["schema"], "euf-viper.fabric-shadow-offline-audit.v1", "smoke audit schema")
exact(audit["status"], "verified", "smoke audit status")
exact(audit["revision"], smoke_revision, "smoke audit revision")
exact(audit["corpus_mode"], "smoke", "smoke audit corpus mode")
exact(audit["job_id"], smoke_job, "smoke audit job")
timestamp(audit["audited_at"], "smoke audit timestamp")

scope = fields(
    audit["scope"],
    {
        "stage",
        "mode",
        "default_behavior_change",
        "solver_result_claim",
        "performance_claim",
        "promotion_claim",
        "solver_result_claims_allowed",
        "verification",
        "verified",
    },
    "smoke audit scope",
)
expected_scope = {
    "stage": "F0",
    "mode": "semantic_substrate_shadow_census",
    "default_behavior_change": False,
    "solver_result_claim": False,
    "performance_claim": False,
    "promotion_claim": False,
    "solver_result_claims_allowed": 0,
    "verification": "complete_bound_shadow_census_artifact",
    "verified": True,
}
exact(scope, expected_scope, "smoke audit scope")

expectations = fields(
    audit["operator_expectations"],
    {
        "revision",
        "manifest_sha256",
        "corpus_mode",
        "row_count",
        "slurm_job_id",
        "source",
    },
    "smoke audit operator expectations",
)
exact(expectations["revision"], smoke_revision, "operator smoke revision")
exact(expectations["manifest_sha256"], smoke_manifest_hash, "operator smoke manifest")
exact(expectations["corpus_mode"], "smoke", "operator smoke mode")
exact(expectations["row_count"], smoke_rows, "operator smoke rows")
exact(expectations["slurm_job_id"], smoke_job, "operator smoke job")
exact(expectations["source"], "independent_operator_input", "operator source")

manifest = fields(
    audit["manifest"], {"sha256", "rows", "corpus_root"}, "smoke audit manifest"
)
exact(manifest["sha256"], smoke_manifest_hash, "smoke manifest hash")
exact(manifest["rows"], smoke_rows, "smoke manifest rows")
if type(manifest["corpus_root"]) is not str or not manifest["corpus_root"].startswith("/"):
    raise SystemExit("smoke corpus root must be absolute")

bindings = fields(
    audit["bindings"],
    {
        "input_binding_sha256",
        "solver_sha256",
        "runner_sha256",
        "cargo_sha256",
        "rustc_sha256",
        "python_sha256",
    },
    "smoke audit bindings",
)
for name, value in bindings.items():
    sha256(value, f"smoke audit binding {name}")

counts = fields(
    audit["counts"],
    {
        "manifest_rows",
        "completed_rows",
        "error_rows",
        "missing_rows",
        "duplicate_rows",
        "solver_result_claims",
    },
    "smoke audit counts",
)
exact(counts["manifest_rows"], smoke_rows, "smoke manifest count")
exact(counts["completed_rows"], smoke_rows, "smoke completed count")
for name in ("error_rows", "missing_rows", "duplicate_rows", "solver_result_claims"):
    exact(counts[name], 0, f"smoke {name}")

inputs = fields(
    audit["inputs"],
    {"artifact_directory", "submission_receipt", "artifacts"},
    "smoke audit inputs",
)
if type(inputs["artifact_directory"]) is not str or not inputs["artifact_directory"].startswith("/"):
    raise SystemExit("smoke artifact directory must be absolute")
submission = fields(
    inputs["submission_receipt"], {"path", "sha256", "bytes"}, "smoke submission input"
)
if type(submission["path"]) is not str or not submission["path"].startswith("/"):
    raise SystemExit("smoke submission path must be absolute")
sha256(submission["sha256"], "smoke submission hash")
if type(submission["bytes"]) is not int or submission["bytes"] <= 0:
    raise SystemExit("smoke submission bytes must be a positive integer")
if type(inputs["artifacts"]) is not dict or set(inputs["artifacts"]) != {
    "fabric-shadow.jsonl",
    "summary.json",
    "slurm.json",
    "euf-viper",
    "stdout.log",
    "stderr.log",
}:
    raise SystemExit("smoke audited artifact set is incomplete")
for name, value in inputs["artifacts"].items():
    entry = fields(value, {"path", "sha256", "bytes"}, f"smoke artifact {name}")
    if type(entry["path"]) is not str or not entry["path"].startswith("/"):
        raise SystemExit(f"smoke artifact {name} path must be absolute")
    sha256(entry["sha256"], f"smoke artifact {name} hash")
    if type(entry["bytes"]) is not int or entry["bytes"] < 0:
        raise SystemExit(f"smoke artifact {name} bytes must be nonnegative")
PY_VALIDATE_AUTHORIZATION

umask 077
FINAL_ROOT="$RUN_ROOT/artifacts"
STAGING_ROOT="$RUN_ROOT/.artifacts.$JOB_ID.partial"
BUILD_ROOT="$RUN_ROOT/.build.$JOB_ID.partial"
RUNTIME_HOME="$RUN_ROOT/.runtime-home.$JOB_ID"
[ ! -e "$FINAL_ROOT" ] && [ ! -L "$FINAL_ROOT" ] || \
  die "refuse to replace published Fabric differential artifacts"
[ ! -e "$STAGING_ROOT" ] && [ ! -L "$STAGING_ROOT" ] || \
  die "job-specific artifact staging path already exists"
[ ! -e "$BUILD_ROOT" ] && [ ! -L "$BUILD_ROOT" ] || \
  die "job-specific build root already exists"
[ ! -e "$RUNTIME_HOME" ] && [ ! -L "$RUNTIME_HOME" ] || \
  die "job-specific runtime home already exists"
mkdir "$STAGING_ROOT" "$BUILD_ROOT" "$RUNTIME_HOME"
mkdir "$BUILD_ROOT/target" "$BUILD_ROOT/tmp" "$BUILD_ROOT/home"
case "$STAGING_ROOT:$BUILD_ROOT:$RUNTIME_HOME" in
  /work/*:/work/*:/work/*) ;;
  *) die "all Fabric differential job state must remain below /work" ;;
esac

BUILD_PATH="$(dirname "$RUSTC"):$(dirname "$CARGO"):/usr/local/bin:/usr/bin:/bin"
env -i \
  HOME="$BUILD_ROOT/home" \
  TMPDIR="$BUILD_ROOT/tmp" \
  LANG=C \
  LC_ALL=C \
  TZ=UTC \
  PATH="$BUILD_PATH" \
  CARGO_HOME="$EUF_VIPER_FABRIC_DIFF_CARGO_HOME" \
  CARGO_TARGET_DIR="$BUILD_ROOT/target" \
  CARGO_BUILD_JOBS=1 \
  CARGO_NET_OFFLINE=true \
  RUSTC="$RUSTC" \
  RUSTFLAGS= \
  CARGO_ENCODED_RUSTFLAGS= \
  SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$EXPECTED_REVISION")" \
  "$CARGO" build --release --locked --features fabric

REBUILT_BINARY="$BUILD_ROOT/target/release/euf-viper"
canonical_executable "$REBUILT_BINARY" "rebuilt Fabric differential binary"
REBUILT_BINARY_SHA256="$(sha256sum "$REBUILT_BINARY" | awk '{print $1}')"
[ "$REBUILT_BINARY_SHA256" = "$EXPECTED_BINARY_SHA256" ] || \
  die "rebuilt binary differs from the submit-time preflight binary"
PERSISTED_BINARY="$STAGING_ROOT/euf-viper"
install -m 0555 "$REBUILT_BINARY" "$PERSISTED_BINARY"
PERSISTED_BINARY_SHA256="$(sha256sum "$PERSISTED_BINARY" | awk '{print $1}')"
[ "$PERSISTED_BINARY_SHA256" = "$EXPECTED_BINARY_SHA256" ] || \
  die "persisted Fabric differential binary hash mismatch"
install -m 0444 "$AUTHORIZATION_RECEIPT" "$STAGING_ROOT/authorization.json"
install -m 0444 "$SMOKE_AUDIT_RECEIPT" "$STAGING_ROOT/audited-smoke.json"

STDOUT_CANDIDATE="$STAGING_ROOT/.stdout.$JOB_ID.tmp"
STDERR_CANDIDATE="$STAGING_ROOT/.stderr.$JOB_ID.tmp"
RUNTIME_PATH="/usr/local/bin:/usr/bin:/bin"
set +e
env -i \
  HOME="$RUNTIME_HOME" \
  TMPDIR="$RUNTIME_HOME" \
  LANG=C \
  LC_ALL=C \
  TZ=UTC \
  PATH="$RUNTIME_PATH" \
  OMP_NUM_THREADS=1 \
  OPENBLAS_NUM_THREADS=1 \
  MKL_NUM_THREADS=1 \
  NUMEXPR_NUM_THREADS=1 \
  RAYON_NUM_THREADS=1 \
  "$PERSISTED_BINARY" fabric-differential \
    --cases "$CASE_COUNT" \
    --first "$FIRST_CASE" \
    --seed "$CAMPAIGN_SEED" \
    >"$STDOUT_CANDIDATE" 2>"$STDERR_CANDIDATE"
COMMAND_STATUS=$?
set -e
[ "$COMMAND_STATUS" -eq 0 ] || \
  die "Fabric differential command returned nonzero status $COMMAND_STATUS"

"$PYTHON" - \
  "$STDOUT_CANDIDATE" \
  "$GENERATOR_VERSION" \
  "$CAMPAIGN_SEED" \
  "$FIRST_CASE" \
  "$CASE_COUNT" \
  "$LAST_CASE" <<'PY_VALIDATE_OUTPUT'
import json
import sys
from pathlib import Path

output_raw, generator_raw, seed_raw, first_raw, count_raw, last_raw = sys.argv[1:]


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


raw = Path(output_raw).read_bytes()
if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
    raise SystemExit("Fabric differential stdout must be exactly one newline-terminated JSON line")
try:
    text = raw.decode("ascii", errors="strict")
    payload = json.loads(
        text,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid Fabric differential stdout JSON: {error}") from error
if type(payload) is not dict:
    raise SystemExit("Fabric differential stdout must be a JSON object")

expected_fields = {
    "schema_version",
    "status",
    "generator_version",
    "seed",
    "first_case",
    "cases_run",
    "sat_cases",
    "unsat_cases",
    "abstained_cases",
    "oracle_cases",
    "oracle_skipped",
    "total_terms",
    "total_atoms",
    "total_expression_nodes",
    "campaign_fingerprint",
    "elapsed_ns",
}
actual_fields = set(payload)
if actual_fields != expected_fields:
    raise SystemExit(
        f"Fabric differential stdout fields differ: "
        f"missing={sorted(expected_fields - actual_fields)}, "
        f"extra={sorted(actual_fields - expected_fields)}"
    )
for name in expected_fields - {"status"}:
    if type(payload[name]) is not int or payload[name] < 0:
        raise SystemExit(f"Fabric differential {name} must be a nonnegative JSON integer")

generator = int(generator_raw)
seed = int(seed_raw)
first = int(first_raw)
count = int(count_raw)
last = int(last_raw)
if payload["schema_version"] != 1:
    raise SystemExit("Fabric differential schema version mismatch")
if payload["status"] != "complete":
    raise SystemExit("Fabric differential reported disagreement or an incomplete status")
if payload["generator_version"] != generator:
    raise SystemExit("Fabric differential generator version mismatch")
if payload["seed"] != seed:
    raise SystemExit("Fabric differential seed mismatch")
if payload["first_case"] != first:
    raise SystemExit("Fabric differential first case mismatch")
if payload["cases_run"] != count:
    raise SystemExit("Fabric differential case count mismatch")
if first + count - 1 != last:
    raise SystemExit("bound Fabric differential case range is inconsistent")
if payload["sat_cases"] + payload["unsat_cases"] != count:
    raise SystemExit("Fabric differential SAT/UNSAT counts do not cover the case range")
if payload["abstained_cases"] != 0:
    raise SystemExit("Fabric differential contains unchecked abstentions")
if payload["oracle_cases"] != count or payload["oracle_skipped"] != 0:
    raise SystemExit("Fabric differential finite-oracle counts are incomplete")
for name in ("total_terms", "total_atoms", "total_expression_nodes", "elapsed_ns"):
    if payload[name] <= 0:
        raise SystemExit(f"Fabric differential {name} must be positive")

canonical = json.dumps(
    payload,
    ensure_ascii=True,
    allow_nan=False,
    separators=(",", ":"),
)
if raw != (canonical + "\n").encode("ascii"):
    raise SystemExit("Fabric differential stdout is not canonical compact JSON")
PY_VALIDATE_OUTPUT

mv "$STDOUT_CANDIDATE" "$STAGING_ROOT/stdout.json"
mv "$STDERR_CANDIDATE" "$STAGING_ROOT/stderr.log"

[ "$(git rev-parse --verify 'HEAD^{commit}')" = "$EXPECTED_REVISION" ] || \
  die "repository revision drifted during Fabric differential"
[ "$(git rev-parse --verify 'HEAD^{tree}')" = "$ACTUAL_TREE" ] || \
  die "repository tree drifted during Fabric differential"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "repository changed during Fabric differential"
[ "$(sha256sum "$CARGO" | awk '{print $1}')" = "$EXPECTED_CARGO_SHA256" ] || \
  die "cargo changed during Fabric differential"
[ "$(sha256sum "$RUSTC" | awk '{print $1}')" = "$EXPECTED_RUSTC_SHA256" ] || \
  die "rustc changed during Fabric differential"
[ "$(sha256sum "$PYTHON" | awk '{print $1}')" = "$EXPECTED_PYTHON_SHA256" ] || \
  die "python changed during Fabric differential"
[ "$(sha256sum "$PERSISTED_BINARY" | awk '{print $1}')" = "$EXPECTED_BINARY_SHA256" ] || \
  die "binary changed during Fabric differential"
[ "$(sha256sum "$AUTHORIZATION_RECEIPT" | awk '{print $1}')" = "$EXPECTED_AUTHORIZATION_SHA256" ] || \
  die "authorization changed during Fabric differential"
[ "$(sha256sum "$SMOKE_AUDIT_RECEIPT" | awk '{print $1}')" = "$EXPECTED_SMOKE_AUDIT_SHA256" ] || \
  die "smoke audit changed during Fabric differential"

METADATA_CANDIDATE="$STAGING_ROOT/metadata.json"
HASHES_CANDIDATE="$STAGING_ROOT/SHA256SUMS"
"$PYTHON" - \
  "$METADATA_CANDIDATE" \
  "$HASHES_CANDIDATE" \
  "$STAGING_ROOT" \
  "$FINAL_ROOT" \
  "$EXPECTED_REVISION" \
  "$ACTUAL_TREE" \
  "$JOB_SCRIPT" \
  "$EXPECTED_JOB_SCRIPT_SHA256" \
  "$EXPECTED_CARGO_TOML_SHA256" \
  "$EXPECTED_CARGO_LOCK_SHA256" \
  "$EXPECTED_RUST_TOOLCHAIN_SHA256" \
  "$CARGO" \
  "$EXPECTED_CARGO_SHA256" \
  "$EXPECTED_CARGO_VERSION" \
  "$RUSTC" \
  "$EXPECTED_RUSTC_SHA256" \
  "$EXPECTED_RUSTC_VERSION" \
  "$PYTHON" \
  "$EXPECTED_PYTHON_SHA256" \
  "$EXPECTED_PYTHON_VERSION" \
  "$EUF_VIPER_FABRIC_DIFF_CARGO_HOME" \
  "$EXPECTED_BINARY_SHA256" \
  "$EXPECTED_AUTHORIZATION_SHA256" \
  "$EXPECTED_SMOKE_AUDIT_SHA256" \
  "$GENERATOR_VERSION" \
  "$CAMPAIGN_SEED" \
  "$FIRST_CASE" \
  "$CASE_COUNT" \
  "$LAST_CASE" \
  "$COMMAND_STATUS" <<'PY_METADATA'
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    metadata_raw,
    hashes_raw,
    staging_raw,
    final_raw,
    revision,
    tree,
    job_script_raw,
    job_script_hash,
    cargo_toml_hash,
    cargo_lock_hash,
    rust_toolchain_hash,
    cargo_raw,
    cargo_hash,
    cargo_version,
    rustc_raw,
    rustc_hash,
    rustc_version,
    python_raw,
    python_hash,
    python_version,
    cargo_home_raw,
    binary_hash,
    authorization_hash,
    smoke_audit_hash,
    generator_raw,
    seed_raw,
    first_raw,
    count_raw,
    last_raw,
    command_status_raw,
) = sys.argv[1:]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact(path: Path, final: Path) -> dict[str, object]:
    return {
        "path": str(final / path.name),
        "sha256": sha256(path),
        "bytes": path.stat().st_size,
    }


staging = Path(staging_raw)
final = Path(final_raw)
stdout_path = staging / "stdout.json"
stderr_path = staging / "stderr.log"
binary_path = staging / "euf-viper"
authorization_path = staging / "authorization.json"
smoke_audit_path = staging / "audited-smoke.json"
result = json.loads(stdout_path.read_text(encoding="ascii"))

payload = {
    "schema": "euf-viper.fabric-differential-wmi-run.v1",
    "status": "verified_complete",
    "revision": revision,
    "tree": tree,
    "source": {
        "job_script": {"path": job_script_raw, "sha256": job_script_hash},
        "cargo_toml_sha256": cargo_toml_hash,
        "cargo_lock_sha256": cargo_lock_hash,
        "rust_toolchain_sha256": rust_toolchain_hash,
    },
    "campaign": {
        "generator_version": int(generator_raw),
        "seed": int(seed_raw),
        "first_case": int(first_raw),
        "case_count": int(count_raw),
        "last_case": int(last_raw),
        "command": [
            str(final / "euf-viper"),
            "fabric-differential",
            "--cases",
            count_raw,
            "--first",
            first_raw,
            "--seed",
            seed_raw,
        ],
    },
    "authorization": {
        "receipt_sha256": authorization_hash,
        "audited_smoke_receipt_sha256": smoke_audit_hash,
        "smoke_revision": "51fc7d31a0e499fc9ffc4c30bf9227e6b8c0fdcc",
        "smoke_manifest_sha256": "84364115fb1b169f96d3e78885ecbf4609e0d935f5aff21aa1b89cddb5d3e291",
        "smoke_rows": 2,
        "smoke_job_id": 169653,
    },
    "execution": {
        "exit_code": int(command_status_raw),
        "single_core": True,
        "tasks": 1,
        "cpus_per_task": int(os.environ["SLURM_CPUS_PER_TASK"]),
        "thread_limits": {
            "OMP_NUM_THREADS": 1,
            "OPENBLAS_NUM_THREADS": 1,
            "MKL_NUM_THREADS": 1,
            "NUMEXPR_NUM_THREADS": 1,
            "RAYON_NUM_THREADS": 1,
            "CARGO_BUILD_JOBS": 1,
        },
        "build_cache_root": cargo_home_raw,
    },
    "tools": {
        "cargo": {"path": cargo_raw, "sha256": cargo_hash, "version": cargo_version},
        "rustc": {"path": rustc_raw, "sha256": rustc_hash, "version": rustc_version},
        "python": {
            "path": python_raw,
            "sha256": python_hash,
            "version": python_version,
        },
        "binary": {
            "path": str(final / "euf-viper"),
            "submit_preflight_sha256": binary_hash,
            "job_rebuild_sha256": sha256(binary_path),
        },
    },
    "slurm": {
        "job_id": os.environ["SLURM_JOB_ID"],
        "job_name": os.environ.get("SLURM_JOB_NAME"),
        "cluster": os.environ.get("SLURM_CLUSTER_NAME"),
        "partition": os.environ.get("SLURM_JOB_PARTITION"),
        "account": os.environ.get("SLURM_JOB_ACCOUNT"),
        "node_list": os.environ.get("SLURM_JOB_NODELIST"),
        "submit_dir": os.environ["SLURM_SUBMIT_DIR"],
    },
    "result": result,
    "artifacts": {
        "stdout": artifact(stdout_path, final),
        "stderr": artifact(stderr_path, final),
        "binary": artifact(binary_path, final),
        "authorization": artifact(authorization_path, final),
        "audited_smoke": artifact(smoke_audit_path, final),
    },
    "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}

metadata = Path(metadata_raw)
encoded = (
    json.dumps(payload, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True)
    + "\n"
).encode("ascii")
descriptor = os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as handle:
    handle.write(encoded)
    handle.flush()
    os.fsync(handle.fileno())

names = (
    "audited-smoke.json",
    "authorization.json",
    "euf-viper",
    metadata.name,
    "stderr.log",
    "stdout.json",
)
hashes = Path(hashes_raw)
descriptor = os.open(hashes, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as handle:
    for name in names:
        handle.write(f"{sha256(staging / name)}  {name}\n")
    handle.flush()
    os.fsync(handle.fileno())
PY_METADATA

(
  cd "$STAGING_ROOT"
  sha256sum -c SHA256SUMS
)
"$PYTHON" - "$STAGING_ROOT" <<'PY_FSYNC'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY_FSYNC

[ ! -e "$FINAL_ROOT" ] && [ ! -L "$FINAL_ROOT" ] || \
  die "refuse to replace published Fabric differential artifacts"
mv "$STAGING_ROOT" "$FINAL_ROOT"
"$PYTHON" - "$RUN_ROOT" <<'PY_FSYNC_PARENT'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY_FSYNC_PARENT

cat "$FINAL_ROOT/metadata.json"
