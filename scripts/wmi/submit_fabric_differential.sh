#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REPOSITORY_URL="${EUF_VIPER_FABRIC_DIFF_REPOSITORY_URL:-https://github.com/nasqret/euf-viper.git}"
PUBLISHED_REF="${EUF_VIPER_FABRIC_DIFF_PUBLISHED_REF:-refs/heads/perf-viper-fabric-next}"
REQUESTED_WORK_ROOT="${EUF_VIPER_FABRIC_DIFF_WORK_ROOT:-}"
PARTITION="${EUF_VIPER_FABRIC_DIFF_PARTITION:-cpu_idle}"
WALL_TIME="${EUF_VIPER_FABRIC_DIFF_WALL_TIME:-12:00:00}"
RUN_ID="${EUF_VIPER_FABRIC_DIFF_RUN_ID:-}"
AUTHORIZATION_RECEIPT=""

GENERATOR_VERSION=1
CAMPAIGN_SEED=7640891576956012809
FIRST_CASE=0
CASE_COUNT=1000000
LAST_CASE=999999
SMOKE_REVISION=51fc7d31a0e499fc9ffc4c30bf9227e6b8c0fdcc
SMOKE_MANIFEST_SHA256=84364115fb1b169f96d3e78885ecbf4609e0d935f5aff21aa1b89cddb5d3e291
SMOKE_ROWS=2
SMOKE_JOB_ID=169653

usage() {
  cat >&2 <<'USAGE'
usage: submit_fabric_differential.sh --authorization-receipt RECEIPT.json
                                     [--run-id ID]

Submission is impossible without an explicit
euf-viper.fabric-differential-authorization.v1 receipt. That receipt must bind
the clean published target revision and the exact one-million-case command, and
must hash-bind the verified offline audit receipt for frozen Fabric shadow smoke
job 169653. This command submits; it has no implicit or receipt-free mode.
USAGE
}

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

canonical_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

safe_remote_value() {
  [[ "$1" =~ ^[A-Za-z0-9_./:@%+-]+$ ]]
}

absolute_remote_path() {
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *'/../'*|*/..) return 1 ;;
  esac
  safe_remote_value "$1"
}

validate_wall_time() {
  local hours minutes seconds remainder

  [[ "$1" =~ ^[0-9][0-9]:[0-5][0-9]:[0-5][0-9]$ ]] || return 1
  hours="${1%%:*}"
  remainder="${1#*:}"
  minutes="${remainder%%:*}"
  seconds="${remainder##*:}"
  ((10#$hours * 3600 + 10#$minutes * 60 + 10#$seconds > 0))
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --authorization-receipt)
      [ "$#" -ge 2 ] || { usage; die "--authorization-receipt requires a path"; }
      [ -z "$AUTHORIZATION_RECEIPT" ] || die "authorization receipt was specified twice"
      AUTHORIZATION_RECEIPT="$2"
      shift 2
      ;;
    --run-id)
      [ "$#" -ge 2 ] || { usage; die "--run-id requires an ID"; }
      [ -z "$RUN_ID" ] || die "run ID was specified twice"
      RUN_ID="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown argument: $1"
      ;;
  esac
done

[ -n "$AUTHORIZATION_RECEIPT" ] || {
  usage
  die "--authorization-receipt is required; Fabric differential submission is default-off"
}
[ "${EUF_VIPER_FABRIC_DIFF_ENABLE:-0}" = 1 ] || \
  die "Fabric differential submission is default-off; set EUF_VIPER_FABRIC_DIFF_ENABLE=1"
[ -n "$REQUESTED_WORK_ROOT" ] || \
  die "set EUF_VIPER_FABRIC_DIFF_WORK_ROOT to an absolute remote /work path"
absolute_remote_path "$REQUESTED_WORK_ROOT" || \
  die "EUF_VIPER_FABRIC_DIFF_WORK_ROOT must be a conservative absolute remote path"
case "$REQUESTED_WORK_ROOT" in
  /work/*) ;;
  *) die "EUF_VIPER_FABRIC_DIFF_WORK_ROOT must be below absolute /work" ;;
esac
safe_remote_value "$REMOTE_HOST" || die "remote host contains unsafe characters"
safe_remote_value "$REPOSITORY_URL" || die "repository URL contains unsafe characters"
safe_remote_value "$PUBLISHED_REF" || die "published ref contains unsafe characters"
case "$PUBLISHED_REF" in
  refs/heads/*) ;;
  *) die "published ref must be an explicit refs/heads/* name" ;;
esac
case "$PARTITION" in
  ''|*[!A-Za-z0-9_-]*) die "partition contains unsafe characters" ;;
esac
validate_wall_time "$WALL_TIME" || die "wall time must be a positive canonical HH:MM:SS value"

cd "$ROOT"
command -v git >/dev/null || die "git is required"
command -v ssh >/dev/null || die "ssh is required"
command -v python3 >/dev/null || die "python3 is required for authorization validation"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "repository must be completely clean before Fabric differential submission"
REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
canonical_revision "$REVISION" || die "HEAD is not a full lowercase Git revision"

LOCAL_SNAPSHOT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/euf-viper-fabric-diff.XXXXXX")"
cleanup_local_snapshots() {
  rm -f -- "$LOCAL_SNAPSHOT_ROOT/authorization.json" "$LOCAL_SNAPSHOT_ROOT/audited-smoke.json"
  rmdir "$LOCAL_SNAPSHOT_ROOT" 2>/dev/null || true
}
trap cleanup_local_snapshots EXIT HUP INT TERM

AUTHORIZATION_BINDING="$(python3 - \
  "$AUTHORIZATION_RECEIPT" \
  "$LOCAL_SNAPSHOT_ROOT" \
  "$REVISION" \
  "$GENERATOR_VERSION" \
  "$CAMPAIGN_SEED" \
  "$FIRST_CASE" \
  "$CASE_COUNT" \
  "$LAST_CASE" \
  "$SMOKE_REVISION" \
  "$SMOKE_MANIFEST_SHA256" \
  "$SMOKE_ROWS" \
  "$SMOKE_JOB_ID" <<'PY_AUTHORIZATION'
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    authorization_raw,
    snapshot_root_raw,
    target_revision,
    generator_raw,
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


def snapshot(path_raw: str, label: str) -> tuple[Path, bytes, str]:
    path = Path(os.path.abspath(os.path.expanduser(path_raw)))
    try:
        if path.resolve(strict=True) != path:
            raise SystemExit(f"{label} must use its canonical non-symlink path")
    except OSError as error:
        raise SystemExit(f"cannot resolve {label}: {error}") from error
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"{label} must be a regular file")
        if before.st_size <= 0 or before.st_size > 1024 * 1024:
            raise SystemExit(f"{label} size is outside the 1..1048576 byte bound")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            chunks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise SystemExit(f"{label} changed while being read")
    finally:
        os.close(descriptor)
    return path, b"".join(chunks), digest.hexdigest()


def parse(raw: bytes, label: str) -> dict[str, object]:
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


generator = int(generator_raw)
seed = int(seed_raw)
first = int(first_raw)
count = int(count_raw)
last = int(last_raw)
smoke_rows = int(smoke_rows_raw)
smoke_job = int(smoke_job_raw)
authorization_path, authorization_bytes, authorization_hash = snapshot(
    authorization_raw, "authorization receipt"
)
authorization = parse(authorization_bytes, "authorization receipt")

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
exact(target["generator_version"], generator, "authorized generator version")
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
audit_path, audit_bytes, audit_hash = snapshot(
    audited_smoke["receipt_path"], "smoke audit receipt"
)
exact(
    sha256(audited_smoke["receipt_sha256"], "authorized smoke receipt hash"),
    audit_hash,
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

audit = parse(audit_bytes, "smoke audit receipt")
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
exact(
    scope,
    {
        "stage": "F0",
        "mode": "semantic_substrate_shadow_census",
        "default_behavior_change": False,
        "solver_result_claim": False,
        "performance_claim": False,
        "promotion_claim": False,
        "solver_result_claims_allowed": 0,
        "verification": "complete_bound_shadow_census_artifact",
        "verified": True,
    },
    "smoke audit scope",
)

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

snapshot_root = Path(snapshot_root_raw)
for name, content in (
    ("authorization.json", authorization_bytes),
    ("audited-smoke.json", audit_bytes),
):
    output = snapshot_root / name
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
directory_descriptor = os.open(
    snapshot_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
)
try:
    os.fsync(directory_descriptor)
finally:
    os.close(directory_descriptor)

print(f"{authorization_hash}\t{audit_hash}")
PY_AUTHORIZATION
)"
IFS=$'\t' read -r AUTHORIZATION_SHA256 SMOKE_AUDIT_SHA256 <<<"$AUTHORIZATION_BINDING"
canonical_sha256 "$AUTHORIZATION_SHA256" || die "authorization validator returned an invalid hash"
canonical_sha256 "$SMOKE_AUDIT_SHA256" || die "authorization validator returned an invalid smoke audit hash"

PUBLISHED_LINE="$(git ls-remote --exit-code "$REPOSITORY_URL" "$PUBLISHED_REF")"
case "$PUBLISHED_LINE" in
  *$'\n'*) die "$PUBLISHED_REF resolved to multiple revisions" ;;
esac
PUBLISHED_REVISION="${PUBLISHED_LINE%%$'\t'*}"
canonical_revision "$PUBLISHED_REVISION" || die "published ref did not resolve to one commit"
[ "$REVISION" = "$PUBLISHED_REVISION" ] || \
  die "HEAD $REVISION is not the published $PUBLISHED_REF revision $PUBLISHED_REVISION"

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
absolute_remote_path "$REMOTE_HOME" || die "remote HOME is not a conservative absolute path"
REMOTE_HOME="$(ssh "$REMOTE_HOST" "readlink -f -- '$REMOTE_HOME'")"
absolute_remote_path "$REMOTE_HOME" || die "cannot canonicalize remote HOME"
REMOTE_WORK_ROOT="$(ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REQUESTED_WORK_ROOT'; test -d '$REQUESTED_WORK_ROOT'; test -w '$REQUESTED_WORK_ROOT'; readlink -f -- '$REQUESTED_WORK_ROOT'")"
absolute_remote_path "$REMOTE_WORK_ROOT" || die "cannot canonicalize remote Fabric differential work root"
case "$REMOTE_WORK_ROOT" in
  /work/*) ;;
  *) die "canonical Fabric differential work root must stay below absolute /work" ;;
esac
case "$REMOTE_WORK_ROOT" in
  "$REMOTE_HOME"|"$REMOTE_HOME"/*) die "Fabric differential work root must be outside remote HOME" ;;
esac

REQUESTED_CARGO="${EUF_VIPER_FABRIC_DIFF_REMOTE_CARGO:-$REMOTE_HOME/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/bin/cargo}"
REQUESTED_RUSTC="${EUF_VIPER_FABRIC_DIFF_REMOTE_RUSTC:-$REMOTE_HOME/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/bin/rustc}"
REQUESTED_PYTHON="${EUF_VIPER_FABRIC_DIFF_REMOTE_PYTHON:-/usr/bin/python3}"
for value in "$REQUESTED_CARGO" "$REQUESTED_RUSTC" "$REQUESTED_PYTHON"; do
  absolute_remote_path "$value" || die "remote tool paths must be conservative absolute paths: $value"
done
REMOTE_CARGO="$(ssh "$REMOTE_HOST" "readlink -f -- '$REQUESTED_CARGO'")"
REMOTE_RUSTC="$(ssh "$REMOTE_HOST" "readlink -f -- '$REQUESTED_RUSTC'")"
REMOTE_PYTHON="$(ssh "$REMOTE_HOST" "readlink -f -- '$REQUESTED_PYTHON'")"
for value in "$REMOTE_CARGO" "$REMOTE_RUSTC" "$REMOTE_PYTHON"; do
  absolute_remote_path "$value" || die "failed to canonicalize a remote tool path"
done
REMOTE_CARGO_SHA256="$(ssh "$REMOTE_HOST" "test -f '$REMOTE_CARGO' && test -x '$REMOTE_CARGO' && sha256sum '$REMOTE_CARGO' | awk '{print \$1}'")"
REMOTE_RUSTC_SHA256="$(ssh "$REMOTE_HOST" "test -f '$REMOTE_RUSTC' && test -x '$REMOTE_RUSTC' && sha256sum '$REMOTE_RUSTC' | awk '{print \$1}'")"
REMOTE_PYTHON_SHA256="$(ssh "$REMOTE_HOST" "test -f '$REMOTE_PYTHON' && test -x '$REMOTE_PYTHON' && sha256sum '$REMOTE_PYTHON' | awk '{print \$1}'")"
for value in "$REMOTE_CARGO_SHA256" "$REMOTE_RUSTC_SHA256" "$REMOTE_PYTHON_SHA256"; do
  canonical_sha256 "$value" || die "failed to pin a remote tool executable"
done
REMOTE_CARGO_VERSION="$(ssh "$REMOTE_HOST" "'$REMOTE_CARGO' --version")"
REMOTE_RUSTC_VERSION="$(ssh "$REMOTE_HOST" "'$REMOTE_RUSTC' --version")"
REMOTE_PYTHON_VERSION="$(ssh "$REMOTE_HOST" "'$REMOTE_PYTHON' --version 2>&1")"
case "$REMOTE_CARGO_VERSION" in
  'cargo 1.93.0 '*) ;;
  *) die "remote cargo must be version 1.93.0: $REMOTE_CARGO_VERSION" ;;
esac
case "$REMOTE_RUSTC_VERSION" in
  'rustc 1.93.0 '*) ;;
  *) die "remote rustc must be version 1.93.0: $REMOTE_RUSTC_VERSION" ;;
esac
case "$REMOTE_PYTHON_VERSION" in
  'Python 3.'*) ;;
  *) die "remote Python is not Python 3: $REMOTE_PYTHON_VERSION" ;;
esac
for value in "$REMOTE_CARGO_VERSION" "$REMOTE_RUSTC_VERSION" "$REMOTE_PYTHON_VERSION"; do
  case "$value" in
    *','*|*$'\n'*|*$'\r'*|*\'*) die "remote tool version cannot be exported safely: $value" ;;
  esac
done

REMOTE_WORK="$REMOTE_WORK_ROOT/checkouts/$REVISION"
REMOTE_CARGO_HOME="$REMOTE_WORK_ROOT/cargo-home"
ssh "$REMOTE_HOST" "set -euo pipefail
mkdir -p '$REMOTE_WORK_ROOT/checkouts' '$REMOTE_WORK_ROOT/runs' '$REMOTE_CARGO_HOME'
test ! -L '$REMOTE_CARGO_HOME'
test ! -e '$REMOTE_CARGO_HOME/config'
test ! -e '$REMOTE_CARGO_HOME/config.toml'
if [ ! -e '$REMOTE_WORK' ]; then
  git clone --quiet '$REPOSITORY_URL' '$REMOTE_WORK'
else
  test -d '$REMOTE_WORK/.git'
  test -z \"\$(git -C '$REMOTE_WORK' status --porcelain=v1 --untracked-files=all)\"
fi
git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'
git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'
test \"\$(git -C '$REMOTE_WORK' rev-parse --verify 'HEAD^{commit}')\" = '$REVISION'
test -z \"\$(git -C '$REMOTE_WORK' status --porcelain=v1 --untracked-files=all)\"
test -f '$REMOTE_WORK/scripts/wmi/euf_viper_fabric_differential.sbatch'
test ! -L '$REMOTE_WORK/scripts/wmi/euf_viper_fabric_differential.sbatch'
grep -Fqx 'channel = \"1.93.0\"' '$REMOTE_WORK/rust-toolchain.toml'
directory=\$(dirname '$REMOTE_WORK')
while :; do
  test ! -e \"\$directory/.cargo/config\"
  test ! -e \"\$directory/.cargo/config.toml\"
  [ \"\$directory\" = / ] && break
  directory=\$(dirname \"\$directory\")
done"

if [ -z "$RUN_ID" ]; then
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${REVISION:0:12}"
fi
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "run ID contains unsafe characters"
RUN_ROOT="$REMOTE_WORK_ROOT/runs/fabric-differential-$RUN_ID"
REMOTE_INPUTS="$RUN_ROOT/inputs"
REMOTE_AUTHORIZATION="$REMOTE_INPUTS/authorization.json"
REMOTE_SMOKE_AUDIT="$REMOTE_INPUTS/audited-smoke.json"
REMOTE_EXPECTED_BINARY="$REMOTE_INPUTS/euf-viper.preflight"
REMOTE_PREFLIGHT_BUILD="$RUN_ROOT/.preflight-build"
REMOTE_PREFLIGHT_HOME="$RUN_ROOT/.preflight-home"
REMOTE_JOB_HOME="$RUN_ROOT/.job-home"

ssh "$REMOTE_HOST" "set -euo pipefail; umask 077; test ! -e '$RUN_ROOT'; test ! -L '$RUN_ROOT'; mkdir '$RUN_ROOT'; mkdir '$REMOTE_INPUTS' '$REMOTE_PREFLIGHT_BUILD' '$REMOTE_PREFLIGHT_HOME' '$REMOTE_JOB_HOME'; mkdir '$REMOTE_PREFLIGHT_BUILD/target' '$REMOTE_PREFLIGHT_BUILD/tmp'"
ssh "$REMOTE_HOST" "set -euo pipefail; umask 077; test ! -e '$REMOTE_AUTHORIZATION.tmp'; cat > '$REMOTE_AUTHORIZATION.tmp'; chmod 0400 '$REMOTE_AUTHORIZATION.tmp'; mv '$REMOTE_AUTHORIZATION.tmp' '$REMOTE_AUTHORIZATION'" < "$LOCAL_SNAPSHOT_ROOT/authorization.json"
ssh "$REMOTE_HOST" "set -euo pipefail; umask 077; test ! -e '$REMOTE_SMOKE_AUDIT.tmp'; cat > '$REMOTE_SMOKE_AUDIT.tmp'; chmod 0400 '$REMOTE_SMOKE_AUDIT.tmp'; mv '$REMOTE_SMOKE_AUDIT.tmp' '$REMOTE_SMOKE_AUDIT'" < "$LOCAL_SNAPSHOT_ROOT/audited-smoke.json"
REMOTE_RECEIPT_HASHES="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_AUTHORIZATION' '$REMOTE_SMOKE_AUDIT' | awk '{print \$1}'")"
read -r REMOTE_AUTHORIZATION_SHA256 REMOTE_SMOKE_AUDIT_SHA256 <<<"$(printf '%s\n' "$REMOTE_RECEIPT_HASHES" | tr '\n' ' ')"
[ "$REMOTE_AUTHORIZATION_SHA256" = "$AUTHORIZATION_SHA256" ] || die "remote authorization upload hash mismatch"
[ "$REMOTE_SMOKE_AUDIT_SHA256" = "$SMOKE_AUDIT_SHA256" ] || die "remote smoke audit upload hash mismatch"

REMOTE_BUILD_PATH="$(dirname "$REMOTE_RUSTC"):$(dirname "$REMOTE_CARGO"):/usr/local/bin:/usr/bin:/bin"
SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$REVISION")"
canonical_positive_integer "$SOURCE_DATE_EPOCH" || die "revision timestamp is not canonical"
ssh "$REMOTE_HOST" "set -euo pipefail
cd '$REMOTE_WORK'
env -i HOME='$REMOTE_PREFLIGHT_HOME' TMPDIR='$REMOTE_PREFLIGHT_BUILD/tmp' LANG=C LC_ALL=C TZ=UTC PATH='$REMOTE_BUILD_PATH' CARGO_HOME='$REMOTE_CARGO_HOME' CARGO_TARGET_DIR='$REMOTE_PREFLIGHT_BUILD/target' CARGO_BUILD_JOBS=1 RUSTC='$REMOTE_RUSTC' RUSTFLAGS= CARGO_ENCODED_RUSTFLAGS= SOURCE_DATE_EPOCH='$SOURCE_DATE_EPOCH' '$REMOTE_CARGO' fetch --locked
env -i HOME='$REMOTE_PREFLIGHT_HOME' TMPDIR='$REMOTE_PREFLIGHT_BUILD/tmp' LANG=C LC_ALL=C TZ=UTC PATH='$REMOTE_BUILD_PATH' CARGO_HOME='$REMOTE_CARGO_HOME' CARGO_TARGET_DIR='$REMOTE_PREFLIGHT_BUILD/target' CARGO_BUILD_JOBS=1 CARGO_NET_OFFLINE=true RUSTC='$REMOTE_RUSTC' RUSTFLAGS= CARGO_ENCODED_RUSTFLAGS= SOURCE_DATE_EPOCH='$SOURCE_DATE_EPOCH' '$REMOTE_CARGO' build --release --locked --features fabric
test -f '$REMOTE_PREFLIGHT_BUILD/target/release/euf-viper'
test -x '$REMOTE_PREFLIGHT_BUILD/target/release/euf-viper'
install -m 0555 '$REMOTE_PREFLIGHT_BUILD/target/release/euf-viper' '$REMOTE_EXPECTED_BINARY'
test \"\$(git rev-parse --verify 'HEAD^{commit}')\" = '$REVISION'
test -z \"\$(git status --porcelain=v1 --untracked-files=all)\""

REMOTE_BINARY_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_EXPECTED_BINARY' | awk '{print \$1}'")"
JOB_SCRIPT_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/scripts/wmi/euf_viper_fabric_differential.sbatch' | awk '{print \$1}'")"
CARGO_TOML_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/Cargo.toml' | awk '{print \$1}'")"
CARGO_LOCK_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/Cargo.lock' | awk '{print \$1}'")"
RUST_TOOLCHAIN_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/rust-toolchain.toml' | awk '{print \$1}'")"
for value in "$REMOTE_BINARY_SHA256" "$JOB_SCRIPT_SHA256" "$CARGO_TOML_SHA256" \
  "$CARGO_LOCK_SHA256" "$RUST_TOOLCHAIN_SHA256"; do
  canonical_sha256 "$value" || die "remote build or source binding returned a malformed SHA-256"
done

[ "$(git rev-parse --verify 'HEAD^{commit}')" = "$REVISION" ] || \
  die "local revision drifted after authorization validation"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "local repository changed after authorization validation"
FINAL_PUBLISHED_LINE="$(git ls-remote --exit-code "$REPOSITORY_URL" "$PUBLISHED_REF")"
[ "$FINAL_PUBLISHED_LINE" = "$PUBLISHED_LINE" ] || \
  die "published target changed after authorization validation"
[ "$(ssh "$REMOTE_HOST" "git -C '$REMOTE_WORK' rev-parse --verify 'HEAD^{commit}'")" = "$REVISION" ] || \
  die "remote revision drifted after preflight build"
[ -z "$(ssh "$REMOTE_HOST" "git -C '$REMOTE_WORK' status --porcelain=v1 --untracked-files=all")" ] || \
  die "remote checkout changed after preflight build"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_CARGO' | awk '{print \$1}'")" = "$REMOTE_CARGO_SHA256" ] || \
  die "remote cargo target drifted before submission"
[ "$(ssh "$REMOTE_HOST" "'$REMOTE_CARGO' --version")" = "$REMOTE_CARGO_VERSION" ] || \
  die "remote cargo version drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_RUSTC' | awk '{print \$1}'")" = "$REMOTE_RUSTC_SHA256" ] || \
  die "remote rustc target drifted before submission"
[ "$(ssh "$REMOTE_HOST" "'$REMOTE_RUSTC' --version")" = "$REMOTE_RUSTC_VERSION" ] || \
  die "remote rustc version drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_PYTHON' | awk '{print \$1}'")" = "$REMOTE_PYTHON_SHA256" ] || \
  die "remote python target drifted before submission"
[ "$(ssh "$REMOTE_HOST" "'$REMOTE_PYTHON' --version 2>&1")" = "$REMOTE_PYTHON_VERSION" ] || \
  die "remote python version drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_EXPECTED_BINARY' | awk '{print \$1}'")" = "$REMOTE_BINARY_SHA256" ] || \
  die "remote preflight binary drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_AUTHORIZATION' | awk '{print \$1}'")" = "$AUTHORIZATION_SHA256" ] || \
  die "remote authorization receipt drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_SMOKE_AUDIT' | awk '{print \$1}'")" = "$SMOKE_AUDIT_SHA256" ] || \
  die "remote smoke audit receipt drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/scripts/wmi/euf_viper_fabric_differential.sbatch' | awk '{print \$1}'")" = "$JOB_SCRIPT_SHA256" ] || \
  die "remote job script drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/Cargo.toml' | awk '{print \$1}'")" = "$CARGO_TOML_SHA256" ] || \
  die "remote Cargo.toml drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/Cargo.lock' | awk '{print \$1}'")" = "$CARGO_LOCK_SHA256" ] || \
  die "remote Cargo.lock drifted before submission"
[ "$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/rust-toolchain.toml' | awk '{print \$1}'")" = "$RUST_TOOLCHAIN_SHA256" ] || \
  die "remote rust-toolchain.toml drifted before submission"

SUBMISSION_DIRECTORY="$ROOT/results/fabric-differential-submissions"
SUBMISSION_PATH="$SUBMISSION_DIRECTORY/$RUN_ID.json"
mkdir -p "$SUBMISSION_DIRECTORY"
[ ! -e "$SUBMISSION_PATH" ] && [ ! -L "$SUBMISSION_PATH" ] || \
  die "submission receipt already exists for run ID: $SUBMISSION_PATH"

JOB_ID=""
SBATCH_CLUSTER=""
SBATCH_RAW=""
write_receipt() {
  local status="$1"
  python3 - \
    "$SUBMISSION_PATH" \
    "$status" \
    "$RUN_ID" \
    "$REVISION" \
    "$PUBLISHED_REF" \
    "$REMOTE_HOST" \
    "$REMOTE_WORK_ROOT" \
    "$REMOTE_WORK" \
    "$RUN_ROOT" \
    "$AUTHORIZATION_SHA256" \
    "$SMOKE_AUDIT_SHA256" \
    "$REMOTE_CARGO" \
    "$REMOTE_CARGO_SHA256" \
    "$REMOTE_CARGO_VERSION" \
    "$REMOTE_RUSTC" \
    "$REMOTE_RUSTC_SHA256" \
    "$REMOTE_RUSTC_VERSION" \
    "$REMOTE_PYTHON" \
    "$REMOTE_PYTHON_SHA256" \
    "$REMOTE_PYTHON_VERSION" \
    "$REMOTE_CARGO_HOME" \
    "$REMOTE_BINARY_SHA256" \
    "$JOB_SCRIPT_SHA256" \
    "$PARTITION" \
    "$WALL_TIME" \
    "$JOB_ID" \
    "$SBATCH_CLUSTER" \
    "$SBATCH_RAW" <<'PY_SUBMISSION_RECEIPT'
import json
import os
import sys
import tempfile
from pathlib import Path

(
    output_raw,
    status,
    run_id,
    revision,
    published_ref,
    remote_host,
    work_root,
    remote_worktree,
    run_root,
    authorization_hash,
    smoke_audit_hash,
    cargo,
    cargo_hash,
    cargo_version,
    rustc,
    rustc_hash,
    rustc_version,
    python,
    python_hash,
    python_version,
    cargo_home,
    binary_hash,
    job_script_hash,
    partition,
    wall_time,
    job_id,
    cluster,
    sbatch_raw,
) = sys.argv[1:]

payload = {
    "schema": "euf-viper.fabric-differential-wmi-submission.v1",
    "status": status,
    "run_id": run_id,
    "revision": revision,
    "published_ref": published_ref,
    "remote_host": remote_host,
    "work_root": work_root,
    "remote_worktree": remote_worktree,
    "run_root": run_root,
    "campaign": {
        "generator_version": 1,
        "seed": 7640891576956012809,
        "first_case": 0,
        "case_count": 1000000,
        "last_case": 999999,
        "command": [
            "euf-viper",
            "fabric-differential",
            "--cases",
            "1000000",
            "--first",
            "0",
            "--seed",
            "7640891576956012809",
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
    "tools": {
        "cargo": {"path": cargo, "sha256": cargo_hash, "version": cargo_version},
        "rustc": {"path": rustc, "sha256": rustc_hash, "version": rustc_version},
        "python": {"path": python, "sha256": python_hash, "version": python_version},
        "cargo_home": cargo_home,
        "binary_sha256": binary_hash,
        "job_script_sha256": job_script_hash,
    },
    "slurm": {
        "job_id": int(job_id) if job_id else None,
        "cluster": cluster or None,
        "partition": partition,
        "wall_time": wall_time,
        "nodes": 1,
        "tasks": 1,
        "cpus_per_task": 1,
        "raw_submission": sbatch_raw or None,
    },
    "submission_state_may_be_incomplete": status != "submitted",
    "artifacts": {
        "root": f"{run_root}/artifacts",
        "stdout": f"{run_root}/artifacts/stdout.json",
        "metadata": f"{run_root}/artifacts/metadata.json",
        "hashes": f"{run_root}/artifacts/SHA256SUMS",
    },
}

output = Path(output_raw)
output.parent.mkdir(parents=True, exist_ok=True)
descriptor, temporary_raw = tempfile.mkstemp(
    prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
)
temporary = Path(temporary_raw)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        json.dump(
            payload,
            handle,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
finally:
    temporary.unlink(missing_ok=True)
PY_SUBMISSION_RECEIPT
}

write_receipt submission_intent
submission_failed() {
  local status=$?
  trap - ERR
  write_receipt submission_failed || true
  exit "$status"
}
trap submission_failed ERR

EXPORTS="HOME=$REMOTE_JOB_HOME,EUF_VIPER_FABRIC_DIFF_ENABLE=1,EUF_VIPER_FABRIC_DIFF_EXPECTED_REVISION=$REVISION,EUF_VIPER_FABRIC_DIFF_WORK_ROOT=$REMOTE_WORK_ROOT,EUF_VIPER_FABRIC_DIFF_RUN_ROOT=$RUN_ROOT,EUF_VIPER_FABRIC_DIFF_REMOTE_LOGIN_HOME=$REMOTE_HOME,EUF_VIPER_FABRIC_DIFF_CARGO=$REMOTE_CARGO,EUF_VIPER_FABRIC_DIFF_CARGO_SHA256=$REMOTE_CARGO_SHA256,EUF_VIPER_FABRIC_DIFF_CARGO_VERSION=$REMOTE_CARGO_VERSION,EUF_VIPER_FABRIC_DIFF_RUSTC=$REMOTE_RUSTC,EUF_VIPER_FABRIC_DIFF_RUSTC_SHA256=$REMOTE_RUSTC_SHA256,EUF_VIPER_FABRIC_DIFF_RUSTC_VERSION=$REMOTE_RUSTC_VERSION,EUF_VIPER_FABRIC_DIFF_PYTHON=$REMOTE_PYTHON,EUF_VIPER_FABRIC_DIFF_PYTHON_SHA256=$REMOTE_PYTHON_SHA256,EUF_VIPER_FABRIC_DIFF_PYTHON_VERSION=$REMOTE_PYTHON_VERSION,EUF_VIPER_FABRIC_DIFF_CARGO_HOME=$REMOTE_CARGO_HOME,EUF_VIPER_FABRIC_DIFF_EXPECTED_BINARY=$REMOTE_EXPECTED_BINARY,EUF_VIPER_FABRIC_DIFF_EXPECTED_BINARY_SHA256=$REMOTE_BINARY_SHA256,EUF_VIPER_FABRIC_DIFF_AUTHORIZATION_RECEIPT=$REMOTE_AUTHORIZATION,EUF_VIPER_FABRIC_DIFF_AUTHORIZATION_SHA256=$AUTHORIZATION_SHA256,EUF_VIPER_FABRIC_DIFF_SMOKE_AUDIT_RECEIPT=$REMOTE_SMOKE_AUDIT,EUF_VIPER_FABRIC_DIFF_SMOKE_AUDIT_SHA256=$SMOKE_AUDIT_SHA256,EUF_VIPER_FABRIC_DIFF_JOB_SCRIPT_SHA256=$JOB_SCRIPT_SHA256,EUF_VIPER_FABRIC_DIFF_CARGO_TOML_SHA256=$CARGO_TOML_SHA256,EUF_VIPER_FABRIC_DIFF_CARGO_LOCK_SHA256=$CARGO_LOCK_SHA256,EUF_VIPER_FABRIC_DIFF_RUST_TOOLCHAIN_SHA256=$RUST_TOOLCHAIN_SHA256,EUF_VIPER_FABRIC_DIFF_SEED=$CAMPAIGN_SEED,EUF_VIPER_FABRIC_DIFF_FIRST_CASE=$FIRST_CASE,EUF_VIPER_FABRIC_DIFF_CASE_COUNT=$CASE_COUNT,EUF_VIPER_FABRIC_DIFF_LAST_CASE=$LAST_CASE"

SBATCH_RAW="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes --nodes=1 --ntasks=1 --cpus-per-task=1 --partition='$PARTITION' --time='$WALL_TIME' --chdir='$REMOTE_WORK' --output='$RUN_ROOT/scheduler-%j.out' --error='$RUN_ROOT/scheduler-%j.err' --export='$EXPORTS' scripts/wmi/euf_viper_fabric_differential.sbatch")"
JOB_ID="${SBATCH_RAW%%;*}"
canonical_positive_integer "$JOB_ID" || die "sbatch returned an invalid job ID: $SBATCH_RAW"
if [ "$SBATCH_RAW" != "$JOB_ID" ]; then
  SBATCH_CLUSTER="${SBATCH_RAW#*;}"
  case "$SBATCH_CLUSTER" in
    ''|*[!A-Za-z0-9._-]*) die "sbatch returned an invalid cluster name: $SBATCH_RAW" ;;
  esac
fi

trap - ERR
write_receipt submitted
cat "$SUBMISSION_PATH"
