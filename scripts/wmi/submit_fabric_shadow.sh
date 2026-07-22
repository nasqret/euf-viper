#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REPOSITORY_URL="${EUF_VIPER_FABRIC_REPOSITORY_URL:-https://github.com/nasqret/euf-viper.git}"
PUBLISHED_REF="${EUF_VIPER_FABRIC_PUBLISHED_REF:-refs/heads/perf-viper-fabric}"
FROZEN_FULL_MANIFEST_SHA256="9c509b0ffd35a371738dbb31865f975b43350fca5f54393f7bb5014d450a08db"
REQUESTED_WORK_ROOT="${EUF_VIPER_FABRIC_WORK_ROOT:-}"
REQUESTED_CORPUS_ROOT="${EUF_VIPER_FABRIC_CORPUS_ROOT:-}"
FULL_MANIFEST="${EUF_VIPER_FABRIC_FULL_MANIFEST:-}"
SMOKE_MANIFEST="${EUF_VIPER_FABRIC_SMOKE_MANIFEST:-}"
PARTITION="${EUF_VIPER_FABRIC_PARTITION:-cpu_idle}"
DEPENDENCY="${EUF_VIPER_FABRIC_DEPENDENCY:-}"
RUN_ID="${EUF_VIPER_FABRIC_RUN_ID:-}"
RESUME="${EUF_VIPER_FABRIC_RESUME:-0}"
INSTANCE_TIMEOUT_S="${EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S:-60}"
MODE=full
MANIFEST=""
WALL_TIME=""

usage() {
  cat >&2 <<'USAGE'
usage: submit_fabric_shadow.sh [--full MANIFEST | --smoke MANIFEST]
                               [--run-id ID | --resume ID]

The full manifest defaults to EUF_VIPER_FABRIC_FULL_MANIFEST. An optional
EUF_VIPER_FABRIC_SMOKE_MANIFEST selects smoke mode when no mode flag is given.
USAGE
}

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

positive_integer() {
  case "$1" in
    ''|0|0*|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

canonical_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
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

positive_finite_decimal() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  python3 -c \
    'import math, sys; value = float(sys.argv[1]); raise SystemExit(not (math.isfinite(value) and value > 0))' \
    "$1"
}

MODE_EXPLICIT=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --full)
      [ "$#" -ge 2 ] || { usage; die "--full requires a remote manifest path"; }
      [ "$MODE_EXPLICIT" = 0 ] || die "choose exactly one of --full and --smoke"
      MODE=full
      MANIFEST="$2"
      MODE_EXPLICIT=1
      shift 2
      ;;
    --smoke)
      [ "$#" -ge 2 ] || { usage; die "--smoke requires a remote manifest path"; }
      [ "$MODE_EXPLICIT" = 0 ] || die "choose exactly one of --full and --smoke"
      MODE=smoke
      MANIFEST="$2"
      MODE_EXPLICIT=1
      shift 2
      ;;
    --run-id)
      [ "$#" -ge 2 ] || { usage; die "--run-id requires an ID"; }
      [ "$RESUME" = 0 ] || die "--run-id cannot be combined with resume mode"
      RUN_ID="$2"
      shift 2
      ;;
    --resume)
      [ "$#" -ge 2 ] || { usage; die "--resume requires the existing run ID"; }
      [ -z "$RUN_ID" ] || die "--resume cannot be combined with another run ID"
      RESUME=1
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

case "$RESUME" in
  0|1) ;;
  *) die "EUF_VIPER_FABRIC_RESUME must be 0 or 1" ;;
esac
positive_finite_decimal "$INSTANCE_TIMEOUT_S" || \
  die "EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S must be finite and positive"
if [ "$MODE_EXPLICIT" = 0 ]; then
  if [ -n "$SMOKE_MANIFEST" ]; then
    MODE=smoke
    MANIFEST="$SMOKE_MANIFEST"
  else
    MODE=full
    MANIFEST="$FULL_MANIFEST"
  fi
fi
[ -n "$MANIFEST" ] || \
  die "set EUF_VIPER_FABRIC_FULL_MANIFEST or pass --full/--smoke"
[ "${EUF_VIPER_FABRIC_SHADOW_ENABLE:-0}" = 1 ] || \
  die "Fabric shadow census is default-off; set EUF_VIPER_FABRIC_SHADOW_ENABLE=1"
[ -n "$REQUESTED_WORK_ROOT" ] || \
  die "set EUF_VIPER_FABRIC_WORK_ROOT to an absolute remote path outside HOME"
[ -n "$REQUESTED_CORPUS_ROOT" ] || \
  die "set EUF_VIPER_FABRIC_CORPUS_ROOT; remote corpus locations are never guessed"

absolute_remote_path "$REQUESTED_WORK_ROOT" || \
  die "EUF_VIPER_FABRIC_WORK_ROOT must be a conservative absolute remote path"
case "$REQUESTED_WORK_ROOT" in
  /work/*) ;;
  *) die "EUF_VIPER_FABRIC_WORK_ROOT must be below absolute /work" ;;
esac
absolute_remote_path "$REQUESTED_CORPUS_ROOT" || \
  die "EUF_VIPER_FABRIC_CORPUS_ROOT must be a conservative absolute remote path"
absolute_remote_path "$MANIFEST" || \
  die "Fabric manifest must be a conservative absolute remote path"
safe_remote_value "$REMOTE_HOST" || die "remote host contains unsafe characters"
safe_remote_value "$REPOSITORY_URL" || die "repository URL contains unsafe characters"
safe_remote_value "$PUBLISHED_REF" || die "published ref contains unsafe characters"
case "$PARTITION" in
  ''|*[!A-Za-z0-9_-]*) die "partition contains unsafe characters" ;;
esac
if [ -n "$DEPENDENCY" ]; then
  positive_integer "$DEPENDENCY" || die "dependency must be a canonical positive job ID"
fi

if [ "$MODE" = full ]; then
  WALL_TIME="${EUF_VIPER_FABRIC_FULL_WALL_TIME:-08:00:00}"
else
  WALL_TIME="${EUF_VIPER_FABRIC_SMOKE_WALL_TIME:-00:15:00}"
fi
validate_wall_time "$WALL_TIME" || die "wall time must be a positive canonical HH:MM:SS value"

cd "$ROOT"
command -v git >/dev/null || die "git is required"
command -v ssh >/dev/null || die "ssh is required"
command -v python3 >/dev/null || die "python3 is required for the local receipt"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "repository must be completely clean before Fabric WMI submission"
REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || die "HEAD is not a full lowercase Git revision"
PUBLISHED_LINE="$(git ls-remote --exit-code "$REPOSITORY_URL" "$PUBLISHED_REF")"
case "$PUBLISHED_LINE" in
  *$'\n'*) die "$PUBLISHED_REF resolved to multiple revisions" ;;
esac
PUBLISHED_REVISION="${PUBLISHED_LINE%%$'\t'*}"
[[ "$PUBLISHED_REVISION" =~ ^[0-9a-f]{40}$ ]] || die "published ref did not resolve to one commit"
[ "$REVISION" = "$PUBLISHED_REVISION" ] || \
  die "HEAD $REVISION is not the published $PUBLISHED_REF revision $PUBLISHED_REVISION"

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
absolute_remote_path "$REMOTE_HOME" || die "remote HOME is not a conservative absolute path"
REMOTE_HOME="$(ssh "$REMOTE_HOST" "readlink -f -- '$REMOTE_HOME'")"
absolute_remote_path "$REMOTE_HOME" || die "cannot canonicalize remote HOME"

REMOTE_WORK_ROOT="$(ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$REQUESTED_WORK_ROOT'; test -d '$REQUESTED_WORK_ROOT'; test -w '$REQUESTED_WORK_ROOT'; readlink -f -- '$REQUESTED_WORK_ROOT'")"
absolute_remote_path "$REMOTE_WORK_ROOT" || die "cannot canonicalize remote Fabric work root"
case "$REMOTE_WORK_ROOT" in
  /work/*) ;;
  *) die "canonical Fabric work root must stay below absolute /work" ;;
esac
case "$REMOTE_WORK_ROOT" in
  "$REMOTE_HOME"|"$REMOTE_HOME"/*) die "Fabric work root must be outside remote HOME" ;;
esac

REMOTE_CORPUS_ROOT="$(ssh "$REMOTE_HOST" "set -euo pipefail; test -d '$REQUESTED_CORPUS_ROOT'; test ! -L '$REQUESTED_CORPUS_ROOT'; test -r '$REQUESTED_CORPUS_ROOT'; test -x '$REQUESTED_CORPUS_ROOT'; readlink -f -- '$REQUESTED_CORPUS_ROOT'")"
absolute_remote_path "$REMOTE_CORPUS_ROOT" || die "cannot canonicalize remote Fabric corpus root"
case "$REMOTE_WORK_ROOT" in
  "$REMOTE_CORPUS_ROOT"|"$REMOTE_CORPUS_ROOT"/*)
    die "Fabric work root must stay outside the read-only corpus root"
    ;;
esac

REMOTE_MANIFEST="$(ssh "$REMOTE_HOST" "set -euo pipefail; test -f '$MANIFEST'; test ! -L '$MANIFEST'; test -r '$MANIFEST'; readlink -f -- '$MANIFEST'")"
absolute_remote_path "$REMOTE_MANIFEST" || die "cannot canonicalize remote Fabric manifest"
MANIFEST_INFO="$(ssh "$REMOTE_HOST" "set -euo pipefail; rows=\$(awk 'END {print NR}' '$REMOTE_MANIFEST'); hash=\$(sha256sum '$REMOTE_MANIFEST' | awk '{print \$1}'); printf '%s %s' \"\$rows\" \"\$hash\"")"
read -r EXPECTED_SOURCES MANIFEST_SHA256 <<<"$MANIFEST_INFO"
positive_integer "$EXPECTED_SOURCES" || die "remote Fabric manifest is empty or unreadable"
canonical_sha256 "$MANIFEST_SHA256" || die "could not pin remote Fabric manifest"
if [ "$MODE" = full ] && [ "$EXPECTED_SOURCES" != 7503 ]; then
  die "full Fabric manifest must contain exactly 7503 rows, got $EXPECTED_SOURCES"
fi
if [ "$MODE" = full ] && [ "$MANIFEST_SHA256" != "$FROZEN_FULL_MANIFEST_SHA256" ]; then
  die "full Fabric manifest does not match the frozen F0 SHA-256"
fi
if [ "$MODE" = smoke ] && [ "$EXPECTED_SOURCES" -gt 7503 ]; then
  die "smoke manifest cannot exceed the 7503-source full corpus"
fi

REQUESTED_CARGO="${EUF_VIPER_FABRIC_REMOTE_CARGO:-$REMOTE_HOME/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/bin/cargo}"
REQUESTED_RUSTC="${EUF_VIPER_FABRIC_REMOTE_RUSTC:-$REMOTE_HOME/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/bin/rustc}"
REQUESTED_PYTHON="${EUF_VIPER_FABRIC_REMOTE_PYTHON:-/usr/bin/python3}"
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

SHORT_REVISION="${REVISION:0:12}"
REMOTE_WORK="$REMOTE_WORK_ROOT/checkouts/$SHORT_REVISION"
ssh "$REMOTE_HOST" "set -euo pipefail
mkdir -p '$REMOTE_WORK_ROOT/checkouts' '$REMOTE_WORK_ROOT/runs'
if [ ! -d '$REMOTE_WORK/.git' ]; then
  git clone --quiet '$REPOSITORY_URL' '$REMOTE_WORK'
fi
git -C '$REMOTE_WORK' fetch --quiet origin '$REVISION'
git -C '$REMOTE_WORK' checkout --quiet --detach '$REVISION'
test \"\$(git -C '$REMOTE_WORK' rev-parse --verify 'HEAD^{commit}')\" = '$REVISION'
test -z \"\$(git -C '$REMOTE_WORK' status --porcelain=v1 --untracked-files=all)\"
test -f '$REMOTE_WORK/scripts/bench/run_fabric_shadow.py'
test ! -L '$REMOTE_WORK/scripts/bench/run_fabric_shadow.py'
grep -Fqx 'channel = \"1.93.0\"' '$REMOTE_WORK/rust-toolchain.toml'
mkdir -p '$REMOTE_WORK/results'"
RUNNER_SHA256="$(ssh "$REMOTE_HOST" "sha256sum '$REMOTE_WORK/scripts/bench/run_fabric_shadow.py' | awk '{print \$1}'")"
canonical_sha256 "$RUNNER_SHA256" || die "failed to pin the remote Fabric runner"

if [ -z "$RUN_ID" ]; then
  [ "$RESUME" = 0 ] || die "resume mode requires an explicit run ID"
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$SHORT_REVISION-$MODE"
fi
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "run ID contains unsafe characters"
RUN_ROOT="$REMOTE_WORK_ROOT/runs/fabric-shadow-$RUN_ID"
if [ "$RESUME" = 0 ]; then
  ssh "$REMOTE_HOST" "test ! -e '$RUN_ROOT' && test ! -L '$RUN_ROOT'"
else
  ssh "$REMOTE_HOST" "test -d '$RUN_ROOT/.artifacts.partial' && test ! -e '$RUN_ROOT/artifacts' && test -s '$RUN_ROOT/.artifacts.partial/fabric-shadow.jsonl'"
fi

SUBMISSION_TAG="$(date -u +%Y%m%dT%H%M%SZ)-$$"
SUBMISSION_DIRECTORY="$ROOT/results/fabric-shadow-submissions"
SUBMISSION_PATH="$SUBMISSION_DIRECTORY/$RUN_ID-$SUBMISSION_TAG.json"
mkdir -p "$SUBMISSION_DIRECTORY"
[ ! -e "$SUBMISSION_PATH" ] && [ ! -L "$SUBMISSION_PATH" ] || \
  die "local submission receipt already exists: $SUBMISSION_PATH"

JOB_ID=""
SBATCH_CLUSTER=""
SBATCH_RAW=""
write_receipt() {
  local status="$1"
  python3 - \
    "$SUBMISSION_PATH" \
    "$status" \
    "$RUN_ID" \
    "$MODE" \
    "$REVISION" \
    "$PUBLISHED_REF" \
    "$REMOTE_HOST" \
    "$REMOTE_WORK_ROOT" \
    "$REMOTE_WORK" \
    "$RUN_ROOT" \
    "$REMOTE_MANIFEST" \
    "$MANIFEST_SHA256" \
    "$EXPECTED_SOURCES" \
    "$INSTANCE_TIMEOUT_S" \
    "$REMOTE_CORPUS_ROOT" \
    "$REMOTE_CARGO" \
    "$REMOTE_CARGO_SHA256" \
    "$REMOTE_CARGO_VERSION" \
    "$REMOTE_RUSTC" \
    "$REMOTE_RUSTC_SHA256" \
    "$REMOTE_RUSTC_VERSION" \
    "$REMOTE_PYTHON" \
    "$REMOTE_PYTHON_SHA256" \
    "$REMOTE_PYTHON_VERSION" \
    "$RUNNER_SHA256" \
    "$PARTITION" \
    "$WALL_TIME" \
    "$DEPENDENCY" \
    "$RESUME" \
    "$JOB_ID" \
    "$SBATCH_CLUSTER" \
    "$SBATCH_RAW" <<'PY_RECEIPT'
import json
import os
import sys
import tempfile
from pathlib import Path

(
    output_raw,
    status,
    run_id,
    mode,
    revision,
    published_ref,
    remote_host,
    work_root,
    remote_worktree,
    run_root,
    manifest,
    manifest_hash,
    expected_sources,
    instance_timeout,
    corpus_root,
    cargo,
    cargo_hash,
    cargo_version,
    rustc,
    rustc_hash,
    rustc_version,
    python,
    python_hash,
    python_version,
    runner_hash,
    partition,
    wall_time,
    dependency,
    resume,
    job_id,
    cluster,
    sbatch_raw,
) = sys.argv[1:]

payload = {
    "schema": "euf-viper.fabric-shadow-wmi-submission.v1",
    "status": status,
    "run_id": run_id,
    "scope": {
        "stage": "F0",
        "mode": "semantic_substrate_shadow_census",
        "default_behavior_change": False,
        "solver_result_claim": False,
        "performance_claim": False,
        "promotion_claim": False,
        "solver_result_claims_allowed": 0,
    },
    "revision": revision,
    "published_ref": published_ref,
    "corpus_mode": mode,
    "remote_host": remote_host,
    "work_root": work_root,
    "remote_worktree": remote_worktree,
    "run_root": run_root,
    "manifest": {
        "path": manifest,
        "sha256": manifest_hash,
        "expected_sources": int(expected_sources),
        "corpus_root": corpus_root,
        "corpus_access": "read_only",
    },
    "tools": {
        "runner": {"sha256": runner_hash},
        "cargo": {"path": cargo, "sha256": cargo_hash, "version": cargo_version},
        "rustc": {"path": rustc, "sha256": rustc_hash, "version": rustc_version},
        "python": {
            "path": python,
            "sha256": python_hash,
            "version": python_version,
        },
    },
    "slurm": {
        "job_id": int(job_id) if job_id else None,
        "cluster": cluster or None,
        "partition": partition,
        "wall_time": wall_time,
        "dependency": f"afterok:{dependency}" if dependency else None,
        "cpus_per_task": 1,
        "runner_jobs": 1,
        "instance_timeout_s": float(instance_timeout),
        "raw_submission": sbatch_raw or None,
    },
    "resume": resume == "1",
    "submission_state_may_be_incomplete": status != "submitted",
    "artifacts": {
        "root": f"{run_root}/artifacts",
        "rows": f"{run_root}/artifacts/fabric-shadow.jsonl",
        "summary": f"{run_root}/artifacts/summary.json",
        "slurm": f"{run_root}/artifacts/slurm.json",
        "stdout": f"{run_root}/artifacts/stdout.log",
        "stderr": f"{run_root}/artifacts/stderr.log",
    },
}

output = Path(output_raw)
output.parent.mkdir(parents=True, exist_ok=True)
descriptor, temporary_raw = tempfile.mkstemp(
    prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
)
temporary = Path(temporary_raw)
try:
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        json.dump(
            payload,
            handle,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
finally:
    temporary.unlink(missing_ok=True)
PY_RECEIPT
}

write_receipt submission_intent
submission_failed() {
  local status=$?
  trap - ERR
  write_receipt submission_failed || true
  exit "$status"
}
trap submission_failed ERR

EXPORTS="HOME=$REMOTE_HOME,EUF_VIPER_FABRIC_SHADOW_ENABLE=1,EUF_VIPER_FABRIC_EXPECTED_REVISION=$REVISION,EUF_VIPER_FABRIC_WORK_ROOT=$REMOTE_WORK_ROOT,EUF_VIPER_FABRIC_RUN_ROOT=$RUN_ROOT,EUF_VIPER_FABRIC_MANIFEST=$REMOTE_MANIFEST,EUF_VIPER_FABRIC_CORPUS_ROOT=$REMOTE_CORPUS_ROOT,EUF_VIPER_FABRIC_MANIFEST_SHA256=$MANIFEST_SHA256,EUF_VIPER_FABRIC_EXPECTED_SOURCES=$EXPECTED_SOURCES,EUF_VIPER_FABRIC_MODE=$MODE,EUF_VIPER_FABRIC_RESUME=$RESUME,EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S=$INSTANCE_TIMEOUT_S,EUF_VIPER_FABRIC_CARGO=$REMOTE_CARGO,EUF_VIPER_FABRIC_CARGO_SHA256=$REMOTE_CARGO_SHA256,EUF_VIPER_FABRIC_CARGO_VERSION=$REMOTE_CARGO_VERSION,EUF_VIPER_FABRIC_RUSTC=$REMOTE_RUSTC,EUF_VIPER_FABRIC_RUSTC_SHA256=$REMOTE_RUSTC_SHA256,EUF_VIPER_FABRIC_RUSTC_VERSION=$REMOTE_RUSTC_VERSION,EUF_VIPER_FABRIC_PYTHON=$REMOTE_PYTHON,EUF_VIPER_FABRIC_PYTHON_SHA256=$REMOTE_PYTHON_SHA256,EUF_VIPER_FABRIC_PYTHON_VERSION=$REMOTE_PYTHON_VERSION"
DEPENDENCY_OPTION=""
if [ -n "$DEPENDENCY" ]; then
  DEPENDENCY_OPTION="--dependency=afterok:$DEPENDENCY"
fi

SBATCH_RAW="$(ssh "$REMOTE_HOST" "cd '$REMOTE_WORK' && sbatch --parsable --kill-on-invalid-dep=yes $DEPENDENCY_OPTION --partition='$PARTITION' --time='$WALL_TIME' --export='$EXPORTS' scripts/wmi/euf_viper_fabric_shadow.sbatch")"
JOB_ID="${SBATCH_RAW%%;*}"
positive_integer "$JOB_ID" || die "sbatch returned an invalid job ID: $SBATCH_RAW"
if [ "$SBATCH_RAW" != "$JOB_ID" ]; then
  SBATCH_CLUSTER="${SBATCH_RAW#*;}"
  case "$SBATCH_CLUSTER" in
    ''|*[!A-Za-z0-9._-]*) die "sbatch returned an invalid cluster name: $SBATCH_RAW" ;;
  esac
fi

trap - ERR
write_receipt submitted
cat "$SUBMISSION_PATH"
