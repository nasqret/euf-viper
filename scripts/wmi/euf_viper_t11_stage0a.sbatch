#!/usr/bin/env bash
#SBATCH --job-name=euf-t11-stage0a
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=t11-stage0a-%j.out
#SBATCH --error=t11-stage0a-%j.err

set -euo pipefail
umask 077

[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
  echo "T11 Stage 0A requires Linux x86_64 semantics" >&2
  exit 2
}

REPO_ROOT_INPUT="${EUF_VIPER_T11_REPO_ROOT:?set absolute clean checkout root}"
RUN_BASE_INPUT="${EUF_VIPER_T11_RUN_BASE:?set absolute external run base}"
CARGO_HOME_INPUT="${CARGO_HOME:?set absolute external Cargo home}"
CORPUS_ROOT_INPUT="${EUF_VIPER_T11_CORPUS_ROOT:?set absolute frozen QF_UF corpus root}"
case "$REPO_ROOT_INPUT:$RUN_BASE_INPUT:$CARGO_HOME_INPUT:$CORPUS_ROOT_INPUT" in
  /*:/*:/*:/*) ;;
  *)
    echo "checkout, run base, Cargo home, and corpus root must be absolute" >&2
    exit 2
    ;;
esac
for directory in \
  "$REPO_ROOT_INPUT" "$RUN_BASE_INPUT" "$CARGO_HOME_INPUT" "$CORPUS_ROOT_INPUT"; do
  [ -d "$directory" ] || {
    echo "required directory is missing: $directory" >&2
    exit 2
  }
done
REPO_ROOT="$(cd "$REPO_ROOT_INPUT" && pwd -P)"
RUN_BASE="$(cd "$RUN_BASE_INPUT" && pwd -P)"
CARGO_HOME="$(cd "$CARGO_HOME_INPUT" && pwd -P)"
CORPUS_ROOT="$(cd "$CORPUS_ROOT_INPUT" && pwd -P)"
SUBMIT_ROOT="$(cd "${SLURM_SUBMIT_DIR:-$PWD}" && pwd -P)"
case "$RUN_BASE:$CARGO_HOME" in
  "$REPO_ROOT":*|"$REPO_ROOT"/*:*|*:"$REPO_ROOT"|*:"$REPO_ROOT"/*)
    echo "run base and Cargo home must be outside the checkout" >&2
    exit 2
    ;;
esac
[ "$SUBMIT_ROOT" = "$RUN_BASE" ] || {
  echo "submit directory must equal the external run base" >&2
  exit 2
}

export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1
export RUSTUP_TOOLCHAIN=1.93.0
export CARGO_HOME

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set exact T11 revision}"
CARGO="${EUF_VIPER_CARGO:?set absolute cargo path}"
CARGO_SHA256="${EUF_VIPER_CARGO_SHA256:?set cargo SHA-256}"
CARGO_VERSION="${EUF_VIPER_CARGO_VERSION:?set exact cargo version}"
RUSTC="${EUF_VIPER_RUSTC:?set absolute rustc path}"
RUSTC_SHA256="${EUF_VIPER_RUSTC_SHA256:?set rustc SHA-256}"
RUSTC_VERSION="${EUF_VIPER_RUSTC_VERSION:?set exact rustc version}"
PYTHON="${EUF_VIPER_PYTHON:?set absolute Python path}"
PYTHON_SHA256="${EUF_VIPER_PYTHON_SHA256:?set Python SHA-256}"
PYTHON_VERSION="${EUF_VIPER_PYTHON_VERSION:?set exact Python version}"
readonly \
  EXPECTED_REVISION CARGO CARGO_SHA256 CARGO_VERSION RUSTC RUSTC_SHA256 \
  RUSTC_VERSION PYTHON PYTHON_SHA256 PYTHON_VERSION

TARGET_RELATIVE_PATH="QF_UF/2018-Goel-hwbench/QF_UF_sokoban.2.prop1_ab_br_max.smt2"
TARGET_SHA256="cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112"
ATOM_MAP_SHA256="2fa9cabb8279cf59a9ca73cd254c0c60fe028753e8aa01d1794dd0c645167496"
BASELINE_CNF_SHA256="adb6885f8ee5d5230e81a3293d183bd4ae14d985f3df5bba9bc6c9fcd9fb1bb0"
BASELINE_PROBLEM_SHA256="652e7b303accb7396dd9dfd5fdf40d17abd523f4a87897609390b6aa94d33597"
readonly \
  TARGET_RELATIVE_PATH TARGET_SHA256 ATOM_MAP_SHA256 BASELINE_CNF_SHA256 \
  BASELINE_PROBLEM_SHA256

canonical_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
    *) return 0 ;;
  esac
}

require_sha256() {
  local path="$1"
  local expected="$2"
  local label="$3"
  [ "$(sha256sum "$path" | awk '{print $1}')" = "$expected" ] || {
    echo "$label SHA-256 mismatch" >&2
    return 1
  }
}

pinned_python() {
  /usr/bin/env -i LANG=C LC_ALL=C TZ=UTC \
    "$PYTHON" -I -S -B "$@"
}

[ "${#EXPECTED_REVISION}" -eq 40 ] || {
  echo "expected revision must be a full 40-character commit" >&2
  exit 2
}
case "$EXPECTED_REVISION" in
  *[!0-9a-f]*) echo "expected revision is not canonical" >&2; exit 2 ;;
esac
for digest in \
  "$CARGO_SHA256" "$RUSTC_SHA256" "$PYTHON_SHA256" "$TARGET_SHA256" \
  "$ATOM_MAP_SHA256" "$BASELINE_CNF_SHA256" "$BASELINE_PROBLEM_SHA256"; do
  canonical_sha256 "$digest" || {
    echo "required SHA-256 is not canonical" >&2
    exit 2
  }
done
case "$CARGO:$RUSTC:$PYTHON" in
  /*:/*:/*) ;;
  *) echo "cargo, rustc, and Python paths must be absolute" >&2; exit 2 ;;
esac
for executable in "$CARGO" "$RUSTC" "$PYTHON"; do
  [ -x "$executable" ] || {
    echo "required executable is missing: $executable" >&2
    exit 2
  }
done
require_sha256 "$CARGO" "$CARGO_SHA256" cargo || exit 2
require_sha256 "$RUSTC" "$RUSTC_SHA256" rustc || exit 2
require_sha256 "$PYTHON" "$PYTHON_SHA256" Python || exit 2
[ "$($CARGO --version)" = "$CARGO_VERSION" ] || {
  echo "cargo version mismatch" >&2
  exit 2
}
[ "$($RUSTC --version)" = "$RUSTC_VERSION" ] || {
  echo "rustc version mismatch" >&2
  exit 2
}
[ "$(pinned_python --version 2>&1)" = "$PYTHON_VERSION" ] || {
  echo "Python version mismatch" >&2
  exit 2
}

cd "$REPO_ROOT"
[ "$(git rev-parse HEAD^{commit})" = "$EXPECTED_REVISION" ] || {
  echo "T11 checkout revision mismatch" >&2
  exit 2
}
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || {
  echo "T11 checkout is dirty" >&2
  exit 2
}

RUNNER="$REPO_ROOT/scripts/wmi/euf_viper_t11_stage0a.sbatch"
VALIDATOR="$REPO_ROOT/scripts/bench/validate_t11_stage0a.py"
DESIGN_NOTE="$REPO_ROOT/research-vault/02-design/2026-07-17-t11-bounded-equality-resolution-compiler.md"
HASH_CONTRACT="$REPO_ROOT/research-vault/02-design/2026-07-17-t11-canonical-hash-contract.md"
AUDIT_CONTRACT="$REPO_ROOT/research-vault/02-design/2026-07-17-t11-external-audit-receipt.md"
for artifact in "$RUNNER" "$VALIDATOR" "$DESIGN_NOTE" "$HASH_CONTRACT" "$AUDIT_CONTRACT"; do
  [ -f "$artifact" ] || {
    echo "required T11 contract artifact is missing: $artifact" >&2
    exit 2
  }
done

TARGET="$CORPUS_ROOT/$TARGET_RELATIVE_PATH"
[ -f "$TARGET" ] && [ ! -L "$TARGET" ] || {
  echo "frozen T11 target is missing or is a symlink" >&2
  exit 2
}
SOURCE_BEFORE_SHA256="$(sha256sum "$TARGET" | awk '{print $1}')"
[ "$SOURCE_BEFORE_SHA256" = "$TARGET_SHA256" ] || {
  echo "frozen T11 target SHA-256 mismatch" >&2
  exit 2
}

SLURM_JOB_ID="${SLURM_JOB_ID:?T11 Stage 0A requires a SLURM job ID}"
case "$SLURM_JOB_ID" in
  ''|*[!0-9]*) echo "SLURM job ID must be decimal" >&2; exit 2 ;;
esac
RUN_ROOT="$RUN_BASE/t11-stage0a-$SLURM_JOB_ID"
mkdir -m 700 "$RUN_ROOT"
export CARGO_TARGET_DIR="$RUN_ROOT/target"
export RUSTC

BUILD_STDOUT="$RUN_ROOT/build.stdout"
BUILD_STDERR="$RUN_ROOT/build.stderr"
"$CARGO" build --locked --features certificates --release \
  >"$BUILD_STDOUT" 2>"$BUILD_STDERR"
BINARY="$CARGO_TARGET_DIR/release/euf-viper"
[ -x "$BINARY" ] || {
  echo "T11 certificate release binary was not produced" >&2
  exit 2
}
chmod 500 "$BINARY"
chmod 400 "$BUILD_STDOUT" "$BUILD_STDERR"

BUNDLE="$RUN_ROOT/projection-bundle.json"
RECEIPT="$RUN_ROOT/audit-receipt.json"
PROJECT_STDOUT="$RUN_ROOT/project.stdout"
PROJECT_STDERR="$RUN_ROOT/project.stderr"
AUDIT_STDOUT="$RUN_ROOT/audit.stdout"
AUDIT_STDERR="$RUN_ROOT/audit.stderr"
METADATA="$RUN_ROOT/metadata.json"
REJECTION="$RUN_ROOT/rejection.json"

seal_run_root() {
  chmod -R a-w "$RUN_ROOT"
  pinned_python -c \
    'import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(fd); os.close(fd)' \
    "$RUN_ROOT"
}

scientific_reject() {
  local reason="$1"
  local project_exit="$2"
  local audit_exit="$3"
  local source_after
  source_after="$(sha256sum "$TARGET" | awk '{print $1}')"
  for artifact in \
    "$BUILD_STDOUT" "$BUILD_STDERR" "$PROJECT_STDOUT" "$PROJECT_STDERR" \
    "$AUDIT_STDOUT" "$AUDIT_STDERR" "$BUNDLE" "$RECEIPT"; do
    [ ! -e "$artifact" ] || chmod 400 "$artifact"
  done
  pinned_python - \
    "$REJECTION" "$reason" "$project_exit" "$audit_exit" "$EXPECTED_REVISION" \
    "$SLURM_JOB_ID" "$TARGET" "$TARGET_RELATIVE_PATH" "$SOURCE_BEFORE_SHA256" \
    "$source_after" "$BINARY" "$BUNDLE" "$RECEIPT" "$PROJECT_STDOUT" \
    "$PROJECT_STDERR" "$AUDIT_STDOUT" "$AUDIT_STDERR" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


output = Path(sys.argv[1])
artifacts = {}
for label, raw_path in zip(
    ("binary", "bundle", "receipt", "project_stdout", "project_stderr", "audit_stdout", "audit_stderr"),
    sys.argv[11:18],
):
    path = Path(raw_path)
    if path.is_file():
        metadata = path.stat()
        artifacts[label] = {
            "path": str(path.resolve()),
            "bytes": metadata.st_size,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "sha256": sha256(path),
        }
payload = {
    "schema": "euf-viper.t11-stage0a-rejection.v1",
    "status": "rejected",
    "decision": "stop_before_stage0b",
    "reason": sys.argv[2],
    "project_exit": int(sys.argv[3]),
    "audit_exit": int(sys.argv[4]),
    "revision": sys.argv[5],
    "job_id": int(sys.argv[6]),
    "target": {
        "path": str(Path(sys.argv[7]).resolve()),
        "relative_path": sys.argv[8],
        "source_before_sha256": sys.argv[9],
        "source_after_sha256": sys.argv[10],
    },
    "artifacts": artifacts,
}
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
parent_fd = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    descriptor = os.open(
        output.name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=parent_fd,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise SystemExit("short rejection-record write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
  seal_run_root
  echo "T11 Stage 0A rejected: $reason" >&2
  echo "t11_stage0a_root=$RUN_ROOT"
  exit 3
}

set +e
/usr/bin/env -i LANG=C LC_ALL=C TZ=UTC \
  EUF_VIPER_T11_EQRES=clique-er-auto \
  "$BINARY" project-t11 "$TARGET" --bundle-out "$BUNDLE" \
  >"$PROJECT_STDOUT" 2>"$PROJECT_STDERR"
PROJECT_EXIT=$?
set -e
case "$PROJECT_EXIT" in
  4) ;;
  3) scientific_reject projector_rejected 3 -1 ;;
  *)
    echo "T11 projector violated its execution contract: $PROJECT_EXIT" >&2
    exit 2
    ;;
esac
[ -f "$BUNDLE" ] || {
  echo "T11 projector accepted without producing a bundle" >&2
  exit 2
}

set +e
/usr/bin/env -i LANG=C LC_ALL=C TZ=UTC \
  "$BINARY" audit-t11 "$TARGET" --bundle "$BUNDLE" --receipt-out "$RECEIPT" \
  >"$AUDIT_STDOUT" 2>"$AUDIT_STDERR"
AUDIT_EXIT=$?
set -e
case "$AUDIT_EXIT" in
  0) ;;
  3) scientific_reject external_auditor_rejected 4 3 ;;
  *)
    echo "T11 external auditor violated its execution contract: $AUDIT_EXIT" >&2
    exit 2
    ;;
esac
[ -f "$RECEIPT" ] || {
  echo "T11 external auditor accepted without producing a receipt" >&2
  exit 2
}

SOURCE_AFTER_SHA256="$(sha256sum "$TARGET" | awk '{print $1}')"
if [ "$SOURCE_AFTER_SHA256" != "$SOURCE_BEFORE_SHA256" ] \
  || [ "$SOURCE_AFTER_SHA256" != "$TARGET_SHA256" ]; then
  scientific_reject source_identity_changed 4 0
fi
chmod 400 \
  "$BUNDLE" "$RECEIPT" "$PROJECT_STDOUT" "$PROJECT_STDERR" \
  "$AUDIT_STDOUT" "$AUDIT_STDERR"

set +e
pinned_python "$VALIDATOR" \
  --source "$TARGET" \
  --bundle "$BUNDLE" \
  --receipt "$RECEIPT" \
  --binary "$BINARY" \
  --metadata-out "$METADATA" \
  --revision "$EXPECTED_REVISION" \
  --job-id "$SLURM_JOB_ID" \
  --target-relative-path "$TARGET_RELATIVE_PATH" \
  --source-before-sha256 "$SOURCE_BEFORE_SHA256" \
  --source-after-sha256 "$SOURCE_AFTER_SHA256" \
  --project-exit "$PROJECT_EXIT" \
  --audit-exit "$AUDIT_EXIT" \
  --cargo "$CARGO" \
  --cargo-sha256 "$CARGO_SHA256" \
  --cargo-version "$CARGO_VERSION" \
  --rustc "$RUSTC" \
  --rustc-sha256 "$RUSTC_SHA256" \
  --rustc-version "$RUSTC_VERSION" \
  --python "$PYTHON" \
  --python-sha256 "$PYTHON_SHA256" \
  --python-version "$PYTHON_VERSION" \
  --artifact "source=$TARGET" \
  --artifact "binary=$BINARY" \
  --artifact "cargo_toml=$REPO_ROOT/Cargo.toml" \
  --artifact "cargo_lock=$REPO_ROOT/Cargo.lock" \
  --artifact "design_note=$DESIGN_NOTE" \
  --artifact "hash_contract=$HASH_CONTRACT" \
  --artifact "audit_contract=$AUDIT_CONTRACT" \
  --artifact "runner=$RUNNER" \
  --artifact "validator=$VALIDATOR" \
  --artifact "build_stdout=$BUILD_STDOUT" \
  --artifact "build_stderr=$BUILD_STDERR" \
  --artifact "bundle=$BUNDLE" \
  --artifact "audit_receipt=$RECEIPT" \
  --artifact "project_stdout=$PROJECT_STDOUT" \
  --artifact "project_stderr=$PROJECT_STDERR" \
  --artifact "audit_stdout=$AUDIT_STDOUT" \
  --artifact "audit_stderr=$AUDIT_STDERR"
VALIDATION_EXIT=$?
set -e
case "$VALIDATION_EXIT" in
  0) ;;
  3) scientific_reject independent_validation_rejected 4 0 ;;
  *)
    echo "T11 Stage 0A validator violated its execution contract: $VALIDATION_EXIT" >&2
    exit 2
    ;;
esac

[ -f "$METADATA" ] && [ "$(stat -c '%a' "$METADATA")" = 400 ] || {
  echo "T11 Stage 0A metadata is missing or not immutable" >&2
  exit 2
}
seal_run_root

printf 't11_stage0a_root=%s\n' "$RUN_ROOT"
printf 't11_stage0a_revision=%s\n' "$EXPECTED_REVISION"
printf 't11_stage0a_target_sha256=%s\n' "$SOURCE_AFTER_SHA256"
printf 't11_stage0a_bundle_sha256=%s\n' "$(sha256sum "$BUNDLE" | awk '{print $1}')"
printf 't11_stage0a_receipt_sha256=%s\n' "$(sha256sum "$RECEIPT" | awk '{print $1}')"
