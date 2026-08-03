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

readonly BOOTSTRAP_PYTHON=/usr/bin/python3
readonly TARGET_RELATIVE_PATH="QF_UF/2018-Goel-hwbench/QF_UF_sokoban.2.prop1_ab_br_max.smt2"
readonly TARGET_SHA256="cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112"
readonly ATOM_MAP_SHA256="2fa9cabb8279cf59a9ca73cd254c0c60fe028753e8aa01d1794dd0c645167496"
readonly BASELINE_CNF_SHA256="adb6885f8ee5d5230e81a3293d183bd4ae14d985f3df5bba9bc6c9fcd9fb1bb0"
readonly BASELINE_PROBLEM_SHA256="652e7b303accb7396dd9dfd5fdf40d17abd523f4a87897609390b6aa94d33597"

bootstrap_python() {
  /usr/bin/env -i \
    HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$BOOTSTRAP_PYTHON" -I -S -B "$@"
}

die() {
  local message="$*"
  echo "T11 Stage 0A infrastructure rejection: $message" >&2
  if [ "${RUN_ROOT_CREATED:-0}" = 1 ] &&
    [ "${TERMINAL_STATE:-running}" = running ]; then
    infrastructure_reject "$message" 2 ||
      echo "T11 Stage 0A could not persist its infrastructure rejection" >&2
  fi
  exit 2
}

canonical_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
    *) return 0 ;;
  esac
}

sha256_file() {
  bootstrap_python -c \
    'import hashlib,sys; h=hashlib.sha256(); f=open(sys.argv[1],"rb"); [h.update(b) for b in iter(lambda:f.read(1048576),b"")]; print(h.hexdigest())' \
    "$1"
}

require_sha256() {
  local path="$1"
  local expected="$2"
  local label="$3"
  [ -f "$path" ] && [ ! -L "$path" ] ||
    die "$label is missing, nonregular, or a symlink: $path"
  [ "$(sha256_file "$path")" = "$expected" ] ||
    die "$label SHA-256 mismatch"
}

canonical_directory() {
  local input="$1"
  local label="$2"
  case "$input" in
    /*) ;;
    *) die "$label must be absolute" ;;
  esac
  [ -d "$input" ] && [ ! -L "$input" ] || die "$label is missing or a symlink"
  (cd "$input" && pwd -P)
}

fsync_path() {
  local interpreter="$BOOTSTRAP_PYTHON"
  if [ "${PINNED_PYTHON_READY:-0}" = 1 ]; then
    interpreter="$PYTHON_SNAPSHOT"
  fi
  /usr/bin/env -i \
    HOME="${RUN_HOME:-/}" LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$interpreter" -I -S -B -c \
    'import os,sys; p=sys.argv[1]; flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0); flags|=getattr(os,"O_DIRECTORY",0) if os.path.isdir(p) else 0; fd=os.open(p,flags); os.fsync(fd); os.close(fd)' \
    "$1"
}

infrastructure_reject() {
  local reason="$1"
  local exit_code="${2:-2}"
  if [ "${INFRA_REJECTING:-0}" = 1 ]; then
    return 1
  fi
  INFRA_REJECTING=1
  if bootstrap_python - \
    "$RUN_ROOT" "$RUN_BASE" "$reason" "$exit_code" \
    "${STAGE0A_PHASE:-unknown}" "${SLURM_JOB_ID:-}" \
    "${LAUNCH_MANIFEST_SHA256:-}" "${EXPECTED_REVISION:-}" <<'PY'
import hashlib
import json
import os
import stat
import sys

root, base, reason, exit_code, phase, job_id, manifest, revision = sys.argv[1:]
output_name = "infrastructure-rejection.json"


def write_all(descriptor, data):
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise RuntimeError("short infrastructure-rejection write")
        offset += written


def artifact_inventory():
    entries = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            entries.append(
                {"kind": "vanished", "mode": None, "name": name, "size": None}
            )
            continue
        if stat.S_ISREG(metadata.st_mode):
            kind = "regular"
            size = metadata.st_size
        elif stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
            size = None
        elif stat.S_ISLNK(metadata.st_mode):
            kind = "symlink"
            size = None
        else:
            kind = "other"
            size = None
        entries.append(
            {
                "kind": kind,
                "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
                "name": name,
                "size": size,
            }
        )
    return entries


root_fd = os.open(
    root,
    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
)
base_fd = os.open(
    base,
    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
)
try:
    os.fchmod(root_fd, 0o700)
    inventory = artifact_inventory()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    rejection_fd = None
    for index in range(1000):
        output_name = (
            "infrastructure-rejection.json"
            if index == 0
            else f"infrastructure-rejection-{index}.json"
        )
        try:
            rejection_fd = os.open(output_name, flags, 0o600, dir_fd=root_fd)
            break
        except FileExistsError:
            continue
    if rejection_fd is None:
        raise RuntimeError("no fresh infrastructure rejection filename remains")
    payload = {
        "schema": "euf-viper.t11-stage0a-infrastructure-rejection.v1",
        "status": "rejected",
        "classification": "infrastructure",
        "decision": "stop_before_stage0b",
        "reason": reason,
        "exit_code": int(exit_code),
        "phase": phase,
        "job_id": int(job_id) if job_id.isdecimal() else None,
        "launch_manifest_sha256": manifest or None,
        "revision": revision or None,
        "record_file": output_name,
        "available_artifacts": inventory,
    }
    encoded = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    try:
        write_all(rejection_fd, encoded)
        os.fsync(rejection_fd)
        os.fchmod(rejection_fd, 0o400)
        os.fsync(rejection_fd)
    finally:
        os.close(rejection_fd)

    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        for name in files:
            path = os.path.join(current, name)
            metadata = os.lstat(path)
            if stat.S_ISREG(metadata.st_mode):
                os.chmod(
                    path,
                    stat.S_IMODE(metadata.st_mode) & ~0o222,
                    follow_symlinks=False,
                )
        for name in directories:
            path = os.path.join(current, name)
            metadata = os.lstat(path)
            if stat.S_ISDIR(metadata.st_mode):
                os.chmod(
                    path,
                    stat.S_IMODE(metadata.st_mode) & ~0o222,
                    follow_symlinks=False,
                )
        metadata = os.lstat(current)
        os.chmod(
            current,
            stat.S_IMODE(metadata.st_mode) & ~0o222,
            follow_symlinks=False,
        )

    os.fsync(root_fd)
    os.fsync(base_fd)
finally:
    os.close(base_fd)
    os.close(root_fd)
PY
  then
    TERMINAL_STATE=infrastructure_rejection
    return 0
  fi
  INFRA_REJECTING=0
  return 1
}

stage0a_exit_trap() {
  local status="$1"
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ] && [ "${RUN_ROOT_CREATED:-0}" = 1 ] &&
    [ "${TERMINAL_STATE:-running}" = running ]; then
    infrastructure_reject \
      "unexpected runner exit during ${STAGE0A_PHASE:-unknown}" "$status" || true
  fi
  exit "$status"
}

stage0a_signal() {
  die "received signal $1 during ${STAGE0A_PHASE:-unknown}"
}

readonly REPO_ROOT_INPUT="${EUF_VIPER_T11_REPO_ROOT:?set absolute clean checkout root}"
readonly RUN_BASE_INPUT="${EUF_VIPER_T11_RUN_BASE:?set absolute external run base}"
readonly CORPUS_ROOT_INPUT="${EUF_VIPER_T11_CORPUS_ROOT:?set absolute frozen QF_UF corpus root}"
readonly LAUNCH_MANIFEST_INPUT="${EUF_VIPER_T11_LAUNCH_MANIFEST:?set frozen launch manifest path}"
readonly LAUNCH_MANIFEST_SHA256="${EUF_VIPER_T11_LAUNCH_MANIFEST_SHA256:?set wrapper-frozen manifest SHA-256}"
readonly RUN_NONCE="${EUF_VIPER_T11_RUN_NONCE:?set wrapper-generated 128-bit run nonce}"
readonly SLURM_JOB_ID="${SLURM_JOB_ID:?T11 Stage 0A requires a SLURM job ID}"

[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] ||
  die "Stage 0A requires Linux x86_64"
case "$SLURM_JOB_ID" in
  ''|*[!0-9]*) die "SLURM job ID must be decimal" ;;
esac
case "$RUN_NONCE" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) die "run nonce must be exactly 128 bits of lowercase hexadecimal" ;;
esac
canonical_sha256 "$LAUNCH_MANIFEST_SHA256" ||
  die "launch manifest SHA-256 is not canonical"

readonly REPO_ROOT="$(canonical_directory "$REPO_ROOT_INPUT" "checkout root")"
readonly RUN_BASE="$(canonical_directory "$RUN_BASE_INPUT" "run base")"
readonly CORPUS_ROOT="$(canonical_directory "$CORPUS_ROOT_INPUT" "corpus root")"
readonly SUBMIT_ROOT="$(canonical_directory "${SLURM_SUBMIT_DIR:-$PWD}" "submit directory")"
[ "$SUBMIT_ROOT" = "$RUN_BASE" ] ||
  die "submit directory must equal the external run base"
case "$RUN_BASE" in
  "$REPO_ROOT"|"$REPO_ROOT"/*) die "run base must be outside the checkout" ;;
esac
case "$LAUNCH_MANIFEST_INPUT" in
  /*) ;;
  *) die "launch manifest path must be absolute" ;;
esac
[ -f "$LAUNCH_MANIFEST_INPUT" ] && [ ! -L "$LAUNCH_MANIFEST_INPUT" ] ||
  die "launch manifest is missing, nonregular, or a symlink"
readonly LAUNCH_MANIFEST="$(cd "$(dirname "$LAUNCH_MANIFEST_INPUT")" && pwd -P)/$(basename "$LAUNCH_MANIFEST_INPUT")"
[ "$(sha256_file "$LAUNCH_MANIFEST")" = "$LAUNCH_MANIFEST_SHA256" ] ||
  die "launch manifest differs from the wrapper-frozen SHA-256"

readonly VALIDATOR="$REPO_ROOT/scripts/bench/validate_t11_stage0a.py"
readonly EXEC_HELPER="$REPO_ROOT/scripts/bench/exec_t11_stage0a.py"
readonly SUBMITTER="$REPO_ROOT/scripts/wmi/submit_t11_stage0a.sh"
readonly REPO_RUNNER="$REPO_ROOT/scripts/wmi/euf_viper_t11_stage0a.sbatch"
readonly FINALIZER_SBATCH="$REPO_ROOT/scripts/wmi/euf_viper_t11_stage0a_finalize.sbatch"
readonly FINALIZER="$REPO_ROOT/scripts/bench/finalize_t11_stage0a.py"
readonly AUTHORIZER="$REPO_ROOT/scripts/bench/authorize_t11_stage0a.py"
readonly BUILD_CLOSURE_TOOL="$REPO_ROOT/scripts/bench/t11_build_closure.py"
readonly DESIGN_NOTE="$REPO_ROOT/research-vault/02-design/2026-07-17-t11-bounded-equality-resolution-compiler.md"
readonly HASH_CONTRACT="$REPO_ROOT/research-vault/02-design/2026-07-17-t11-canonical-hash-contract.md"
readonly AUDIT_CONTRACT="$REPO_ROOT/research-vault/02-design/2026-07-17-t11-external-audit-receipt.md"

readonly RUN_ROOT="$RUN_BASE/t11-stage0a-$SLURM_JOB_ID"
RUN_ROOT_CREATED=0
TERMINAL_STATE=running
INFRA_REJECTING=0
STAGE0A_PHASE=create_run_root
mkdir -m 700 "$RUN_ROOT"
RUN_ROOT_CREATED=1
trap 'stage0a_exit_trap "$?"' EXIT
trap 'stage0a_signal HUP' HUP
trap 'stage0a_signal INT' INT
trap 'stage0a_signal TERM' TERM
fsync_path "$RUN_BASE"
readonly RUN_HOME="$RUN_ROOT/home"
readonly RUN_TMP="$RUN_ROOT/tmp"
readonly PROVENANCE_ROOT="$RUN_ROOT/provenance"
mkdir -m 700 "$RUN_HOME" "$RUN_TMP" "$PROVENANCE_ROOT"
readonly LAUNCH_VALUES="$RUN_ROOT/launch.values"

snapshot_file() {
  local source="$1"
  local destination="$2"
  local expected_sha256="$3"
  local mode="$4"
  bootstrap_python - "$source" "$destination" "$expected_sha256" "$mode" <<'PY'
import hashlib
import os
import stat
import sys

source, destination, expected, raw_mode = sys.argv[1:]
mode = int(raw_mode, 8)
source_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
source_fd = os.open(source, source_flags)
parent_fd = os.open(
    os.path.dirname(destination),
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
)
destination_fd = None
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("snapshot source is not regular")
    destination_fd = os.open(
        os.path.basename(destination),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
        dir_fd=parent_fd,
    )
    digest = hashlib.sha256()
    copied = 0
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        offset = 0
        while offset < len(chunk):
            written = os.write(destination_fd, chunk[offset:])
            if written <= 0:
                raise RuntimeError("short provenance snapshot write")
            offset += written
        copied += len(chunk)
    after = os.fstat(source_fd)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(before) != identity(after) or copied != after.st_size:
        raise RuntimeError("snapshot source changed while copied")
    actual = digest.hexdigest()
    if actual != expected:
        raise RuntimeError(
            f"snapshot SHA-256 mismatch: expected {expected}, found {actual}"
        )
    os.fsync(destination_fd)
    os.fchmod(destination_fd, mode)
    os.fsync(destination_fd)
    os.fsync(parent_fd)
finally:
    if destination_fd is not None:
        os.close(destination_fd)
    os.close(parent_fd)
    os.close(source_fd)
PY
}

readonly LAUNCH_MANIFEST_SNAPSHOT="$PROVENANCE_ROOT/launch-manifest.json"
snapshot_file "$LAUNCH_MANIFEST" "$LAUNCH_MANIFEST_SNAPSHOT" \
  "$LAUNCH_MANIFEST_SHA256" 0400 || die "could not snapshot launch manifest"
readonly BOOTSTRAP_VALIDATOR_SHA256="$(
  bootstrap_python -c \
    'import json,sys; v=json.load(open(sys.argv[1],"rb")); print(v["artifacts"]["validator_sha256"])' \
    "$LAUNCH_MANIFEST_SNAPSHOT"
)"
canonical_sha256 "$BOOTSTRAP_VALIDATOR_SHA256" ||
  die "manifest validator digest is malformed"
readonly VALIDATOR_SNAPSHOT="$PROVENANCE_ROOT/validate_t11_stage0a.py"
snapshot_file "$VALIDATOR" "$VALIDATOR_SNAPSHOT" \
  "$BOOTSTRAP_VALIDATOR_SHA256" 0500 || die "could not snapshot validator"

STAGE0A_PHASE=inspect_launch_manifest
set +e
bootstrap_python "$VALIDATOR_SNAPSHOT" inspect-launch \
  --launch-manifest "$LAUNCH_MANIFEST_SNAPSHOT" \
  --launch-manifest-sha256 "$LAUNCH_MANIFEST_SHA256" >"$LAUNCH_VALUES"
INSPECT_EXIT=$?
set -e
[ "$INSPECT_EXIT" -eq 0 ] || die "strict launch-manifest inspection failed"
chmod 400 "$LAUNCH_VALUES"
fsync_path "$LAUNCH_VALUES"
mapfile -d '' -t LAUNCH <"$LAUNCH_VALUES"
[ "${#LAUNCH[@]}" -eq 56 ] || die "launch inspector returned the wrong field count"

readonly EXPECTED_REVISION="${LAUNCH[0]}"
readonly CARGO_HOME="${LAUNCH[1]}"
readonly RUSTUP_HOME="${LAUNCH[2]}"
readonly CARGO="${LAUNCH[3]}"
readonly CARGO_SHA256="${LAUNCH[4]}"
readonly CARGO_VERSION="${LAUNCH[5]}"
readonly RUSTC="${LAUNCH[6]}"
readonly RUSTC_SHA256="${LAUNCH[7]}"
readonly RUSTC_VERSION="${LAUNCH[8]}"
readonly PYTHON="${LAUNCH[9]}"
readonly PYTHON_SHA256="${LAUNCH[10]}"
readonly PYTHON_VERSION="${LAUNCH[11]}"
readonly SUBMITTER_SHA256="${LAUNCH[12]}"
readonly RUNNER_SHA256="${LAUNCH[13]}"
readonly FINALIZER_SBATCH_SHA256="${LAUNCH[14]}"
readonly FINALIZER_SHA256="${LAUNCH[15]}"
readonly AUTHORIZER_SHA256="${LAUNCH[16]}"
readonly VALIDATOR_SHA256="${LAUNCH[17]}"
readonly EXEC_HELPER_SHA256="${LAUNCH[18]}"
readonly BUILD_CLOSURE_TOOL_SHA256="${LAUNCH[19]}"
readonly CARGO_TOML_SHA256="${LAUNCH[20]}"
readonly CARGO_LOCK_SHA256="${LAUNCH[21]}"
readonly DESIGN_NOTE_SHA256="${LAUNCH[22]}"
readonly HASH_CONTRACT_SHA256="${LAUNCH[23]}"
readonly AUDIT_CONTRACT_SHA256="${LAUNCH[24]}"
readonly BUILD_CLOSURE="${LAUNCH[25]}"
readonly BUILD_CLOSURE_SHA256="${LAUNCH[26]}"
readonly BUILD_CLOSURE_MANIFEST_SHA256="${LAUNCH[27]}"
readonly BUILD_CLOSURE_REVISION="${LAUNCH[28]}"
readonly CONTROL_GIT="${LAUNCH[29]}"
readonly CONTROL_GIT_SHA256="${LAUNCH[30]}"
readonly CONTROL_GIT_VERSION="${LAUNCH[31]}"

for digest in \
  "$CARGO_SHA256" "$RUSTC_SHA256" "$PYTHON_SHA256" "$RUNNER_SHA256" \
  "$SUBMITTER_SHA256" "$VALIDATOR_SHA256" "$EXEC_HELPER_SHA256" \
  "$FINALIZER_SBATCH_SHA256" "$FINALIZER_SHA256" "$AUTHORIZER_SHA256" \
  "$BUILD_CLOSURE_TOOL_SHA256" "$CARGO_TOML_SHA256" \
  "$CARGO_LOCK_SHA256" "$DESIGN_NOTE_SHA256" "$HASH_CONTRACT_SHA256" \
  "$AUDIT_CONTRACT_SHA256" "$BUILD_CLOSURE_SHA256" \
  "$BUILD_CLOSURE_MANIFEST_SHA256" "$CONTROL_GIT_SHA256"; do
  canonical_sha256 "$digest" || die "manifest contains a malformed SHA-256"
done
[ "$VALIDATOR_SHA256" = "$BOOTSTRAP_VALIDATOR_SHA256" ] ||
  die "strict and bootstrap validator bindings differ"
[ "$BUILD_CLOSURE_REVISION" = "$EXPECTED_REVISION" ] ||
  die "build closure revision differs from the solver revision"
case "$BUILD_CLOSURE" in
  /*) ;;
  *) die "build closure path must be absolute" ;;
esac
[ -f "$BUILD_CLOSURE" ] && [ ! -L "$BUILD_CLOSURE" ] ||
  die "build closure is missing, nonregular, or a symlink"
[ "$PYTHON" = "$(readlink -f "$PYTHON")" ] ||
  die "manifest Python path must be resolved and nonsymlinked"

readonly CARGO_HOME_CANONICAL="$(canonical_directory "$CARGO_HOME" "Cargo home")"
readonly RUSTUP_HOME_CANONICAL="$(canonical_directory "$RUSTUP_HOME" "rustup home")"
[ "$CARGO_HOME" = "$CARGO_HOME_CANONICAL" ] || die "Cargo home is not canonical"
[ "$RUSTUP_HOME" = "$RUSTUP_HOME_CANONICAL" ] || die "rustup home is not canonical"

pinned_python() {
  /usr/bin/env -i \
    HOME="$RUN_HOME" LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$PYTHON_SNAPSHOT" -I -S -B "$@"
}

STAGE0A_PHASE=verify_toolchain_and_artifacts
require_sha256 "$CARGO" "$CARGO_SHA256" cargo
require_sha256 "$RUSTC" "$RUSTC_SHA256" rustc
require_sha256 "$PYTHON" "$PYTHON_SHA256" Python
PINNED_PYTHON_READY=1
require_sha256 "$REPO_RUNNER" "$RUNNER_SHA256" runner
require_sha256 "$SUBMITTER" "$SUBMITTER_SHA256" submitter
require_sha256 "$FINALIZER_SBATCH" "$FINALIZER_SBATCH_SHA256" "finalizer runner"
require_sha256 "$FINALIZER" "$FINALIZER_SHA256" finalizer
require_sha256 "$AUTHORIZER" "$AUTHORIZER_SHA256" authorizer
require_sha256 "$VALIDATOR" "$VALIDATOR_SHA256" validator
require_sha256 "$EXEC_HELPER" "$EXEC_HELPER_SHA256" "execution helper"
require_sha256 "$BUILD_CLOSURE_TOOL" "$BUILD_CLOSURE_TOOL_SHA256" \
  "build-closure utility"
require_sha256 "$REPO_ROOT/Cargo.toml" "$CARGO_TOML_SHA256" Cargo.toml
require_sha256 "$REPO_ROOT/Cargo.lock" "$CARGO_LOCK_SHA256" Cargo.lock
require_sha256 "$DESIGN_NOTE" "$DESIGN_NOTE_SHA256" "design note"
require_sha256 "$HASH_CONTRACT" "$HASH_CONTRACT_SHA256" "hash contract"
require_sha256 "$AUDIT_CONTRACT" "$AUDIT_CONTRACT_SHA256" "audit contract"
require_sha256 "$CONTROL_GIT" "$CONTROL_GIT_SHA256" "control git"

readonly CARGO_SNAPSHOT="$PROVENANCE_ROOT/cargo"
readonly RUSTC_SNAPSHOT="$PROVENANCE_ROOT/rustc"
readonly PYTHON_SNAPSHOT="$PROVENANCE_ROOT/python3"
readonly EXEC_HELPER_SNAPSHOT="$PROVENANCE_ROOT/exec_t11_stage0a.py"
readonly SUBMITTER_SNAPSHOT="$PROVENANCE_ROOT/submit_t11_stage0a.sh"
readonly FINALIZER_SBATCH_SNAPSHOT="$PROVENANCE_ROOT/euf_viper_t11_stage0a_finalize.sbatch"
readonly FINALIZER_SNAPSHOT="$PROVENANCE_ROOT/finalize_t11_stage0a.py"
readonly AUTHORIZER_SNAPSHOT="$PROVENANCE_ROOT/authorize_t11_stage0a.py"
readonly CONTROL_GIT_SNAPSHOT="$PROVENANCE_ROOT/git"
readonly BUILD_CLOSURE_TOOL_SNAPSHOT="$PROVENANCE_ROOT/t11_build_closure.py"
readonly CARGO_TOML_SNAPSHOT="$PROVENANCE_ROOT/Cargo.toml"
readonly CARGO_LOCK_SNAPSHOT="$PROVENANCE_ROOT/Cargo.lock"
readonly DESIGN_NOTE_SNAPSHOT="$PROVENANCE_ROOT/design-note.md"
readonly HASH_CONTRACT_SNAPSHOT="$PROVENANCE_ROOT/hash-contract.md"
readonly AUDIT_CONTRACT_SNAPSHOT="$PROVENANCE_ROOT/audit-contract.md"
snapshot_file "$CARGO" "$CARGO_SNAPSHOT" "$CARGO_SHA256" 0500 ||
  die "could not snapshot cargo"
snapshot_file "$RUSTC" "$RUSTC_SNAPSHOT" "$RUSTC_SHA256" 0500 ||
  die "could not snapshot rustc"
snapshot_file "$PYTHON" "$PYTHON_SNAPSHOT" "$PYTHON_SHA256" 0500 ||
  die "could not snapshot Python"
snapshot_file "$EXEC_HELPER" "$EXEC_HELPER_SNAPSHOT" "$EXEC_HELPER_SHA256" 0500 ||
  die "could not snapshot execution helper"
snapshot_file "$SUBMITTER" "$SUBMITTER_SNAPSHOT" "$SUBMITTER_SHA256" 0500 ||
  die "could not snapshot submitter"
snapshot_file "$FINALIZER_SBATCH" "$FINALIZER_SBATCH_SNAPSHOT" \
  "$FINALIZER_SBATCH_SHA256" 0500 || die "could not snapshot finalizer runner"
snapshot_file "$FINALIZER" "$FINALIZER_SNAPSHOT" "$FINALIZER_SHA256" 0500 ||
  die "could not snapshot finalizer"
snapshot_file "$AUTHORIZER" "$AUTHORIZER_SNAPSHOT" "$AUTHORIZER_SHA256" 0500 ||
  die "could not snapshot authorizer"
snapshot_file "$CONTROL_GIT" "$CONTROL_GIT_SNAPSHOT" "$CONTROL_GIT_SHA256" 0500 ||
  die "could not snapshot control git"
[ "$("$CONTROL_GIT_SNAPSHOT" --version)" = "$CONTROL_GIT_VERSION" ] ||
  die "control git version differs from the launch manifest"
snapshot_file "$BUILD_CLOSURE_TOOL" "$BUILD_CLOSURE_TOOL_SNAPSHOT" \
  "$BUILD_CLOSURE_TOOL_SHA256" 0500 || die "could not snapshot build-closure utility"
snapshot_file "$REPO_ROOT/Cargo.toml" "$CARGO_TOML_SNAPSHOT" \
  "$CARGO_TOML_SHA256" 0400 || die "could not snapshot Cargo.toml"
snapshot_file "$REPO_ROOT/Cargo.lock" "$CARGO_LOCK_SNAPSHOT" \
  "$CARGO_LOCK_SHA256" 0400 || die "could not snapshot Cargo.lock"
snapshot_file "$DESIGN_NOTE" "$DESIGN_NOTE_SNAPSHOT" "$DESIGN_NOTE_SHA256" 0400 ||
  die "could not snapshot design note"
snapshot_file "$HASH_CONTRACT" "$HASH_CONTRACT_SNAPSHOT" \
  "$HASH_CONTRACT_SHA256" 0400 || die "could not snapshot hash contract"
snapshot_file "$AUDIT_CONTRACT" "$AUDIT_CONTRACT_SNAPSHOT" \
  "$AUDIT_CONTRACT_SHA256" 0400 || die "could not snapshot audit contract"

readonly EXECUTED_RUNNER="$(readlink -f "${BASH_SOURCE[0]}")"
require_sha256 "$EXECUTED_RUNNER" "$RUNNER_SHA256" "executed runner"
readonly RUNNER_SNAPSHOT="$RUN_ROOT/executed-runner.sbatch"
pinned_python -c \
  'import os,sys; src,dst=sys.argv[1:]; data=open(src,"rb").read(); fd=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600); n=0
while n < len(data):
 written=os.write(fd,data[n:])
 if written <= 0: raise RuntimeError("short runner-snapshot write")
 n += written
os.fsync(fd); os.fchmod(fd,0o400); os.fsync(fd); os.close(fd)' \
  "$EXECUTED_RUNNER" "$RUNNER_SNAPSHOT"
require_sha256 "$RUNNER_SNAPSHOT" "$RUNNER_SHA256" "runner snapshot"

version_in_isolation() {
  /usr/bin/env -i \
    HOME="$RUN_HOME" LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    CARGO_HOME="$CARGO_HOME" RUSTUP_HOME="$RUSTUP_HOME" \
    RUSTUP_TOOLCHAIN=1.93.0-x86_64-unknown-linux-gnu \
    "$1" --version
}
[ "$(version_in_isolation "$CARGO_SNAPSHOT")" = "$CARGO_VERSION" ] ||
  die "cargo version differs from the launch manifest"
[ "$(version_in_isolation "$RUSTC_SNAPSHOT")" = "$RUSTC_VERSION" ] ||
  die "rustc version differs from the launch manifest"
[ "$(pinned_python --version 2>&1)" = "$PYTHON_VERSION" ] ||
  die "Python version differs from the launch manifest"

enforce_cargo_config() {
  local path="$1"
  local state="$2"
  local digest="$3"
  case "$state" in
    absent)
      [ "$digest" = "-" ] || die "absent Cargo config has a digest"
      [ ! -e "$path" ] && [ ! -L "$path" ] ||
        die "launch manifest requires absent Cargo config: $path"
      ;;
    present)
      canonical_sha256 "$digest" || die "Cargo config digest is malformed"
      require_sha256 "$path" "$digest" "Cargo config"
      ;;
    *) die "Cargo config state is invalid" ;;
  esac
}

[ "${LAUNCH[44]}" = repository/config ] || die "Cargo config scope order differs"
enforce_cargo_config "$REPO_ROOT/.cargo/config" "${LAUNCH[45]}" "${LAUNCH[46]}"
[ "${LAUNCH[47]}" = repository/config.toml ] || die "Cargo config scope order differs"
enforce_cargo_config "$REPO_ROOT/.cargo/config.toml" "${LAUNCH[48]}" "${LAUNCH[49]}"
[ "${LAUNCH[50]}" = cargo_home/config ] || die "Cargo config scope order differs"
enforce_cargo_config "$CARGO_HOME/config" "${LAUNCH[51]}" "${LAUNCH[52]}"
[ "${LAUNCH[53]}" = cargo_home/config.toml ] || die "Cargo config scope order differs"
enforce_cargo_config "$CARGO_HOME/config.toml" "${LAUNCH[54]}" "${LAUNCH[55]}"
[ ! -e /.cargo/config ] && [ ! -L /.cargo/config ] ||
  die "unpinned root Cargo config exists: /.cargo/config"
[ ! -e /.cargo/config.toml ] && [ ! -L /.cargo/config.toml ] ||
  die "unpinned root Cargo config exists: /.cargo/config.toml"

clean_git() {
  /usr/bin/env -i \
    HOME="$RUN_HOME" LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROL_GIT_SNAPSHOT" "$@"
}

cd "$REPO_ROOT"
STAGE0A_PHASE=verify_checkout
[ "$(clean_git rev-parse HEAD^{commit})" = "$EXPECTED_REVISION" ] ||
  die "checkout revision differs from the launch manifest"
assert_clean_checkout() {
  [ -z "$(clean_git status --porcelain=v1 --untracked-files=all)" ] ||
    die "T11 checkout is dirty"
  [ "$(clean_git rev-parse HEAD^{commit})" = "$EXPECTED_REVISION" ] ||
    die "T11 checkout revision changed"
}
assert_clean_checkout

readonly TARGET="$CORPUS_ROOT/$TARGET_RELATIVE_PATH"
STAGE0A_PHASE=verify_frozen_target
[ -f "$TARGET" ] && [ ! -L "$TARGET" ] ||
  die "frozen target is missing, nonregular, or a symlink"
readonly SOURCE_BEFORE_SHA256="$(sha256_file "$TARGET")"
[ "$SOURCE_BEFORE_SHA256" = "$TARGET_SHA256" ] ||
  die "frozen target SHA-256 mismatch"
readonly SOURCE_SNAPSHOT="$PROVENANCE_ROOT/frozen-target.smt2"
snapshot_file "$TARGET" "$SOURCE_SNAPSHOT" "$SOURCE_BEFORE_SHA256" 0400 ||
  die "could not snapshot frozen target"

readonly BUILD_CLOSURE_ROOT="$RUN_ROOT/build-closure"
readonly BUILD_CLOSURE_STDOUT="$RUN_ROOT/build-closure.stdout"
readonly BUILD_CLOSURE_STDERR="$RUN_ROOT/build-closure.stderr"
readonly BUILD_STDOUT="$RUN_ROOT/build.stdout"
readonly BUILD_STDERR="$RUN_ROOT/build.stderr"
readonly BINARY="$PROVENANCE_ROOT/euf-viper"
readonly PRIVATE_CLOSURE_ROOT="$BUILD_CLOSURE_ROOT/extracted"
readonly UNSHARE_TOOL=/usr/bin/unshare
readonly MOUNT_TOOL=/usr/bin/mount
readonly BASH_TOOL=/usr/bin/bash

require_root_enforcement_tool() {
  local path="$1"
  local label="$2"
  pinned_python - "$path" "$label" <<'PY'
import os
import stat
import sys

path, label = sys.argv[1:]
metadata = os.stat(path, follow_symlinks=False)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
    raise SystemExit(f"{label} is not a root-owned regular file")
if metadata.st_mode & 0o022 or metadata.st_mode & 0o111 == 0:
    raise SystemExit(f"{label} is mutable by non-root or nonexecutable")
if os.path.realpath(path) != path:
    raise SystemExit(f"{label} path is not canonical and nonsymlinked")
PY
}

require_root_enforcement_tool "$UNSHARE_TOOL" unshare ||
  die "user-namespace enforcement tool is not trusted"
require_root_enforcement_tool "$MOUNT_TOOL" mount ||
  die "mount-namespace enforcement tool is not trusted"
require_root_enforcement_tool "$BASH_TOOL" bash ||
  die "namespace bootstrap shell is not trusted"
readonly UNSHARE_TOOL_SHA256="$(sha256_file "$UNSHARE_TOOL")"
readonly MOUNT_TOOL_SHA256="$(sha256_file "$MOUNT_TOOL")"
readonly BASH_TOOL_SHA256="$(sha256_file "$BASH_TOOL")"
readonly OUTSIDE_UID="$(id -u)"
readonly OUTSIDE_GID="$(id -g)"

STAGE0A_PHASE=private_build
mkdir -m 700 "$BUILD_CLOSURE_ROOT"
set +e
bootstrap_python -c '
import errno
import fcntl
import hashlib
import os
import stat
import sys

(
    unshare_path,
    unshare_sha256,
    python_path,
    python_sha256,
    closure_tool_path,
    closure_tool_sha256,
    archive_path,
    archive_sha256,
    *command,
) = sys.argv[1:]
proc_root = "/proc/self/fd"
base_seals = (
    fcntl.F_SEAL_WRITE
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_SEAL
)
future_write = getattr(fcntl, "F_SEAL_FUTURE_WRITE", 0x0010)


def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def hash_open_file(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def open_verified(path, expected, role, executable=False):
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{role} is not regular")
    if executable and before.st_mode & 0o111 == 0:
        raise RuntimeError(f"{role} is not executable")
    actual = hash_open_file(descriptor)
    after = os.fstat(descriptor)
    if identity(before) != identity(after):
        raise RuntimeError(f"{role} changed while hashed")
    if actual != expected:
        raise RuntimeError(f"{role} SHA-256 mismatch")
    return descriptor, after


def copy_sealed(path, expected, mode, role):
    source, before = open_verified(path, expected, role, executable=bool(mode & 0o100))
    snapshot = os.memfd_create(
        f"euf-viper-t11-private-build-{role}",
        flags=os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
    )
    try:
        while True:
            block = os.read(source, 1024 * 1024)
            if not block:
                break
            offset = 0
            while offset < len(block):
                written = os.write(snapshot, block[offset:])
                if written <= 0:
                    raise RuntimeError(f"short {role} memfd write")
                offset += written
        if identity(os.fstat(source)) != identity(before):
            raise RuntimeError(f"{role} changed while copied")
        os.fchmod(snapshot, mode)
        try:
            fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, base_seals | future_write)
        except OSError as error:
            if error.errno not in (errno.EINVAL, getattr(errno, "EOPNOTSUPP", 95)):
                raise
            if fcntl.fcntl(snapshot, fcntl.F_GET_SEALS) != 0:
                raise RuntimeError(f"{role} future-write seal partially applied")
            fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, base_seals)
        if fcntl.fcntl(snapshot, fcntl.F_GET_SEALS) & base_seals != base_seals:
            raise RuntimeError(f"{role} memfd lacks mandatory seals")
        if hash_open_file(snapshot) != expected:
            raise RuntimeError(f"sealed {role} SHA-256 mismatch")
        return snapshot
    except BaseException:
        os.close(snapshot)
        raise
    finally:
        os.close(source)


unshare_fd, _ = open_verified(
    unshare_path, unshare_sha256, "unshare", executable=True
)
os.close(unshare_fd)
python_fd = copy_sealed(python_path, python_sha256, 0o500, "python")
closure_tool_fd = copy_sealed(
    closure_tool_path, closure_tool_sha256, 0o400, "closure-tool"
)
archive_fd, archive_metadata = open_verified(
    archive_path, archive_sha256, "build-closure archive"
)
replacements = {
    "@ARCHIVE@": f"{proc_root}/{archive_fd}",
    "@ARCHIVE_DEVICE@": str(archive_metadata.st_dev),
    "@ARCHIVE_INODE@": str(archive_metadata.st_ino),
    "@ARCHIVE_SIZE@": str(archive_metadata.st_size),
    "@ARCHIVE_MTIME_NS@": str(archive_metadata.st_mtime_ns),
    "@ARCHIVE_CTIME_NS@": str(archive_metadata.st_ctime_ns),
    "@CLOSURE_TOOL@": f"{proc_root}/{closure_tool_fd}",
    "@PYTHON@": f"{proc_root}/{python_fd}",
}
for placeholder in replacements:
    if command.count(placeholder) != 1:
        raise RuntimeError(f"private-build placeholder count differs: {placeholder}")
command = [replacements.get(argument, argument) for argument in command]
required = {archive_fd, closure_tool_fd, python_fd}
for entry in os.listdir(proc_root):
    if not entry.isdecimal():
        continue
    descriptor = int(entry)
    if descriptor <= 2:
        continue
    try:
        os.set_inheritable(descriptor, descriptor in required)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
for descriptor in required:
    if not os.get_inheritable(descriptor):
        raise RuntimeError("private-build descriptor is not inheritable")
os.execve(
    unshare_path,
    [
        unshare_path,
        "--user",
        "--map-root-user",
        "--mount",
        "--fork",
        *command,
    ],
    {"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
)
' \
  "$UNSHARE_TOOL" "$UNSHARE_TOOL_SHA256" \
  "$PYTHON_SNAPSHOT" "$PYTHON_SHA256" \
  "$BUILD_CLOSURE_TOOL_SNAPSHOT" "$BUILD_CLOSURE_TOOL_SHA256" \
  "$BUILD_CLOSURE" "$BUILD_CLOSURE_SHA256" \
  "$BASH_TOOL" --noprofile --norc -s -- \
  "$BUILD_CLOSURE_ROOT" @ARCHIVE@ "$BUILD_CLOSURE_SHA256" \
  @CLOSURE_TOOL@ @PYTHON@ "$CARGO_SHA256" \
  "$CARGO_VERSION" "$RUSTC_SHA256" "$RUSTC_VERSION" \
  "$CARGO_TOML_SHA256" "$CARGO_LOCK_SHA256" "$EXPECTED_REVISION" \
  "$BUILD_CLOSURE_MANIFEST_SHA256" "$BUILD_STDOUT" "$BUILD_STDERR" \
  "$BINARY" "$OUTSIDE_UID" "$OUTSIDE_GID" \
  "$UNSHARE_TOOL" "$UNSHARE_TOOL_SHA256" \
  "$MOUNT_TOOL" "$MOUNT_TOOL_SHA256" \
  "$BASH_TOOL" "$BASH_TOOL_SHA256" \
  @ARCHIVE_DEVICE@ @ARCHIVE_INODE@ @ARCHIVE_SIZE@ \
  @ARCHIVE_MTIME_NS@ @ARCHIVE_CTIME_NS@ "$BUILD_CLOSURE" \
  >"$BUILD_CLOSURE_STDOUT" 2>"$BUILD_CLOSURE_STDERR" <<'PRIVATE_BUILD'
set -euo pipefail
umask 077

root="$1"
archive="$2"
archive_sha256="$3"
closure_tool="$4"
python="$5"
cargo_sha256="$6"
cargo_version="$7"
rustc_sha256="$8"
rustc_version="$9"
cargo_toml_sha256="${10}"
cargo_lock_sha256="${11}"
revision="${12}"
manifest_sha256="${13}"
build_stdout="${14}"
build_stderr="${15}"
binary_out="${16}"
outside_uid="${17}"
outside_gid="${18}"
unshare_tool="${19}"
unshare_sha256="${20}"
mount_tool="${21}"
mount_sha256="${22}"
bash_tool="${23}"
bash_sha256="${24}"
archive_device="${25}"
archive_inode="${26}"
archive_size="${27}"
archive_mtime_ns="${28}"
archive_ctime_ns="${29}"
archive_source_path="${30}"

"$mount_tool" --make-rprivate /
"$mount_tool" -t tmpfs -o nodev,nosuid,mode=0700,size=7168M \
  tmpfs "$root"

private_closure="$root/extracted"
private_cargo_home="$root/cargo-home"
private_target="$root/target"
private_home="$root/home"
private_tmp="$root/tmp"
closure_report="$root/closure-report.json"
mkdir -m 700 "$private_cargo_home" "$private_target" "$private_home" "$private_tmp"

private_python() {
  /usr/bin/env -i \
    HOME="$private_home" LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$python" -I -S -B "$@"
}

private_python "$closure_tool" extract \
  --archive "$archive" --sha256 "$archive_sha256" \
  --destination "$private_closure" >"$closure_report"

payload="$private_closure/payload"
source_root="$payload/source-tree"
cargo="$payload/cargo-executable"
cargo_home="$payload/cargo-home"
rustc="$payload/rustc-executable"
native_compiler="$payload/native-compiler"
native_archiver="$payload/native-archiver"
native_linker="$payload/native-linker"
native_libs="$payload/native-libs"

private_python -c '
import hashlib,os,stat,sys
for path, expected, label in zip(sys.argv[1::3], sys.argv[2::3], sys.argv[3::3]):
    metadata=os.stat(path,follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode): raise SystemExit(f"{label} is not regular")
    digest=hashlib.sha256(open(path,"rb").read()).hexdigest()
    if digest != expected: raise SystemExit(f"{label} SHA-256 mismatch")
' \
  "$cargo" "$cargo_sha256" cargo \
  "$rustc" "$rustc_sha256" rustc \
  "$source_root/Cargo.toml" "$cargo_toml_sha256" Cargo.toml \
  "$source_root/Cargo.lock" "$cargo_lock_sha256" Cargo.lock

[ "$(/usr/bin/env -i HOME="$private_home" LANG=C LC_ALL=C TZ=UTC \
  PATH=/usr/bin:/bin "$cargo" --version)" = "$cargo_version" ]
[ "$(/usr/bin/env -i HOME="$private_home" LANG=C LC_ALL=C TZ=UTC \
  PATH=/usr/bin:/bin "$rustc" --version)" = "$rustc_version" ]
[ -d "$cargo_home/registry" ] && [ ! -L "$cargo_home/registry" ]
private_python -c '
import os,sys
source,destination,parent=sys.argv[1:]
os.symlink(source,destination)
descriptor=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
os.fsync(descriptor); os.close(descriptor)
' "$cargo_home/registry" "$private_cargo_home/registry" "$private_cargo_home"

(
  cd /
  /usr/bin/env -i \
    HOME="$private_home" LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    TMPDIR="$private_tmp" OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
    RAYON_NUM_THREADS=1 CARGO_HOME="$private_cargo_home" \
    CARGO_TARGET_DIR="$private_target" CARGO_NET_OFFLINE=true \
    RUSTC="$rustc" CC="$native_compiler" CXX="$native_compiler" \
    AR="$native_archiver" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$native_linker" \
    LIBRARY_PATH="$native_libs" LD_LIBRARY_PATH="$native_libs" \
    EUF_VIPER_T11_BUILD_STDOUT="$build_stdout" \
    "$cargo" build --manifest-path "$source_root/Cargo.toml" \
    --locked --offline --features certificates --release
) >"$build_stdout" 2>"$build_stderr"

private_python - \
  "$closure_report" "$archive_sha256" "$manifest_sha256" "$revision" \
  "$private_closure" "$root" "$private_target/release/euf-viper" \
  "$binary_out" "$outside_uid" "$outside_gid" \
  "$unshare_tool" "$unshare_sha256" "$mount_tool" "$mount_sha256" \
  "$bash_tool" "$bash_sha256" "$archive" "$archive_source_path" \
  "$archive_device" "$archive_inode" "$archive_size" \
  "$archive_mtime_ns" "$archive_ctime_ns" <<'PRIVATE_BUILD_REPORT_PY'
import hashlib
import json
import os
import re
import stat
import sys

(
    closure_report_path,
    archive_sha256,
    manifest_sha256,
    revision,
    private_closure,
    root,
    built_binary,
    binary_out,
    outside_uid,
    outside_gid,
    unshare_tool,
    unshare_sha256,
    mount_tool,
    mount_sha256,
    bash_tool,
    bash_sha256,
    archive_descriptor_path,
    archive_source_path,
    archive_device,
    archive_inode,
    archive_size,
    archive_mtime_ns,
    archive_ctime_ns,
) = sys.argv[1:]


def canonical(value):
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


encoded = open(closure_report_path, "rb").read()
closure = json.loads(encoded)
if encoded != canonical(closure):
    raise SystemExit("build-closure report is not canonical")
expected_closure = {
    "archive_sha256": archive_sha256,
    "manifest_sha256": manifest_sha256,
    "schema": "euf-viper.t11-build-closure.v1",
    "source_revision": revision,
    "status": "verified",
    "destination": private_closure,
}
for key, value in expected_closure.items():
    if closure.get(key) != value:
        raise SystemExit(f"build-closure report mismatch: {key}")

descriptor_match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]*)", archive_descriptor_path)
if descriptor_match is None:
    raise SystemExit("build-closure archive is not descriptor-bound")
archive_fd = os.dup(int(descriptor_match.group(1)))
try:
    archive_before = os.fstat(archive_fd)
    expected_archive_identity = (
        int(archive_device),
        int(archive_inode),
        int(archive_size),
        int(archive_mtime_ns),
        int(archive_ctime_ns),
    )
    observed_archive_identity = (
        archive_before.st_dev,
        archive_before.st_ino,
        archive_before.st_size,
        archive_before.st_mtime_ns,
        archive_before.st_ctime_ns,
    )
    if observed_archive_identity != expected_archive_identity:
        raise SystemExit("build-closure archive identity changed before final verification")
    archive_digest = hashlib.sha256()
    os.lseek(archive_fd, 0, os.SEEK_SET)
    while True:
        block = os.read(archive_fd, 1024 * 1024)
        if not block:
            break
        archive_digest.update(block)
    archive_after = os.fstat(archive_fd)
finally:
    os.close(archive_fd)
if (
    not stat.S_ISREG(archive_after.st_mode)
    or archive_after.st_mode & 0o222
    or (
        archive_after.st_dev,
        archive_after.st_ino,
        archive_after.st_size,
        archive_after.st_mtime_ns,
        archive_after.st_ctime_ns,
    )
    != expected_archive_identity
    or archive_digest.hexdigest() != archive_sha256
):
    raise SystemExit("build-closure archive changed during the private build")
archive_binding = {
    "bytes": archive_after.st_size,
    "ctime_ns": archive_after.st_ctime_ns,
    "device": archive_after.st_dev,
    "inode": archive_after.st_ino,
    "links": archive_after.st_nlink,
    "mode": f"{stat.S_IMODE(archive_after.st_mode):04o}",
    "mtime_ns": archive_after.st_mtime_ns,
    "path": archive_source_path,
    "sha256": archive_digest.hexdigest(),
}


def parse_id_map(path):
    rows = []
    for line in open(path, "r", encoding="ascii"):
        fields = line.split()
        if len(fields) != 3:
            raise SystemExit(f"malformed namespace mapping: {path}")
        rows.append([int(field) for field in fields])
    return rows


uid_map = parse_id_map("/proc/self/uid_map")
gid_map = parse_id_map("/proc/self/gid_map")
if uid_map != [[0, int(outside_uid), 1]]:
    raise SystemExit("private build UID mapping differs")
if gid_map != [[0, int(outside_gid), 1]]:
    raise SystemExit("private build GID mapping differs")
if os.getuid() != 0 or os.getgid() != 0:
    raise SystemExit("private build did not enter namespace root")


def unescape_mount(value):
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


mount_record = None
for line in open("/proc/self/mountinfo", "r", encoding="ascii"):
    fields = line.split()
    separator = fields.index("-")
    if unescape_mount(fields[4]) == root:
        mount_record = (fields, separator)
        break
if mount_record is None:
    raise SystemExit("private build tmpfs mount is absent")
fields, separator = mount_record
if fields[separator + 1] != "tmpfs":
    raise SystemExit("private build filesystem is not tmpfs")
optional_fields = fields[6:separator]
if any(value.startswith(("shared:", "master:", "propagate_from:")) for value in optional_fields):
    raise SystemExit("private build mount propagation is not private")
mount_options = sorted(
    set(fields[5].split(",")) | set(fields[separator + 3].split(","))
)
for required in ("rw", "nosuid", "nodev"):
    if required not in mount_options:
        raise SystemExit(f"private build mount lacks {required}")


def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


source_fd = os.open(
    built_binary,
    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
)
parent_fd = os.open(
    os.path.dirname(binary_out),
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
)
output_fd = None
try:
    source_before = os.fstat(source_fd)
    if not stat.S_ISREG(source_before.st_mode) or source_before.st_nlink != 1:
        raise SystemExit("private build binary is not a unique regular file")
    output_fd = os.open(
        os.path.basename(binary_out),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
        dir_fd=parent_fd,
    )
    digest = hashlib.sha256()
    copied = 0
    while True:
        block = os.read(source_fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
        view = memoryview(block)
        while view:
            written = os.write(output_fd, view)
            if written <= 0:
                raise SystemExit("short private binary publication")
            view = view[written:]
        copied += len(block)
    source_after = os.fstat(source_fd)
    if identity(source_before) != identity(source_after) or copied != source_after.st_size:
        raise SystemExit("private build binary changed while published")
    os.fsync(output_fd)
    os.fchmod(output_fd, 0o500)
    os.fsync(output_fd)
    os.fsync(parent_fd)
    published = os.fstat(output_fd)
finally:
    if output_fd is not None:
        os.close(output_fd)
    os.close(parent_fd)
    os.close(source_fd)

named = os.stat(binary_out, follow_symlinks=False)
if identity(named) != identity(published):
    raise SystemExit("published binary pathname identity differs")
binary_binding = {
    "artifact": "binary",
    "bytes": published.st_size,
    "ctime_ns": published.st_ctime_ns,
    "device": published.st_dev,
    "inode": published.st_ino,
    "links": published.st_nlink,
    "mode": f"{stat.S_IMODE(published.st_mode):04o}",
    "mtime_ns": published.st_mtime_ns,
    "path": binary_out,
    "schema": "euf-viper.t11-publication-binding.v1",
    "sha256": digest.hexdigest(),
}

report = {
    "archive": archive_binding,
    "binary": binary_binding,
    "build_closure": closure,
    "enforcement_tools": {
        "bash": {"path": bash_tool, "sha256": bash_sha256},
        "mount": {"path": mount_tool, "sha256": mount_sha256},
        "unshare": {"path": unshare_tool, "sha256": unshare_sha256},
    },
    "isolation": {
        "filesystem": "tmpfs",
        "gid_map": gid_map,
        "host_visible_transient_tree": False,
        "mount_options": mount_options,
        "mount_propagation": "private",
        "namespace_gid": os.getgid(),
        "namespace_uid": os.getuid(),
        "uid_map": uid_map,
        "user_namespace": True,
    },
    "schema": "euf-viper.t11-private-build.v1",
    "status": "verified",
}
sys.stdout.buffer.write(canonical(report))
PRIVATE_BUILD_REPORT_PY
PRIVATE_BUILD
BUILD_EXIT=$?
set -e
for artifact in \
  "$BUILD_CLOSURE_STDOUT" "$BUILD_CLOSURE_STDERR" \
  "$BUILD_STDOUT" "$BUILD_STDERR"; do
  [ -f "$artifact" ] && [ ! -L "$artifact" ] ||
    die "private build omitted an expected output: $artifact"
  chmod 400 "$artifact"
  fsync_path "$artifact"
done
[ "$BUILD_EXIT" -eq 0 ] || die "private tmpfs certificate build failed"
[ ! -s "$BUILD_CLOSURE_STDERR" ] ||
  die "private build controller emitted stderr"
[ -d "$BUILD_CLOSURE_ROOT" ] && [ ! -L "$BUILD_CLOSURE_ROOT" ] ||
  die "private build mountpoint vanished or became a symlink"
[ "$(stat -c '%a' "$BUILD_CLOSURE_ROOT")" = 700 ] ||
  die "private build host mountpoint mode changed"
pinned_python -c '
import os,sys
if os.listdir(sys.argv[1]):
    raise SystemExit("private build tree propagated into the host mount namespace")
' "$BUILD_CLOSURE_ROOT" || die "private build state escaped its mount namespace"

BINARY_BEFORE_SHA256_VALUE="$(pinned_python - \
  "$BUILD_CLOSURE_STDOUT" "$BINARY" "$BUILD_CLOSURE" \
  "$BUILD_CLOSURE_SHA256" \
  "$BUILD_CLOSURE_MANIFEST_SHA256" "$EXPECTED_REVISION" \
  "$PRIVATE_CLOSURE_ROOT" "$OUTSIDE_UID" "$OUTSIDE_GID" \
  "$UNSHARE_TOOL" "$UNSHARE_TOOL_SHA256" \
  "$MOUNT_TOOL" "$MOUNT_TOOL_SHA256" \
  "$BASH_TOOL" "$BASH_TOOL_SHA256" <<'PY'
import hashlib
import json
import os
import stat
import sys

(
    report_path,
    binary_path,
    archive_path,
    archive_sha256,
    manifest_sha256,
    revision,
    destination,
    outside_uid,
    outside_gid,
    unshare_path,
    unshare_sha256,
    mount_path,
    mount_sha256,
    bash_path,
    bash_sha256,
) = sys.argv[1:]
encoded = open(report_path, "rb").read()
record = json.loads(encoded)
canonical = (
    json.dumps(
        record,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("ascii")
if encoded != canonical:
    raise SystemExit("private-build report is not canonical")
if set(record) != {"archive", "binary", "build_closure", "enforcement_tools", "isolation", "schema", "status"}:
    raise SystemExit("private-build report keys differ")
if record["schema"] != "euf-viper.t11-private-build.v1" or record["status"] != "verified":
    raise SystemExit("private-build report status differs")
closure = record["build_closure"]
expected_closure = {
    "archive_sha256": archive_sha256,
    "destination": destination,
    "manifest_sha256": manifest_sha256,
    "schema": "euf-viper.t11-build-closure.v1",
    "source_revision": revision,
    "status": "verified",
}
for key, value in expected_closure.items():
    if closure.get(key) != value:
        raise SystemExit(f"private-build closure mismatch: {key}")
archive_binding = record["archive"]
if set(archive_binding) != {
    "bytes", "ctime_ns", "device", "inode", "links", "mode", "mtime_ns",
    "path", "sha256",
}:
    raise SystemExit("private-build archive binding keys differ")
if (
    archive_binding["path"] != archive_path
    or archive_binding["sha256"] != archive_sha256
    or archive_binding["links"] != 1
):
    raise SystemExit("private-build archive binding identity differs")
archive_fd = os.open(
    archive_path,
    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
)
try:
    archive_before = os.fstat(archive_fd)
    archive_digest = hashlib.sha256()
    while True:
        block = os.read(archive_fd, 1024 * 1024)
        if not block:
            break
        archive_digest.update(block)
    archive_after = os.fstat(archive_fd)
finally:
    os.close(archive_fd)
archive_identity = lambda value: (
    value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
    value.st_mtime_ns, value.st_ctime_ns,
)
if archive_identity(archive_before) != archive_identity(archive_after):
    raise SystemExit("build-closure archive changed during final host verification")
expected_archive_binding = {
    "bytes": archive_after.st_size,
    "ctime_ns": archive_after.st_ctime_ns,
    "device": archive_after.st_dev,
    "inode": archive_after.st_ino,
    "links": archive_after.st_nlink,
    "mode": f"{stat.S_IMODE(archive_after.st_mode):04o}",
    "mtime_ns": archive_after.st_mtime_ns,
    "path": archive_path,
    "sha256": archive_digest.hexdigest(),
}
if archive_binding != expected_archive_binding or archive_after.st_mode & 0o222:
    raise SystemExit("private-build archive changed after namespace exit")
expected_tools = {
    "bash": {"path": bash_path, "sha256": bash_sha256},
    "mount": {"path": mount_path, "sha256": mount_sha256},
    "unshare": {"path": unshare_path, "sha256": unshare_sha256},
}
if record["enforcement_tools"] != expected_tools:
    raise SystemExit("private-build enforcement tools differ")
isolation = record["isolation"]
if set(isolation) != {
    "filesystem",
    "gid_map",
    "host_visible_transient_tree",
    "mount_options",
    "mount_propagation",
    "namespace_gid",
    "namespace_uid",
    "uid_map",
    "user_namespace",
}:
    raise SystemExit("private-build isolation keys differ")
if (
    isolation["filesystem"] != "tmpfs"
    or isolation["mount_propagation"] != "private"
    or isolation["host_visible_transient_tree"] is not False
    or isolation["user_namespace"] is not True
    or isolation["namespace_uid"] != 0
    or isolation["namespace_gid"] != 0
    or isolation["uid_map"] != [[0, int(outside_uid), 1]]
    or isolation["gid_map"] != [[0, int(outside_gid), 1]]
):
    raise SystemExit("private-build isolation attestation differs")
if not {"rw", "nosuid", "nodev"}.issubset(isolation["mount_options"]):
    raise SystemExit("private-build mount options differ")

binding = record["binary"]
expected_binding_keys = {
    "artifact", "bytes", "ctime_ns", "device", "inode", "links",
    "mode", "mtime_ns", "path", "schema", "sha256",
}
if set(binding) != expected_binding_keys:
    raise SystemExit("private-build binary binding keys differ")
if (
    binding["artifact"] != "binary"
    or binding["path"] != binary_path
    or binding["schema"] != "euf-viper.t11-publication-binding.v1"
    or binding["mode"] != "0500"
    or binding["links"] != 1
):
    raise SystemExit("private-build binary binding identity differs")
descriptor = os.open(
    binary_path,
    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
)
try:
    before = os.fstat(descriptor)
    digest = hashlib.sha256()
    size = 0
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        digest.update(block)
        size += len(block)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
identity = lambda value: (
    value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
    value.st_mtime_ns, value.st_ctime_ns,
)
if identity(before) != identity(after):
    raise SystemExit("published private-build binary changed while read")
named = os.stat(binary_path, follow_symlinks=False)
if identity(named) != identity(after):
    raise SystemExit("published private-build binary pathname changed")
expected_binding = {
    "bytes": size,
    "ctime_ns": after.st_ctime_ns,
    "device": after.st_dev,
    "inode": after.st_ino,
    "links": after.st_nlink,
    "mode": f"{stat.S_IMODE(after.st_mode):04o}",
    "mtime_ns": after.st_mtime_ns,
    "sha256": digest.hexdigest(),
}
for key, value in expected_binding.items():
    if binding[key] != value:
        raise SystemExit(f"private-build binary {key} differs from its producer binding")
print(binding["sha256"])
PY
)" || die "private build report or binary binding differs"
readonly BINARY_BEFORE_SHA256="$BINARY_BEFORE_SHA256_VALUE"
assert_clean_checkout

readonly BUNDLE="$RUN_ROOT/projection-bundle.json"
readonly RECEIPT="$RUN_ROOT/audit-receipt.json"
readonly PROJECT_STDOUT="$RUN_ROOT/project.stdout"
readonly PROJECT_STDERR="$RUN_ROOT/project.stderr"
readonly AUDIT_STDOUT="$RUN_ROOT/audit.stdout"
readonly AUDIT_STDERR="$RUN_ROOT/audit.stderr"
readonly VALIDATION_STDOUT="$RUN_ROOT/validation.stdout"
readonly VALIDATION_STDERR="$RUN_ROOT/validation.stderr"
readonly METADATA="$RUN_ROOT/metadata.json"
readonly REJECTION="$RUN_ROOT/rejection.json"
readonly PROJECT_REQUEST="$RUN_ROOT/project-request.json"
readonly AUDIT_REQUEST="$RUN_ROOT/audit-request.json"
readonly VALIDATION_REQUEST="$RUN_ROOT/validation-request.json"
readonly COMPUTE_INDEX="$RUN_ROOT/compute-index.json"

write_exec_request() {
  local kind="$1"
  local output="$2"
  local home="$3"
  local executable="$4"
  local executable_sha256="$5"
  shift 5
  pinned_python - "$kind" "$output" "$home" "$executable" \
    "$executable_sha256" "$@" <<'PY'
import hashlib
import json
import os
import sys

kind, output, home, executable, executable_sha256, *values = sys.argv[1:]
inputs = []
argv = None
index = 0
while index < len(values):
    marker = values[index]
    if marker == "--input":
        if index + 3 >= len(values):
            raise SystemExit("truncated execution-request input")
        placeholder, path, sha256 = values[index + 1 : index + 4]
        inputs.append(
            {"placeholder": placeholder, "path": path, "sha256": sha256}
        )
        index += 4
        continue
    if marker == "--argv":
        argv = values[index + 1 :]
        break
    raise SystemExit(f"unexpected execution-request marker: {marker!r}")
if not inputs or not argv:
    raise SystemExit("execution request requires inputs and argv")

base_environment = {
    "HOME": home,
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "RUST_BACKTRACE": "0",
    "TZ": "UTC",
}
if kind == "project":
    base_environment["EUF_VIPER_T11_EQRES"] = "clique-er-auto"
elif kind == "audit":
    pass
elif kind == "validate":
    pass
else:
    raise SystemExit("unknown request kind")
request = {
    "schema": "euf-viper.t11-stage0a-exec.v1",
    "executable": {"path": executable, "sha256": executable_sha256},
    "inputs": inputs,
    "argv": argv,
    "environment": base_environment,
}
encoded = (
    json.dumps(
        request,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("ascii")
parent = os.path.dirname(output)
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    fd = os.open(
        os.path.basename(output),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
        dir_fd=parent_fd,
    )
    try:
        written = 0
        while written < len(encoded):
            count = os.write(fd, encoded[written:])
            if count <= 0:
                raise RuntimeError("short request write")
            written += count
        os.fsync(fd)
        os.fchmod(fd, 0o400)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
print(hashlib.sha256(encoded).hexdigest())
PY
}

sealed_exec_request() {
  local request="$1"
  local request_sha256="$2"
  canonical_sha256 "$request_sha256" ||
    die "execution request producer returned a malformed SHA-256"
  /usr/bin/env -i \
    HOME="$RUN_HOME" LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$PYTHON_SNAPSHOT" -I -S -B -c '
import errno
import fcntl
import hashlib
import os
import stat
import sys

python_path, python_sha, helper_path, helper_sha, request_path, request_sha = sys.argv[1:]
proc_root = "/proc/self/fd"
future_write = getattr(fcntl, "F_SEAL_FUTURE_WRITE", 0x0010)
base_seals = (
    fcntl.F_SEAL_WRITE
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_SEAL
)


def copy_sealed(path, expected, mode, role):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    source = os.open(path, flags)
    snapshot = None
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"{role} is not regular")
        if mode & 0o100 and before.st_mode & 0o111 == 0:
            raise RuntimeError(f"{role} is not executable")
        snapshot = os.memfd_create(
            f"euf-viper-t11-bootstrap-{role}",
            flags=os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(snapshot, chunk[offset:])
                if written <= 0:
                    raise RuntimeError(f"short {role} snapshot write")
                offset += written
            copied += len(chunk)
        after = os.fstat(source)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after) or copied != after.st_size:
            raise RuntimeError(f"{role} changed while copied")
        actual = digest.hexdigest()
        if actual != expected:
            raise RuntimeError(
                f"{role} SHA-256 mismatch: expected {expected}, found {actual}"
            )
        os.fchmod(snapshot, mode)
        try:
            fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, base_seals | future_write)
        except OSError as error:
            if error.errno not in (errno.EINVAL, getattr(errno, "EOPNOTSUPP", 95)):
                raise
            if fcntl.fcntl(snapshot, fcntl.F_GET_SEALS) != 0:
                raise RuntimeError(f"{role} future-write seal partially applied")
            fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, base_seals)
        seals = fcntl.fcntl(snapshot, fcntl.F_GET_SEALS)
        if seals & base_seals != base_seals:
            raise RuntimeError(f"{role} snapshot lacks mandatory seals")
        os.lseek(snapshot, 0, os.SEEK_SET)
        sealed_digest = hashlib.sha256()
        while True:
            chunk = os.read(snapshot, 1024 * 1024)
            if not chunk:
                break
            sealed_digest.update(chunk)
        if sealed_digest.hexdigest() != expected:
            raise RuntimeError(f"sealed {role} digest differs")
        metadata = os.fstat(snapshot)
        proc_metadata = os.stat(f"{proc_root}/{snapshot}")
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            stat.S_IMODE(metadata.st_mode),
        ) != (
            proc_metadata.st_dev,
            proc_metadata.st_ino,
            proc_metadata.st_size,
            mode,
        ):
            raise RuntimeError(f"{role} proc-fd binding differs")
        result = snapshot
        snapshot = None
        return result
    finally:
        if snapshot is not None:
            os.close(snapshot)
        os.close(source)


python_fd = copy_sealed(python_path, python_sha, 0o500, "python")
helper_fd = copy_sealed(helper_path, helper_sha, 0o500, "helper")
request_fd = copy_sealed(request_path, request_sha, 0o400, "request")
required = {helper_fd, request_fd}
for entry in os.listdir(proc_root):
    if not entry.isdecimal():
        continue
    descriptor = int(entry)
    if descriptor <= 2:
        continue
    try:
        os.set_inheritable(descriptor, descriptor in required)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
for descriptor in required:
    if not os.get_inheritable(descriptor):
        raise RuntimeError("required bootstrap descriptor is not inheritable")
os.execve(
    f"{proc_root}/{python_fd}",
    [
        "python3",
        "-I",
        "-S",
        "-B",
        f"{proc_root}/{helper_fd}",
        "--request-fd",
        str(request_fd),
        "--request-sha256",
        request_sha,
        "--self-fd",
        str(helper_fd),
        "--self-sha256",
        helper_sha,
    ],
    {
        "HOME": os.environ["HOME"],
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    },
)
' "$PYTHON_SNAPSHOT" "$PYTHON_SHA256" \
    "$EXEC_HELPER_SNAPSHOT" "$EXEC_HELPER_SHA256" \
    "$request" "$request_sha256"
}

seal_file() {
  local path="$1"
  [ -f "$path" ] && [ ! -L "$path" ] || die "cannot seal missing artifact: $path"
  chmod 400 "$path"
  fsync_path "$path"
}

verify_publication_binding() {
  local binding_path="$1"
  local artifact_path="$2"
  local expected_artifact="$3"
  pinned_python - "$binding_path" "$artifact_path" "$expected_artifact" <<'PY'
import hashlib
import json
import os
import stat
import sys

binding_path, artifact_path, expected_artifact = sys.argv[1:]
encoded = open(binding_path, "rb").read()
if not encoded.endswith(b"\n") or encoded.count(b"\n") != 1:
    raise SystemExit("publication binding must be exactly one newline-terminated record")
record = json.loads(encoded)
canonical = (
    json.dumps(record, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    + "\n"
).encode("ascii")
if encoded != canonical:
    raise SystemExit("publication binding is not canonical JSON")
expected_keys = {
    "artifact",
    "bytes",
    "ctime_ns",
    "device",
    "inode",
    "links",
    "mode",
    "mtime_ns",
    "path",
    "schema",
    "sha256",
}
if set(record) != expected_keys:
    raise SystemExit("publication binding keys differ")
if record["schema"] != "euf-viper.t11-publication-binding.v1":
    raise SystemExit("publication binding schema differs")
if record["artifact"] != expected_artifact or record["path"] != artifact_path:
    raise SystemExit("publication binding role or path differs")
for key in ("bytes", "ctime_ns", "device", "inode", "links", "mtime_ns"):
    if isinstance(record[key], bool) or not isinstance(record[key], int) or record[key] < 0:
        raise SystemExit(f"publication binding {key} is malformed")
if record["mode"] != "0400" or record["links"] != 1:
    raise SystemExit("publication binding mode or link count differs")
if not isinstance(record["sha256"], str) or len(record["sha256"]) != 64:
    raise SystemExit("publication binding digest is malformed")
if any(character not in "0123456789abcdef" for character in record["sha256"]):
    raise SystemExit("publication binding digest is malformed")

flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(artifact_path, flags)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit("published artifact is not regular")
    digest = hashlib.sha256()
    size = 0
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        digest.update(block)
        size += len(block)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
identity = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_mode,
    value.st_nlink,
    value.st_size,
    value.st_mtime_ns,
    value.st_ctime_ns,
)
if identity(before) != identity(after):
    raise SystemExit("published artifact changed while it was read")
named = os.stat(artifact_path, follow_symlinks=False)
if identity(named) != identity(after):
    raise SystemExit("published artifact pathname identity differs")
expected = {
    "bytes": size,
    "ctime_ns": after.st_ctime_ns,
    "device": after.st_dev,
    "inode": after.st_ino,
    "links": after.st_nlink,
    "mode": f"{stat.S_IMODE(after.st_mode):04o}",
    "mtime_ns": after.st_mtime_ns,
    "sha256": digest.hexdigest(),
}
for key, value in expected.items():
    if record[key] != value:
        raise SystemExit(f"published artifact {key} differs from producer binding")
print(record["sha256"])
PY
}

seal_run_root() {
  chmod -R a-w "$RUN_ROOT"
  fsync_path "$RUN_ROOT"
  fsync_path "$RUN_BASE"
}

discard_transient_tree() {
  local path="$1"
  pinned_python - "$RUN_ROOT" "$path" <<'PY'
import os
import stat
import sys

root, path = map(os.path.realpath, sys.argv[1:])
if os.path.commonpath((root, path)) != root or path == root:
    raise SystemExit("transient path escapes the private run root")
metadata = os.lstat(path)
if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("transient path is not a real directory")
for current, directories, files in os.walk(path, topdown=True, followlinks=False):
    for name in directories:
        child = os.path.join(current, name)
        child_metadata = os.lstat(child)
        if not stat.S_ISDIR(child_metadata.st_mode) or stat.S_ISLNK(child_metadata.st_mode):
            raise SystemExit(f"special transient build directory: {child}")
    for name in files:
        child = os.path.join(current, name)
        if not stat.S_ISREG(os.lstat(child).st_mode):
            raise SystemExit(f"special transient build artifact: {child}")
    os.chmod(current, 0o700, follow_symlinks=False)
for current, directories, files in os.walk(path, topdown=False, followlinks=False):
    for name in files:
        child = os.path.join(current, name)
        child_metadata = os.lstat(child)
        if not stat.S_ISREG(child_metadata.st_mode):
            raise SystemExit(f"special transient build artifact: {child}")
        os.unlink(child)
    for name in directories:
        child = os.path.join(current, name)
        child_metadata = os.lstat(child)
        if not stat.S_ISDIR(child_metadata.st_mode) or stat.S_ISLNK(child_metadata.st_mode):
            raise SystemExit(f"special transient build directory: {child}")
        os.rmdir(child)
os.rmdir(path)
PY
}

write_compute_index() {
  local output="$1"
  shift
  pinned_python - "$output" "$RUN_ROOT" "$RUN_NONCE" "$EXPECTED_REVISION" \
    "$LAUNCH_MANIFEST_SHA256" "$SLURM_JOB_ID" \
    "${SLURM_CLUSTER_NAME:-unknown}" "${SLURM_RESTART_COUNT:-0}" \
    "${SLURM_ARRAY_JOB_ID:-}" "${SLURM_ARRAY_TASK_ID:-}" \
    "${SLURMD_NODENAME:-$(hostname)}" "$SUBMIT_ROOT" "$@" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

(
    output,
    run_root,
    nonce,
    revision,
    launch_sha256,
    job_id,
    cluster,
    restart_count,
    array_job_id,
    array_task_id,
    hostname,
    submit_dir,
    *values,
) = sys.argv[1:]
if len(values) % 2:
    raise SystemExit("compute-index artifact arguments are not role/path pairs")
if not re.fullmatch(r"[0-9a-f]{32}", nonce):
    raise SystemExit("compute-index run nonce is malformed")
if not job_id.isdecimal() or not restart_count.isdecimal():
    raise SystemExit("compute-index scheduler counters are malformed")
root = os.path.realpath(run_root)
records = []
roles = set()
inodes = set()
for role, path in zip(values[0::2], values[1::2]):
    if not re.fullmatch(r"[a-z][a-z0-9_]*", role) or role in roles:
        raise SystemExit(f"invalid or duplicate compute-index role: {role!r}")
    roles.add(role)
    resolved = os.path.realpath(path)
    if os.path.commonpath((root, resolved)) != root:
        raise SystemExit(f"compute-index artifact escapes run root: {role}")
    relative = os.path.relpath(resolved, root)
    if relative == "." or relative.startswith("../"):
        raise SystemExit(f"compute-index artifact has invalid relative path: {role}")
    before_lstat = os.lstat(path)
    if stat.S_ISLNK(before_lstat.st_mode):
        raise SystemExit(f"compute-index artifact is a symlink: {role}")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"compute-index artifact is not regular: {role}")
        if stat.S_IMODE(before.st_mode) & 0o222:
            raise SystemExit(f"compute-index artifact is writable: {role}")
        identity = (before.st_dev, before.st_ino)
        if identity in inodes:
            raise SystemExit(f"compute-index artifact has a hard-link alias: {role}")
        inodes.add(identity)
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or size != after.st_size
        ):
            raise SystemExit(f"compute-index artifact changed while read: {role}")
    finally:
        os.close(descriptor)
    named = os.lstat(path)
    if stat.S_ISLNK(named.st_mode) or (named.st_dev, named.st_ino) != identity:
        raise SystemExit(f"compute-index artifact path identity changed: {role}")
    records.append(
        {
            "role": role,
            "path_rel": relative,
            "mode": format(stat.S_IMODE(after.st_mode), "04o"),
            "size": size,
            "sha256": digest.hexdigest(),
        }
    )

metadata = next((record for record in records if record["role"] == "validation_candidate"), None)
if metadata is None:
    raise SystemExit("compute-index lacks validation candidate")
payload = {
    "schema": "euf-viper.t11-stage0a-compute-index.v1",
    "status": "candidate_complete",
    "decision": "requires_scheduler_finalization",
    "stage0b_authority": False,
    "classification": "scientific_candidate",
    "candidate_outcome": "accept",
    "reason": None,
    "intended_exit_code": 0,
    "attempt": {
        "run_nonce": nonce,
        "cluster": cluster,
        "job_id": int(job_id),
        "array_job_id": int(array_job_id) if array_job_id.isdecimal() else None,
        "array_task_id": int(array_task_id) if array_task_id.isdecimal() else None,
        "step_id": "batch",
        "restart_count": int(restart_count),
        "hostname": hostname,
        "submit_dir": submit_dir,
    },
    "revision": revision,
    "launch_manifest_sha256": launch_sha256,
    "root_mode": "0500",
    "semantic_metadata_path": metadata["path_rel"],
    "validation_candidate_sha256": metadata["sha256"],
    "artifacts": sorted(records, key=lambda record: record["role"]),
    "missing_expected": [],
}
encoded = (
    json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    + "\n"
).encode("ascii")
parent_fd = os.open(
    os.path.dirname(output), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
)
try:
    descriptor = os.open(
        os.path.basename(output),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
        dir_fd=parent_fd,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise RuntimeError("short compute-index write")
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
}

scientific_reject() {
  local reason="$1"
  local project_exit="$2"
  local audit_exit="$3"
  local source_after
  source_after="$(sha256_file "$TARGET")"
  pinned_python - "$REJECTION" "$reason" "$project_exit" "$audit_exit" \
    "$EXPECTED_REVISION" "$SLURM_JOB_ID" "$TARGET_RELATIVE_PATH" \
    "$SOURCE_BEFORE_SHA256" "$source_after" "$LAUNCH_MANIFEST_SHA256" <<'PY'
import json
import os
import sys

output, reason, project_exit, audit_exit, revision, job_id, relative, before, after, manifest = sys.argv[1:]
payload = {
    "schema": "euf-viper.t11-stage0a-rejection.v2",
    "status": "rejected",
    "decision": "stop_before_stage0b",
    "reason": reason,
    "project_exit": int(project_exit),
    "audit_exit": int(audit_exit),
    "revision": revision,
    "job_id": int(job_id),
    "launch_manifest_sha256": manifest,
    "target": {
        "relative_path": relative,
        "source_before_sha256": before,
        "source_after_sha256": after,
    },
}
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
parent_fd = os.open(os.path.dirname(output), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    fd = os.open(
        os.path.basename(output),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
        dir_fd=parent_fd,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(fd, encoded[offset:])
            if written <= 0:
                raise RuntimeError("short scientific-rejection write")
            offset += written
        os.fsync(fd)
        os.fchmod(fd, 0o400)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
  for artifact in \
    "$BUILD_STDOUT" "$BUILD_STDERR" "$PROJECT_STDOUT" "$PROJECT_STDERR" \
    "$AUDIT_STDOUT" "$AUDIT_STDERR" "$BUNDLE" "$RECEIPT"; do
    if [ -f "$artifact" ] && [ ! -L "$artifact" ]; then
      chmod 400 "$artifact"
      fsync_path "$artifact"
    fi
  done
  seal_run_root
  TERMINAL_STATE=scientific_rejection
  echo "T11 Stage 0A rejected: $reason" >&2
  echo "t11_stage0a_root=$RUN_ROOT"
  exit 3
}

STAGE0A_PHASE=project
PROJECT_REQUEST_SHA256_VALUE="$(write_exec_request project "$PROJECT_REQUEST" "$RUN_HOME" \
  "$BINARY" "$BINARY_BEFORE_SHA256" \
  --input @SOURCE@ "$SOURCE_SNAPSHOT" "$SOURCE_BEFORE_SHA256" \
  --argv euf-viper project-t11 @SOURCE@ --bundle-out "$BUNDLE")" ||
  die "project request publication failed"
readonly PROJECT_REQUEST_SHA256="$PROJECT_REQUEST_SHA256_VALUE"
canonical_sha256 "$PROJECT_REQUEST_SHA256" || die "project request digest is malformed"
set +e
sealed_exec_request "$PROJECT_REQUEST" "$PROJECT_REQUEST_SHA256" \
  >"$PROJECT_STDOUT" 2>"$PROJECT_STDERR"
PROJECT_EXIT=$?
set -e
seal_file "$PROJECT_STDOUT"
seal_file "$PROJECT_STDERR"
case "$PROJECT_EXIT" in
  4|3) ;;
  *) die "projector execution contract failed with exit $PROJECT_EXIT" ;;
esac
[ -f "$BUNDLE" ] && [ ! -L "$BUNDLE" ] ||
  die "projector accepted without a regular bundle"
BUNDLE_PROJECT_SHA256_VALUE="$(
  verify_publication_binding "$PROJECT_STDOUT" "$BUNDLE" bundle
)" || die "projector bundle differs from its producer binding"
readonly BUNDLE_PROJECT_SHA256="$BUNDLE_PROJECT_SHA256_VALUE"
fsync_path "$BUNDLE"
if [ "$PROJECT_EXIT" -eq 3 ]; then
  scientific_reject projector_rejected 3 -1
fi
assert_clean_checkout

STAGE0A_PHASE=audit
verify_publication_binding "$PROJECT_STDOUT" "$BUNDLE" bundle >/dev/null ||
  die "bundle changed before external audit"
AUDIT_REQUEST_SHA256_VALUE="$(write_exec_request audit "$AUDIT_REQUEST" "$RUN_HOME" \
  "$BINARY" "$BINARY_BEFORE_SHA256" \
  --input @SOURCE@ "$SOURCE_SNAPSHOT" "$SOURCE_BEFORE_SHA256" \
  --input @BUNDLE@ "$BUNDLE" "$BUNDLE_PROJECT_SHA256" \
  --argv euf-viper audit-t11 @SOURCE@ --bundle @BUNDLE@ \
  --receipt-out "$RECEIPT")" || die "audit request publication failed"
readonly AUDIT_REQUEST_SHA256="$AUDIT_REQUEST_SHA256_VALUE"
canonical_sha256 "$AUDIT_REQUEST_SHA256" || die "audit request digest is malformed"
set +e
sealed_exec_request "$AUDIT_REQUEST" "$AUDIT_REQUEST_SHA256" \
  >"$AUDIT_STDOUT" 2>"$AUDIT_STDERR"
AUDIT_EXIT=$?
set -e
seal_file "$AUDIT_STDOUT"
seal_file "$AUDIT_STDERR"
case "$AUDIT_EXIT" in
  0|3) ;;
  *) die "external-auditor execution contract failed with exit $AUDIT_EXIT" ;;
esac
[ -f "$RECEIPT" ] && [ ! -L "$RECEIPT" ] ||
  die "external auditor accepted without a regular receipt"
RECEIPT_SHA256_VALUE="$(
  verify_publication_binding "$AUDIT_STDOUT" "$RECEIPT" "audit receipt"
)" || die "audit receipt differs from its producer binding"
readonly RECEIPT_SHA256="$RECEIPT_SHA256_VALUE"
fsync_path "$RECEIPT"
BUNDLE_AUDIT_SHA256_VALUE="$(
  verify_publication_binding "$PROJECT_STDOUT" "$BUNDLE" bundle
)" || die "bundle changed during external audit"
readonly BUNDLE_AUDIT_SHA256="$BUNDLE_AUDIT_SHA256_VALUE"
if [ "$AUDIT_EXIT" -eq 3 ]; then
  scientific_reject external_auditor_rejected 4 3
fi
readonly BINARY_AFTER_SHA256="$(sha256_file "$BINARY")"
readonly SOURCE_AFTER_SHA256="$(sha256_file "$TARGET")"
[ "$BUNDLE_AUDIT_SHA256" = "$BUNDLE_PROJECT_SHA256" ] ||
  die "bundle identity changed between projection and audit"
[ "$BINARY_AFTER_SHA256" = "$BINARY_BEFORE_SHA256" ] ||
  die "binary identity changed after execution"
[ "$SOURCE_AFTER_SHA256" = "$SOURCE_BEFORE_SHA256" ] &&
  [ "$SOURCE_AFTER_SHA256" = "$TARGET_SHA256" ] ||
  die "source identity changed after snapshotting"
assert_clean_checkout

STAGE0A_PHASE=validate
verify_publication_binding "$PROJECT_STDOUT" "$BUNDLE" bundle >/dev/null ||
  die "bundle changed before independent validation"
verify_publication_binding "$AUDIT_STDOUT" "$RECEIPT" "audit receipt" >/dev/null ||
  die "audit receipt changed before independent validation"
readonly BUILD_STDOUT_SHA256="$(sha256_file "$BUILD_STDOUT")"
readonly BUILD_STDERR_SHA256="$(sha256_file "$BUILD_STDERR")"
readonly BUILD_CLOSURE_STDOUT_SHA256="$(sha256_file "$BUILD_CLOSURE_STDOUT")"
readonly BUILD_CLOSURE_STDERR_SHA256="$(sha256_file "$BUILD_CLOSURE_STDERR")"
readonly PROJECT_STDOUT_SHA256="$(sha256_file "$PROJECT_STDOUT")"
readonly PROJECT_STDERR_SHA256="$(sha256_file "$PROJECT_STDERR")"
readonly AUDIT_STDOUT_SHA256="$(sha256_file "$AUDIT_STDOUT")"
readonly AUDIT_STDERR_SHA256="$(sha256_file "$AUDIT_STDERR")"
VALIDATION_REQUEST_SHA256_VALUE="$(write_exec_request validate "$VALIDATION_REQUEST" "$RUN_HOME" \
  "$PYTHON_SNAPSHOT" "$PYTHON_SHA256" \
  --input @VALIDATOR@ "$VALIDATOR_SNAPSHOT" "$VALIDATOR_SHA256" \
  --input @SOURCE@ "$SOURCE_SNAPSHOT" "$SOURCE_AFTER_SHA256" \
  --input @BUNDLE@ "$BUNDLE" "$BUNDLE_AUDIT_SHA256" \
  --input @RECEIPT@ "$RECEIPT" "$RECEIPT_SHA256" \
  --input @BINARY@ "$BINARY" "$BINARY_AFTER_SHA256" \
  --input @LAUNCH_MANIFEST@ "$LAUNCH_MANIFEST_SNAPSHOT" "$LAUNCH_MANIFEST_SHA256" \
  --input @CARGO@ "$CARGO_SNAPSHOT" "$CARGO_SHA256" \
  --input @RUSTC@ "$RUSTC_SNAPSHOT" "$RUSTC_SHA256" \
  --input @PYTHON_TOOL@ "$PYTHON_SNAPSHOT" "$PYTHON_SHA256" \
  --input @CARGO_TOML@ "$CARGO_TOML_SNAPSHOT" "$CARGO_TOML_SHA256" \
  --input @CARGO_LOCK@ "$CARGO_LOCK_SNAPSHOT" "$CARGO_LOCK_SHA256" \
  --input @DESIGN_NOTE@ "$DESIGN_NOTE_SNAPSHOT" "$DESIGN_NOTE_SHA256" \
  --input @HASH_CONTRACT@ "$HASH_CONTRACT_SNAPSHOT" "$HASH_CONTRACT_SHA256" \
  --input @AUDIT_CONTRACT@ "$AUDIT_CONTRACT_SNAPSHOT" "$AUDIT_CONTRACT_SHA256" \
  --input @SUBMITTER@ "$SUBMITTER_SNAPSHOT" "$SUBMITTER_SHA256" \
  --input @RUNNER@ "$RUNNER_SNAPSHOT" "$RUNNER_SHA256" \
  --input @FINALIZER_SBATCH@ "$FINALIZER_SBATCH_SNAPSHOT" "$FINALIZER_SBATCH_SHA256" \
  --input @FINALIZER@ "$FINALIZER_SNAPSHOT" "$FINALIZER_SHA256" \
  --input @AUTHORIZER@ "$AUTHORIZER_SNAPSHOT" "$AUTHORIZER_SHA256" \
  --input @EXEC_HELPER@ "$EXEC_HELPER_SNAPSHOT" "$EXEC_HELPER_SHA256" \
  --input @CONTROL_GIT@ "$CONTROL_GIT_SNAPSHOT" "$CONTROL_GIT_SHA256" \
  --input @BUILD_CLOSURE_TOOL@ "$BUILD_CLOSURE_TOOL_SNAPSHOT" "$BUILD_CLOSURE_TOOL_SHA256" \
  --input @BUILD_CLOSURE_STDOUT@ "$BUILD_CLOSURE_STDOUT" "$BUILD_CLOSURE_STDOUT_SHA256" \
  --input @BUILD_CLOSURE_STDERR@ "$BUILD_CLOSURE_STDERR" "$BUILD_CLOSURE_STDERR_SHA256" \
  --input @BUILD_STDOUT@ "$BUILD_STDOUT" "$BUILD_STDOUT_SHA256" \
  --input @BUILD_STDERR@ "$BUILD_STDERR" "$BUILD_STDERR_SHA256" \
  --input @PROJECT_STDOUT@ "$PROJECT_STDOUT" "$PROJECT_STDOUT_SHA256" \
  --input @PROJECT_STDERR@ "$PROJECT_STDERR" "$PROJECT_STDERR_SHA256" \
  --input @AUDIT_STDOUT@ "$AUDIT_STDOUT" "$AUDIT_STDOUT_SHA256" \
  --input @AUDIT_STDERR@ "$AUDIT_STDERR" "$AUDIT_STDERR_SHA256" \
  --argv python3 -I -S -B @VALIDATOR@ \
  --source @SOURCE@ --bundle @BUNDLE@ \
  --receipt @RECEIPT@ --binary @BINARY@ \
  --metadata-out "$METADATA" \
  --launch-manifest @LAUNCH_MANIFEST@ \
  --launch-manifest-sha256 "$LAUNCH_MANIFEST_SHA256" \
  --job-id "$SLURM_JOB_ID" \
  --source-before-sha256 "$SOURCE_BEFORE_SHA256" \
  --source-after-sha256 "$SOURCE_AFTER_SHA256" \
  --binary-before-sha256 "$BINARY_BEFORE_SHA256" \
  --binary-after-sha256 "$BINARY_AFTER_SHA256" \
  --bundle-project-sha256 "$BUNDLE_PROJECT_SHA256" \
  --bundle-audit-sha256 "$BUNDLE_AUDIT_SHA256" \
  --project-exit "$PROJECT_EXIT" \
  --audit-exit "$AUDIT_EXIT" \
  --artifact source "$TARGET" @SOURCE@ \
  --artifact binary "$BINARY" @BINARY@ \
  --artifact cargo "$CARGO" @CARGO@ \
  --artifact rustc "$RUSTC" @RUSTC@ \
  --artifact python "$PYTHON" @PYTHON_TOOL@ \
  --artifact cargo_toml "$REPO_ROOT/Cargo.toml" @CARGO_TOML@ \
  --artifact cargo_lock "$REPO_ROOT/Cargo.lock" @CARGO_LOCK@ \
  --artifact design_note "$DESIGN_NOTE" @DESIGN_NOTE@ \
  --artifact hash_contract "$HASH_CONTRACT" @HASH_CONTRACT@ \
  --artifact audit_contract "$AUDIT_CONTRACT" @AUDIT_CONTRACT@ \
  --artifact submitter "$SUBMITTER" @SUBMITTER@ \
  --artifact runner "$RUNNER_SNAPSHOT" @RUNNER@ \
  --artifact finalizer_sbatch "$FINALIZER_SBATCH" @FINALIZER_SBATCH@ \
  --artifact finalizer "$FINALIZER" @FINALIZER@ \
  --artifact authorizer "$AUTHORIZER" @AUTHORIZER@ \
  --artifact validator "$VALIDATOR" @VALIDATOR@ \
  --artifact exec_helper "$EXEC_HELPER" @EXEC_HELPER@ \
  --artifact control_git "$CONTROL_GIT" @CONTROL_GIT@ \
  --artifact build_closure_tool "$BUILD_CLOSURE_TOOL" @BUILD_CLOSURE_TOOL@ \
  --artifact build_closure_stdout "$BUILD_CLOSURE_STDOUT" @BUILD_CLOSURE_STDOUT@ \
  --artifact build_closure_stderr "$BUILD_CLOSURE_STDERR" @BUILD_CLOSURE_STDERR@ \
  --artifact launch_manifest "$LAUNCH_MANIFEST" @LAUNCH_MANIFEST@ \
  --artifact build_stdout "$BUILD_STDOUT" @BUILD_STDOUT@ \
  --artifact build_stderr "$BUILD_STDERR" @BUILD_STDERR@ \
  --artifact bundle "$BUNDLE" @BUNDLE@ \
  --artifact audit_receipt "$RECEIPT" @RECEIPT@ \
  --artifact project_stdout "$PROJECT_STDOUT" @PROJECT_STDOUT@ \
  --artifact project_stderr "$PROJECT_STDERR" @PROJECT_STDERR@ \
  --artifact audit_stdout "$AUDIT_STDOUT" @AUDIT_STDOUT@ \
  --artifact audit_stderr "$AUDIT_STDERR" @AUDIT_STDERR@)" ||
  die "validation request publication failed"
readonly VALIDATION_REQUEST_SHA256="$VALIDATION_REQUEST_SHA256_VALUE"
canonical_sha256 "$VALIDATION_REQUEST_SHA256" ||
  die "validation request digest is malformed"
set +e
sealed_exec_request "$VALIDATION_REQUEST" "$VALIDATION_REQUEST_SHA256" \
  >"$VALIDATION_STDOUT" 2>"$VALIDATION_STDERR"
VALIDATION_EXIT=$?
set -e
seal_file "$VALIDATION_STDOUT"
seal_file "$VALIDATION_STDERR"
case "$VALIDATION_EXIT" in
  0) ;;
  3) die "independent validator rejected the candidate evidence" ;;
  *) die "independent-validator execution contract failed with exit $VALIDATION_EXIT" ;;
esac

[ -f "$METADATA" ] && [ ! -L "$METADATA" ] &&
  [ "$(stat -c '%a' "$METADATA")" = 400 ] ||
  die "Stage 0A metadata is missing, mutable, or a symlink"
METADATA_SHA256_VALUE="$(
  verify_publication_binding "$VALIDATION_STDOUT" "$METADATA" "validation metadata"
)" || die "validation metadata differs from its producer binding"
readonly METADATA_SHA256="$METADATA_SHA256_VALUE"
fsync_path "$METADATA"
verify_publication_binding "$PROJECT_STDOUT" "$BUNDLE" bundle >/dev/null ||
  die "bundle changed after independent validation"
verify_publication_binding "$AUDIT_STDOUT" "$RECEIPT" "audit receipt" >/dev/null ||
  die "audit receipt changed after independent validation"
assert_clean_checkout
STAGE0A_PHASE=discard_transient_build_state
discard_transient_tree "$BUILD_CLOSURE_ROOT"
discard_transient_tree "$RUN_TMP"
discard_transient_tree "$RUN_HOME"
STAGE0A_PHASE=write_compute_index
write_compute_index "$COMPUTE_INDEX" \
  validation_candidate "$METADATA" \
  launch_values "$LAUNCH_VALUES" \
  executed_runner "$RUNNER_SNAPSHOT" \
  submitter "$SUBMITTER_SNAPSHOT" \
  finalizer_sbatch "$FINALIZER_SBATCH_SNAPSHOT" \
  finalizer "$FINALIZER_SNAPSHOT" \
  authorizer "$AUTHORIZER_SNAPSHOT" \
  launch_manifest "$LAUNCH_MANIFEST_SNAPSHOT" \
  validator "$VALIDATOR_SNAPSHOT" \
  exec_helper "$EXEC_HELPER_SNAPSHOT" \
  control_git "$CONTROL_GIT_SNAPSHOT" \
  build_closure_tool "$BUILD_CLOSURE_TOOL_SNAPSHOT" \
  build_closure_stdout "$BUILD_CLOSURE_STDOUT" \
  build_closure_stderr "$BUILD_CLOSURE_STDERR" \
  cargo "$CARGO_SNAPSHOT" \
  rustc "$RUSTC_SNAPSHOT" \
  python "$PYTHON_SNAPSHOT" \
  cargo_toml "$CARGO_TOML_SNAPSHOT" \
  cargo_lock "$CARGO_LOCK_SNAPSHOT" \
  design_note "$DESIGN_NOTE_SNAPSHOT" \
  hash_contract "$HASH_CONTRACT_SNAPSHOT" \
  audit_contract "$AUDIT_CONTRACT_SNAPSHOT" \
  source_snapshot "$SOURCE_SNAPSHOT" \
  binary "$BINARY" \
  build_stdout "$BUILD_STDOUT" \
  build_stderr "$BUILD_STDERR" \
  project_request "$PROJECT_REQUEST" \
  project_stdout "$PROJECT_STDOUT" \
  project_stderr "$PROJECT_STDERR" \
  bundle "$BUNDLE" \
  audit_request "$AUDIT_REQUEST" \
  audit_stdout "$AUDIT_STDOUT" \
  audit_stderr "$AUDIT_STDERR" \
  audit_receipt "$RECEIPT" \
  validation_request "$VALIDATION_REQUEST" \
  validation_stdout "$VALIDATION_STDOUT" \
  validation_stderr "$VALIDATION_STDERR"
seal_file "$COMPUTE_INDEX"
STAGE0A_PHASE=seal_success
seal_run_root
TERMINAL_STATE=candidate_complete

printf 't11_stage0a_root=%s\n' "$RUN_ROOT"
printf 't11_stage0a_revision=%s\n' "$EXPECTED_REVISION"
printf 't11_stage0a_manifest_sha256=%s\n' "$LAUNCH_MANIFEST_SHA256"
printf 't11_stage0a_target_sha256=%s\n' "$SOURCE_AFTER_SHA256"
printf 't11_stage0a_binary_sha256=%s\n' "$BINARY_AFTER_SHA256"
printf 't11_stage0a_bundle_sha256=%s\n' "$BUNDLE_AUDIT_SHA256"
printf 't11_stage0a_receipt_sha256=%s\n' "$RECEIPT_SHA256"
printf 't11_stage0a_compute_index_sha256=%s\n' "$(sha256_file "$COMPUTE_INDEX")"
printf 't11_stage0a_decision=requires_scheduler_finalization\n'
