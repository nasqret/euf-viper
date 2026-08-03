#!/usr/bin/env bash
set -euo pipefail
umask 077

# This submitter runs on the Slurm submit host. The launch-manifest fields named
# below are an explicit integration requirement for the T11 finalization work.

die() {
  echo "T11 Stage 0A submission rejected: $*" >&2
  exit 2
}

canonical_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
    *) return 0 ;;
  esac
}

canonical_positive_decimal() {
  case "$1" in
    ''|0|0*|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

canonical_nonnegative_number() {
  local value="$1"
  local integer
  local fraction
  case "$value" in
    ''|*[!0-9.]*|*.*.*|.*|*.) return 1 ;;
  esac
  case "$value" in
    *.*)
      integer="${value%%.*}"
      fraction="${value#*.}"
      case "$integer" in 0|[1-9]|[1-9][0-9]*) ;; *) return 1 ;; esac
      case "$fraction" in ''|*[!0-9]*) return 1 ;; esac
      ;;
    *)
      case "$value" in 0|[1-9]|[1-9][0-9]*) ;; *) return 1 ;; esac
      ;;
  esac
}

safe_cluster_name() {
  case "$1" in
    ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    *) return 0 ;;
  esac
}

safe_partition_name() {
  case "$1" in
    ''|*[!A-Za-z0-9_-]*) return 1 ;;
    *) return 0 ;;
  esac
}

safe_export_value() {
  case "$1" in
    ''|*[!A-Za-z0-9_./:@+-]*) return 1 ;;
    *) return 0 ;;
  esac
}

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly SUBMITTER="$ROOT/scripts/wmi/submit_t11_stage0a.sh"
readonly REPO_RUNNER="$ROOT/scripts/wmi/euf_viper_t11_stage0a.sbatch"
readonly REPO_FINALIZER_RUNNER="$ROOT/scripts/wmi/euf_viper_t11_stage0a_finalize.sbatch"
readonly VALIDATOR="$ROOT/scripts/bench/validate_t11_stage0a.py"
readonly EXEC_HELPER="$ROOT/scripts/bench/exec_t11_stage0a.py"
readonly FINALIZER="${EUF_VIPER_T11_FINALIZER_PATH:-$ROOT/scripts/bench/finalize_t11_stage0a.py}"
readonly AUTHORIZER="${EUF_VIPER_T11_AUTHORIZER_PATH:-$ROOT/scripts/bench/authorize_t11_stage0a.py}"

readonly CONTROLLER_PYTHON="${EUF_VIPER_T11_CONTROLLER_PYTHON:?set an absolute pinned controller Python path}"
readonly CONTROLLER_PYTHON_SHA256="${EUF_VIPER_T11_CONTROLLER_PYTHON_SHA256:?set the controller Python SHA-256}"
readonly GIT="${EUF_VIPER_T11_GIT:?set an absolute pinned git path}"
readonly GIT_SHA256="${EUF_VIPER_T11_GIT_SHA256:?set the git SHA-256}"
readonly SBATCH="${EUF_VIPER_T11_SBATCH:?set an absolute pinned sbatch path}"
readonly SBATCH_SHA256="${EUF_VIPER_T11_SBATCH_SHA256:?set the sbatch SHA-256}"
readonly SCONTROL="${EUF_VIPER_T11_SCONTROL:?set an absolute pinned scontrol path}"
readonly SCONTROL_SHA256="${EUF_VIPER_T11_SCONTROL_SHA256:?set the scontrol SHA-256}"
readonly SCANCEL="${EUF_VIPER_T11_SCANCEL:?set an absolute pinned scancel path}"
readonly SCANCEL_SHA256="${EUF_VIPER_T11_SCANCEL_SHA256:?set the scancel SHA-256}"
readonly SACCT="${EUF_VIPER_T11_SACCT:?set an absolute pinned sacct path}"
readonly SACCT_SHA256="${EUF_VIPER_T11_SACCT_SHA256:?set the sacct SHA-256}"

readonly RUN_BASE_INPUT="${EUF_VIPER_T11_RUN_BASE:?set an absolute external run base}"
readonly CORPUS_ROOT_INPUT="${EUF_VIPER_T11_CORPUS_ROOT:?set an absolute frozen corpus root}"
readonly LAUNCH_MANIFEST_INPUT="${EUF_VIPER_T11_LAUNCH_MANIFEST:?set an absolute reviewed launch manifest path}"
readonly LAUNCH_MANIFEST_SHA256="${EUF_VIPER_T11_LAUNCH_MANIFEST_SHA256:?set the reviewed launch manifest SHA-256}"
readonly EXPECTED_REVISION="${EUF_VIPER_T11_EXPECTED_REVISION:?set the exact 40-hex solver revision}"
readonly CLUSTER="${EUF_VIPER_T11_CLUSTER:?set the exact Slurm cluster name}"
readonly PARTITION="${EUF_VIPER_T11_PARTITION:-cpu_idle}"
readonly FINALIZER_POLL_ATTEMPTS="${EUF_VIPER_T11_FINALIZER_POLL_ATTEMPTS:-12}"
readonly FINALIZER_POLL_INTERVAL_SECONDS="${EUF_VIPER_T11_FINALIZER_POLL_INTERVAL_SECONDS:-5}"

canonical_sha256 "$CONTROLLER_PYTHON_SHA256" || die "controller Python SHA-256 is malformed"
canonical_sha256 "$GIT_SHA256" || die "git SHA-256 is malformed"
canonical_sha256 "$SBATCH_SHA256" || die "sbatch SHA-256 is malformed"
canonical_sha256 "$SCONTROL_SHA256" || die "scontrol SHA-256 is malformed"
canonical_sha256 "$SCANCEL_SHA256" || die "scancel SHA-256 is malformed"
canonical_sha256 "$SACCT_SHA256" || die "sacct SHA-256 is malformed"
canonical_sha256 "$LAUNCH_MANIFEST_SHA256" || die "launch manifest SHA-256 is malformed"
case "$EXPECTED_REVISION" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]* ) ;;
  *) die "expected revision is malformed" ;;
esac
[ "${#EXPECTED_REVISION}" -eq 40 ] || die "expected revision must contain 40 lowercase hex digits"
case "$EXPECTED_REVISION" in *[!0-9a-f]*) die "expected revision is malformed" ;; esac
safe_cluster_name "$CLUSTER" || die "cluster name contains unsafe characters"
safe_partition_name "$PARTITION" || die "partition name contains unsafe characters"
canonical_positive_decimal "$FINALIZER_POLL_ATTEMPTS" ||
  die "finalizer poll-attempt count must be canonical and positive"
canonical_nonnegative_number "$FINALIZER_POLL_INTERVAL_SECONDS" ||
  die "finalizer poll interval must be a canonical nonnegative decimal"

for path in "$CONTROLLER_PYTHON" "$GIT" "$SBATCH" "$SCONTROL" "$SCANCEL" "$SACCT"; do
  case "$path" in /*) ;; *) die "control executable path must be absolute: $path" ;; esac
  [ -f "$path" ] && [ ! -L "$path" ] && [ -x "$path" ] ||
    die "control executable is missing, nonregular, nonexecutable, or a symlink: $path"
done

sha256_file() {
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B -c \
    'import hashlib,sys; h=hashlib.sha256(); f=open(sys.argv[1],"rb"); [h.update(b) for b in iter(lambda:f.read(1048576),b"")]; print(h.hexdigest())' \
    "$1"
}

require_sha256() {
  local path="$1"
  local expected="$2"
  local label="$3"
  [ -f "$path" ] && [ ! -L "$path" ] ||
    die "$label is missing, nonregular, or a symlink: $path"
  [ "$(sha256_file "$path")" = "$expected" ] || die "$label SHA-256 mismatch"
}

# The pinned Python is the explicit submit-host bootstrap trust anchor.
require_sha256 "$CONTROLLER_PYTHON" "$CONTROLLER_PYTHON_SHA256" "controller Python"
require_sha256 "$GIT" "$GIT_SHA256" git
require_sha256 "$SBATCH" "$SBATCH_SHA256" sbatch
require_sha256 "$SCONTROL" "$SCONTROL_SHA256" scontrol
require_sha256 "$SCANCEL" "$SCANCEL_SHA256" scancel
require_sha256 "$SACCT" "$SACCT_SHA256" sacct

sealed_control() {
  local executable="$1"
  local expected_sha256="$2"
  shift 2
  "$CONTROLLER_PYTHON" -I -S -B - "$executable" "$expected_sha256" "$@" <<'PY'
import fcntl
import hashlib
import os
import stat
import subprocess
import sys

path, expected, *arguments = sys.argv[1:]
flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
source_fd = os.open(path, flags)
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
        raise SystemExit("control executable is not an executable regular file")
    if before.st_size > 1024 * 1024 * 1024:
        raise SystemExit("control executable exceeds its size bound")
    payload = bytearray()
    while True:
        block = os.read(source_fd, 1024 * 1024)
        if not block:
            break
        payload.extend(block)
    after = os.fstat(source_fd)
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    if identity != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise SystemExit("control executable changed while it was read")
finally:
    os.close(source_fd)
if hashlib.sha256(payload).hexdigest() != expected:
    raise SystemExit("control executable digest differs")

if sys.platform.startswith("linux"):
    if not hasattr(os, "memfd_create"):
        raise SystemExit("Linux control execution requires memfd support")
    descriptor = os.memfd_create(
        "t11-submit-control",
        getattr(os, "MFD_CLOEXEC", 0x0001)
        | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
    )
    executable_path = f"/proc/self/fd/{descriptor}"
else:
    descriptor = -1
    executable_path = path
try:
    if sys.platform.startswith("linux"):
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise SystemExit("short control executable snapshot write")
            offset += written
        os.fchmod(descriptor, 0o500)
        seals = (
            getattr(fcntl, "F_SEAL_WRITE", 0x0008)
            | getattr(fcntl, "F_SEAL_GROW", 0x0004)
            | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
            | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
        )
        fcntl.fcntl(descriptor, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
        if fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS", 1034)) & seals != seals:
            raise SystemExit("control executable snapshot lacks mandatory seals")
        inherited_descriptors = (descriptor,)
    else:
        inherited_descriptors = ()
    environment = os.environ.copy()
    environment.update({"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"})
    completed = subprocess.run(
        [path, *arguments],
        executable=executable_path,
        check=False,
        env=environment,
        pass_fds=inherited_descriptors,
    )
finally:
    if descriptor >= 0:
        os.close(descriptor)

named = os.stat(path, follow_symlinks=False)
if not stat.S_ISREG(named.st_mode):
    raise SystemExit("control executable pathname changed type")
current = (
    named.st_dev,
    named.st_ino,
    named.st_mode,
    named.st_size,
    named.st_mtime_ns,
    named.st_ctime_ns,
)
if current != identity:
    raise SystemExit("control executable pathname changed during execution")
raise SystemExit(completed.returncode)
PY
}

canonical_directory() {
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B - "$1" "$2" <<'PY'
import os
import sys

path, label = sys.argv[1:]
if not os.path.isabs(path):
    raise SystemExit(f"{label} must be absolute")
if os.path.islink(path) or not os.path.isdir(path):
    raise SystemExit(f"{label} must be an existing nonsymlink directory")
print(os.path.realpath(path))
PY
}

readonly RUN_BASE="$(canonical_directory "$RUN_BASE_INPUT" "run base")"
readonly CORPUS_ROOT="$(canonical_directory "$CORPUS_ROOT_INPUT" "corpus root")"
case "$RUN_BASE" in "$ROOT"|"$ROOT"/*) die "run base must be outside the checkout" ;; esac
for value in \
  "$ROOT" "$RUN_BASE" "$CORPUS_ROOT" "$LAUNCH_MANIFEST_INPUT" "$FINALIZER" "$AUTHORIZER" \
  "$CONTROLLER_PYTHON" "$SACCT" "$SCONTROL"; do
  safe_export_value "$value" || die "path cannot be represented in a Slurm export: $value"
done

case "$LAUNCH_MANIFEST_INPUT" in /*) ;; *) die "launch manifest path must be absolute" ;; esac
case "$FINALIZER" in /*) ;; *) die "finalizer path must be absolute" ;; esac
require_sha256 "$LAUNCH_MANIFEST_INPUT" "$LAUNCH_MANIFEST_SHA256" "launch manifest"

cd "$ROOT"
GIT_STATUS="$(sealed_control "$GIT" "$GIT_SHA256" status --porcelain=v1 --untracked-files=all)" ||
  die "sealed git status failed"
[ -z "$GIT_STATUS" ] ||
  die "checkout must be completely clean before submission"
REVISION_VALUE="$(sealed_control "$GIT" "$GIT_SHA256" rev-parse --verify 'HEAD^{commit}')" ||
  die "sealed git revision lookup failed"
readonly REVISION="$REVISION_VALUE"
[ "$REVISION" = "$EXPECTED_REVISION" ] || die "checkout revision differs from the expected revision"

readonly MANIFEST_VALUES="$({
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B - \
    "$LAUNCH_MANIFEST_INPUT" "$LAUNCH_MANIFEST_SHA256" <<'PY'
import hashlib
import json
import re
import sys

path, expected = sys.argv[1:]
with open(path, "rb") as handle:
    encoded = handle.read()
if hashlib.sha256(encoded).hexdigest() != expected:
    raise SystemExit("launch manifest digest drifted while inspecting it")
manifest = json.loads(encoded)
revision = manifest.get("solver_revision")
if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
    raise SystemExit("launch manifest solver revision is malformed")
toolchain = manifest.get("toolchain")
artifacts = manifest.get("artifacts")
control_tools = manifest.get("control_tools")
if not isinstance(toolchain, dict) or not isinstance(artifacts, dict) or not isinstance(control_tools, dict):
    raise SystemExit("launch manifest lacks toolchain, control_tools, or artifacts")
python = toolchain.get("python")
if not isinstance(python, dict):
    raise SystemExit("launch manifest lacks the pinned Python record")
fields = [
    revision,
    python.get("path"),
    python.get("sha256"),
    artifacts.get("submitter_sha256"),
    artifacts.get("runner_sha256"),
    artifacts.get("finalizer_sbatch_sha256"),
    artifacts.get("finalizer_sha256"),
    artifacts.get("authorizer_sha256"),
    artifacts.get("validator_sha256"),
    artifacts.get("exec_helper_sha256"),
]
if not isinstance(fields[1], str) or not fields[1].startswith("/"):
    raise SystemExit("launch manifest Python path is malformed")
for name, value in zip(
    (
        "python",
        "submitter",
        "runner",
        "finalizer_sbatch",
        "finalizer",
        "authorizer",
        "validator",
        "exec_helper",
    ),
    fields[2:],
):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SystemExit(f"launch manifest {name} digest is malformed or absent")
for name in ("git", "sbatch", "scontrol", "scancel", "sacct"):
    tool = control_tools.get(name)
    if not isinstance(tool, dict):
        raise SystemExit(f"launch manifest lacks control tool {name}")
    tool_path, tool_sha256 = tool.get("path"), tool.get("sha256")
    if not isinstance(tool_path, str) or not tool_path.startswith("/"):
        raise SystemExit(f"launch manifest control tool {name} path is malformed")
    if not isinstance(tool_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", tool_sha256) is None:
        raise SystemExit(f"launch manifest control tool {name} digest is malformed")
    fields.extend((tool_path, tool_sha256))
print(" ".join(fields))
PY
})"
set -- $MANIFEST_VALUES
[ "$#" -eq 20 ] || die "launch manifest inspector returned the wrong field count"
readonly MANIFEST_REVISION="$1"
readonly MANIFEST_PYTHON="$2"
readonly MANIFEST_PYTHON_SHA256="$3"
readonly SUBMITTER_SHA256="$4"
readonly RUNNER_SHA256="$5"
readonly FINALIZER_RUNNER_SHA256="$6"
readonly FINALIZER_SHA256="$7"
readonly AUTHORIZER_SHA256="$8"
readonly VALIDATOR_SHA256="$9"
readonly EXEC_HELPER_SHA256="${10}"
readonly MANIFEST_GIT="${11}"
readonly MANIFEST_GIT_SHA256="${12}"
readonly MANIFEST_SBATCH="${13}"
readonly MANIFEST_SBATCH_SHA256="${14}"
readonly MANIFEST_SCONTROL="${15}"
readonly MANIFEST_SCONTROL_SHA256="${16}"
readonly MANIFEST_SCANCEL="${17}"
readonly MANIFEST_SCANCEL_SHA256="${18}"
readonly MANIFEST_SACCT="${19}"
readonly MANIFEST_SACCT_SHA256="${20}"

[ "$MANIFEST_REVISION" = "$REVISION" ] || die "launch manifest revision differs from the checkout"
[ "$MANIFEST_PYTHON" = "$CONTROLLER_PYTHON" ] || die "controller Python differs from the manifest"
[ "$MANIFEST_PYTHON_SHA256" = "$CONTROLLER_PYTHON_SHA256" ] || die "controller Python digest differs from the manifest"
[ "$MANIFEST_GIT" = "$GIT" ] && [ "$MANIFEST_GIT_SHA256" = "$GIT_SHA256" ] ||
  die "git differs from the launch manifest"
[ "$MANIFEST_SBATCH" = "$SBATCH" ] && [ "$MANIFEST_SBATCH_SHA256" = "$SBATCH_SHA256" ] ||
  die "sbatch differs from the launch manifest"
[ "$MANIFEST_SCONTROL" = "$SCONTROL" ] && [ "$MANIFEST_SCONTROL_SHA256" = "$SCONTROL_SHA256" ] ||
  die "scontrol differs from the launch manifest"
[ "$MANIFEST_SCANCEL" = "$SCANCEL" ] && [ "$MANIFEST_SCANCEL_SHA256" = "$SCANCEL_SHA256" ] ||
  die "scancel differs from the launch manifest"
[ "$MANIFEST_SACCT" = "$SACCT" ] && [ "$MANIFEST_SACCT_SHA256" = "$SACCT_SHA256" ] ||
  die "sacct differs from the launch manifest"
require_sha256 "$SUBMITTER" "$SUBMITTER_SHA256" submitter
require_sha256 "$REPO_RUNNER" "$RUNNER_SHA256" "compute runner"
require_sha256 "$REPO_FINALIZER_RUNNER" "$FINALIZER_RUNNER_SHA256" "finalizer runner"
require_sha256 "$FINALIZER" "$FINALIZER_SHA256" finalizer
require_sha256 "$AUTHORIZER" "$AUTHORIZER_SHA256" authorizer
require_sha256 "$VALIDATOR" "$VALIDATOR_SHA256" validator
require_sha256 "$EXEC_HELPER" "$EXEC_HELPER_SHA256" "execution helper"

if [ -n "${EUF_VIPER_T11_RUN_NONCE:-}" ]; then
  readonly RUN_NONCE="$EUF_VIPER_T11_RUN_NONCE"
else
  readonly RUN_NONCE="$(/usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B -c 'import secrets; print(secrets.token_hex(16))')"
fi
case "$RUN_NONCE" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]* ) ;;
  *) die "run nonce is malformed" ;;
esac
[ "${#RUN_NONCE}" -eq 32 ] || die "run nonce must contain 32 lowercase hex digits"
case "$RUN_NONCE" in *[!0-9a-f]*) die "run nonce is malformed" ;; esac

readonly CAMPAIGN_ROOT="$RUN_BASE/t11-stage0a-submission-$RUN_NONCE"
readonly CONTROL_ROOT="$CAMPAIGN_ROOT/control"
readonly SCHEDULER_ROOT="$CAMPAIGN_ROOT/scheduler"
readonly FINALIZER_HOME="$CAMPAIGN_ROOT/finalizer-home"
readonly FINALIZER_TMP="$CAMPAIGN_ROOT/finalizer-tmp"
readonly SUBMISSION_RECORD="$CONTROL_ROOT/submission.json"
readonly ORCHESTRATION_RECORD="$CONTROL_ROOT/submission-orchestration.json"
readonly AUTHORIZATION_REQUEST="$CONTROL_ROOT/authorization-request.json"
readonly SCHEDULER_CANDIDATE="$CAMPAIGN_ROOT/scheduler-candidate.json"
readonly FINAL_DECISION="$CAMPAIGN_ROOT/stage0b-decision.json"
readonly COMPUTE_STDOUT="$SCHEDULER_ROOT/compute.stdout"
readonly COMPUTE_STDERR="$SCHEDULER_ROOT/compute.stderr"
readonly FINALIZER_STDOUT="$SCHEDULER_ROOT/finalizer.stdout"
readonly FINALIZER_STDERR="$SCHEDULER_ROOT/finalizer.stderr"

[ ! -e "$CAMPAIGN_ROOT" ] && [ ! -L "$CAMPAIGN_ROOT" ] || die "campaign root already exists"
mkdir -m 700 "$CAMPAIGN_ROOT"
mkdir -m 700 "$CONTROL_ROOT" "$SCHEDULER_ROOT" "$FINALIZER_HOME" "$FINALIZER_TMP"

fsync_path() {
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B -c \
    'import os,sys; p=sys.argv[1]; flags=os.O_RDONLY|os.O_CLOEXEC|(os.O_DIRECTORY if os.path.isdir(p) else 0); fd=os.open(p,flags); os.fsync(fd); os.close(fd)' \
    "$1"
}
fsync_path "$CAMPAIGN_ROOT"
fsync_path "$RUN_BASE"

snapshot_file() {
  local source="$1"
  local destination="$2"
  local expected="$3"
  local mode="$4"
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B - \
    "$source" "$destination" "$expected" "$mode" <<'PY'
import hashlib
import os
import stat
import sys

source, destination, expected, mode_text = sys.argv[1:]
flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
source_fd = os.open(source, flags)
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit("snapshot source is not regular")
    payload = bytearray()
    while True:
        block = os.read(source_fd, 1024 * 1024)
        if not block:
            break
        payload.extend(block)
    after = os.fstat(source_fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SystemExit("snapshot source identity changed while reading")
finally:
    os.close(source_fd)
if hashlib.sha256(payload).hexdigest() != expected:
    raise SystemExit("snapshot source digest differs")
parent = os.path.dirname(destination)
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    destination_fd = os.open(
        os.path.basename(destination),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        int(mode_text, 8),
        dir_fd=parent_fd,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(destination_fd, payload[offset:])
            if written <= 0:
                raise RuntimeError("short snapshot write")
            offset += written
        os.fsync(destination_fd)
        os.fchmod(destination_fd, int(mode_text, 8))
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
}

readonly COMPUTE_SCRIPT="$CONTROL_ROOT/euf_viper_t11_stage0a.sbatch"
readonly FINALIZER_SCRIPT="$CONTROL_ROOT/euf_viper_t11_stage0a_finalize.sbatch"
readonly FINALIZER_SNAPSHOT="$CONTROL_ROOT/finalize_t11_stage0a.py"
readonly AUTHORIZER_SNAPSHOT="$CONTROL_ROOT/authorize_t11_stage0a.py"
readonly VALIDATOR_SNAPSHOT="$CONTROL_ROOT/validate_t11_stage0a.py"
readonly EXEC_HELPER_SNAPSHOT="$CONTROL_ROOT/exec_t11_stage0a.py"
readonly MANIFEST_SNAPSHOT="$CONTROL_ROOT/launch-manifest.json"
snapshot_file "$REPO_RUNNER" "$COMPUTE_SCRIPT" "$RUNNER_SHA256" 0500
snapshot_file "$REPO_FINALIZER_RUNNER" "$FINALIZER_SCRIPT" "$FINALIZER_RUNNER_SHA256" 0500
snapshot_file "$FINALIZER" "$FINALIZER_SNAPSHOT" "$FINALIZER_SHA256" 0500
snapshot_file "$AUTHORIZER" "$AUTHORIZER_SNAPSHOT" "$AUTHORIZER_SHA256" 0500
snapshot_file "$VALIDATOR" "$VALIDATOR_SNAPSHOT" "$VALIDATOR_SHA256" 0500
snapshot_file "$EXEC_HELPER" "$EXEC_HELPER_SNAPSHOT" "$EXEC_HELPER_SHA256" 0500
snapshot_file "$LAUNCH_MANIFEST_INPUT" "$MANIFEST_SNAPSHOT" "$LAUNCH_MANIFEST_SHA256" 0400

readonly STRICT_LAUNCH_VALUES="$CONTROL_ROOT/launch.values"
/usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
  "$CONTROLLER_PYTHON" -I -S -B "$VALIDATOR_SNAPSHOT" inspect-launch \
  --launch-manifest "$MANIFEST_SNAPSHOT" \
  --launch-manifest-sha256 "$LAUNCH_MANIFEST_SHA256" >"$STRICT_LAUNCH_VALUES" ||
  die "strict launch-manifest inspection failed before scheduler submission"
chmod 400 "$STRICT_LAUNCH_VALUES"
fsync_path "$STRICT_LAUNCH_VALUES"

readonly OWNER_UID="${UID:?Bash UID is unavailable}"
readonly COMPUTE_COMMENT="euf-viper-t11:$RUN_NONCE:compute"
readonly FINALIZER_COMMENT="euf-viper-t11:$RUN_NONCE:finalizer"
readonly COMPUTE_JOB_NAME="euf-t11-stage0a"
readonly FINALIZER_JOB_NAME="euf-t11-stage0a-finalize"

COMPUTE_JOB_ID=""
FINALIZER_JOB_ID=""
SUBMISSION_COMPLETE=0

validate_scheduler_record() {
  local record="$1"
  local job_id="$2"
  local job_name="$3"
  local comment="$4"
  local command="$5"
  local stdout_path="$6"
  local stderr_path="$7"
  local work_dir="$8"
  local expected_reason="$9"
  local expected_dependency="${10}"
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B - \
    "$record" "$job_id" "$job_name" "$comment" "$command" \
    "$stdout_path" "$stderr_path" "$work_dir" "$OWNER_UID" "$expected_reason" \
    "$expected_dependency" <<'PY'
import re
import sys

path, job_id, job_name, comment, command, stdout, stderr, workdir, uid, reason, dependency = sys.argv[1:]
with open(path, "rb") as handle:
    encoded = handle.read()
try:
    text = encoded.decode("utf-8")
except UnicodeDecodeError as error:
    raise SystemExit(f"scheduler record is not UTF-8: {error}")
lines = [line for line in text.splitlines() if line]
if len(lines) != 1:
    raise SystemExit("scheduler record must contain exactly one nonempty line")
fields = dict(re.findall(r"(?:^| )([A-Za-z][A-Za-z0-9]*)=([^ ]*)", lines[0]))
required = {
    "JobId": job_id,
    "JobName": job_name,
    "JobState": "PENDING",
    "Reason": reason,
    "Comment": comment,
    "Command": command,
    "WorkDir": workdir,
    "StdOut": stdout,
    "StdErr": stderr,
    "Requeue": "0",
}
for name, expected in required.items():
    if fields.get(name) != expected:
        raise SystemExit(
            f"scheduler ownership mismatch for {name}: {fields.get(name)!r} != {expected!r}"
        )
match = re.fullmatch(r"[^()]+\(([0-9]+)\)", fields.get("UserId", ""))
if match is None or match.group(1) != uid:
    raise SystemExit("scheduler ownership mismatch for UserId")
observed_dependency = fields.get("Dependency")
allowed_dependencies = {dependency}
if dependency != "(null)":
    allowed_dependencies.add(f"{dependency}(unfulfilled)")
if observed_dependency not in allowed_dependencies:
    raise SystemExit(
        f"scheduler ownership mismatch for Dependency: "
        f"{observed_dependency!r} not in {sorted(allowed_dependencies)!r}"
    )
PY
}

capture_scheduler_record() {
  local output="$1"
  local job_id="$2"
  local job_name="$3"
  local comment="$4"
  local command="$5"
  local stdout_path="$6"
  local stderr_path="$7"
  local work_dir="$8"
  local expected_reason="$9"
  local expected_dependency="${10}"
  local temporary="$output.tmp.$$"
  [ ! -e "$output" ] && [ ! -L "$output" ] || return 1
  sealed_control "$SCONTROL" "$SCONTROL_SHA256" show job -o "$job_id" >"$temporary" || {
    rm -f "$temporary"
    return 1
  }
  validate_scheduler_record "$temporary" "$job_id" "$job_name" "$comment" \
    "$command" "$stdout_path" "$stderr_path" "$work_dir" "$expected_reason" \
    "$expected_dependency" || {
    rm -f "$temporary"
    return 1
  }
  chmod 400 "$temporary" || return 1
  fsync_path "$temporary" || return 1
  mv "$temporary" "$output" || return 1
  fsync_path "$(dirname "$output")" || return 1
}

revalidate_scheduler_record() {
  local reference="$1"
  local job_id="$2"
  local job_name="$3"
  local comment="$4"
  local command="$5"
  local stdout_path="$6"
  local stderr_path="$7"
  local work_dir="$8"
  local expected_reason="$9"
  local expected_dependency="${10}"
  local temporary="$SCHEDULER_ROOT/.revalidate-$job_id-$$"
  sealed_control "$SCONTROL" "$SCONTROL_SHA256" show job -o "$job_id" >"$temporary" || {
    rm -f "$temporary"
    return 1
  }
  validate_scheduler_record "$temporary" "$job_id" "$job_name" "$comment" \
    "$command" "$stdout_path" "$stderr_path" "$work_dir" "$expected_reason" \
    "$expected_dependency" || {
    rm -f "$temporary"
    return 1
  }
  if [ -n "$reference" ]; then
    cmp -s "$reference" "$temporary" || {
      rm -f "$temporary"
      return 1
    }
  fi
  rm -f "$temporary"
}

job_is_owned() {
  local job_id="$1"
  local job_name="$2"
  local comment="$3"
  local command="$4"
  local stdout_path="$5"
  local stderr_path="$6"
  local work_dir="$7"
  local expected_dependency="$8"
  local temporary="$SCHEDULER_ROOT/.cleanup-$job_id-$$"
  sealed_control "$SCONTROL" "$SCONTROL_SHA256" show job -o "$job_id" >"$temporary" 2>/dev/null || {
    rm -f "$temporary"
    return 1
  }
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B - \
    "$temporary" "$job_id" "$job_name" "$comment" "$command" \
    "$stdout_path" "$stderr_path" "$work_dir" "$OWNER_UID" \
    "$expected_dependency" <<'PY'
import re
import sys

path, job_id, job_name, comment, command, stdout, stderr, workdir, uid, dependency = sys.argv[1:]
text = open(path, "rb").read().decode("utf-8")
lines = [line for line in text.splitlines() if line]
if len(lines) != 1:
    raise SystemExit(1)
fields = dict(re.findall(r"(?:^| )([A-Za-z][A-Za-z0-9]*)=([^ ]*)", lines[0]))
expected = {
    "JobId": job_id,
    "JobName": job_name,
    "Comment": comment,
    "Command": command,
    "WorkDir": workdir,
    "StdOut": stdout,
    "StdErr": stderr,
    "Requeue": "0",
}
if any(fields.get(name) != value for name, value in expected.items()):
    raise SystemExit(1)
match = re.fullmatch(r"[^()]+\(([0-9]+)\)", fields.get("UserId", ""))
if match is None or match.group(1) != uid:
    raise SystemExit(1)
observed_dependency = fields.get("Dependency")
allowed_dependencies = {dependency}
if dependency != "(null)":
    allowed_dependencies.add(f"{dependency}(unfulfilled)")
if observed_dependency not in allowed_dependencies:
    raise SystemExit(1)
PY
  local status=$?
  rm -f "$temporary"
  return "$status"
}

cancel_if_owned() {
  local job_id="$1"
  local job_name="$2"
  local comment="$3"
  local command="$4"
  local stdout_path="$5"
  local stderr_path="$6"
  local expected_dependency="$7"
  [ -n "$job_id" ] || return 0
  if job_is_owned "$job_id" "$job_name" "$comment" "$command" \
    "$stdout_path" "$stderr_path" "$RUN_BASE" "$expected_dependency"; then
    sealed_control "$SCANCEL" "$SCANCEL_SHA256" "$job_id" >/dev/null 2>&1 ||
      echo "could not cancel proven-owned job $job_id" >&2
  else
    echo "retaining job $job_id because scheduler ownership could not be proven" >&2
  fi
}

cleanup_submission() {
  local status="$1"
  trap - EXIT HUP INT TERM
  if [ "$SUBMISSION_COMPLETE" -ne 1 ]; then
    cancel_if_owned "$FINALIZER_JOB_ID" "$FINALIZER_JOB_NAME" "$FINALIZER_COMMENT" \
      "$FINALIZER_SCRIPT" "$FINALIZER_STDOUT" "$FINALIZER_STDERR" \
      "afterany:$COMPUTE_JOB_ID"
    cancel_if_owned "$COMPUTE_JOB_ID" "$COMPUTE_JOB_NAME" "$COMPUTE_COMMENT" \
      "$COMPUTE_SCRIPT" "$COMPUTE_STDOUT" "$COMPUTE_STDERR" "(null)"
  fi
  exit "$status"
}
trap 'cleanup_submission "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

parse_submission() {
  local raw="$1"
  local job_id
  local returned_cluster
  case "$raw" in
    *$'\n'*) return 1 ;;
  esac
  job_id="${raw%%;*}"
  canonical_positive_decimal "$job_id" || return 1
  [ "$raw" != "$job_id" ] || return 1
  returned_cluster="${raw#*;}"
  [ "$raw" = "$job_id;$returned_cluster" ] || return 1
  safe_cluster_name "$returned_cluster" || return 1
  [ "$returned_cluster" = "$CLUSTER" ] || return 1
  printf '%s\n' "$job_id"
}

validate_scheduler_argv() {
  local role="$1"
  shift
  local argument
  for argument in "$SBATCH" "$@"; do
    case "$argument" in
      ''|*'|'*|*[[:space:]]*)
        die "$role scheduler argv contains whitespace, a pipe, or an empty argument"
        ;;
    esac
  done
}

readonly COMPUTE_EXPORT="EUF_VIPER_T11_REPO_ROOT=$ROOT,EUF_VIPER_T11_RUN_BASE=$RUN_BASE,EUF_VIPER_T11_CORPUS_ROOT=$CORPUS_ROOT,EUF_VIPER_T11_LAUNCH_MANIFEST=$MANIFEST_SNAPSHOT,EUF_VIPER_T11_LAUNCH_MANIFEST_SHA256=$LAUNCH_MANIFEST_SHA256,EUF_VIPER_T11_RUN_NONCE=$RUN_NONCE,SLURM_CLUSTER_NAME=$CLUSTER,SLURM_RESTART_COUNT=0"
COMPUTE_ARGS=(
  --parsable
  --clusters="$CLUSTER"
  --hold
  --no-requeue
  --job-name="$COMPUTE_JOB_NAME"
  --partition="$PARTITION"
  --nodes=1
  --ntasks=1
  --cpus-per-task=1
  --mem=8G
  --time=01:00:00
  --chdir="$RUN_BASE"
  --open-mode=truncate
  --output="$COMPUTE_STDOUT"
  --error="$COMPUTE_STDERR"
  --comment="$COMPUTE_COMMENT"
  --export="$COMPUTE_EXPORT"
  "$COMPUTE_SCRIPT"
)
validate_scheduler_argv compute "${COMPUTE_ARGS[@]}"
set +e
COMPUTE_SUBMISSION="$(sealed_control "$SBATCH" "$SBATCH_SHA256" "${COMPUTE_ARGS[@]}")"
COMPUTE_SUBMIT_EXIT=$?
set -e
[ "$COMPUTE_SUBMIT_EXIT" -eq 0 ] || die "held compute submission failed"
COMPUTE_JOB_ID="$(parse_submission "$COMPUTE_SUBMISSION")" ||
  die "held compute submission returned an invalid job identity; it remains held"
readonly CANDIDATE_ROOT="$RUN_BASE/t11-stage0a-$COMPUTE_JOB_ID"

readonly FINALIZER_EXPORT="EUF_VIPER_T11_CONTROLLER_PYTHON=$CONTROLLER_PYTHON,EUF_VIPER_T11_CONTROLLER_PYTHON_SHA256=$CONTROLLER_PYTHON_SHA256,EUF_VIPER_T11_FINALIZER_PATH=$FINALIZER_SNAPSHOT,EUF_VIPER_T11_FINALIZER_SHA256=$FINALIZER_SHA256,EUF_VIPER_T11_FINALIZER_SBATCH_SHA256=$FINALIZER_RUNNER_SHA256,EUF_VIPER_T11_SUBMISSION_RECORD=$SUBMISSION_RECORD,EUF_VIPER_T11_RUN_NONCE=$RUN_NONCE,EUF_VIPER_T11_COMPUTE_JOB_ID=$COMPUTE_JOB_ID,EUF_VIPER_T11_CANDIDATE_ROOT=$CANDIDATE_ROOT,EUF_VIPER_T11_LAUNCH_MANIFEST=$MANIFEST_SNAPSHOT,EUF_VIPER_T11_LAUNCH_MANIFEST_SHA256=$LAUNCH_MANIFEST_SHA256,EUF_VIPER_T11_EXPECTED_REVISION=$REVISION,EUF_VIPER_T11_FINALIZER_HOME=$FINALIZER_HOME,EUF_VIPER_T11_FINALIZER_TMP=$FINALIZER_TMP,EUF_VIPER_T11_SCHEDULER_CANDIDATE=$SCHEDULER_CANDIDATE,EUF_VIPER_T11_FINALIZER_POLL_ATTEMPTS=$FINALIZER_POLL_ATTEMPTS,EUF_VIPER_T11_FINALIZER_POLL_INTERVAL_SECONDS=$FINALIZER_POLL_INTERVAL_SECONDS,EUF_VIPER_T11_SACCT=$SACCT,EUF_VIPER_T11_SACCT_SHA256=$SACCT_SHA256,EUF_VIPER_T11_SCONTROL=$SCONTROL,EUF_VIPER_T11_SCONTROL_SHA256=$SCONTROL_SHA256,SLURM_CLUSTER_NAME=$CLUSTER,SLURM_RESTART_COUNT=0"
FINALIZER_ARGS=(
  --parsable
  --clusters="$CLUSTER"
  --hold
  --no-requeue
  --kill-on-invalid-dep=yes
  --dependency="afterany:$COMPUTE_JOB_ID"
  --job-name="$FINALIZER_JOB_NAME"
  --partition="$PARTITION"
  --nodes=1
  --ntasks=1
  --cpus-per-task=1
  --mem=1G
  --time=00:10:00
  --chdir="$RUN_BASE"
  --open-mode=truncate
  --output="$FINALIZER_STDOUT"
  --error="$FINALIZER_STDERR"
  --comment="$FINALIZER_COMMENT"
  --export="$FINALIZER_EXPORT"
  "$FINALIZER_SCRIPT"
)
validate_scheduler_argv finalizer "${FINALIZER_ARGS[@]}"
set +e
FINALIZER_SUBMISSION="$(sealed_control "$SBATCH" "$SBATCH_SHA256" "${FINALIZER_ARGS[@]}")"
FINALIZER_SUBMIT_EXIT=$?
set -e
[ "$FINALIZER_SUBMIT_EXIT" -eq 0 ] || die "held afterany finalizer submission failed"
FINALIZER_JOB_ID="$(parse_submission "$FINALIZER_SUBMISSION")" ||
  die "held finalizer submission returned an invalid job identity; both jobs remain held"
[ "$FINALIZER_JOB_ID" != "$COMPUTE_JOB_ID" ] || die "scheduler reused the compute job ID"

readonly COMPUTE_HELD_RECORD="$SCHEDULER_ROOT/compute-held.scontrol"
readonly FINALIZER_HELD_RECORD="$SCHEDULER_ROOT/finalizer-held.scontrol"
capture_scheduler_record "$COMPUTE_HELD_RECORD" "$COMPUTE_JOB_ID" \
  "$COMPUTE_JOB_NAME" "$COMPUTE_COMMENT" "$COMPUTE_SCRIPT" \
  "$COMPUTE_STDOUT" "$COMPUTE_STDERR" "$RUN_BASE" JobHeldUser "(null)" ||
  die "compute ownership or held state could not be established"
capture_scheduler_record "$FINALIZER_HELD_RECORD" "$FINALIZER_JOB_ID" \
  "$FINALIZER_JOB_NAME" "$FINALIZER_COMMENT" "$FINALIZER_SCRIPT" \
  "$FINALIZER_STDOUT" "$FINALIZER_STDERR" "$RUN_BASE" JobHeldUser \
  "afterany:$COMPUTE_JOB_ID" ||
  die "finalizer ownership or held state could not be established"
readonly COMPUTE_HELD_SHA256="$(sha256_file "$COMPUTE_HELD_RECORD")"
readonly FINALIZER_HELD_SHA256="$(sha256_file "$FINALIZER_HELD_RECORD")"

publish_submission_record() {
  local compute_count="${#COMPUTE_ARGS[@]}"
  local finalizer_count="${#FINALIZER_ARGS[@]}"
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B - \
    "$SUBMISSION_RECORD" "$ORCHESTRATION_RECORD" \
    "$RUN_NONCE" "$REVISION" "$CLUSTER" "$OWNER_UID" \
    "$MANIFEST_SNAPSHOT" "$LAUNCH_MANIFEST_SHA256" \
    "$ROOT" "$RUN_BASE" "$CORPUS_ROOT" "$CAMPAIGN_ROOT" "$CANDIDATE_ROOT" \
    "$COMPUTE_JOB_ID" "$FINALIZER_JOB_ID" "$COMPUTE_JOB_NAME" "$FINALIZER_JOB_NAME" \
    "$PARTITION" \
    "$COMPUTE_STDOUT" "$COMPUTE_STDERR" "$FINALIZER_STDOUT" "$FINALIZER_STDERR" \
    "$SCHEDULER_CANDIDATE" "$FINAL_DECISION" \
    "$COMPUTE_HELD_RECORD" "$COMPUTE_HELD_SHA256" \
    "$FINALIZER_HELD_RECORD" "$FINALIZER_HELD_SHA256" \
    "$SUBMITTER" "$SUBMITTER_SHA256" "$COMPUTE_SCRIPT" "$RUNNER_SHA256" \
    "$FINALIZER_SCRIPT" "$FINALIZER_RUNNER_SHA256" \
    "$FINALIZER_SNAPSHOT" "$FINALIZER_SHA256" \
    "$AUTHORIZER_SNAPSHOT" "$AUTHORIZER_SHA256" \
    "$VALIDATOR" "$VALIDATOR_SHA256" \
    "$EXEC_HELPER" "$EXEC_HELPER_SHA256" \
    "$CONTROLLER_PYTHON" "$CONTROLLER_PYTHON_SHA256" \
    "$GIT" "$GIT_SHA256" "$SBATCH" "$SBATCH_SHA256" \
    "$SCONTROL" "$SCONTROL_SHA256" "$SCANCEL" "$SCANCEL_SHA256" \
    "$SACCT" "$SACCT_SHA256" "$compute_count" "$finalizer_count" \
    "${COMPUTE_ARGS[@]}" "${FINALIZER_ARGS[@]}" <<'PY'
import datetime
import hashlib
import json
import os
import sys

values = iter(sys.argv[1:])
output = next(values)
orchestration_output = next(values)
nonce = next(values)
revision = next(values)
cluster = next(values)
owner_uid = int(next(values))
manifest_path, manifest_sha256 = next(values), next(values)
repo_root, run_base, corpus_root, campaign_root, candidate_root = [
    next(values) for _ in range(5)
]
compute_job, finalizer_job = int(next(values)), int(next(values))
compute_name, finalizer_name = next(values), next(values)
partition = next(values)
compute_stdout, compute_stderr, finalizer_stdout, finalizer_stderr = [
    next(values) for _ in range(4)
]
scheduler_candidate, final_decision = next(values), next(values)
compute_evidence, compute_evidence_sha256 = next(values), next(values)
finalizer_evidence, finalizer_evidence_sha256 = next(values), next(values)

control_names = (
    "submitter",
    "compute_script",
    "finalizer_script",
    "finalizer",
    "authorizer",
    "validator",
    "exec_helper",
    "controller_python",
    "git",
    "sbatch",
    "scontrol",
    "scancel",
    "sacct",
)
control = {}
for name in control_names:
    control[name] = {"path": next(values), "sha256": next(values)}
compute_count, finalizer_count = int(next(values)), int(next(values))
remaining = list(values)
if len(remaining) != compute_count + finalizer_count:
    raise SystemExit("submission argv field count differs")
compute_argv = [control["sbatch"]["path"], *remaining[:compute_count]]
finalizer_argv = [control["sbatch"]["path"], *remaining[compute_count:]]

payload = {
    "schema": "euf-viper.t11-stage0a-submission.v2",
    "run_nonce": nonce,
    "revision": revision,
    "launch_manifest_sha256": manifest_sha256,
    "candidate_root": candidate_root,
    "scheduler_candidate_path": scheduler_candidate,
    "final_decision_path": final_decision,
    "control": {
        "submit_wrapper_sha256": control["submitter"]["sha256"],
        "compute_script_sha256": control["compute_script"]["sha256"],
        "finalizer_script_sha256": control["finalizer_script"]["sha256"],
        "finalizer_sha256": control["finalizer"]["sha256"],
        "authorizer_sha256": control["authorizer"]["sha256"],
        "validator_sha256": control["validator"]["sha256"],
        "exec_helper_sha256": control["exec_helper"]["sha256"],
        "controller_python_sha256": control["controller_python"]["sha256"],
        "git_sha256": control["git"]["sha256"],
        "sbatch_sha256": control["sbatch"]["sha256"],
        "scontrol_sha256": control["scontrol"]["sha256"],
        "scancel_sha256": control["scancel"]["sha256"],
        "sacct_sha256": control["sacct"]["sha256"],
    },
    "slurm": {
        "cluster": cluster,
        "owner_uid": owner_uid,
        "compute_job_id": compute_job,
        "finalizer_job_id": finalizer_job,
        "finalizer_dependency": f"afterany:{compute_job}",
        "compute_job_name": compute_name,
        "compute_comment": f"euf-viper-t11:{nonce}:compute",
        "finalizer_job_name": finalizer_name,
        "finalizer_comment": f"euf-viper-t11:{nonce}:finalizer",
        "partition": partition,
        "requested_nodes": 1,
        "requested_cpus": 1,
        "requested_memory_bytes": 8 * 1024**3,
        "timelimit_seconds": 60 * 60,
        "work_dir": run_base,
        "stdout_path": compute_stdout,
        "stderr_path": compute_stderr,
        "compute_script_path": control["compute_script"]["path"],
        "finalizer_requested_nodes": 1,
        "finalizer_requested_cpus": 1,
        "finalizer_requested_memory_bytes": 1024**3,
        "finalizer_timelimit_seconds": 10 * 60,
        "finalizer_work_dir": run_base,
        "finalizer_stdout_path": finalizer_stdout,
        "finalizer_stderr_path": finalizer_stderr,
        "finalizer_script_path": control["finalizer_script"]["path"],
        "compute_sbatch_argv": compute_argv,
        "finalizer_sbatch_argv": finalizer_argv,
        "compute_held_record": {
            "path": compute_evidence,
            "sha256": compute_evidence_sha256,
        },
        "finalizer_held_record": {
            "path": finalizer_evidence,
            "sha256": finalizer_evidence_sha256,
        },
    },
}
encoded = (
    json.dumps(payload, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    + "\n"
).encode("ascii")
submission_sha256 = hashlib.sha256(encoded).hexdigest()
orchestration = {
    "schema": "euf-viper.t11-stage0a-orchestration.v1",
    "status": "submitted_held",
    "run_nonce": nonce,
    "created_utc": datetime.datetime.now(datetime.timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "revision": revision,
    "submission": {"path": output, "sha256": submission_sha256},
    "launch_manifest": {"path": manifest_path, "sha256": manifest_sha256},
    "control": control,
    "slurm": {
        "cluster": cluster,
        "owner_uid": owner_uid,
        "compute_job_id": compute_job,
        "finalizer_job_id": finalizer_job,
        "compute_job_name": compute_name,
        "finalizer_job_name": finalizer_name,
        "finalizer_dependency": f"afterany:{compute_job}",
        "compute_sbatch_argv": compute_argv,
        "finalizer_sbatch_argv": finalizer_argv,
        "compute_stdout": compute_stdout,
        "compute_stderr": compute_stderr,
        "finalizer_stdout": finalizer_stdout,
        "finalizer_stderr": finalizer_stderr,
        "no_requeue": True,
        "held_at_publication": True,
        "release_order": ["finalizer", "compute"],
    },
    "paths": {
        "repo_root": repo_root,
        "run_base": run_base,
        "corpus_root": corpus_root,
        "campaign_root": campaign_root,
        "submission_record": output,
        "candidate_root": candidate_root,
        "scheduler_candidate": scheduler_candidate,
        "final_decision": final_decision,
    },
    "held_scheduler_evidence": {
        "compute": {"path": compute_evidence, "sha256": compute_evidence_sha256},
        "finalizer": {"path": finalizer_evidence, "sha256": finalizer_evidence_sha256},
    },
}
orchestration_encoded = (
    json.dumps(
        orchestration,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("ascii")


def publish(path, data):
    parent = os.path.dirname(path)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary_name = f".{os.path.basename(path)}.{os.getpid()}.tmp"
    temporary_fd = None
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        offset = 0
        while offset < len(data):
            written = os.write(temporary_fd, data[offset:])
            if written <= 0:
                raise RuntimeError("short canonical-record write")
            offset += written
        os.fsync(temporary_fd)
        os.fchmod(temporary_fd, 0o400)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        os.link(
            temporary_name,
            os.path.basename(path),
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.unlink(temporary_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


publish(output, encoded)
publish(orchestration_output, orchestration_encoded)
print(submission_sha256, hashlib.sha256(orchestration_encoded).hexdigest())
PY
}

readonly PUBLICATION_DIGESTS="$(publish_submission_record)"
set -- $PUBLICATION_DIGESTS
[ "$#" -eq 2 ] || die "submission publication returned the wrong digest count"
readonly SUBMISSION_RECORD_SHA256="$1"
readonly ORCHESTRATION_RECORD_SHA256="$2"
canonical_sha256 "$SUBMISSION_RECORD_SHA256" || die "submission record publication failed"
canonical_sha256 "$ORCHESTRATION_RECORD_SHA256" || die "orchestration record publication failed"
[ "$(sha256_file "$SUBMISSION_RECORD")" = "$SUBMISSION_RECORD_SHA256" ] ||
  die "submission record changed after publication"
[ "$(sha256_file "$ORCHESTRATION_RECORD")" = "$ORCHESTRATION_RECORD_SHA256" ] ||
  die "orchestration record changed after publication"

readonly AUTHORIZATION_REQUEST_SHA256="$({
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B - \
    "$AUTHORIZATION_REQUEST" "$RUN_NONCE" \
    "$CONTROLLER_PYTHON" "$CONTROLLER_PYTHON_SHA256" \
    "$AUTHORIZER_SNAPSHOT" "$AUTHORIZER_SHA256" \
    "$SUBMISSION_RECORD" "$SUBMISSION_RECORD_SHA256" \
    "$SCHEDULER_CANDIDATE" "$FINAL_DECISION" \
    "$FINALIZER_SNAPSHOT" "$FINALIZER_SHA256" \
    "$SACCT" "$SACCT_SHA256" <<'PY'
import hashlib
import json
import os
import sys

(
    output,
    nonce,
    python_path,
    python_sha256,
    authorizer,
    authorizer_sha256,
    submission,
    submission_sha256,
    scheduler_candidate,
    decision,
    finalizer,
    finalizer_sha256,
    sacct,
    sacct_sha256,
) = sys.argv[1:]
bootstrap = r'''import fcntl
import hashlib
import os
import stat
import sys

python_path, python_sha256, authorizer_path, authorizer_sha256, *arguments = sys.argv[1:]
required_seals = (
    getattr(fcntl, "F_SEAL_WRITE", 0x0008)
    | getattr(fcntl, "F_SEAL_GROW", 0x0004)
    | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
    | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
)


def identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def hash_descriptor(descriptor):
    digest = hashlib.sha256()
    offset = 0
    size = os.fstat(descriptor).st_size
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            raise SystemExit("sealed authorization bootstrap input was truncated")
        digest.update(block)
        offset += len(block)
    if os.pread(descriptor, 1, offset):
        raise SystemExit("sealed authorization bootstrap input grew while hashing")
    return digest.hexdigest()


def copy_sealed(path, expected, mode, maximum, role):
    source = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    snapshot = -1
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"{role} is not a regular file")
        if role == "controller Python" and not before.st_mode & 0o111:
            raise SystemExit("controller Python is not executable")
        if before.st_size < 1 or before.st_size > maximum:
            raise SystemExit(f"{role} size is outside its bound")
        snapshot = os.memfd_create(
            f"t11-authorization-{role}",
            getattr(os, "MFD_CLOEXEC", 0x0001)
            | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
        )
        offset = 0
        digest = hashlib.sha256()
        while offset < before.st_size:
            block = os.pread(source, min(1024 * 1024, before.st_size - offset), offset)
            if not block:
                raise SystemExit(f"{role} was truncated while copied")
            digest.update(block)
            written_offset = 0
            while written_offset < len(block):
                written = os.write(snapshot, block[written_offset:])
                if written <= 0:
                    raise SystemExit(f"short sealed {role} write")
                written_offset += written
            offset += len(block)
        after = os.fstat(source)
        if identity(before) != identity(after):
            raise SystemExit(f"{role} changed while copied")
        if digest.hexdigest() != expected:
            raise SystemExit(f"{role} digest mismatch")
        os.fchmod(snapshot, mode)
        fcntl.fcntl(snapshot, getattr(fcntl, "F_ADD_SEALS", 1033), required_seals)
        if (
            fcntl.fcntl(snapshot, getattr(fcntl, "F_GET_SEALS", 1034))
            & required_seals
            != required_seals
        ):
            raise SystemExit(f"sealed {role} lacks mandatory seals")
        if hash_descriptor(snapshot) != expected:
            raise SystemExit(f"sealed {role} digest mismatch")
        result = snapshot
        snapshot = -1
        return result
    finally:
        if snapshot >= 0:
            os.close(snapshot)
        os.close(source)


if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
    raise SystemExit("authorization execution requires Linux sealed memfd support")
running = os.open(
    "/proc/self/exe",
    os.O_RDONLY | os.O_CLOEXEC,
)
try:
    if hash_descriptor(running) != python_sha256:
        raise SystemExit("executed controller Python digest mismatch")
finally:
    os.close(running)
python_fd = copy_sealed(
    python_path, python_sha256, 0o500, 1024 * 1024 * 1024, "controller Python"
)
authorizer_fd = copy_sealed(
    authorizer_path, authorizer_sha256, 0o400, 16 * 1024 * 1024, "authorizer"
)
os.set_inheritable(authorizer_fd, True)
for entry in os.listdir("/proc/self/fd"):
    if not entry.isdecimal():
        continue
    descriptor = int(entry)
    if descriptor <= 2 or descriptor == authorizer_fd:
        continue
    try:
        os.set_inheritable(descriptor, False)
    except OSError:
        pass
environment = {
    "HOME": os.environ.get("HOME", "/"),
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}
os.execve(
    f"/proc/self/fd/{python_fd}",
    [
        "python3",
        "-I",
        "-S",
        "-B",
        f"/proc/self/fd/{authorizer_fd}",
        *arguments,
    ],
    environment,
)
'''
authorizer_argv = [
    "--submission",
    submission,
    "--submission-sha256",
    submission_sha256,
    "--scheduler-candidate",
    scheduler_candidate,
    "--output",
    decision,
    "--finalizer-module",
    finalizer,
    "--finalizer-module-sha256",
    finalizer_sha256,
    "--sacct-bin",
    sacct,
    "--poll-attempts",
    "12",
    "--poll-interval-seconds",
    "5",
]
argv = [
    python_path,
    "-I",
    "-S",
    "-B",
    "-c",
    bootstrap,
    python_path,
    python_sha256,
    authorizer,
    authorizer_sha256,
    *authorizer_argv,
]
payload = {
    "argv": argv,
    "authorizer": {"path": authorizer, "sha256": authorizer_sha256},
    "controller_python": {"path": python_path, "sha256": python_sha256},
    "finalizer_module": {"path": finalizer, "sha256": finalizer_sha256},
    "output_path": decision,
    "run_nonce": nonce,
    "sacct": {"path": sacct, "sha256": sacct_sha256},
    "scheduler_candidate_path": scheduler_candidate,
    "schema": "euf-viper.t11-stage0a-authorization-request.v1",
    "status": "await_finalizer_terminal_accounting",
    "submission": {"path": submission, "sha256": submission_sha256},
}
encoded = (
    json.dumps(payload, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    + "\n"
).encode("ascii")
parent_fd = os.open(os.path.dirname(output), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    descriptor = os.open(
        os.path.basename(output),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o400,
        dir_fd=parent_fd,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise RuntimeError("short authorization-request write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
print(hashlib.sha256(encoded).hexdigest())
PY
})"
canonical_sha256 "$AUTHORIZATION_REQUEST_SHA256" ||
  die "authorization request publication failed"
[ "$(sha256_file "$AUTHORIZATION_REQUEST")" = "$AUTHORIZATION_REQUEST_SHA256" ] ||
  die "authorization request changed after publication"
fsync_path "$SUBMISSION_RECORD"
fsync_path "$ORCHESTRATION_RECORD"
fsync_path "$AUTHORIZATION_REQUEST"
chmod 500 "$CONTROL_ROOT"
fsync_path "$CONTROL_ROOT"
fsync_path "$CAMPAIGN_ROOT"
fsync_path "$RUN_BASE"

# The immutable record must exist before either job can leave its user hold.
revalidate_scheduler_record "$COMPUTE_HELD_RECORD" "$COMPUTE_JOB_ID" \
  "$COMPUTE_JOB_NAME" "$COMPUTE_COMMENT" "$COMPUTE_SCRIPT" \
  "$COMPUTE_STDOUT" "$COMPUTE_STDERR" "$RUN_BASE" JobHeldUser "(null)" ||
  die "compute scheduler identity drifted before release"
revalidate_scheduler_record "$FINALIZER_HELD_RECORD" "$FINALIZER_JOB_ID" \
  "$FINALIZER_JOB_NAME" "$FINALIZER_COMMENT" "$FINALIZER_SCRIPT" \
  "$FINALIZER_STDOUT" "$FINALIZER_STDERR" "$RUN_BASE" JobHeldUser \
  "afterany:$COMPUTE_JOB_ID" ||
  die "finalizer scheduler identity drifted before release"
require_sha256 "$SUBMITTER" "$SUBMITTER_SHA256" submitter
require_sha256 "$MANIFEST_SNAPSHOT" "$LAUNCH_MANIFEST_SHA256" "manifest snapshot"
require_sha256 "$COMPUTE_SCRIPT" "$RUNNER_SHA256" "compute script snapshot"
require_sha256 "$FINALIZER_SCRIPT" "$FINALIZER_RUNNER_SHA256" "finalizer script snapshot"
require_sha256 "$FINALIZER_SNAPSHOT" "$FINALIZER_SHA256" "finalizer snapshot"
require_sha256 "$AUTHORIZER_SNAPSHOT" "$AUTHORIZER_SHA256" "authorizer snapshot"
[ "$(sha256_file "$AUTHORIZATION_REQUEST")" = "$AUTHORIZATION_REQUEST_SHA256" ] ||
  die "authorization request changed before release"
require_sha256 "$VALIDATOR" "$VALIDATOR_SHA256" validator
require_sha256 "$EXEC_HELPER" "$EXEC_HELPER_SHA256" "execution helper"
require_sha256 "$CONTROLLER_PYTHON" "$CONTROLLER_PYTHON_SHA256" "controller Python"
require_sha256 "$GIT" "$GIT_SHA256" git
require_sha256 "$SBATCH" "$SBATCH_SHA256" sbatch
require_sha256 "$SCONTROL" "$SCONTROL_SHA256" scontrol
require_sha256 "$SCANCEL" "$SCANCEL_SHA256" scancel
require_sha256 "$SACCT" "$SACCT_SHA256" sacct

sealed_control "$SCONTROL" "$SCONTROL_SHA256" release "$FINALIZER_JOB_ID"
FINALIZER_DEPENDENCY_READY=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if revalidate_scheduler_record "" "$FINALIZER_JOB_ID" "$FINALIZER_JOB_NAME" \
    "$FINALIZER_COMMENT" "$FINALIZER_SCRIPT" "$FINALIZER_STDOUT" \
    "$FINALIZER_STDERR" "$RUN_BASE" Dependency "afterany:$COMPUTE_JOB_ID"; then
    FINALIZER_DEPENDENCY_READY=1
    break
  fi
  "$CONTROLLER_PYTHON" -I -S -B -c 'import time; time.sleep(0.25)'
done
[ "$FINALIZER_DEPENDENCY_READY" -eq 1 ] ||
  die "finalizer did not become dependency-blocked after release"
revalidate_scheduler_record "$COMPUTE_HELD_RECORD" "$COMPUTE_JOB_ID" \
  "$COMPUTE_JOB_NAME" "$COMPUTE_COMMENT" "$COMPUTE_SCRIPT" \
  "$COMPUTE_STDOUT" "$COMPUTE_STDERR" "$RUN_BASE" JobHeldUser "(null)" ||
  die "compute scheduler identity drifted at the release boundary"
[ "$(sha256_file "$SUBMISSION_RECORD")" = "$SUBMISSION_RECORD_SHA256" ] ||
  die "submission record changed at the release boundary"
[ "$(sha256_file "$ORCHESTRATION_RECORD")" = "$ORCHESTRATION_RECORD_SHA256" ] ||
  die "orchestration record changed at the release boundary"
[ "$(sha256_file "$AUTHORIZATION_REQUEST")" = "$AUTHORIZATION_REQUEST_SHA256" ] ||
  die "authorization request changed at the release boundary"
GIT_STATUS="$(sealed_control "$GIT" "$GIT_SHA256" status --porcelain=v1 --untracked-files=all)" ||
  die "sealed git status failed at the release boundary"
[ -z "$GIT_STATUS" ] ||
  die "checkout changed at the release boundary"
REVISION_VALUE="$(sealed_control "$GIT" "$GIT_SHA256" rev-parse --verify 'HEAD^{commit}')" ||
  die "sealed git revision lookup failed at the release boundary"
[ "$REVISION_VALUE" = "$REVISION" ] ||
  die "checkout revision changed at the release boundary"

sealed_control "$SCONTROL" "$SCONTROL_SHA256" release "$COMPUTE_JOB_ID"
SUBMISSION_COMPLETE=1
trap - EXIT HUP INT TERM

printf 't11_stage0a_submission_record=%s\n' "$SUBMISSION_RECORD"
printf 't11_stage0a_submission_sha256=%s\n' "$SUBMISSION_RECORD_SHA256"
printf 't11_stage0a_orchestration_record=%s\n' "$ORCHESTRATION_RECORD"
printf 't11_stage0a_orchestration_sha256=%s\n' "$ORCHESTRATION_RECORD_SHA256"
printf 't11_stage0a_compute_job_id=%s\n' "$COMPUTE_JOB_ID"
printf 't11_stage0a_finalizer_job_id=%s\n' "$FINALIZER_JOB_ID"
printf 't11_stage0a_authorization_request=%s\n' "$AUTHORIZATION_REQUEST"
printf 't11_stage0a_authorization_request_sha256=%s\n' "$AUTHORIZATION_REQUEST_SHA256"
printf 't11_stage0a_scheduler_candidate=%s\n' "$SCHEDULER_CANDIDATE"
printf 't11_stage0a_authorization_output=%s\n' "$FINAL_DECISION"
printf 't11_stage0a_authorizer=%s\n' "$AUTHORIZER_SNAPSHOT"
printf 't11_stage0a_authorizer_sha256=%s\n' "$AUTHORIZER_SHA256"
printf 't11_stage0a_finalizer_module=%s\n' "$FINALIZER_SNAPSHOT"
printf 't11_stage0a_finalizer_module_sha256=%s\n' "$FINALIZER_SHA256"
printf 't11_stage0a_sacct=%s\n' "$SACCT"
printf 't11_stage0a_sacct_sha256=%s\n' "$SACCT_SHA256"
