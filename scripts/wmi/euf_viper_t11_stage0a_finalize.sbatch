#!/usr/bin/env bash
#SBATCH --job-name=euf-t11-stage0a-finalize
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=1G
#SBATCH --time=00:10:00

set -euo pipefail
umask 077

# This afterany job can validate the compute attempt, but it cannot attest its
# own terminal state. It therefore publishes only a non-authorizing scheduler
# candidate for a later submit-host observer.

die() {
  echo "T11 Stage 0A finalizer infrastructure rejection: $*" >&2
  exit 2
}

canonical_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac
}

canonical_positive_decimal() {
  case "$1" in ''|0|0*|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

canonical_nonnegative_number() {
  local value="$1"
  local integer
  local fraction
  case "$value" in ''|*[!0-9.]*|*.*.*|.*|*.) return 1 ;; esac
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

readonly CONTROLLER_PYTHON="${EUF_VIPER_T11_CONTROLLER_PYTHON:?set pinned controller Python path}"
readonly CONTROLLER_PYTHON_SHA256="${EUF_VIPER_T11_CONTROLLER_PYTHON_SHA256:?set controller Python SHA-256}"
readonly FINALIZER="${EUF_VIPER_T11_FINALIZER_PATH:?set manifest-pinned finalizer path}"
readonly FINALIZER_SHA256="${EUF_VIPER_T11_FINALIZER_SHA256:?set finalizer SHA-256}"
readonly FINALIZER_SBATCH_SHA256="${EUF_VIPER_T11_FINALIZER_SBATCH_SHA256:?set finalizer sbatch SHA-256}"
readonly SUBMISSION_RECORD="${EUF_VIPER_T11_SUBMISSION_RECORD:?set immutable submission record path}"
readonly RUN_NONCE="${EUF_VIPER_T11_RUN_NONCE:?set submission nonce}"
readonly COMPUTE_JOB_ID="${EUF_VIPER_T11_COMPUTE_JOB_ID:?set compute job ID}"
readonly CANDIDATE_ROOT="${EUF_VIPER_T11_CANDIDATE_ROOT:?set exact compute candidate root}"
readonly LAUNCH_MANIFEST="${EUF_VIPER_T11_LAUNCH_MANIFEST:?set launch manifest snapshot path}"
readonly LAUNCH_MANIFEST_SHA256="${EUF_VIPER_T11_LAUNCH_MANIFEST_SHA256:?set launch manifest SHA-256}"
readonly EXPECTED_REVISION="${EUF_VIPER_T11_EXPECTED_REVISION:?set expected revision}"
readonly FINALIZER_HOME="${EUF_VIPER_T11_FINALIZER_HOME:?set private finalizer home}"
readonly FINALIZER_TMP="${EUF_VIPER_T11_FINALIZER_TMP:?set private finalizer temporary directory}"
readonly SCHEDULER_CANDIDATE="${EUF_VIPER_T11_SCHEDULER_CANDIDATE:?set scheduler candidate path}"
readonly POLL_ATTEMPTS="${EUF_VIPER_T11_FINALIZER_POLL_ATTEMPTS:?set finalizer poll attempts}"
readonly POLL_INTERVAL_SECONDS="${EUF_VIPER_T11_FINALIZER_POLL_INTERVAL_SECONDS:?set finalizer poll interval}"
readonly SACCT="${EUF_VIPER_T11_SACCT:?set pinned sacct path}"
readonly SACCT_SHA256="${EUF_VIPER_T11_SACCT_SHA256:?set sacct SHA-256}"
readonly SCONTROL="${EUF_VIPER_T11_SCONTROL:?set pinned scontrol path}"
readonly SCONTROL_SHA256="${EUF_VIPER_T11_SCONTROL_SHA256:?set scontrol SHA-256}"
readonly FINALIZER_JOB_ID="${SLURM_JOB_ID:?finalizer requires a Slurm job ID}"
readonly FINALIZER_CLUSTER="${SLURM_CLUSTER_NAME:?finalizer requires the Slurm cluster name}"

for digest in "$CONTROLLER_PYTHON_SHA256" "$FINALIZER_SHA256" \
  "$FINALIZER_SBATCH_SHA256" "$LAUNCH_MANIFEST_SHA256" \
  "$SACCT_SHA256" "$SCONTROL_SHA256"; do
  canonical_sha256 "$digest" || die "malformed SHA-256 in finalizer environment"
done
canonical_positive_decimal "$COMPUTE_JOB_ID" || die "compute job ID is malformed"
canonical_positive_decimal "$FINALIZER_JOB_ID" || die "finalizer job ID is malformed"
canonical_positive_decimal "$POLL_ATTEMPTS" || die "poll attempts are malformed"
canonical_nonnegative_number "$POLL_INTERVAL_SECONDS" || die "poll interval is malformed"
[ "$COMPUTE_JOB_ID" != "$FINALIZER_JOB_ID" ] || die "compute and finalizer IDs coincide"
case "$FINALIZER_CLUSTER" in
  ''|*[!A-Za-z0-9_.-]*) die "Slurm cluster name is malformed" ;;
esac
case "$RUN_NONCE" in *[!0-9a-f]*) die "run nonce is malformed" ;; esac
[ "${#RUN_NONCE}" -eq 32 ] || die "run nonce must contain 32 lowercase hex digits"
case "$EXPECTED_REVISION" in *[!0-9a-f]*) die "revision is malformed" ;; esac
[ "${#EXPECTED_REVISION}" -eq 40 ] || die "revision must contain 40 lowercase hex digits"

for path in "$CONTROLLER_PYTHON" "$FINALIZER" "$SUBMISSION_RECORD" \
  "$LAUNCH_MANIFEST" "$SACCT" "$SCONTROL"; do
  case "$path" in /*) ;; *) die "finalizer input path must be absolute: $path" ;; esac
  [ -f "$path" ] && [ ! -L "$path" ] || die "finalizer input is missing, nonregular, or a symlink: $path"
done
for directory in "$FINALIZER_HOME" "$FINALIZER_TMP"; do
  case "$directory" in /*) ;; *) die "finalizer private directory must be absolute" ;; esac
  [ -d "$directory" ] && [ ! -L "$directory" ] || die "finalizer private directory is missing or a symlink"
done
case "$SCHEDULER_CANDIDATE" in /*) ;; *) die "scheduler candidate path must be absolute" ;; esac
case "$CANDIDATE_ROOT" in /*) ;; *) die "candidate root must be absolute" ;; esac
[ ! -e "$SCHEDULER_CANDIDATE" ] && [ ! -L "$SCHEDULER_CANDIDATE" ] ||
  die "scheduler candidate already exists"

sha256_file() {
  /usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
    "$CONTROLLER_PYTHON" -I -S -B -c \
    'import hashlib,sys; h=hashlib.sha256(); f=open(sys.argv[1],"rb"); [h.update(b) for b in iter(lambda:f.read(1048576),b"")]; print(h.hexdigest())' \
    "$1"
}

# The controller Python and the Slurm-spooled script are the explicit bootstrap
# roots. Everything passed to the Python finalizer is then hash-bound.
[ "$(sha256_file "$CONTROLLER_PYTHON")" = "$CONTROLLER_PYTHON_SHA256" ] ||
  die "controller Python digest mismatch"
readonly EXECUTED_FINALIZER_SBATCH="$(/usr/bin/env -i HOME=/ LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
  "$CONTROLLER_PYTHON" -I -S -B -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
[ "$(sha256_file "$EXECUTED_FINALIZER_SBATCH")" = "$FINALIZER_SBATCH_SHA256" ] ||
  die "executed finalizer sbatch digest mismatch"
[ "$(sha256_file "$FINALIZER")" = "$FINALIZER_SHA256" ] || die "finalizer digest mismatch"
[ "$(sha256_file "$LAUNCH_MANIFEST")" = "$LAUNCH_MANIFEST_SHA256" ] ||
  die "launch manifest digest mismatch"
[ "$(sha256_file "$SACCT")" = "$SACCT_SHA256" ] || die "sacct digest mismatch"
[ "$(sha256_file "$SCONTROL")" = "$SCONTROL_SHA256" ] || die "scontrol digest mismatch"

# The public finalizer accepts pathname inputs and rejects /proc/self/fd
# symlinks, so only its executable is sealed in a memfd. The submission lives
# in a nonwritable private control directory and is validated again by the
# finalizer's stable, no-follow path reader.
exec /usr/bin/env -i \
  HOME="$FINALIZER_HOME" LANG=C LC_ALL=C TZ=UTC PATH=/usr/bin:/bin \
  TMPDIR="$FINALIZER_TMP" \
  "$CONTROLLER_PYTHON" -I -S -B - \
  "$FINALIZER" "$FINALIZER_SHA256" "$FINALIZER_SBATCH_SHA256" \
  "$SUBMISSION_RECORD" "$RUN_NONCE" "$COMPUTE_JOB_ID" "$FINALIZER_JOB_ID" \
  "$CANDIDATE_ROOT" "$FINALIZER_CLUSTER" \
  "$LAUNCH_MANIFEST" "$LAUNCH_MANIFEST_SHA256" "$EXPECTED_REVISION" \
  "$SCHEDULER_CANDIDATE" "$POLL_ATTEMPTS" "$POLL_INTERVAL_SECONDS" \
  "$SACCT" "$SACCT_SHA256" "$SCONTROL" "$SCONTROL_SHA256" <<'PY'
import fcntl
import hashlib
import json
import os
import stat
import sys

(
    finalizer,
    finalizer_sha256,
    finalizer_sbatch_sha256,
    submission,
    nonce,
    compute_job,
    finalizer_job,
    candidate_root,
    cluster,
    manifest,
    manifest_sha256,
    revision,
    decision,
    poll_attempts,
    poll_interval,
    sacct,
    sacct_sha256,
    scontrol,
    scontrol_sha256,
) = sys.argv[1:]


def read_once(path, expected, label):
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"{label} is not regular")
        payload = bytearray()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SystemExit(f"{label} identity changed while reading")
    finally:
        os.close(descriptor)
    if expected is not None and hashlib.sha256(payload).hexdigest() != expected:
        raise SystemExit(f"{label} digest mismatch")
    return bytes(payload)


def sealed_memfd(name, payload, executable=False):
    flags = getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(os, "MFD_ALLOW_SEALING", 0x0002)
    descriptor = os.memfd_create(name, flags)
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise RuntimeError("short memfd write")
        offset += written
    os.fchmod(descriptor, 0o500 if executable else 0o400)
    seals = (
        getattr(fcntl, "F_SEAL_WRITE", 0x0008)
        | getattr(fcntl, "F_SEAL_GROW", 0x0004)
        | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
        | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
    )
    fcntl.fcntl(descriptor, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
    if fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS", 1034)) & seals != seals:
        raise SystemExit("mandatory memfd seals are absent")
    os.set_inheritable(descriptor, True)
    return descriptor


finalizer_bytes = read_once(finalizer, finalizer_sha256, "finalizer")
submission_bytes = read_once(
    submission,
    None,
    "submission record",
)
manifest_bytes = read_once(manifest, manifest_sha256, "launch manifest")
record = json.loads(submission_bytes)
canonical = (
    json.dumps(record, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    + "\n"
).encode("ascii")
if canonical != submission_bytes:
    raise SystemExit("submission record is not canonical JSON")
if set(record) != {
    "schema",
    "run_nonce",
    "revision",
    "launch_manifest_sha256",
    "candidate_root",
    "scheduler_candidate_path",
    "final_decision_path",
    "control",
    "slurm",
}:
    raise SystemExit("submission record top-level keys differ")
if record.get("schema") != "euf-viper.t11-stage0a-submission.v2":
    raise SystemExit("submission record schema differs")
if record.get("run_nonce") != nonce:
    raise SystemExit("submission record nonce differs")
if record.get("revision") != revision:
    raise SystemExit("submission record revision differs")
if record.get("launch_manifest_sha256") != manifest_sha256:
    raise SystemExit("submission launch-manifest digest differs")
if record.get("candidate_root") != candidate_root:
    raise SystemExit("submission candidate root differs")
if record.get("scheduler_candidate_path") != decision:
    raise SystemExit("submission scheduler-candidate path differs")
slurm = record.get("slurm", {})
if not isinstance(slurm, dict):
    raise SystemExit("submission Slurm record is malformed")
if slurm.get("cluster") != cluster:
    raise SystemExit("submission cluster differs")
if slurm.get("compute_job_id") != int(compute_job):
    raise SystemExit("submission record compute job differs")
if slurm.get("finalizer_job_id") != int(finalizer_job):
    raise SystemExit("submission record finalizer job differs")
if slurm.get("finalizer_dependency") != f"afterany:{compute_job}":
    raise SystemExit("submission record dependency differs")
manifest_record = json.loads(manifest_bytes)
if manifest_record.get("solver_revision") != revision:
    raise SystemExit("launch manifest revision differs")
artifacts = manifest_record.get("artifacts", {})
toolchain = manifest_record.get("toolchain", {})
control_tools = manifest_record.get("control_tools", {})
if artifacts.get("finalizer_sha256") != finalizer_sha256:
    raise SystemExit("launch manifest finalizer binding differs")
if artifacts.get("finalizer_sbatch_sha256") != finalizer_sbatch_sha256:
    raise SystemExit("launch manifest finalizer-sbatch binding differs")
control = record.get("control", {})
expected_control = {
    "submit_wrapper_sha256": artifacts.get("submitter_sha256"),
    "compute_script_sha256": artifacts.get("runner_sha256"),
    "finalizer_script_sha256": finalizer_sbatch_sha256,
    "finalizer_sha256": finalizer_sha256,
    "authorizer_sha256": artifacts.get("authorizer_sha256"),
    "validator_sha256": artifacts.get("validator_sha256"),
    "exec_helper_sha256": artifacts.get("exec_helper_sha256"),
    "controller_python_sha256": toolchain.get("python", {}).get("sha256"),
    "git_sha256": control_tools.get("git", {}).get("sha256"),
    "sbatch_sha256": control_tools.get("sbatch", {}).get("sha256"),
    "scontrol_sha256": control_tools.get("scontrol", {}).get("sha256"),
    "scancel_sha256": control_tools.get("scancel", {}).get("sha256"),
    "sacct_sha256": control_tools.get("sacct", {}).get("sha256"),
}
if control != expected_control:
    raise SystemExit("submission control hashes differ from the launch manifest")
read_once(
    slurm.get("compute_script_path", ""),
    expected_control["compute_script_sha256"],
    "compute script snapshot",
)
if expected_control["controller_python_sha256"] != hashlib.sha256(
    read_once(sys.executable, None, "executed controller Python")
).hexdigest():
    raise SystemExit("submission controller Python binding differs")
if expected_control["sacct_sha256"] != sacct_sha256:
    raise SystemExit("submission sacct binding differs")
if expected_control["scontrol_sha256"] != scontrol_sha256:
    raise SystemExit("submission scontrol binding differs")

finalizer_fd = sealed_memfd("t11-finalizer", finalizer_bytes, executable=True)
sacct_fd = sealed_memfd(
    "t11-sacct", read_once(sacct, sacct_sha256, "sacct"), executable=True
)
scontrol_fd = sealed_memfd(
    "t11-scontrol", read_once(scontrol, scontrol_sha256, "scontrol"), executable=True
)
submission_sha256 = hashlib.sha256(submission_bytes).hexdigest()
argv = [
    sys.executable,
    "-I",
    "-S",
    "-B",
    f"/proc/self/fd/{finalizer_fd}",
    "--submission",
    submission,
    "--submission-sha256",
    submission_sha256,
    "--candidate-root",
    candidate_root,
    "--output",
    decision,
    "--poll-attempts",
    poll_attempts,
    "--poll-interval-seconds",
    poll_interval,
    "--sacct-bin",
    f"/proc/self/fd/{sacct_fd}",
    "--scontrol-bin",
    f"/proc/self/fd/{scontrol_fd}",
]
environment = {
    "HOME": os.environ["HOME"],
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TMPDIR": os.environ["TMPDIR"],
    "TZ": "UTC",
}
os.execve("/proc/self/exe", argv, environment)
PY
