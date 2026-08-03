#!/usr/bin/env python3
"""Create or execute one exact T11 Stage 0A authorization request."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


REQUEST_SCHEMA = "euf-viper.t11-stage0a-authorization-request.v3"
REQUEST_STATUS = "await_finalizer_terminal_accounting"
SUBMISSION_SCHEMA = "euf-viper.t11-stage0a-submission.v3"
AUTHORIZATION_SCHEMA = "euf-viper.t11-stage0a-authorization.v1"
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_AUTHORIZER_BYTES = 16 * 1024 * 1024
MAX_AUTHORIZATION_BYTES = 256 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
POSITIVE_RE = re.compile(r"[1-9][0-9]*\Z")
NONNEGATIVE_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
MODE_RE = re.compile(r"0[0-7]{3}\Z")

SUBMISSION_CONTROL_FIELDS = (
    "submit_wrapper_sha256",
    "compute_script_sha256",
    "finalizer_script_sha256",
    "finalizer_sha256",
    "authorizer_sha256",
    "authorization_request_executor_sha256",
    "validator_sha256",
    "exec_helper_sha256",
    "controller_python_sha256",
    "git_sha256",
    "sbatch_sha256",
    "scontrol_sha256",
    "scancel_sha256",
    "sacct_sha256",
)

AUTHORIZATION_FIELDS = (
    "authorization_id",
    "candidate_root",
    "candidate_root_binding",
    "classification",
    "control",
    "decision",
    "finalizer_scheduler",
    "launch_manifest_sha256",
    "policy",
    "revision",
    "run_nonce",
    "scheduler_candidate",
    "schema",
    "stage0b_authority",
    "status",
    "submission",
    "submission_evidence",
)


AUTHORIZATION_BOOTSTRAP = r'''import fcntl
import hashlib
import os
import stat
import sys

python_sha256, authorizer_path, authorizer_sha256, *arguments = sys.argv[1:]
required_seals = (
    getattr(fcntl, "F_SEAL_WRITE", 0x0008)
    | getattr(fcntl, "F_SEAL_GROW", 0x0004)
    | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
    | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
)


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


def digest_fd(descriptor, size):
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            raise SystemExit("authorization bootstrap input was truncated")
        digest.update(block)
        offset += len(block)
    if os.pread(descriptor, 1, offset):
        raise SystemExit("authorization bootstrap input grew")
    return digest.hexdigest()


if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
    raise SystemExit("authorization execution requires Linux sealed memfd support")
running = os.open("/proc/self/exe", os.O_RDONLY | os.O_CLOEXEC)
try:
    running_size = os.fstat(running).st_size
    if digest_fd(running, running_size) != python_sha256:
        raise SystemExit("executed controller Python digest mismatch")
finally:
    os.close(running)

source = os.open(
    authorizer_path,
    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
)
snapshot = -1
try:
    before = os.fstat(source)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("authorizer is not one regular file")
    if before.st_mode & 0o222:
        raise SystemExit("authorizer is writable")
    if before.st_size < 1 or before.st_size > 16 * 1024 * 1024:
        raise SystemExit("authorizer size is outside its bound")
    snapshot = os.memfd_create(
        "t11-authorization-authorizer",
        getattr(os, "MFD_CLOEXEC", 0x0001)
        | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
    )
    offset = 0
    digest = hashlib.sha256()
    while offset < before.st_size:
        block = os.pread(source, min(1024 * 1024, before.st_size - offset), offset)
        if not block:
            raise SystemExit("authorizer was truncated while copied")
        digest.update(block)
        written = 0
        while written < len(block):
            count = os.write(snapshot, block[written:])
            if count <= 0:
                raise SystemExit("short sealed authorizer write")
            written += count
        offset += len(block)
    after = os.fstat(source)
    if identity(before) != identity(after):
        raise SystemExit("authorizer changed while copied")
    if digest.hexdigest() != authorizer_sha256:
        raise SystemExit("authorizer digest mismatch")
    os.fchmod(snapshot, 0o400)
    fcntl.fcntl(snapshot, getattr(fcntl, "F_ADD_SEALS", 1033), required_seals)
    if (
        fcntl.fcntl(snapshot, getattr(fcntl, "F_GET_SEALS", 1034))
        & required_seals
        != required_seals
    ):
        raise SystemExit("sealed authorizer lacks mandatory seals")
    if digest_fd(snapshot, before.st_size) != authorizer_sha256:
        raise SystemExit("sealed authorizer digest mismatch")
finally:
    os.close(source)

os.set_inheritable(snapshot, True)
for entry in os.listdir("/proc/self/fd"):
    if not entry.isdecimal():
        continue
    descriptor = int(entry)
    if descriptor <= 2 or descriptor == snapshot:
        continue
    try:
        os.set_inheritable(descriptor, False)
    except OSError:
        pass
environment = {
    "HOME": "/",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}
os.execve(
    "/proc/self/exe",
    [
        "python3",
        "-I",
        "-S",
        "-B",
        f"/proc/self/fd/{snapshot}",
        *arguments,
    ],
    environment,
)
'''


class RequestError(RuntimeError):
    """The authorization request is malformed or failed closed."""


@dataclass(frozen=True)
class StableFile:
    data: bytes
    sha256: str
    identity: tuple[int, ...]


def _fail(message: str) -> None:
    raise RequestError(message)


def _reject_constant(value: str) -> None:
    _fail(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json_bytes(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        _fail(f"value cannot be encoded as canonical JSON: {error}")


def _decode_canonical(data: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("ascii", "strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        _fail(f"{context} is invalid JSON: {error}")
    if not isinstance(value, dict) or canonical_json_bytes(value) != data:
        _fail(f"{context} is not one canonical JSON object")
    return value


def _exact_keys(value: object, keys: Sequence[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail(f"{context} fields differ from the strict schema")
    return value


def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail(f"{context} is not a canonical SHA-256")
    return value


def _absolute_path(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or "\0" in value
        or "\n" in value
    ):
        _fail(f"{context} must be a canonical absolute path")
    return value


def _file_record(value: object, context: str) -> dict[str, str]:
    record = dict(_exact_keys(value, ("path", "sha256"), context))
    record["path"] = _absolute_path(record["path"], f"{context}.path")
    record["sha256"] = _sha256(record["sha256"], f"{context}.sha256")
    return record


def _positive_integer(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail(f"{context} is not a positive integer")
    return value


def _nonnegative_integer(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{context} is not a nonnegative integer")
    return value


def _submission_binding(
    request: Mapping[str, Any], submission_file: StableFile
) -> dict[str, Any]:
    if submission_file.sha256 != request["submission"]["sha256"]:
        _fail("submission SHA-256 differs from the authorization request")
    submission = dict(
        _exact_keys(
            _decode_canonical(submission_file.data, "submission record"),
            (
                "schema",
                "run_nonce",
                "revision",
                "launch_manifest_sha256",
                "candidate_root",
                "scheduler_candidate_path",
                "final_decision_path",
                "control",
                "slurm",
            ),
            "submission record",
        )
    )
    if submission["schema"] != SUBMISSION_SCHEMA:
        _fail("submission schema differs from the authorization contract")
    if submission["run_nonce"] != request["run_nonce"]:
        _fail("submission run nonce differs from the authorization request")
    if (
        not isinstance(submission["revision"], str)
        or REVISION_RE.fullmatch(submission["revision"]) is None
    ):
        _fail("submission revision is malformed")
    submission["launch_manifest_sha256"] = _sha256(
        submission["launch_manifest_sha256"], "submission launch manifest SHA-256"
    )
    for field in (
        "candidate_root",
        "scheduler_candidate_path",
        "final_decision_path",
    ):
        submission[field] = _absolute_path(submission[field], f"submission {field}")
    if submission["scheduler_candidate_path"] != request["scheduler_candidate_path"]:
        _fail("submission scheduler-candidate path differs from the request")
    if submission["final_decision_path"] != request["output_path"]:
        _fail("submission final-decision path differs from the request")
    control = dict(
        _exact_keys(
            submission["control"], SUBMISSION_CONTROL_FIELDS, "submission control"
        )
    )
    for field in SUBMISSION_CONTROL_FIELDS:
        control[field] = _sha256(control[field], f"submission control {field}")
    expected_control = {
        "authorizer_sha256": request["authorizer"]["sha256"],
        "controller_python_sha256": request["controller_python"]["sha256"],
        "finalizer_sha256": request["finalizer_module"]["sha256"],
        "sacct_sha256": request["sacct"]["sha256"],
    }
    for field, expected in expected_control.items():
        if control[field] != expected:
            _fail(f"submission control {field} differs from the request")
    slurm = submission["slurm"]
    if not isinstance(slurm, dict):
        _fail("submission Slurm record is malformed")
    cluster = slurm.get("cluster")
    if not isinstance(cluster, str) or not cluster or "\0" in cluster or "\n" in cluster:
        _fail("submission cluster is malformed")
    for field in ("compute_job_id", "finalizer_job_id"):
        _positive_integer(slurm.get(field), f"submission Slurm {field}")
    if slurm["compute_job_id"] == slurm["finalizer_job_id"]:
        _fail("submission reuses one Slurm job ID")
    submission["control"] = control
    return submission


def _validate_authorization(
    value: object,
    request: Mapping[str, Any],
    submission: Mapping[str, Any],
) -> dict[str, Any]:
    authorization = dict(_exact_keys(value, AUTHORIZATION_FIELDS, "authorization"))
    if (
        authorization["schema"] != AUTHORIZATION_SCHEMA
        or authorization["status"] != "stage0b_authorized"
        or authorization["decision"] != "authorize_stage0b"
        or authorization["stage0b_authority"] is not True
    ):
        _fail("authorization does not grant the exact Stage 0B decision")
    if authorization["run_nonce"] != request["run_nonce"]:
        _fail("authorization run nonce differs from the request")
    if authorization["revision"] != submission["revision"]:
        _fail("authorization revision differs from the submission")
    if authorization["launch_manifest_sha256"] != submission["launch_manifest_sha256"]:
        _fail("authorization launch-manifest digest differs from the submission")
    if authorization["candidate_root"] != submission["candidate_root"]:
        _fail("authorization candidate root differs from the submission")
    if authorization["control"] != submission["control"]:
        _fail("authorization control hashes differ from the submission")

    submission_record = dict(
        _exact_keys(
            authorization["submission"],
            ("bytes", "mode", "path", "sha256"),
            "authorization submission",
        )
    )
    _positive_integer(submission_record["bytes"], "authorization submission bytes")
    if (
        not isinstance(submission_record["mode"], str)
        or MODE_RE.fullmatch(submission_record["mode"]) is None
    ):
        _fail("authorization submission mode is malformed")
    if submission_record["path"] != request["submission"]["path"]:
        _fail("authorization submission path differs from the request")
    if submission_record["sha256"] != request["submission"]["sha256"]:
        _fail("authorization submission digest differs from the request")

    candidate_record = dict(
        _exact_keys(
            authorization["scheduler_candidate"],
            ("attempt_id", "bytes", "mode", "path", "sha256"),
            "authorization scheduler candidate",
        )
    )
    _sha256(candidate_record["attempt_id"], "authorization attempt ID")
    _positive_integer(candidate_record["bytes"], "authorization candidate bytes")
    if (
        not isinstance(candidate_record["mode"], str)
        or MODE_RE.fullmatch(candidate_record["mode"]) is None
    ):
        _fail("authorization candidate mode is malformed")
    if candidate_record["path"] != request["scheduler_candidate_path"]:
        _fail("authorization scheduler-candidate path differs from the request")
    _sha256(candidate_record["sha256"], "authorization scheduler-candidate SHA-256")

    root_binding = dict(
        _exact_keys(
            authorization["candidate_root_binding"],
            ("device", "inode", "inventory_sha256", "mode", "path"),
            "authorization candidate-root binding",
        )
    )
    _nonnegative_integer(root_binding["device"], "authorization root device")
    _positive_integer(root_binding["inode"], "authorization root inode")
    _sha256(root_binding["inventory_sha256"], "authorization root inventory")
    if (
        not isinstance(root_binding["mode"], str)
        or MODE_RE.fullmatch(root_binding["mode"]) is None
    ):
        _fail("authorization root mode is malformed")
    if root_binding["path"] != authorization["candidate_root"]:
        _fail("authorization root binding path differs")

    scheduler = dict(
        _exact_keys(
            authorization["finalizer_scheduler"],
            ("allocation", "batch", "commands", "raw_sha256"),
            "authorization finalizer scheduler",
        )
    )
    allocation = scheduler["allocation"]
    if not isinstance(allocation, dict):
        _fail("authorization finalizer allocation is malformed")
    if allocation.get("Cluster") != submission["slurm"]["cluster"]:
        _fail("authorization finalizer cluster differs from the submission")
    if allocation.get("JobIDRaw") != str(submission["slurm"]["finalizer_job_id"]):
        _fail("authorization finalizer job differs from the submission")
    raw_sha256 = dict(
        _exact_keys(
            scheduler["raw_sha256"],
            ("allocation", "batch"),
            "authorization finalizer raw hashes",
        )
    )
    for field in ("allocation", "batch"):
        _sha256(raw_sha256[field], f"authorization finalizer {field} raw SHA-256")

    evidence = dict(
        _exact_keys(
            authorization["submission_evidence"],
            (
                "compute_held_record",
                "compute_sbatch_argv",
                "finalizer_held_record",
                "finalizer_sbatch_argv",
                "owner_uid",
            ),
            "authorization submission evidence",
        )
    )
    if evidence["owner_uid"] != submission["slurm"].get("owner_uid"):
        _fail("authorization owner UID differs from the submission")

    identity = {
        "candidate_root": authorization["candidate_root"],
        "candidate_root_binding": root_binding,
        "cluster": submission["slurm"]["cluster"],
        "finalizer_job_id": submission["slurm"]["finalizer_job_id"],
        "finalizer_scheduler_raw_sha256": raw_sha256,
        "launch_manifest_sha256": authorization["launch_manifest_sha256"],
        "revision": authorization["revision"],
        "run_nonce": authorization["run_nonce"],
        "scheduler_candidate_sha256": candidate_record["sha256"],
        "submission_sha256": submission_record["sha256"],
    }
    expected_id = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    if authorization["authorization_id"] != expected_id:
        _fail("authorization ID differs from its bound identity")
    return authorization


def _metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_read(
    path: Path,
    maximum: int,
    context: str,
    *,
    executable: bool = False,
    nonwritable: bool = False,
) -> StableFile:
    raw = _absolute_path(os.fspath(path), f"{context} path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        _fail(f"cannot resolve {context}: {error}")
    if os.fspath(resolved) != raw:
        _fail(f"{context} path contains a symbolic-link component")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        _fail(f"cannot open {context}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail(f"{context} must be one regular file")
        if executable and not before.st_mode & 0o111:
            _fail(f"{context} is not executable")
        if nonwritable and before.st_mode & 0o222:
            _fail(f"{context} is writable")
        if before.st_size < 1 or before.st_size > maximum:
            _fail(f"{context} size is outside its bound")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            if not block:
                _fail(f"{context} was truncated while read")
            chunks.append(block)
            digest.update(block)
            offset += len(block)
        if os.pread(descriptor, 1, offset):
            _fail(f"{context} grew while read")
        after = os.fstat(descriptor)
        if _metadata(before) != _metadata(after):
            _fail(f"{context} changed while read")
    finally:
        os.close(descriptor)
    return StableFile(b"".join(chunks), digest.hexdigest(), _metadata(before))


def _authorization_arguments(request: Mapping[str, Any]) -> list[str]:
    poll = request["poll"]
    return [
        "--submission",
        request["submission"]["path"],
        "--submission-sha256",
        request["submission"]["sha256"],
        "--scheduler-candidate",
        request["scheduler_candidate_path"],
        "--output",
        request["output_path"],
        "--finalizer-module",
        request["finalizer_module"]["path"],
        "--finalizer-module-sha256",
        request["finalizer_module"]["sha256"],
        "--sacct-bin",
        request["sacct"]["path"],
        "--poll-attempts",
        poll["attempts"],
        "--poll-interval-seconds",
        poll["interval_seconds"],
    ]


def _expected_argv(request: Mapping[str, Any]) -> list[str]:
    return [
        request["controller_python"]["path"],
        "-I",
        "-S",
        "-B",
        "-c",
        AUTHORIZATION_BOOTSTRAP,
        request["controller_python"]["sha256"],
        request["authorizer"]["path"],
        request["authorizer"]["sha256"],
        *_authorization_arguments(request),
    ]


def validate_request(value: object) -> dict[str, Any]:
    request = dict(
        _exact_keys(
            value,
            (
                "argv",
                "authorizer",
                "controller_python",
                "finalizer_module",
                "output_path",
                "poll",
                "run_nonce",
                "sacct",
                "scheduler_candidate_path",
                "schema",
                "status",
                "submission",
            ),
            "authorization request",
        )
    )
    if request["schema"] != REQUEST_SCHEMA or request["status"] != REQUEST_STATUS:
        _fail("authorization request schema or status differs")
    request["authorizer"] = _file_record(request["authorizer"], "authorizer")
    request["controller_python"] = _file_record(
        request["controller_python"], "controller_python"
    )
    request["finalizer_module"] = _file_record(
        request["finalizer_module"], "finalizer_module"
    )
    request["sacct"] = _file_record(request["sacct"], "sacct")
    request["submission"] = _file_record(request["submission"], "submission")
    request["output_path"] = _absolute_path(request["output_path"], "output_path")
    request["scheduler_candidate_path"] = _absolute_path(
        request["scheduler_candidate_path"], "scheduler_candidate_path"
    )
    if not isinstance(request["run_nonce"], str) or NONCE_RE.fullmatch(
        request["run_nonce"]
    ) is None:
        _fail("run_nonce is not canonical")
    poll = dict(
        _exact_keys(
            request["poll"], ("attempts", "interval_seconds"), "poll"
        )
    )
    if not isinstance(poll["attempts"], str) or POSITIVE_RE.fullmatch(
        poll["attempts"]
    ) is None:
        _fail("poll.attempts is not a canonical positive decimal")
    if not isinstance(poll["interval_seconds"], str) or NONNEGATIVE_RE.fullmatch(
        poll["interval_seconds"]
    ) is None:
        _fail("poll.interval_seconds is not canonical")
    request["poll"] = poll
    if request["argv"] != _expected_argv(request):
        _fail("authorization request argv differs from the exact contract")
    return request


def _publish_fresh(path: Path, data: bytes) -> None:
    parent = path.parent.resolve(strict=True)
    if parent != path.parent or path.name in ("", ".", ".."):
        _fail("request output path is not canonical")
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
            dir_fd=directory,
        )
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    _fail("short authorization-request write")
                offset += written
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)
    except FileExistsError:
        _fail("authorization request output must be fresh")
    finally:
        os.close(directory)


def create_request(
    output: Path,
    *,
    controller_python: str,
    controller_python_sha256: str,
    authorizer: str,
    authorizer_sha256: str,
    submission: str,
    submission_sha256: str,
    scheduler_candidate: str,
    decision: str,
    finalizer_module: str,
    finalizer_module_sha256: str,
    sacct: str,
    sacct_sha256: str,
    run_nonce: str,
    poll_attempts: str,
    poll_interval_seconds: str,
) -> tuple[dict[str, Any], bytes]:
    request: dict[str, Any] = {
        "argv": [],
        "authorizer": {"path": authorizer, "sha256": authorizer_sha256},
        "controller_python": {
            "path": controller_python,
            "sha256": controller_python_sha256,
        },
        "finalizer_module": {
            "path": finalizer_module,
            "sha256": finalizer_module_sha256,
        },
        "output_path": decision,
        "poll": {
            "attempts": poll_attempts,
            "interval_seconds": poll_interval_seconds,
        },
        "run_nonce": run_nonce,
        "sacct": {"path": sacct, "sha256": sacct_sha256},
        "scheduler_candidate_path": scheduler_candidate,
        "schema": REQUEST_SCHEMA,
        "status": REQUEST_STATUS,
        "submission": {"path": submission, "sha256": submission_sha256},
    }
    request["argv"] = _expected_argv(request)
    request = validate_request(request)
    submission_file = _stable_read(
        Path(request["submission"]["path"]),
        MAX_REQUEST_BYTES,
        "submission record",
        nonwritable=True,
    )
    _submission_binding(request, submission_file)
    input_contracts = (
        ("controller_python", MAX_EXECUTABLE_BYTES, True, False),
        ("authorizer", MAX_AUTHORIZER_BYTES, False, True),
        ("finalizer_module", MAX_AUTHORIZER_BYTES, False, True),
        ("sacct", MAX_EXECUTABLE_BYTES, True, False),
    )
    for name, maximum, executable, nonwritable in input_contracts:
        bound = _stable_read(
            Path(request[name]["path"]),
            maximum,
            name.replace("_", " "),
            executable=executable,
            nonwritable=nonwritable,
        )
        if bound.sha256 != request[name]["sha256"]:
            _fail(f"{name.replace('_', ' ')} SHA-256 differs from the request")
    encoded = canonical_json_bytes(request)
    _publish_fresh(output, encoded)
    return request, encoded


def _copy_sealed_executable(source: StableFile, context: str) -> int:
    if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
        _fail("authorization execution requires Linux sealed memfd support")
    descriptor = os.memfd_create(
        f"t11-request-{context}",
        getattr(os, "MFD_CLOEXEC", 0x0001)
        | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
    )
    try:
        offset = 0
        while offset < len(source.data):
            written = os.write(descriptor, source.data[offset:])
            if written <= 0:
                _fail(f"short sealed {context} write")
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
            _fail(f"sealed {context} lacks mandatory seals")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def execute_request(path: Path, expected_sha256: str) -> tuple[dict[str, Any], bytes]:
    expected = _sha256(expected_sha256, "request SHA-256")
    request_file = _stable_read(
        path, MAX_REQUEST_BYTES, "authorization request", nonwritable=True
    )
    if request_file.sha256 != expected:
        _fail("authorization request SHA-256 differs from the caller binding")
    request = validate_request(
        _decode_canonical(request_file.data, "authorization request")
    )
    submission_file = _stable_read(
        Path(request["submission"]["path"]),
        MAX_REQUEST_BYTES,
        "submission record",
        nonwritable=True,
    )
    submission = _submission_binding(request, submission_file)
    controller = _stable_read(
        Path(request["controller_python"]["path"]),
        MAX_EXECUTABLE_BYTES,
        "controller Python",
        executable=True,
    )
    if controller.sha256 != request["controller_python"]["sha256"]:
        _fail("controller Python SHA-256 differs from the request")
    authorizer = _stable_read(
        Path(request["authorizer"]["path"]),
        MAX_AUTHORIZER_BYTES,
        "authorizer",
        nonwritable=True,
    )
    if authorizer.sha256 != request["authorizer"]["sha256"]:
        _fail("authorizer SHA-256 differs from the request")
    finalizer = _stable_read(
        Path(request["finalizer_module"]["path"]),
        MAX_AUTHORIZER_BYTES,
        "finalizer module",
        nonwritable=True,
    )
    if finalizer.sha256 != request["finalizer_module"]["sha256"]:
        _fail("finalizer module SHA-256 differs from the request")
    sacct = _stable_read(
        Path(request["sacct"]["path"]),
        MAX_EXECUTABLE_BYTES,
        "sacct executable",
        executable=True,
    )
    if sacct.sha256 != request["sacct"]["sha256"]:
        _fail("sacct executable SHA-256 differs from the request")
    descriptor = _copy_sealed_executable(controller, "controller-python")
    try:
        completed = subprocess.run(
            request["argv"],
            executable=f"/proc/self/fd/{descriptor}",
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": "/",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "TZ": "UTC",
            },
            pass_fds=(descriptor,),
        )
    except (OSError, subprocess.SubprocessError) as error:
        _fail(f"authorization argv failed to execute: {error}")
    finally:
        os.close(descriptor)
    if completed.returncode != 0:
        _fail(
            f"authorization argv exited {completed.returncode}: "
            f"{completed.stderr[:1024]!r}"
        )
    if completed.stderr:
        _fail(f"authorization argv emitted stderr: {completed.stderr[:1024]!r}")
    if not completed.stdout or len(completed.stdout) > MAX_AUTHORIZATION_BYTES:
        _fail("authorization stdout size is outside its bound")
    decision = _stable_read(
        Path(request["output_path"]),
        MAX_AUTHORIZATION_BYTES,
        "authorization decision",
        nonwritable=True,
    )
    if decision.data != completed.stdout:
        _fail("authorization stdout differs from the published decision")
    authorization = _validate_authorization(
        _decode_canonical(completed.stdout, "authorization stdout"),
        request,
        submission,
    )
    submission_record = authorization["submission"]
    if (
        submission_record["bytes"] != len(submission_file.data)
        or submission_record["mode"]
        != f"{stat.S_IMODE(submission_file.identity[2]):04o}"
    ):
        _fail("authorization submission metadata differs from the bound file")
    candidate_record = authorization["scheduler_candidate"]
    candidate_file = _stable_read(
        Path(request["scheduler_candidate_path"]),
        MAX_AUTHORIZATION_BYTES,
        "scheduler candidate",
        nonwritable=True,
    )
    if (
        candidate_record["bytes"] != len(candidate_file.data)
        or candidate_record["mode"]
        != f"{stat.S_IMODE(candidate_file.identity[2]):04o}"
        or candidate_record["sha256"] != candidate_file.sha256
    ):
        _fail("authorization scheduler-candidate binding differs from the file")
    candidate = _decode_canonical(candidate_file.data, "scheduler candidate")
    if (
        candidate.get("attempt_id") != candidate_record["attempt_id"]
        or candidate.get("classification") != authorization["classification"]
        or candidate.get("policy") != authorization["policy"]
    ):
        _fail("authorization differs from the scheduler candidate")
    current_request = _stable_read(
        path, MAX_REQUEST_BYTES, "authorization request", nonwritable=True
    )
    if current_request != request_file:
        _fail("authorization request changed during execution")
    current_submission = _stable_read(
        Path(request["submission"]["path"]),
        MAX_REQUEST_BYTES,
        "submission record",
        nonwritable=True,
    )
    if current_submission != submission_file:
        _fail("submission record changed during authorization")
    for name, initial, maximum, executable, nonwritable in (
        ("authorizer", authorizer, MAX_AUTHORIZER_BYTES, False, True),
        ("finalizer module", finalizer, MAX_AUTHORIZER_BYTES, False, True),
        ("sacct executable", sacct, MAX_EXECUTABLE_BYTES, True, False),
    ):
        current = _stable_read(
            Path(
                request[
                    "finalizer_module" if name == "finalizer module" else name.split()[0]
                ]["path"]
            ),
            maximum,
            name,
            executable=executable,
            nonwritable=nonwritable,
        )
        if current != initial:
            _fail(f"{name} changed during authorization")
    return authorization, completed.stdout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", allow_abbrev=False)
    create.add_argument("--output", type=Path, required=True)
    for name in (
        "controller-python",
        "controller-python-sha256",
        "authorizer",
        "authorizer-sha256",
        "submission",
        "submission-sha256",
        "scheduler-candidate",
        "decision",
        "finalizer-module",
        "finalizer-module-sha256",
        "sacct",
        "sacct-sha256",
        "run-nonce",
        "poll-attempts",
        "poll-interval-seconds",
    ):
        create.add_argument(f"--{name}", required=True)
    execute = subparsers.add_parser("execute", allow_abbrev=False)
    execute.add_argument("--request", type=Path, required=True)
    execute.add_argument("--request-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "create":
            _, encoded = create_request(
                arguments.output,
                controller_python=arguments.controller_python,
                controller_python_sha256=arguments.controller_python_sha256,
                authorizer=arguments.authorizer,
                authorizer_sha256=arguments.authorizer_sha256,
                submission=arguments.submission,
                submission_sha256=arguments.submission_sha256,
                scheduler_candidate=arguments.scheduler_candidate,
                decision=arguments.decision,
                finalizer_module=arguments.finalizer_module,
                finalizer_module_sha256=arguments.finalizer_module_sha256,
                sacct=arguments.sacct,
                sacct_sha256=arguments.sacct_sha256,
                run_nonce=arguments.run_nonce,
                poll_attempts=arguments.poll_attempts,
                poll_interval_seconds=arguments.poll_interval_seconds,
            )
            print(hashlib.sha256(encoded).hexdigest())
        else:
            _, encoded = execute_request(arguments.request, arguments.request_sha256)
            sys.stdout.buffer.write(encoded)
    except RequestError as error:
        print(f"authorization-request executor rejected: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
