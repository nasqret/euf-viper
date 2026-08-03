#!/usr/bin/env python3
"""Validate one T11 Stage 0A compute candidate inside its Slurm finalizer."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence


SUBMISSION_SCHEMA = "euf-viper.t11-stage0a-submission.v3"
CANDIDATE_SCHEMA = "euf-viper.t11-stage0a-compute-index.v1"
SEMANTIC_SCHEMA = "euf-viper.t11-stage0a-validation-candidate.v2"
SCHEDULER_CANDIDATE_SCHEMA = "euf-viper.t11-stage0a-scheduler-candidate.v1"
COMPUTE_INDEX_NAME = "compute-index.json"
NONAUTHORIZING_DECISION = "requires_scheduler_finalization"
TERMINAL_ATTESTATION_DECISION = "requires_finalizer_terminal_attestation"
FORBIDDEN_AUTHORIZATION_DECISION = "authorize_" + "stage0b"

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
ROLE_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
CLUSTER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
JOB_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PARTITION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MODE_RE = re.compile(r"0[0-7]{3}\Z")
MEMORY_RE = re.compile(r"([1-9][0-9]*)([KMGTPE]?)([cn]?)\Z")
TRES_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_/.:-]*\Z")

MAX_JSON_BYTES = 256 * 1024 * 1024
MAX_COMMAND_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
EXPECTED_CPUS = 1
EXPECTED_NODES = 1
EXPECTED_MEMORY_BYTES = 8 * 1024**3
EXPECTED_TIMELIMIT_SECONDS = 60 * 60
EXPECTED_FINALIZER_MEMORY_BYTES = 1024**3
EXPECTED_FINALIZER_TIMELIMIT_SECONDS = 10 * 60
COMPUTE_JOB_NAME = "euf-t11-stage0a"
FINALIZER_JOB_NAME = "euf-t11-stage0a-finalize"

ALLOCATION_FIELDS = (
    "Cluster",
    "DBIndex",
    "JobIDRaw",
    "JobName",
    "User",
    "UID",
    "State",
    "ExitCode",
    "DerivedExitCode",
    "Submit",
    "Eligible",
    "Start",
    "End",
    "ElapsedRaw",
    "Partition",
    "NodeList",
    "NNodes",
    "ReqCPUS",
    "AllocCPUS",
    "ReqMem",
    "ReqTRES",
    "AllocTRES",
    "TimelimitRaw",
    "Comment",
    "SubmitLine",
    "WorkDir",
    "StdOut",
    "StdErr",
)
BATCH_FIELDS = (
    "Cluster",
    "DBIndex",
    "JobIDRaw",
    "JobName",
    "State",
    "ExitCode",
    "DerivedExitCode",
    "Submit",
    "Start",
    "End",
    "ElapsedRaw",
    "NodeList",
    "NNodes",
    "ReqCPUS",
    "AllocCPUS",
    "AllocTRES",
)


class FinalizationError(RuntimeError):
    """The compute candidate is not eligible for scheduler validation."""


class SchedulerPending(FinalizationError):
    """Slurm has not exposed a complete accounting record yet."""


@dataclass(frozen=True)
class CommandOutput:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class FileRead:
    data: bytes
    mode: str
    size: int
    sha256: str
    device: int
    inode: int


@dataclass(frozen=True)
class SchedulerEvidence:
    allocation: Mapping[str, str]
    batch: Mapping[str, str]
    scontrol: Mapping[str, str]
    allocation_command: tuple[str, ...]
    batch_command: tuple[str, ...]
    scontrol_command: tuple[str, ...]
    allocation_sha256: str
    batch_sha256: str
    scontrol_sha256: str


CommandRunner = Callable[[Sequence[str]], CommandOutput]
Sleeper = Callable[[float], None]


def _fail(message: str) -> None:
    raise FinalizationError(message)


def _no_duplicate_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_number(value: str) -> None:
    _fail(f"non-integral or non-finite JSON number is forbidden: {value}")


def _validate_json_value(value: object, context: str = "JSON") -> None:
    if value is None or type(value) in (bool, int, str):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{context}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail(f"{context} contains a non-string key")
            _validate_json_value(item, f"{context}.{key}")
        return
    _fail(f"{context} contains an unsupported value type")


def canonical_json_bytes(value: object) -> bytes:
    _validate_json_value(value)
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def decode_canonical_json(data: bytes, context: str) -> dict[str, Any]:
    if not data or len(data) > MAX_JSON_BYTES:
        _fail(f"{context} size is outside the JSON bound")
    if not data.endswith(b"\n") or data.endswith(b"\n\n") or b"\n" in data[:-1]:
        _fail(f"{context} must be one JSON record with one terminal newline")
    try:
        body = data[:-1].decode("ascii")
    except UnicodeDecodeError:
        _fail(f"{context} is not ASCII")
    try:
        value = json.loads(
            body,
            object_pairs_hook=_no_duplicate_object,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except (json.JSONDecodeError, FinalizationError) as error:
        _fail(f"cannot decode {context}: {error}")
    if not isinstance(value, dict):
        _fail(f"{context} root must be an object")
    _validate_json_value(value, context)
    if canonical_json_bytes(value) != data:
        _fail(f"{context} is not compact canonical JSON")
    return value


def _exact_keys(value: object, expected: Sequence[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{context} must be an object")
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        _fail(
            f"{context} keys differ: missing={sorted(wanted - actual)}, "
            f"extra={sorted(actual - wanted)}"
        )
    return dict(value)


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value:
        _fail(f"{context} must be nonempty single-line text")
    return value


def _positive_int(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail(f"{context} must be a positive integer")
    return value


def _nonnegative_int(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{context} must be a nonnegative integer")
    return value


def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail(f"{context} must be 64 lowercase hexadecimal digits")
    return value


def _canonical_absolute_path(value: object, context: str) -> str:
    path_text = _text(value, context)
    path = Path(path_text)
    if not path.is_absolute() or os.path.normpath(path_text) != path_text:
        _fail(f"{context} must be a canonical absolute path")
    return path_text


def _relative_path(value: object, context: str) -> str:
    path_text = _text(value, context)
    try:
        path_text.encode("ascii")
    except UnicodeEncodeError:
        _fail(f"{context} must be ASCII")
    path = PurePosixPath(path_text)
    if (
        path.is_absolute()
        or path.as_posix() != path_text
        or any(part in ("", ".", "..") for part in path.parts)
        or "\\" in path_text
    ):
        _fail(f"{context} must be a canonical relative POSIX path")
    return path_text


def _mode(value: object, context: str) -> str:
    if not isinstance(value, str) or MODE_RE.fullmatch(value) is None:
        _fail(f"{context} must be a four-digit octal mode")
    if int(value, 8) & 0o222:
        _fail(f"{context} must not contain write bits")
    return value


def _stable_read_descriptor(
    descriptor: int,
    maximum_bytes: int,
    context: str,
    *,
    capture: bool = True,
) -> FileRead:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        _fail(f"{context} is not a regular file")
    if before.st_nlink != 1:
        _fail(f"{context} has a hardlink alias")
    if stat.S_IMODE(before.st_mode) & 0o222:
        _fail(f"{context} is writable")
    if before.st_size < 0 or before.st_size > maximum_bytes:
        _fail(f"{context} size is outside the bound")
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not chunk:
            _fail(f"{context} was truncated while reading")
        digest.update(chunk)
        if capture:
            chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, offset):
        _fail(f"{context} grew while reading")
    after = os.fstat(descriptor)
    stable = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if stable(before) != stable(after):
        _fail(f"{context} changed while reading")
    return FileRead(
        data=b"".join(chunks) if capture else b"",
        mode=f"{stat.S_IMODE(before.st_mode):04o}",
        size=before.st_size,
        sha256=digest.hexdigest(),
        device=before.st_dev,
        inode=before.st_ino,
    )


def _stable_read_path(path: Path, maximum_bytes: int, context: str) -> FileRead:
    if not path.is_absolute():
        _fail(f"{context} path must be absolute")
    try:
        initial = path.lstat()
    except OSError as error:
        _fail(f"cannot inspect {context}: {error}")
    if stat.S_ISLNK(initial.st_mode):
        _fail(f"{context} must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        _fail(f"cannot open {context}: {error}")
    try:
        result = _stable_read_descriptor(descriptor, maximum_bytes, context)
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as error:
        _fail(f"cannot re-inspect {context}: {error}")
    if (
        (initial.st_dev, initial.st_ino) != (result.device, result.inode)
        or (final.st_dev, final.st_ino) != (result.device, result.inode)
        or stat.S_IMODE(final.st_mode) != int(result.mode, 8)
        or final.st_size != result.size
    ):
        _fail(f"{context} identity changed while reading")
    return result


def load_canonical_json(path: Path, context: str) -> tuple[dict[str, Any], FileRead]:
    result = _stable_read_path(path, MAX_JSON_BYTES, context)
    return decode_canonical_json(result.data, context), result


def _entry_record(path: str, metadata: os.stat_result, digest: str | None = None) -> dict[str, Any]:
    if stat.S_ISDIR(metadata.st_mode):
        return {
            "kind": "directory",
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "path": path,
        }
    if digest is None:
        _fail(f"internal inventory error for {path}")
    return {
        "bytes": metadata.st_size,
        "kind": "file",
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "path": path,
        "sha256": digest,
    }


def _inventory_directory(
    descriptor: int,
    prefix: str,
    records: list[dict[str, Any]],
    file_identities: set[tuple[int, int]],
    directory_identities: set[tuple[int, int]],
) -> None:
    before = os.fstat(descriptor)
    if not stat.S_ISDIR(before.st_mode):
        _fail(f"inventory path is not a directory: {prefix or '.'}")
    if stat.S_IMODE(before.st_mode) & 0o222:
        _fail(f"sealed run directory is writable: {prefix or '.'}")
    directory_identity = (before.st_dev, before.st_ino)
    if directory_identity in directory_identities:
        _fail(f"directory identity is aliased inside the run root: {prefix or '.'}")
    directory_identities.add(directory_identity)
    try:
        names = sorted(os.listdir(descriptor))
    except OSError as error:
        _fail(f"cannot list sealed run directory {prefix or '.'}: {error}")
    for name in names:
        if not name or name in (".", "..") or "/" in name or "\x00" in name:
            _fail(f"invalid directory entry under {prefix or '.'}")
        try:
            name.encode("ascii")
        except UnicodeEncodeError:
            _fail(f"non-ASCII directory entry under {prefix or '.'}")
        relative = f"{prefix}/{name}" if prefix else name
        try:
            named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            _fail(f"cannot inspect run-root entry {relative}: {error}")
        mode = stat.S_IMODE(named.st_mode)
        if stat.S_ISLNK(named.st_mode):
            _fail(f"symbolic links are forbidden in the run root: {relative}")
        if mode & 0o222:
            _fail(f"run-root entry is writable: {relative}")
        if stat.S_ISDIR(named.st_mode):
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                child = os.open(name, flags, dir_fd=descriptor)
            except OSError as error:
                _fail(f"cannot open run-root directory {relative}: {error}")
            try:
                opened = os.fstat(child)
                if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                    _fail(f"run-root directory identity changed: {relative}")
                records.append(_entry_record(relative, opened))
                _inventory_directory(
                    child,
                    relative,
                    records,
                    file_identities,
                    directory_identities,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(named.st_mode):
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                child = os.open(name, flags, dir_fd=descriptor)
            except OSError as error:
                _fail(f"cannot open run-root file {relative}: {error}")
            try:
                opened = os.fstat(child)
                if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                    _fail(f"run-root file identity changed: {relative}")
                result = _stable_read_descriptor(
                    child, MAX_FILE_BYTES, relative, capture=False
                )
            finally:
                os.close(child)
            identity = (result.device, result.inode)
            if identity in file_identities:
                _fail(f"hardlink alias detected in the run root: {relative}")
            file_identities.add(identity)
            records.append(_entry_record(relative, opened, result.sha256))
        else:
            _fail(f"special filesystem entries are forbidden in the run root: {relative}")
        try:
            final = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            _fail(f"cannot re-inspect run-root entry {relative}: {error}")
        stable = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if stable(named) != stable(final):
            _fail(f"run-root entry changed during inventory: {relative}")
    after = os.fstat(descriptor)
    stable_directory = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if stable_directory(before) != stable_directory(after):
        _fail(f"run-root directory changed during inventory: {prefix or '.'}")


def inventory_run_root_descriptor(
    root: Path,
    descriptor: int,
) -> tuple[str, list[dict[str, Any]], tuple[int, int]]:
    if not root.is_absolute() or os.path.normpath(os.fspath(root)) != os.fspath(root):
        _fail("candidate root must be a canonical absolute path")
    try:
        initial = root.lstat()
    except OSError as error:
        _fail(f"cannot inspect candidate root: {error}")
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
        _fail("candidate root must be a real directory, not a symbolic link")
    if stat.S_IMODE(initial.st_mode) & 0o222:
        _fail("candidate root is writable")
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode):
        _fail("candidate-root descriptor is not a directory")
    if (initial.st_dev, initial.st_ino) != (opened.st_dev, opened.st_ino):
        _fail("candidate-root descriptor differs from its pathname")
    records: list[dict[str, Any]] = []
    _inventory_directory(descriptor, "", records, set(), set())
    final = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino, opened.st_mode) != (
        final.st_dev,
        final.st_ino,
        final.st_mode,
    ):
        _fail("candidate-root identity changed during inventory")
    try:
        named_final = root.lstat()
    except OSError as error:
        _fail(f"cannot re-inspect candidate root: {error}")
    if (
        stat.S_ISLNK(named_final.st_mode)
        or (named_final.st_dev, named_final.st_ino, named_final.st_mode)
        != (opened.st_dev, opened.st_ino, opened.st_mode)
    ):
        _fail("candidate-root pathname changed during inventory")
    records.sort(key=lambda record: record["path"])
    return (
        f"{stat.S_IMODE(opened.st_mode):04o}",
        records,
        (opened.st_dev, opened.st_ino),
    )


def inventory_run_root(
    root: Path,
) -> tuple[str, list[dict[str, Any]], tuple[int, int]]:
    if not root.is_absolute() or os.path.normpath(os.fspath(root)) != os.fspath(root):
        _fail("candidate root must be a canonical absolute path")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(root, flags)
    try:
        return inventory_run_root_descriptor(root, descriptor)
    finally:
        os.close(descriptor)


def _open_relative_file(
    root: Path,
    relative: str,
    context: str,
    expected_root_identity: tuple[int, int],
) -> FileRead:
    relative = _relative_path(relative, context)
    parts = PurePosixPath(relative).parts
    root_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = [os.open(root, root_flags)]
    try:
        root_metadata = os.fstat(descriptors[0])
        if (root_metadata.st_dev, root_metadata.st_ino) != expected_root_identity:
            _fail(f"candidate root changed before reading {context}")
        for part in parts[:-1]:
            descriptors.append(os.open(part, root_flags, dir_fd=descriptors[-1]))
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(parts[-1], flags, dir_fd=descriptors[-1])
        try:
            return _stable_read_descriptor(descriptor, MAX_JSON_BYTES, context)
        finally:
            os.close(descriptor)
    except OSError as error:
        _fail(f"cannot open {context}: {error}")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _validate_control_hashes(value: object) -> dict[str, str]:
    fields = (
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
    control = _exact_keys(value, fields, "submission.control")
    return {field: _sha256(control[field], f"submission.control.{field}") for field in fields}


def _validate_held_record(value: object, context: str) -> dict[str, str]:
    record = _exact_keys(value, ("path", "sha256"), context)
    return {
        "path": _canonical_absolute_path(record["path"], f"{context}.path"),
        "sha256": _sha256(record["sha256"], f"{context}.sha256"),
    }


def _validate_sbatch_argv(
    value: object,
    *,
    context: str,
    cluster: str,
    partition: str,
    job_name: str,
    comment: str,
    work_dir: str,
    stdout_path: str,
    stderr_path: str,
    script_path: str,
    memory: str,
    timelimit: str,
    dependency: str | None,
) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{context} must be a nonempty string array")
    argv: list[str] = []
    for index, item in enumerate(value):
        if (
            not isinstance(item, str)
            or not item
            or "\0" in item
            or "\n" in item
            or "\r" in item
        ):
            _fail(f"{context}[{index}] is malformed")
        try:
            item.encode("ascii")
        except UnicodeEncodeError:
            _fail(f"{context}[{index}] is not ASCII")
        argv.append(item)
    _canonical_absolute_path(argv[0], f"{context}[0]")
    expected = [
        argv[0],
        "--parsable",
        f"--clusters={cluster}",
        "--hold",
        "--no-requeue",
    ]
    if dependency is not None:
        expected.extend(
            [
                "--kill-on-invalid-dep=yes",
                f"--dependency={dependency}",
            ]
        )
    expected.extend(
        [
            f"--job-name={job_name}",
            f"--partition={partition}",
            "--nodes=1",
            "--ntasks=1",
            "--cpus-per-task=1",
            f"--mem={memory}",
            f"--time={timelimit}",
            f"--chdir={work_dir}",
            "--open-mode=truncate",
            f"--output={stdout_path}",
            f"--error={stderr_path}",
            f"--comment={comment}",
        ]
    )
    if len(argv) != len(expected) + 2 or argv[: len(expected)] != expected:
        _fail(f"{context} differs from the exact submission contract")
    if not argv[-2].startswith("--export=") or len(argv[-2]) == len("--export="):
        _fail(f"{context} lacks one nonempty export record")
    if argv[-1] != script_path:
        _fail(f"{context} script path differs")
    return argv


def validate_submission(value: object) -> dict[str, Any]:
    submission = _exact_keys(
        value,
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
        "submission",
    )
    if submission["schema"] != SUBMISSION_SCHEMA:
        _fail("submission schema differs")
    nonce = submission["run_nonce"]
    if not isinstance(nonce, str) or NONCE_RE.fullmatch(nonce) is None:
        _fail("submission.run_nonce must be 32 lowercase hexadecimal digits")
    revision = submission["revision"]
    if not isinstance(revision, str) or REVISION_RE.fullmatch(revision) is None:
        _fail("submission.revision must be a canonical Git revision")
    submission["launch_manifest_sha256"] = _sha256(
        submission["launch_manifest_sha256"], "submission.launch_manifest_sha256"
    )
    submission["candidate_root"] = _canonical_absolute_path(
        submission["candidate_root"], "submission.candidate_root"
    )
    submission["scheduler_candidate_path"] = _canonical_absolute_path(
        submission["scheduler_candidate_path"],
        "submission.scheduler_candidate_path",
    )
    submission["final_decision_path"] = _canonical_absolute_path(
        submission["final_decision_path"], "submission.final_decision_path"
    )
    submission["control"] = _validate_control_hashes(submission["control"])
    slurm = _exact_keys(
        submission["slurm"],
        (
            "cluster",
            "owner_uid",
            "compute_job_id",
            "finalizer_job_id",
            "finalizer_dependency",
            "compute_job_name",
            "compute_comment",
            "finalizer_job_name",
            "finalizer_comment",
            "partition",
            "requested_nodes",
            "requested_cpus",
            "requested_memory_bytes",
            "timelimit_seconds",
            "work_dir",
            "stdout_path",
            "stderr_path",
            "compute_script_path",
            "finalizer_requested_nodes",
            "finalizer_requested_cpus",
            "finalizer_requested_memory_bytes",
            "finalizer_timelimit_seconds",
            "finalizer_work_dir",
            "finalizer_stdout_path",
            "finalizer_stderr_path",
            "finalizer_script_path",
            "compute_sbatch_argv",
            "finalizer_sbatch_argv",
            "compute_held_record",
            "finalizer_held_record",
        ),
        "submission.slurm",
    )
    cluster = _text(slurm["cluster"], "submission.slurm.cluster")
    if CLUSTER_RE.fullmatch(cluster) is None:
        _fail("submission.slurm.cluster is malformed")
    owner_uid = _nonnegative_int(slurm["owner_uid"], "submission.slurm.owner_uid")
    compute_job_id = _positive_int(slurm["compute_job_id"], "submission.slurm.compute_job_id")
    finalizer_job_id = _positive_int(
        slurm["finalizer_job_id"], "submission.slurm.finalizer_job_id"
    )
    dependency = _text(slurm["finalizer_dependency"], "submission.slurm.finalizer_dependency")
    if dependency != f"afterany:{compute_job_id}":
        _fail("submission finalizer dependency does not bind the compute job")
    job_name = _text(slurm["compute_job_name"], "submission.slurm.compute_job_name")
    if job_name != COMPUTE_JOB_NAME:
        _fail("submission compute job name differs")
    finalizer_job_name = _text(
        slurm["finalizer_job_name"], "submission.slurm.finalizer_job_name"
    )
    if finalizer_job_name != FINALIZER_JOB_NAME:
        _fail("submission finalizer job name differs")
    compute_comment = _text(slurm["compute_comment"], "submission.slurm.compute_comment")
    finalizer_comment = _text(
        slurm["finalizer_comment"], "submission.slurm.finalizer_comment"
    )
    if compute_comment != f"euf-viper-t11:{nonce}:compute":
        _fail("submission compute comment differs")
    if finalizer_comment != f"euf-viper-t11:{nonce}:finalizer":
        _fail("submission finalizer comment differs")
    partition = _text(slurm["partition"], "submission.slurm.partition")
    if PARTITION_RE.fullmatch(partition) is None:
        _fail("submission partition is malformed")
    expected_fixed = {
        "requested_nodes": EXPECTED_NODES,
        "requested_cpus": EXPECTED_CPUS,
        "requested_memory_bytes": EXPECTED_MEMORY_BYTES,
        "timelimit_seconds": EXPECTED_TIMELIMIT_SECONDS,
    }
    for field, expected in expected_fixed.items():
        actual = _positive_int(slurm[field], f"submission.slurm.{field}")
        if actual != expected:
            _fail(f"submission.slurm.{field} differs from the T11 resource contract")
        slurm[field] = actual
    finalizer_fixed = {
        "finalizer_requested_nodes": EXPECTED_NODES,
        "finalizer_requested_cpus": EXPECTED_CPUS,
        "finalizer_requested_memory_bytes": EXPECTED_FINALIZER_MEMORY_BYTES,
        "finalizer_timelimit_seconds": EXPECTED_FINALIZER_TIMELIMIT_SECONDS,
    }
    for field, expected in finalizer_fixed.items():
        actual = _positive_int(slurm[field], f"submission.slurm.{field}")
        if actual != expected:
            _fail(f"submission.slurm.{field} differs from the finalizer resource contract")
        slurm[field] = actual
    for field in ("work_dir", "stdout_path", "stderr_path", "compute_script_path"):
        slurm[field] = _canonical_absolute_path(slurm[field], f"submission.slurm.{field}")
    for field in (
        "finalizer_work_dir",
        "finalizer_stdout_path",
        "finalizer_stderr_path",
        "finalizer_script_path",
    ):
        slurm[field] = _canonical_absolute_path(slurm[field], f"submission.slurm.{field}")
    if slurm["finalizer_work_dir"] != slurm["work_dir"]:
        _fail("submission finalizer work directory differs from the compute work directory")
    slurm["compute_held_record"] = _validate_held_record(
        slurm["compute_held_record"], "submission.slurm.compute_held_record"
    )
    slurm["finalizer_held_record"] = _validate_held_record(
        slurm["finalizer_held_record"], "submission.slurm.finalizer_held_record"
    )
    slurm["compute_sbatch_argv"] = _validate_sbatch_argv(
        slurm["compute_sbatch_argv"],
        context="submission.slurm.compute_sbatch_argv",
        cluster=cluster,
        partition=partition,
        job_name=job_name,
        comment=compute_comment,
        work_dir=slurm["work_dir"],
        stdout_path=slurm["stdout_path"],
        stderr_path=slurm["stderr_path"],
        script_path=slurm["compute_script_path"],
        memory="8G",
        timelimit="01:00:00",
        dependency=None,
    )
    slurm["finalizer_sbatch_argv"] = _validate_sbatch_argv(
        slurm["finalizer_sbatch_argv"],
        context="submission.slurm.finalizer_sbatch_argv",
        cluster=cluster,
        partition=partition,
        job_name=finalizer_job_name,
        comment=finalizer_comment,
        work_dir=slurm["finalizer_work_dir"],
        stdout_path=slurm["finalizer_stdout_path"],
        stderr_path=slurm["finalizer_stderr_path"],
        script_path=slurm["finalizer_script_path"],
        memory="1G",
        timelimit="00:10:00",
        dependency=dependency,
    )
    slurm.update(
        {
            "cluster": cluster,
            "owner_uid": owner_uid,
            "compute_job_id": compute_job_id,
            "finalizer_job_id": finalizer_job_id,
            "finalizer_dependency": dependency,
            "compute_job_name": job_name,
            "compute_comment": compute_comment,
            "finalizer_job_name": finalizer_job_name,
            "finalizer_comment": finalizer_comment,
            "partition": partition,
        }
    )
    submission["slurm"] = slurm
    return submission


def _validate_artifact_record(value: object, context: str) -> dict[str, Any]:
    record = _exact_keys(
        value,
        ("role", "path_rel", "mode", "size", "sha256"),
        context,
    )
    role = _text(record["role"], f"{context}.role")
    if ROLE_RE.fullmatch(role) is None:
        _fail(f"{context}.role is malformed")
    record["role"] = role
    record["path_rel"] = _relative_path(record["path_rel"], f"{context}.path_rel")
    if record["path_rel"] == COMPUTE_INDEX_NAME:
        _fail("compute index must not bind itself")
    record["mode"] = _mode(record["mode"], f"{context}.mode")
    record["size"] = _nonnegative_int(record["size"], f"{context}.size")
    if record["size"] > MAX_FILE_BYTES:
        _fail(f"{context}.size exceeds the artifact bound")
    record["sha256"] = _sha256(record["sha256"], f"{context}.sha256")
    return record


def validate_compute_index(
    value: object,
    submission: Mapping[str, Any],
    root_mode: str,
    inventory: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], str]:
    index = _exact_keys(
        value,
        (
            "schema",
            "status",
            "decision",
            "stage0b_authority",
            "classification",
            "candidate_outcome",
            "reason",
            "intended_exit_code",
            "attempt",
            "revision",
            "launch_manifest_sha256",
            "validation_candidate_sha256",
            "root_mode",
            "semantic_metadata_path",
            "artifacts",
            "missing_expected",
        ),
        "compute index",
    )
    if index["schema"] != CANDIDATE_SCHEMA:
        _fail("compute-index schema differs")
    if index["status"] != "candidate_complete":
        _fail("compute index is not complete")
    if index["decision"] != NONAUTHORIZING_DECISION:
        _fail("compute index decision is not the non-authorizing handoff")
    if type(index["stage0b_authority"]) is not bool or index["stage0b_authority"]:
        _fail("compute index must be explicitly non-authorizing")
    if index["classification"] != "scientific_candidate":
        _fail("compute index classification differs")
    if index["candidate_outcome"] != "accept" or index["intended_exit_code"] != 0:
        _fail("compute candidate is not a successful scientific acceptance")
    if index["reason"] is not None:
        _fail("accepted compute candidate must not contain a rejection reason")
    if index["missing_expected"] != []:
        _fail("compute index reports missing expected artifacts")
    attempt = _exact_keys(
        index["attempt"],
        (
            "run_nonce",
            "cluster",
            "job_id",
            "array_job_id",
            "array_task_id",
            "step_id",
            "restart_count",
            "hostname",
            "submit_dir",
        ),
        "compute-index.attempt",
    )
    if attempt["run_nonce"] != submission["run_nonce"]:
        _fail("compute-index nonce differs from the submission")
    if attempt["cluster"] != submission["slurm"]["cluster"]:
        _fail("compute-index cluster differs from the submission")
    if attempt["job_id"] != submission["slurm"]["compute_job_id"]:
        _fail("compute-index job ID differs from the submission")
    if attempt["array_job_id"] is not None or attempt["array_task_id"] is not None:
        _fail("T11 Stage 0A compute job must not be an array task")
    if attempt["step_id"] != "batch":
        _fail("compute-index attempt step must be batch")
    if attempt["restart_count"] != 0:
        _fail("compute-index attempt restart count is nonzero")
    attempt["hostname"] = _text(attempt["hostname"], "compute-index.attempt.hostname")
    attempt["submit_dir"] = _canonical_absolute_path(
        attempt["submit_dir"], "compute-index.attempt.submit_dir"
    )
    if attempt["submit_dir"] != submission["slurm"]["work_dir"]:
        _fail("compute-index submit directory differs from the submission")
    revision = index["revision"]
    if not isinstance(revision, str) or REVISION_RE.fullmatch(revision) is None:
        _fail("compute-index revision must be 40 lowercase hexadecimal digits")
    if index["launch_manifest_sha256"] != submission["launch_manifest_sha256"]:
        _fail("compute-index launch-manifest digest differs from the submission")
    if _mode(index["root_mode"], "compute-index.root_mode") != root_mode:
        _fail("compute-index root mode differs from the sealed run root")
    semantic_path = _relative_path(
        index["semantic_metadata_path"],
        "compute-index.semantic_metadata_path",
    )
    validation_sha256 = _sha256(
        index["validation_candidate_sha256"],
        "compute-index.validation_candidate_sha256",
    )
    if not isinstance(index["artifacts"], list):
        _fail("compute-index.artifacts must be an array")
    bound = [
        _validate_artifact_record(record, f"compute-index.artifacts[{position}]")
        for position, record in enumerate(index["artifacts"])
    ]
    roles = [record["role"] for record in bound]
    paths = [record["path_rel"] for record in bound]
    if roles != sorted(roles) or len(roles) != len(set(roles)):
        _fail("compute-index artifact roles must be unique and sorted")
    if len(paths) != len(set(paths)):
        _fail("compute-index artifact paths must be unique")
    bound_by_path = {record["path_rel"]: record for record in bound}
    actual_files = {
        record["path"]: record
        for record in inventory
        if record["kind"] == "file" and record["path"] != COMPUTE_INDEX_NAME
    }
    normalized_bound = {
        path: {
            "bytes": record["size"],
            "kind": "file",
            "mode": record["mode"],
            "path": path,
            "sha256": record["sha256"],
        }
        for path, record in bound_by_path.items()
    }
    if normalized_bound != actual_files:
        actual_by_path = actual_files
        missing = sorted(set(bound_by_path) - set(actual_by_path))
        extra = sorted(set(actual_by_path) - set(bound_by_path))
        changed = sorted(
            path
            for path in set(bound_by_path) & set(actual_by_path)
            if normalized_bound[path] != actual_by_path[path]
        )
        _fail(
            "compute-index artifact closure differs from the sealed run root: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    expected_directories: set[str] = set()
    for path in paths:
        parent = PurePosixPath(path).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_directories = {
        record["path"] for record in inventory if record["kind"] == "directory"
    }
    if actual_directories != expected_directories:
        _fail(
            "run-root directory closure differs from bound artifact ancestors: "
            f"missing={sorted(expected_directories - actual_directories)}, "
            f"extra={sorted(actual_directories - expected_directories)}"
        )
    semantic_records = [record for record in bound if record["role"] == "validation_candidate"]
    if len(semantic_records) != 1:
        _fail("compute index must bind one validation_candidate role")
    if semantic_records[0]["path_rel"] != semantic_path:
        _fail("compute-index semantic path differs from the validation_candidate artifact")
    if semantic_records[0]["sha256"] != validation_sha256:
        _fail("compute-index validation-candidate digest differs from its artifact record")
    index["artifacts"] = bound
    index["attempt"] = attempt
    return index, semantic_path


def _contains_authorization(value: object) -> bool:
    if isinstance(value, str):
        return value == FORBIDDEN_AUTHORIZATION_DECISION
    if isinstance(value, list):
        return any(_contains_authorization(item) for item in value)
    if isinstance(value, dict):
        return any(
            key == FORBIDDEN_AUTHORIZATION_DECISION or _contains_authorization(item)
            for key, item in value.items()
        )
    return False


def validate_semantic_candidate(value: object, submission: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("semantic candidate must be an object")
    candidate = dict(value)
    if _contains_authorization(candidate):
        _fail("semantic candidate contains a forbidden authorization decision")
    required = {
        "schema",
        "status",
        "decision",
        "stage0b_authority",
        "revision",
        "launch_manifest_sha256",
        "job_id",
        "resource_contract",
    }
    missing = sorted(required - set(candidate))
    if missing:
        _fail(f"semantic candidate lacks required fields: {missing}")
    if candidate["schema"] != SEMANTIC_SCHEMA:
        _fail("semantic candidate schema differs")
    if candidate["status"] != "validated_candidate":
        _fail("semantic candidate status is not validated_candidate")
    if candidate["decision"] != NONAUTHORIZING_DECISION:
        _fail("semantic candidate decision is not the non-authorizing handoff")
    if type(candidate["stage0b_authority"]) is not bool or candidate["stage0b_authority"]:
        _fail("semantic candidate must explicitly deny Stage 0B authority")
    revision = candidate["revision"]
    if not isinstance(revision, str) or REVISION_RE.fullmatch(revision) is None:
        _fail("semantic candidate revision must be 40 lowercase hexadecimal digits")
    if candidate["launch_manifest_sha256"] != submission["launch_manifest_sha256"]:
        _fail("semantic candidate launch-manifest digest differs")
    if candidate["job_id"] != submission["slurm"]["compute_job_id"]:
        _fail("semantic candidate job ID differs")
    resources = _exact_keys(
        candidate["resource_contract"],
        ("cpus", "memory_bytes", "sat_calls"),
        "semantic candidate resource contract",
    )
    expected = {
        "cpus": EXPECTED_CPUS,
        "memory_bytes": EXPECTED_MEMORY_BYTES,
        "sat_calls": 0,
    }
    if resources != expected:
        _fail("semantic candidate resource contract differs from Stage 0A")
    return candidate


def _parse_sacct_row(
    raw: bytes,
    fields: Sequence[str],
    expected_id: str,
    context: str,
) -> dict[str, str]:
    if not raw:
        raise SchedulerPending(f"{context} accounting output is absent")
    if len(raw) > MAX_COMMAND_BYTES:
        _fail(f"{context} accounting output exceeds its size bound")
    if b"\r" in raw or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        _fail(f"{context} accounting output must be exactly one newline-terminated row")
    try:
        line = raw[:-1].decode("ascii")
    except UnicodeDecodeError:
        _fail(f"{context} accounting output is not ASCII")
    if not line:
        raise SchedulerPending(f"{context} accounting row is not available")
    pieces = line.split("|")
    if len(pieces) != len(fields):
        _fail(f"{context} accounting row has {len(pieces)} fields, expected {len(fields)}")
    record = dict(zip(fields, pieces, strict=True))
    if record["JobIDRaw"] != expected_id:
        _fail(f"{context} accounting job identity differs")
    return record


def _parse_scontrol(raw: bytes) -> dict[str, str]:
    if not raw or len(raw) > MAX_COMMAND_BYTES:
        raise SchedulerPending("scontrol record is absent")
    try:
        text = raw.decode("ascii").strip(" \n")
    except UnicodeDecodeError:
        _fail("scontrol record is not ASCII")
    if not text or "\n" in text or "\r" in text:
        _fail("scontrol output must contain exactly one record")
    result: dict[str, str] = {}
    for token in text.split(" "):
        if not token or "=" not in token:
            _fail("scontrol output contains a malformed field")
        key, value = token.split("=", 1)
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_/:]*", key) is None:
            _fail(f"scontrol output contains a malformed key: {key!r}")
        if key in result:
            _fail(f"duplicate scontrol key: {key}")
        result[key] = value
    if not result or result.get("JobId") is None:
        _fail("scontrol output is not a job record")
    return result


def _scontrol_uid(value: str, context: str) -> int:
    match = re.fullmatch(r"[^()]+\(([0-9]+)\)", value)
    if match is None:
        _fail(f"{context} is malformed")
    return int(match.group(1))


def _validate_held_scheduler_record(
    submission: Mapping[str, Any], role: str
) -> tuple[dict[str, str], FileRead]:
    if role not in ("compute", "finalizer"):
        _fail("internal held-record role is invalid")
    slurm = submission["slurm"]
    binding = slurm[f"{role}_held_record"]
    path = Path(binding["path"])
    record_read = _stable_read_path(path, MAX_COMMAND_BYTES, f"{role} held scheduler record")
    if record_read.sha256 != binding["sha256"]:
        _fail(f"{role} held scheduler record digest differs from the submission")
    record = _parse_scontrol(record_read.data)
    if role == "compute":
        expected = {
            "JobId": str(slurm["compute_job_id"]),
            "JobName": slurm["compute_job_name"],
            "Comment": slurm["compute_comment"],
            "Command": slurm["compute_script_path"],
            "WorkDir": slurm["work_dir"],
            "StdOut": slurm["stdout_path"],
            "StdErr": slurm["stderr_path"],
        }
        expected_dependency = "(null)"
    else:
        expected = {
            "JobId": str(slurm["finalizer_job_id"]),
            "JobName": slurm["finalizer_job_name"],
            "Comment": slurm["finalizer_comment"],
            "Command": slurm["finalizer_script_path"],
            "WorkDir": slurm["finalizer_work_dir"],
            "StdOut": slurm["finalizer_stdout_path"],
            "StdErr": slurm["finalizer_stderr_path"],
        }
        expected_dependency = slurm["finalizer_dependency"]
    expected.update({"JobState": "PENDING", "Reason": "JobHeldUser", "Requeue": "0"})
    for field, value in expected.items():
        if record.get(field) != value:
            _fail(f"{role} held scheduler record {field} differs from the submission")
    if _scontrol_uid(record.get("UserId", ""), f"{role} held UserId") != slurm[
        "owner_uid"
    ]:
        _fail(f"{role} held scheduler owner differs from the submission")
    dependency = record.get("Dependency", "")
    if role == "compute":
        if dependency != expected_dependency:
            _fail("compute held scheduler dependency differs from the submission")
    elif dependency not in (expected_dependency, f"{expected_dependency}(unfulfilled)"):
        _fail("finalizer held scheduler dependency differs from the submission")
    return record, record_read


def _default_command_runner(argv: Sequence[str]) -> CommandOutput:
    pass_fds: tuple[int, ...] = ()
    descriptor_match = re.fullmatch(r"/proc/self/fd/([0-9]+)", argv[0])
    if descriptor_match is not None:
        descriptor = int(descriptor_match.group(1))
        try:
            metadata = os.fstat(descriptor)
        except OSError as error:
            _fail(f"scheduler executable descriptor is unavailable: {error}")
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            _fail("scheduler executable descriptor is not an executable regular file")
        pass_fds = (descriptor,)
    completed = subprocess.run(
        list(argv),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        pass_fds=pass_fds,
        timeout=30,
    )
    return CommandOutput(tuple(argv), completed.returncode, completed.stdout, completed.stderr)


def _run_scheduler_command(argv: Sequence[str], runner: CommandRunner) -> CommandOutput:
    try:
        result = runner(tuple(argv))
    except (OSError, subprocess.SubprocessError) as error:
        _fail(f"scheduler command failed to execute: {argv[0]}: {error}")
    if tuple(result.argv) != tuple(argv):
        _fail("scheduler command runner reported a different argv")
    if result.returncode != 0:
        _fail(
            f"scheduler command failed with exit {result.returncode}: "
            f"{result.stderr[:512]!r}"
        )
    if result.stderr:
        _fail(f"scheduler command emitted stderr: {result.stderr[:512]!r}")
    if len(result.stdout) > MAX_COMMAND_BYTES:
        _fail("scheduler command output exceeds its size bound")
    return result


def collect_scheduler_evidence(
    submission: Mapping[str, Any],
    runner: CommandRunner = _default_command_runner,
    *,
    sacct_bin: str = "/usr/bin/sacct",
    scontrol_bin: str = "/usr/bin/scontrol",
) -> SchedulerEvidence:
    slurm = submission["slurm"]
    job_id = str(slurm["compute_job_id"])
    cluster = slurm["cluster"]
    allocation_argv = (
        sacct_bin,
        "--clusters",
        cluster,
        "--noheader",
        "--parsable2",
        "--duplicates",
        "--allocations",
        "--jobs",
        job_id,
        "--format=" + ",".join(ALLOCATION_FIELDS),
    )
    batch_argv = (
        sacct_bin,
        "--clusters",
        cluster,
        "--noheader",
        "--parsable2",
        "--duplicates",
        "--jobs",
        f"{job_id}.batch",
        "--format=" + ",".join(BATCH_FIELDS),
    )
    scontrol_argv = (scontrol_bin, "show", "job", "-o", job_id)
    allocation_output = _run_scheduler_command(allocation_argv, runner)
    batch_output = _run_scheduler_command(batch_argv, runner)
    scontrol_output = _run_scheduler_command(scontrol_argv, runner)
    return SchedulerEvidence(
        allocation=_parse_sacct_row(
            allocation_output.stdout, ALLOCATION_FIELDS, job_id, "allocation"
        ),
        batch=_parse_sacct_row(
            batch_output.stdout, BATCH_FIELDS, f"{job_id}.batch", "batch"
        ),
        scontrol=_parse_scontrol(scontrol_output.stdout),
        allocation_command=allocation_argv,
        batch_command=batch_argv,
        scontrol_command=scontrol_argv,
        allocation_sha256=hashlib.sha256(allocation_output.stdout).hexdigest(),
        batch_sha256=hashlib.sha256(batch_output.stdout).hexdigest(),
        scontrol_sha256=hashlib.sha256(scontrol_output.stdout).hexdigest(),
    )


def _canonical_decimal(value: str, context: str, *, positive: bool = False) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        _fail(f"{context} is not a canonical decimal integer")
    parsed = int(value)
    if positive and parsed == 0:
        _fail(f"{context} must be positive")
    return parsed


def _parse_timestamp(value: str, context: str) -> dt.datetime:
    if not value or value in ("Unknown", "None", "N/A"):
        _fail(f"{context} is absent")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        _fail(f"{context} is not an ISO-8601 timestamp")
    if parsed.microsecond:
        _fail(f"{context} must have whole-second precision")
    return parsed


def _parse_tres(value: str, context: str) -> dict[str, str]:
    if not value:
        _fail(f"{context} is empty")
    result: dict[str, str] = {}
    for item in value.split(","):
        if item.count("=") != 1:
            _fail(f"{context} contains a malformed item")
        key, raw = item.split("=", 1)
        if TRES_NAME_RE.fullmatch(key) is None or not raw:
            _fail(f"{context} contains a malformed item")
        if key in result:
            _fail(f"{context} contains duplicate resource {key}")
        result[key] = raw
    return result


def _parse_memory(value: str, cpus: int, nodes: int, context: str) -> int:
    match = MEMORY_RE.fullmatch(value)
    if match is None:
        _fail(f"{context} is not a canonical Slurm memory quantity")
    amount = int(match.group(1))
    unit = match.group(2)
    scope = match.group(3)
    multiplier = 1 if not unit else 1024 ** ("KMGTPE".index(unit) + 1)
    total = amount * multiplier
    if scope == "c":
        total *= cpus
    elif scope == "n":
        total *= nodes
    return total


def _require_scheduler_record(
    evidence: SchedulerEvidence, submission: Mapping[str, Any]
) -> dict[str, Any]:
    slurm = submission["slurm"]
    allocation = dict(evidence.allocation)
    batch = dict(evidence.batch)
    control = dict(evidence.scontrol)
    if allocation["Cluster"] != slurm["cluster"]:
        _fail("allocation cluster differs from the submission")
    if batch["Cluster"] != slurm["cluster"]:
        _fail("batch cluster differs from the submission")
    if _canonical_decimal(
        allocation["DBIndex"], "allocation.DBIndex", positive=True
    ) != _canonical_decimal(batch["DBIndex"], "batch.DBIndex", positive=True):
        _fail("allocation and batch DBIndex differ")
    if allocation["JobName"] != slurm["compute_job_name"]:
        _fail("allocation job name differs from the submission")
    if _canonical_decimal(allocation["UID"], "allocation.UID") != slurm["owner_uid"]:
        _fail("allocation owner UID differs from the submission")
    if allocation["Comment"] != slurm["compute_comment"]:
        _fail("allocation comment differs from the submission")
    compute_argv = slurm["compute_sbatch_argv"]
    if any(any(character.isspace() for character in argument) for argument in compute_argv):
        _fail("compute sbatch argv cannot be represented exactly by SubmitLine")
    if allocation["SubmitLine"] != " ".join(compute_argv):
        _fail("allocation SubmitLine differs from the exact submitted argv")
    if allocation["State"] != "COMPLETED" or batch["State"] != "COMPLETED":
        _fail("allocation and batch step must both be COMPLETED")
    if allocation["ExitCode"] != "0:0" or allocation["DerivedExitCode"] != "0:0":
        _fail("allocation exit and derived-exit codes must both be 0:0")
    if batch["ExitCode"] != "0:0":
        _fail("batch exit code must be 0:0")
    if batch["DerivedExitCode"] not in ("", "0:0"):
        _fail("batch derived-exit code must be absent or 0:0")
    if batch["JobName"] != "batch":
        _fail("batch step name differs")
    if allocation["Partition"] != slurm["partition"]:
        _fail("allocation partition differs from the submission")
    nodes = _canonical_decimal(allocation["NNodes"], "allocation.NNodes", positive=True)
    requested_cpus = _canonical_decimal(
        allocation["ReqCPUS"], "allocation.ReqCPUS", positive=True
    )
    allocated_cpus = _canonical_decimal(
        allocation["AllocCPUS"], "allocation.AllocCPUS", positive=True
    )
    if (
        nodes != slurm["requested_nodes"]
        or requested_cpus != slurm["requested_cpus"]
        or allocated_cpus != slurm["requested_cpus"]
    ):
        _fail("allocation CPU or node resources differ from the submission")
    requested_memory = _parse_memory(
        allocation["ReqMem"], requested_cpus, nodes, "allocation.ReqMem"
    )
    if requested_memory != slurm["requested_memory_bytes"]:
        _fail("allocation memory differs from the submission")
    requested_tres = _parse_tres(allocation["ReqTRES"], "allocation.ReqTRES")
    allocated_tres = _parse_tres(allocation["AllocTRES"], "allocation.AllocTRES")
    for context, tres, cpus in (
        ("requested", requested_tres, requested_cpus),
        ("allocated", allocated_tres, allocated_cpus),
    ):
        if _canonical_decimal(tres.get("cpu", ""), f"{context} TRES cpu", positive=True) != cpus:
            _fail(f"{context} TRES CPU count differs")
        if _canonical_decimal(tres.get("node", ""), f"{context} TRES node", positive=True) != nodes:
            _fail(f"{context} TRES node count differs")
        if _parse_memory(tres.get("mem", ""), cpus, nodes, f"{context} TRES memory") != slurm[
            "requested_memory_bytes"
        ]:
            _fail(f"{context} TRES memory differs")
    timelimit_minutes = _canonical_decimal(
        allocation["TimelimitRaw"], "allocation.TimelimitRaw", positive=True
    )
    if timelimit_minutes * 60 != slurm["timelimit_seconds"]:
        _fail("allocation time limit differs from the submission")
    for field, expected in (
        ("WorkDir", slurm["work_dir"]),
        ("StdOut", slurm["stdout_path"]),
        ("StdErr", slurm["stderr_path"]),
    ):
        if allocation[field] != expected:
            _fail(f"allocation {field} differs from the submission")
    if not allocation["NodeList"] or allocation["NodeList"] in ("None", "Unknown"):
        _fail("allocation node list is absent")
    submit = _parse_timestamp(allocation["Submit"], "allocation.Submit")
    eligible = _parse_timestamp(allocation["Eligible"], "allocation.Eligible")
    start = _parse_timestamp(allocation["Start"], "allocation.Start")
    end = _parse_timestamp(allocation["End"], "allocation.End")
    if not submit <= eligible <= start <= end:
        _fail("allocation timestamps are not monotone")
    elapsed = _canonical_decimal(allocation["ElapsedRaw"], "allocation.ElapsedRaw")
    if elapsed != int((end - start).total_seconds()):
        _fail("allocation elapsed time differs from its timestamps")

    batch_nodes = _canonical_decimal(batch["NNodes"], "batch.NNodes", positive=True)
    batch_requested_cpus = _canonical_decimal(
        batch["ReqCPUS"], "batch.ReqCPUS", positive=True
    )
    batch_allocated_cpus = _canonical_decimal(
        batch["AllocCPUS"], "batch.AllocCPUS", positive=True
    )
    if (
        batch_nodes != nodes
        or batch_requested_cpus != requested_cpus
        or batch_allocated_cpus != allocated_cpus
        or batch["NodeList"] != allocation["NodeList"]
    ):
        _fail("batch resources or node list differ from the allocation")
    batch_tres = _parse_tres(batch["AllocTRES"], "batch.AllocTRES")
    if (
        _canonical_decimal(batch_tres.get("cpu", ""), "batch TRES cpu", positive=True)
        != batch_allocated_cpus
        or _canonical_decimal(
            batch_tres.get("node", ""), "batch TRES node", positive=True
        )
        != batch_nodes
        or _parse_memory(
            batch_tres.get("mem", ""),
            batch_allocated_cpus,
            batch_nodes,
            "batch TRES memory",
        )
        != slurm["requested_memory_bytes"]
    ):
        _fail("batch allocated TRES differ from the allocation")
    batch_submit = _parse_timestamp(batch["Submit"], "batch.Submit")
    batch_start = _parse_timestamp(batch["Start"], "batch.Start")
    batch_end = _parse_timestamp(batch["End"], "batch.End")
    if not submit <= batch_submit <= batch_start <= batch_end <= end:
        _fail("batch timestamps are not within the allocation interval")
    batch_elapsed = _canonical_decimal(batch["ElapsedRaw"], "batch.ElapsedRaw")
    if batch_elapsed != int((batch_end - batch_start).total_seconds()):
        _fail("batch elapsed time differs from its timestamps")

    required_control = (
        "JobId",
        "JobName",
        "UserId",
        "JobState",
        "ExitCode",
        "DerivedExitCode",
        "Requeue",
        "Restarts",
        "Partition",
        "NumNodes",
        "NumCPUs",
        "NumTasks",
        "CPUs/Task",
        "MinMemoryNode",
        "TimeLimit",
        "WorkDir",
        "StdOut",
        "StdErr",
        "Command",
        "BatchHost",
        "Comment",
        "Dependency",
    )
    missing = sorted(set(required_control) - set(control))
    if missing:
        _fail(f"scontrol record lacks required fields: {missing}")
    expected_control = {
        "JobId": str(slurm["compute_job_id"]),
        "JobName": slurm["compute_job_name"],
        "Comment": slurm["compute_comment"],
        "Dependency": "(null)",
        "JobState": "COMPLETED",
        "ExitCode": "0:0",
        "DerivedExitCode": "0:0",
        "Requeue": "0",
        "Restarts": "0",
        "Partition": slurm["partition"],
        "NumNodes": str(slurm["requested_nodes"]),
        "NumCPUs": str(slurm["requested_cpus"]),
        "NumTasks": "1",
        "CPUs/Task": "1",
        "TimeLimit": "01:00:00",
        "WorkDir": slurm["work_dir"],
        "StdOut": slurm["stdout_path"],
        "StdErr": slurm["stderr_path"],
        "Command": slurm["compute_script_path"],
        "BatchHost": allocation["NodeList"],
    }
    for field, expected in expected_control.items():
        if control[field] != expected:
            _fail(f"scontrol {field} differs from the submission or accounting record")
    if _scontrol_uid(control["UserId"], "scontrol.UserId") != slurm["owner_uid"]:
        _fail("scontrol owner differs from the submission")
    user_match = re.fullmatch(r"([^()]+)\(([0-9]+)\)", control["UserId"])
    if user_match is None or allocation["User"] != user_match.group(1):
        _fail("allocation user differs from scontrol identity")
    if _parse_memory(
        control["MinMemoryNode"],
        slurm["requested_cpus"],
        slurm["requested_nodes"],
        "scontrol.MinMemoryNode",
    ) != slurm["requested_memory_bytes"]:
        _fail("scontrol memory differs from the submission")
    return {
        "allocation": allocation,
        "batch": batch,
        "scontrol": {field: control[field] for field in sorted(required_control)},
        "commands": {
            "allocation": list(evidence.allocation_command),
            "batch": list(evidence.batch_command),
            "scontrol": list(evidence.scontrol_command),
        },
        "raw_sha256": {
            "allocation": evidence.allocation_sha256,
            "batch": evidence.batch_sha256,
            "scontrol": evidence.scontrol_sha256,
        },
    }


def _load_and_validate_candidate(
    root: Path, submission: Mapping[str, Any]
) -> tuple[
    dict[str, Any],
    FileRead,
    dict[str, Any],
    FileRead,
    str,
    list[dict[str, Any]],
    tuple[int, int],
]:
    root_mode, inventory, root_identity = inventory_run_root(root)
    index_records = [record for record in inventory if record["path"] == COMPUTE_INDEX_NAME]
    if len(index_records) != 1 or index_records[0]["kind"] != "file":
        _fail("sealed run root must contain one regular compute-index.json")
    index_read = _open_relative_file(
        root, COMPUTE_INDEX_NAME, "compute index", root_identity
    )
    if (
        index_read.sha256 != index_records[0]["sha256"]
        or index_read.size != index_records[0]["bytes"]
        or index_read.mode != index_records[0]["mode"]
    ):
        _fail("compute index changed after recursive inventory")
    index_json = decode_canonical_json(index_read.data, "compute index")
    index, semantic_path = validate_compute_index(
        index_json, submission, root_mode, inventory
    )
    semantic_read = _open_relative_file(
        root, semantic_path, "semantic candidate", root_identity
    )
    semantic_record = next(
        record
        for record in index["artifacts"]
        if record["path_rel"] == semantic_path
    )
    if (
        semantic_read.sha256 != semantic_record["sha256"]
        or semantic_read.size != semantic_record["size"]
        or semantic_read.mode != semantic_record["mode"]
    ):
        _fail("semantic candidate changed after recursive inventory")
    semantic_json = decode_canonical_json(semantic_read.data, "semantic candidate")
    semantic = validate_semantic_candidate(semantic_json, submission)
    if semantic["revision"] != index["revision"]:
        _fail("semantic-candidate revision differs from the compute index")
    if semantic_read.sha256 != index["validation_candidate_sha256"]:
        _fail("semantic-candidate digest differs from the compute index")
    return (
        index,
        index_read,
        semantic,
        semantic_read,
        root_mode,
        inventory,
        root_identity,
    )


def build_scheduler_candidate_payload(
    submission_path: Path,
    candidate_root: Path,
    *,
    command_runner: CommandRunner = _default_command_runner,
    sacct_bin: str = "/usr/bin/sacct",
    scontrol_bin: str = "/usr/bin/scontrol",
    poll_attempts: int = 1,
    poll_interval_seconds: float = 0.0,
    sleeper: Sleeper = time.sleep,
    submission_sha256: str | None = None,
) -> dict[str, Any]:
    _canonical_absolute_path(os.fspath(submission_path), "submission path")
    if submission_path.resolve(strict=True) != submission_path:
        _fail("submission path must contain no symbolic-link components")
    submission_json, submission_read = load_canonical_json(submission_path, "submission record")
    if submission_sha256 is not None:
        expected_submission_sha256 = _sha256(
            submission_sha256, "expected submission SHA-256"
        )
        if submission_read.sha256 != expected_submission_sha256:
            _fail("submission record digest differs from the sealed bootstrap binding")
    submission = validate_submission(submission_json)
    compute_held, compute_held_read = _validate_held_scheduler_record(
        submission, "compute"
    )
    finalizer_held, finalizer_held_read = _validate_held_scheduler_record(
        submission, "finalizer"
    )
    _canonical_absolute_path(os.fspath(candidate_root), "candidate-root argument")
    try:
        candidate_root_metadata = candidate_root.lstat()
    except OSError as error:
        _fail(f"cannot inspect candidate-root argument: {error}")
    if stat.S_ISLNK(candidate_root_metadata.st_mode):
        _fail("candidate-root argument must not be a symbolic link")
    canonical_root = candidate_root.resolve(strict=True)
    if os.fspath(canonical_root) != submission["candidate_root"]:
        _fail("candidate-root path differs from the submission")
    (
        index,
        index_read,
        semantic,
        semantic_read,
        root_mode,
        inventory,
        root_identity,
    ) = _load_and_validate_candidate(canonical_root, submission)
    if poll_attempts <= 0 or poll_interval_seconds < 0:
        _fail("scheduler polling parameters are invalid")
    evidence: SchedulerEvidence | None = None
    last_pending: SchedulerPending | None = None
    for attempt in range(poll_attempts):
        try:
            evidence = collect_scheduler_evidence(
                submission,
                command_runner,
                sacct_bin=sacct_bin,
                scontrol_bin=scontrol_bin,
            )
            break
        except SchedulerPending as error:
            last_pending = error
            if attempt + 1 < poll_attempts:
                sleeper(poll_interval_seconds)
    if evidence is None:
        raise last_pending or SchedulerPending("scheduler accounting is unavailable")
    scheduler = _require_scheduler_record(evidence, submission)
    if index["attempt"]["hostname"] != scheduler["scontrol"]["BatchHost"]:
        _fail("compute-index hostname differs from the scheduler batch host")
    final_root_mode, final_inventory, final_root_identity = inventory_run_root(
        canonical_root
    )
    if (
        final_root_identity != root_identity
        or final_root_mode != root_mode
        or final_inventory != inventory
    ):
        _fail("sealed candidate root changed while scheduler evidence was collected")
    submission_after = _stable_read_path(
        submission_path, MAX_JSON_BYTES, "submission record"
    )
    if (
        (submission_after.device, submission_after.inode)
        != (submission_read.device, submission_read.inode)
        or submission_after.mode != submission_read.mode
        or submission_after.sha256 != submission_read.sha256
        or submission_after.data != submission_read.data
    ):
        _fail("submission record changed while scheduler evidence was collected")
    compute_held_after, compute_held_read_after = _validate_held_scheduler_record(
        submission, "compute"
    )
    finalizer_held_after, finalizer_held_read_after = _validate_held_scheduler_record(
        submission, "finalizer"
    )
    for role, before_record, before_read, after_record, after_read in (
        (
            "compute",
            compute_held,
            compute_held_read,
            compute_held_after,
            compute_held_read_after,
        ),
        (
            "finalizer",
            finalizer_held,
            finalizer_held_read,
            finalizer_held_after,
            finalizer_held_read_after,
        ),
    ):
        if (
            before_record != after_record
            or (before_read.device, before_read.inode, before_read.mode, before_read.sha256)
            != (after_read.device, after_read.inode, after_read.mode, after_read.sha256)
        ):
            _fail(f"{role} held scheduler evidence changed during validation")
    attempt_identity = {
        "run_nonce": submission["run_nonce"],
        "cluster": submission["slurm"]["cluster"],
        "compute_job_id": submission["slurm"]["compute_job_id"],
        "finalizer_job_id": submission["slurm"]["finalizer_job_id"],
        "submission_sha256": submission_read.sha256,
        "compute_index_sha256": index_read.sha256,
        "semantic_candidate_sha256": semantic_read.sha256,
        "scheduler_raw_sha256": scheduler["raw_sha256"],
        "compute_held_sha256": compute_held_read.sha256,
        "finalizer_held_sha256": finalizer_held_read.sha256,
    }
    attempt_id = hashlib.sha256(canonical_json_bytes(attempt_identity)).hexdigest()
    payload = {
        "artifacts": inventory,
        "attempt_id": attempt_id,
        "candidate": {
            "compute_index_sha256": index_read.sha256,
            "compute_attempt": index["attempt"],
            "root_mode": root_mode,
            "semantic_candidate_sha256": semantic_read.sha256,
            "semantic_status": semantic["status"],
        },
        "classification": "scientific_candidate",
        "control": submission["control"],
        "decision": TERMINAL_ATTESTATION_DECISION,
        "launch_manifest_sha256": submission["launch_manifest_sha256"],
        "policy": {"sat_calls": 0},
        "revision": index["revision"],
        "run_nonce": submission["run_nonce"],
        "scheduler": scheduler,
        "submission_evidence": {
            "compute_held_sha256": compute_held_read.sha256,
            "finalizer_held_sha256": finalizer_held_read.sha256,
            "owner_uid": submission["slurm"]["owner_uid"],
            "compute_sbatch_argv": submission["slurm"]["compute_sbatch_argv"],
            "finalizer_sbatch_argv": submission["slurm"]["finalizer_sbatch_argv"],
        },
        "schema": SCHEDULER_CANDIDATE_SCHEMA,
        "stage0b_authority": False,
        "status": "scheduler_validated_candidate",
        "submission": {
            "bytes": submission_read.size,
            "mode": submission_read.mode,
            "path": os.fspath(submission_path),
            "sha256": submission_read.sha256,
        },
    }
    canonical_json_bytes(payload)
    return payload


def _ensure_destination_fresh(path: Path) -> tuple[Path, str]:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        _fail("final output path must be an absolute file path")
    parent = path.parent.resolve(strict=True)
    if os.fspath(parent) != os.fspath(path.parent):
        _fail("final output parent must be canonical and contain no symbolic links")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        _fail(f"cannot inspect final output path: {error}")
    else:
        _fail("final output path must be fresh")
    return parent, path.name


def publish_scheduler_candidate(path: Path, payload: Mapping[str, Any]) -> None:
    parent, name = _ensure_destination_fresh(path)
    if (
        payload.get("schema") != SCHEDULER_CANDIDATE_SCHEMA
        or payload.get("decision") != TERMINAL_ATTESTATION_DECISION
        or payload.get("stage0b_authority") is not False
    ):
        _fail("only a non-authorizing scheduler candidate may be published")
    if not sys.platform.startswith("linux") or not hasattr(os, "O_TMPFILE"):
        _fail("final publication requires Linux O_TMPFILE support")
    encoded = canonical_json_bytes(payload)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(parent, directory_flags)
    try:
        parent_before = os.fstat(directory_fd)
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("final output path ceased to be fresh")
        descriptor = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    _fail("short final-payload write")
                offset += written
            os.fsync(descriptor)
            if os.pread(descriptor, len(encoded) + 1, 0) != encoded:
                _fail("staged final payload differs from the intended bytes")
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            staged = os.fstat(descriptor)
            if (
                not stat.S_ISREG(staged.st_mode)
                or staged.st_nlink != 0
                or staged.st_size != len(encoded)
                or stat.S_IMODE(staged.st_mode) != 0o400
            ):
                _fail("anonymous final-payload inode violates the publication contract")
            proc_path = f"/proc/self/fd/{descriptor}"
            proc_metadata = os.stat(proc_path)
            if (staged.st_dev, staged.st_ino) != (proc_metadata.st_dev, proc_metadata.st_ino):
                _fail("final-payload proc descriptor does not bind the staging inode")
            try:
                os.link(
                    proc_path,
                    name,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=True,
                )
            except FileExistsError:
                _fail("final output path ceased to be fresh")
            os.close(descriptor)
            descriptor = -1
            os.fsync(directory_fd)
            final_descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            try:
                final = os.fstat(final_descriptor)
                if (
                    not stat.S_ISREG(final.st_mode)
                    or (final.st_dev, final.st_ino) != (staged.st_dev, staged.st_ino)
                    or final.st_nlink != 1
                    or final.st_size != len(encoded)
                    or stat.S_IMODE(final.st_mode) != 0o400
                    or os.pread(final_descriptor, len(encoded) + 1, 0) != encoded
                ):
                    _fail("published final payload differs from the staging inode")
            finally:
                os.close(final_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        parent_after = os.fstat(directory_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (
            parent_after.st_dev,
            parent_after.st_ino,
        ):
            _fail("final output parent identity changed during publication")
    finally:
        os.close(directory_fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--submission-sha256", required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--poll-attempts", type=int, default=12)
    parser.add_argument("--poll-interval-seconds", type=float, default=5.0)
    parser.add_argument("--sacct-bin", default="/usr/bin/sacct")
    parser.add_argument("--scontrol-bin", default="/usr/bin/scontrol")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = build_scheduler_candidate_payload(
            args.submission,
            args.candidate_root,
            sacct_bin=args.sacct_bin,
            scontrol_bin=args.scontrol_bin,
            poll_attempts=args.poll_attempts,
            poll_interval_seconds=args.poll_interval_seconds,
            submission_sha256=args.submission_sha256,
        )
        publish_scheduler_candidate(args.output, payload)
        print(
            canonical_json_bytes(
                {
                    "attempt_id": payload["attempt_id"],
                    "output": os.fspath(args.output),
                    "output_sha256": hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
                    "status": "scheduler_validated_candidate",
                }
            ).decode("ascii"),
            end="",
        )
        return 0
    except (FinalizationError, OSError) as error:
        print(f"T11 Stage 0A scheduler validation rejected: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
