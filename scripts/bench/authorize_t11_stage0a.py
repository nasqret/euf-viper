#!/usr/bin/env python3
"""Authorize T11 Stage 0B after the Stage 0A finalizer is terminal."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import types
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence


SUBMISSION_SCHEMA = "euf-viper.t11-stage0a-submission.v2"
SCHEDULER_CANDIDATE_SCHEMA = "euf-viper.t11-stage0a-scheduler-candidate.v1"
AUTHORIZATION_SCHEMA = "euf-viper.t11-stage0a-authorization.v1"
TERMINAL_ATTESTATION_DECISION = "requires_finalizer_terminal_attestation"
AUTHORIZATION_DECISION = "authorize_stage0b"

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
MODE_RE = re.compile(r"0[0-7]{3}\Z")
MEMORY_RE = re.compile(r"([1-9][0-9]*)([KMGTPE]?)([cn]?)\Z")
TRES_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_/.:-]*\Z")
SCONTROL_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_/:]*\Z")

MAX_JSON_BYTES = 256 * 1024 * 1024
MAX_COMMAND_BYTES = 16 * 1024 * 1024
MAX_MODULE_BYTES = 16 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024

COMPUTE_ALLOCATION_FIELDS = (
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
COMPUTE_BATCH_FIELDS = (
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
FINALIZER_ALLOCATION_FIELDS = (
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
FINALIZER_BATCH_FIELDS = (
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
COMPUTE_SCONTROL_FIELDS = (
    "BatchHost",
    "CPUs/Task",
    "Comment",
    "Command",
    "Dependency",
    "DerivedExitCode",
    "ExitCode",
    "JobId",
    "JobName",
    "JobState",
    "MinMemoryNode",
    "NumCPUs",
    "NumNodes",
    "NumTasks",
    "Partition",
    "Requeue",
    "Restarts",
    "StdErr",
    "StdOut",
    "TimeLimit",
    "UserId",
    "WorkDir",
)


class AuthorizationError(RuntimeError):
    """The scheduler candidate is not eligible to authorize Stage 0B."""


class SchedulerPending(AuthorizationError):
    """Slurm accounting has not exposed a complete finalizer record yet."""


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
    links: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class BoundInput:
    path: Path
    context: str
    maximum_bytes: int
    require_nonwritable: bool
    require_executable: bool
    initial: FileRead


@dataclass(frozen=True)
class FinalizerEvidence:
    allocation: Mapping[str, str]
    batch: Mapping[str, str]
    allocation_command: tuple[str, ...]
    batch_command: tuple[str, ...]
    allocation_sha256: str
    batch_sha256: str


@dataclass(frozen=True)
class PreparedAuthorization:
    payload: Mapping[str, Any]
    output_path: Path
    inputs: tuple[BoundInput, ...]
    revalidate_candidate_root: Callable[[], None]


CommandRunner = Callable[[Sequence[str]], CommandOutput]
Sleeper = Callable[[float], None]


def _fail(message: str) -> None:
    raise AuthorizationError(message)


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
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        _fail(f"cannot encode canonical JSON: {error}")
    return (encoded + "\n").encode("ascii")


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
    except (json.JSONDecodeError, AuthorizationError) as error:
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
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        _fail(f"{context} must be nonempty single-line text")
    return value


def _nonnegative_int(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{context} must be a nonnegative integer")
    return value


def _positive_int(value: object, context: str) -> int:
    result = _nonnegative_int(value, context)
    if result == 0:
        _fail(f"{context} must be positive")
    return result


def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail(f"{context} must be 64 lowercase hexadecimal digits")
    return value


def _mode(value: object, context: str, *, nonwritable: bool = True) -> str:
    if not isinstance(value, str) or MODE_RE.fullmatch(value) is None:
        _fail(f"{context} must be a four-digit octal mode")
    if nonwritable and int(value, 8) & 0o222:
        _fail(f"{context} must not contain write bits")
    return value


def _canonical_absolute_path(value: object, context: str) -> Path:
    raw = _text(value, context)
    path = Path(raw)
    if not path.is_absolute() or os.path.normpath(raw) != raw:
        _fail(f"{context} must be a canonical absolute path")
    return path


def _relative_path(value: object, context: str) -> str:
    raw = _text(value, context)
    try:
        raw.encode("ascii")
    except UnicodeEncodeError:
        _fail(f"{context} must be ASCII")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or path.as_posix() != raw
        or any(part in ("", ".", "..") for part in path.parts)
        or "\\" in raw
    ):
        _fail(f"{context} must be a canonical relative POSIX path")
    return raw


def _metadata_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_read_path(
    path: Path,
    maximum_bytes: int,
    context: str,
    *,
    require_nonwritable: bool,
    require_executable: bool = False,
) -> FileRead:
    if not path.is_absolute() or os.path.normpath(os.fspath(path)) != os.fspath(path):
        _fail(f"{context} path must be canonical and absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        _fail(f"cannot resolve {context}: {error}")
    if resolved != path:
        _fail(f"{context} path must contain no symbolic-link components")
    try:
        named_before = path.lstat()
    except OSError as error:
        _fail(f"cannot inspect {context}: {error}")
    if stat.S_ISLNK(named_before.st_mode):
        _fail(f"{context} must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        _fail(f"cannot open {context}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"{context} is not a regular file")
        if before.st_nlink != 1:
            _fail(f"{context} has a hardlink alias")
        permissions = stat.S_IMODE(before.st_mode)
        if require_nonwritable and permissions & 0o222:
            _fail(f"{context} is writable")
        if require_executable and not permissions & 0o111:
            _fail(f"{context} is not executable")
        if before.st_size < 0 or before.st_size > maximum_bytes:
            _fail(f"{context} size is outside its bound")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            if not chunk:
                _fail(f"{context} was truncated while reading")
            chunks.append(chunk)
            digest.update(chunk)
            offset += len(chunk)
        if os.pread(descriptor, 1, offset):
            _fail(f"{context} grew while reading")
        after = os.fstat(descriptor)
        if _metadata_tuple(before) != _metadata_tuple(after):
            _fail(f"{context} changed while reading")
    finally:
        os.close(descriptor)
    try:
        named_after = path.lstat()
    except OSError as error:
        _fail(f"cannot re-inspect {context}: {error}")
    if _metadata_tuple(named_before) != _metadata_tuple(named_after):
        _fail(f"{context} pathname identity changed while reading")
    return FileRead(
        data=b"".join(chunks),
        mode=f"{stat.S_IMODE(before.st_mode):04o}",
        size=before.st_size,
        sha256=digest.hexdigest(),
        device=before.st_dev,
        inode=before.st_ino,
        links=before.st_nlink,
        mtime_ns=before.st_mtime_ns,
        ctime_ns=before.st_ctime_ns,
    )


def _bind_input(
    path: Path,
    maximum_bytes: int,
    context: str,
    *,
    require_nonwritable: bool,
    require_executable: bool = False,
) -> BoundInput:
    return BoundInput(
        path=path,
        context=context,
        maximum_bytes=maximum_bytes,
        require_nonwritable=require_nonwritable,
        require_executable=require_executable,
        initial=_stable_read_path(
            path,
            maximum_bytes,
            context,
            require_nonwritable=require_nonwritable,
            require_executable=require_executable,
        ),
    )


def _same_read(left: FileRead, right: FileRead) -> bool:
    return left == right


def _revalidate_inputs(inputs: Sequence[BoundInput]) -> None:
    for binding in inputs:
        current = _stable_read_path(
            binding.path,
            binding.maximum_bytes,
            binding.context,
            require_nonwritable=binding.require_nonwritable,
            require_executable=binding.require_executable,
        )
        if not _same_read(binding.initial, current):
            _fail(f"{binding.context} changed during authorization")


def _load_finalizer_module(
    path: Path, expected_sha256: str
) -> tuple[types.ModuleType, BoundInput]:
    expected = _sha256(expected_sha256, "finalizer module SHA-256")
    binding = _bind_input(
        path,
        MAX_MODULE_BYTES,
        "finalizer module",
        require_nonwritable=True,
    )
    if binding.initial.sha256 != expected:
        _fail("finalizer module SHA-256 differs from the caller binding")
    module_name = f"_t11_stage0a_finalizer_{expected}_{id(binding)}"
    module = types.ModuleType(module_name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        code = compile(binding.initial.data, os.fspath(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException as error:
        sys.modules.pop(module_name, None)
        _fail(f"cannot load the bound finalizer module: {error}")
    required_values = {
        "SUBMISSION_SCHEMA": SUBMISSION_SCHEMA,
        "SCHEDULER_CANDIDATE_SCHEMA": SCHEDULER_CANDIDATE_SCHEMA,
        "TERMINAL_ATTESTATION_DECISION": TERMINAL_ATTESTATION_DECISION,
    }
    for name, expected_value in required_values.items():
        if getattr(module, name, None) != expected_value:
            _fail(f"bound finalizer module has an incompatible {name}")
    for name in (
        "ALLOCATION_FIELDS",
        "BATCH_FIELDS",
        "FinalizationError",
        "SchedulerEvidence",
        "validate_submission",
        "_require_scheduler_record",
    ):
        if not hasattr(module, name):
            _fail(f"bound finalizer module lacks required interface {name}")
    if tuple(module.ALLOCATION_FIELDS) != COMPUTE_ALLOCATION_FIELDS:
        _fail("bound finalizer allocation fields differ from the authorizer contract")
    if tuple(module.BATCH_FIELDS) != COMPUTE_BATCH_FIELDS:
        _fail("bound finalizer batch fields differ from the authorizer contract")
    return module, binding


def _validate_submission_with_module(
    module: types.ModuleType, value: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        validated = module.validate_submission(dict(value))
    except module.FinalizationError as error:
        _fail(f"submission record is invalid: {error}")
    except Exception as error:
        _fail(f"bound finalizer rejected the submission unexpectedly: {error}")
    if not isinstance(validated, dict):
        _fail("bound finalizer returned a non-object submission")
    if validated.get("schema") != SUBMISSION_SCHEMA:
        _fail("validated submission schema differs")
    return validated


def _parse_scontrol_record(data: bytes, context: str) -> dict[str, str]:
    if not data or len(data) > MAX_COMMAND_BYTES or b"\r" in data:
        _fail(f"{context} bytes are malformed")
    try:
        text = data.decode("ascii").strip(" \n")
    except UnicodeDecodeError:
        _fail(f"{context} is not ASCII")
    if not text or "\n" in text:
        _fail(f"{context} must contain exactly one record")
    result: dict[str, str] = {}
    for token in text.split(" "):
        if not token or "=" not in token:
            _fail(f"{context} contains a malformed field")
        key, raw = token.split("=", 1)
        if SCONTROL_KEY_RE.fullmatch(key) is None or key in result:
            _fail(f"{context} contains a malformed or duplicate key")
        result[key] = raw
    return result


def _validate_held_record(
    submission: Mapping[str, Any], role: str
) -> tuple[dict[str, str], BoundInput]:
    if role not in ("compute", "finalizer"):
        _fail("internal held-record role is invalid")
    slurm = submission["slurm"]
    record_binding = slurm[f"{role}_held_record"]
    path = _canonical_absolute_path(record_binding["path"], f"{role} held-record path")
    bound = _bind_input(
        path,
        MAX_COMMAND_BYTES,
        f"{role} held scheduler record",
        require_nonwritable=True,
    )
    if bound.initial.sha256 != record_binding["sha256"]:
        _fail(f"{role} held scheduler record SHA-256 differs from the submission")
    record = _parse_scontrol_record(bound.initial.data, f"{role} held scheduler record")
    if role == "compute":
        expected = {
            "JobId": str(slurm["compute_job_id"]),
            "JobName": slurm["compute_job_name"],
            "Comment": slurm["compute_comment"],
            "Command": slurm["compute_script_path"],
            "WorkDir": slurm["work_dir"],
            "StdOut": slurm["stdout_path"],
            "StdErr": slurm["stderr_path"],
            "Dependency": "(null)",
        }
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
    expected.update({"JobState": "PENDING", "Reason": "JobHeldUser", "Requeue": "0"})
    for field, expected_value in expected.items():
        if record.get(field) != expected_value:
            _fail(f"{role} held scheduler record {field} differs from the submission")
    if role == "finalizer" and record.get("Dependency") not in (
        slurm["finalizer_dependency"],
        f"{slurm['finalizer_dependency']}(unfulfilled)",
    ):
        _fail("finalizer held scheduler dependency differs from the submission")
    user_match = re.fullmatch(r"[^()]+\(([0-9]+)\)", record.get("UserId", ""))
    if user_match is None or int(user_match.group(1)) != slurm["owner_uid"]:
        _fail(f"{role} held scheduler owner differs from the submission")
    return record, bound


def _string_mapping(value: object, fields: Sequence[str], context: str) -> dict[str, str]:
    record = _exact_keys(value, fields, context)
    result: dict[str, str] = {}
    for field in fields:
        raw = record[field]
        if not isinstance(raw, str) or "\x00" in raw or "\n" in raw or "\r" in raw:
            _fail(f"{context}.{field} must be single-line text")
        result[field] = raw
    return result


def _string_array(value: object, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{context} must be a nonempty string array")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_text(item, f"{context}[{index}]"))
    return result


def _validate_artifacts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _fail("scheduler candidate artifacts must be a nonempty array")
    records: list[dict[str, Any]] = []
    paths: list[str] = []
    for index, item in enumerate(value):
        context = f"scheduler candidate artifacts[{index}]"
        if not isinstance(item, dict) or item.get("kind") not in ("directory", "file"):
            _fail(f"{context} has an invalid kind")
        if item["kind"] == "directory":
            record = _exact_keys(item, ("kind", "mode", "path"), context)
        else:
            record = _exact_keys(item, ("bytes", "kind", "mode", "path", "sha256"), context)
            record["bytes"] = _nonnegative_int(record["bytes"], f"{context}.bytes")
            if record["bytes"] > MAX_ARTIFACT_BYTES:
                _fail(f"{context}.bytes exceeds the artifact bound")
            record["sha256"] = _sha256(record["sha256"], f"{context}.sha256")
        record["mode"] = _mode(record["mode"], f"{context}.mode")
        record["path"] = _relative_path(record["path"], f"{context}.path")
        records.append(record)
        paths.append(record["path"])
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        _fail("scheduler candidate artifact paths must be unique and sorted")
    return records


def _contains_authorization(value: object) -> bool:
    if isinstance(value, str):
        return value == AUTHORIZATION_DECISION
    if isinstance(value, list):
        return any(_contains_authorization(item) for item in value)
    if isinstance(value, dict):
        return any(
            key == AUTHORIZATION_DECISION or _contains_authorization(item)
            for key, item in value.items()
        )
    return False


def _validate_compute_attempt(value: object, submission: Mapping[str, Any]) -> dict[str, Any]:
    attempt = _exact_keys(
        value,
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
        "scheduler candidate compute attempt",
    )
    slurm = submission["slurm"]
    expected = {
        "run_nonce": submission["run_nonce"],
        "cluster": slurm["cluster"],
        "job_id": slurm["compute_job_id"],
        "array_job_id": None,
        "array_task_id": None,
        "step_id": "batch",
        "restart_count": 0,
        "submit_dir": slurm["work_dir"],
    }
    for field, expected_value in expected.items():
        if attempt[field] != expected_value:
            _fail(f"scheduler candidate compute attempt {field} differs from the submission")
    attempt["hostname"] = _text(
        attempt["hostname"], "scheduler candidate compute attempt hostname"
    )
    return attempt


def _validate_compute_scheduler(
    value: object,
    submission: Mapping[str, Any],
    module: types.ModuleType,
) -> dict[str, Any]:
    scheduler = _exact_keys(
        value,
        ("allocation", "batch", "scontrol", "commands", "raw_sha256"),
        "scheduler candidate scheduler evidence",
    )
    allocation = _string_mapping(
        scheduler["allocation"], COMPUTE_ALLOCATION_FIELDS, "compute allocation evidence"
    )
    batch = _string_mapping(
        scheduler["batch"], COMPUTE_BATCH_FIELDS, "compute batch evidence"
    )
    scontrol = _string_mapping(
        scheduler["scontrol"], COMPUTE_SCONTROL_FIELDS, "compute scontrol evidence"
    )
    commands = _exact_keys(
        scheduler["commands"], ("allocation", "batch", "scontrol"), "compute commands"
    )
    allocation_command = _string_array(commands["allocation"], "compute allocation command")
    batch_command = _string_array(commands["batch"], "compute batch command")
    scontrol_command = _string_array(commands["scontrol"], "compute scontrol command")
    raw_sha256 = _exact_keys(
        scheduler["raw_sha256"], ("allocation", "batch", "scontrol"), "compute raw hashes"
    )
    raw_sha256 = {
        field: _sha256(raw_sha256[field], f"compute raw hashes.{field}")
        for field in ("allocation", "batch", "scontrol")
    }
    slurm = submission["slurm"]
    job_id = str(slurm["compute_job_id"])
    expected_allocation_arguments = [
        "--clusters",
        slurm["cluster"],
        "--noheader",
        "--parsable2",
        "--duplicates",
        "--allocations",
        "--jobs",
        job_id,
        "--format=" + ",".join(COMPUTE_ALLOCATION_FIELDS),
    ]
    expected_batch_arguments = [
        "--clusters",
        slurm["cluster"],
        "--noheader",
        "--parsable2",
        "--duplicates",
        "--jobs",
        f"{job_id}.batch",
        "--format=" + ",".join(COMPUTE_BATCH_FIELDS),
    ]
    proc_fd = re.compile(r"/proc/self/fd/[0-9]+\Z")
    if (
        len(allocation_command) != len(expected_allocation_arguments) + 1
        or proc_fd.fullmatch(allocation_command[0]) is None
        or allocation_command[1:] != expected_allocation_arguments
    ):
        _fail("scheduler candidate compute allocation command differs")
    if (
        len(batch_command) != len(expected_batch_arguments) + 1
        or batch_command[0] != allocation_command[0]
        or batch_command[1:] != expected_batch_arguments
    ):
        _fail("scheduler candidate compute batch command differs")
    if (
        len(scontrol_command) != 5
        or proc_fd.fullmatch(scontrol_command[0]) is None
        or scontrol_command[0] == allocation_command[0]
        or scontrol_command[1:] != ["show", "job", "-o", job_id]
    ):
        _fail("scheduler candidate compute scontrol command differs")
    try:
        evidence = module.SchedulerEvidence(
            allocation=allocation,
            batch=batch,
            scontrol=scontrol,
            allocation_command=tuple(allocation_command),
            batch_command=tuple(batch_command),
            scontrol_command=tuple(scontrol_command),
            allocation_sha256=raw_sha256["allocation"],
            batch_sha256=raw_sha256["batch"],
            scontrol_sha256=raw_sha256["scontrol"],
        )
        normalized = module._require_scheduler_record(evidence, submission)
    except module.FinalizationError as error:
        _fail(f"scheduler candidate compute evidence is invalid: {error}")
    except Exception as error:
        _fail(f"cannot validate scheduler candidate compute evidence: {error}")
    expected_scheduler = {
        "allocation": allocation,
        "batch": batch,
        "scontrol": scontrol,
        "commands": {
            "allocation": allocation_command,
            "batch": batch_command,
            "scontrol": scontrol_command,
        },
        "raw_sha256": raw_sha256,
    }
    if normalized != expected_scheduler:
        _fail("scheduler candidate compute evidence is not in normalized exact form")
    return expected_scheduler


def validate_scheduler_candidate(
    value: object,
    *,
    candidate_read: FileRead,
    candidate_path: Path,
    submission: Mapping[str, Any],
    submission_read: FileRead,
    submission_path: Path,
    compute_held_read: FileRead,
    finalizer_held_read: FileRead,
    module: types.ModuleType,
) -> dict[str, Any]:
    candidate = _exact_keys(
        value,
        (
            "artifacts",
            "attempt_id",
            "candidate",
            "classification",
            "control",
            "decision",
            "launch_manifest_sha256",
            "policy",
            "revision",
            "run_nonce",
            "scheduler",
            "submission_evidence",
            "schema",
            "stage0b_authority",
            "status",
            "submission",
        ),
        "scheduler candidate",
    )
    if _contains_authorization(candidate):
        _fail("scheduler candidate contains a forbidden authorization decision")
    if candidate["schema"] != SCHEDULER_CANDIDATE_SCHEMA:
        _fail("scheduler candidate schema differs")
    if candidate["status"] != "scheduler_validated_candidate":
        _fail("scheduler candidate status differs")
    if candidate["decision"] != TERMINAL_ATTESTATION_DECISION:
        _fail("scheduler candidate decision differs")
    if type(candidate["stage0b_authority"]) is not bool or candidate["stage0b_authority"]:
        _fail("scheduler candidate must explicitly deny Stage 0B authority")
    if candidate["classification"] != "scientific_candidate":
        _fail("scheduler candidate classification differs")
    if candidate["policy"] != {"sat_calls": 0}:
        _fail("scheduler candidate policy differs")
    if candidate["run_nonce"] != submission["run_nonce"]:
        _fail("scheduler candidate run nonce differs from the submission")
    revision = candidate["revision"]
    if not isinstance(revision, str) or REVISION_RE.fullmatch(revision) is None:
        _fail("scheduler candidate revision is malformed")
    if revision != submission["revision"]:
        _fail("scheduler candidate revision differs from the submission")
    if candidate["launch_manifest_sha256"] != submission["launch_manifest_sha256"]:
        _fail("scheduler candidate launch-manifest digest differs from the submission")
    if candidate["control"] != submission["control"]:
        _fail("scheduler candidate control bindings differ from the submission")

    artifacts = _validate_artifacts(candidate["artifacts"])
    candidate_record = _exact_keys(
        candidate["candidate"],
        (
            "compute_index_sha256",
            "compute_attempt",
            "root_mode",
            "semantic_candidate_sha256",
            "semantic_status",
        ),
        "scheduler candidate candidate record",
    )
    candidate_record["compute_index_sha256"] = _sha256(
        candidate_record["compute_index_sha256"], "scheduler candidate compute-index digest"
    )
    candidate_record["semantic_candidate_sha256"] = _sha256(
        candidate_record["semantic_candidate_sha256"],
        "scheduler candidate semantic-candidate digest",
    )
    candidate_record["root_mode"] = _mode(
        candidate_record["root_mode"], "scheduler candidate root mode"
    )
    if candidate_record["semantic_status"] != "validated_candidate":
        _fail("scheduler candidate semantic status differs")
    compute_attempt = _validate_compute_attempt(candidate_record["compute_attempt"], submission)
    candidate_record["compute_attempt"] = compute_attempt
    index_records = [
        record
        for record in artifacts
        if record["kind"] == "file" and record["path"] == "compute-index.json"
    ]
    if len(index_records) != 1:
        _fail("scheduler candidate must bind one compute-index.json artifact")
    if index_records[0]["sha256"] != candidate_record["compute_index_sha256"]:
        _fail("scheduler candidate compute-index hashes differ")

    scheduler = _validate_compute_scheduler(candidate["scheduler"], submission, module)
    if compute_attempt["hostname"] != scheduler["scontrol"]["BatchHost"]:
        _fail("scheduler candidate compute hostname differs from its scheduler evidence")

    evidence = _exact_keys(
        candidate["submission_evidence"],
        (
            "compute_held_sha256",
            "finalizer_held_sha256",
            "owner_uid",
            "compute_sbatch_argv",
            "finalizer_sbatch_argv",
        ),
        "scheduler candidate submission evidence",
    )
    if evidence["compute_held_sha256"] != compute_held_read.sha256:
        _fail("scheduler candidate compute held-evidence digest differs")
    if evidence["finalizer_held_sha256"] != finalizer_held_read.sha256:
        _fail("scheduler candidate finalizer held-evidence digest differs")
    if evidence["owner_uid"] != submission["slurm"]["owner_uid"]:
        _fail("scheduler candidate owner UID differs")
    if evidence["compute_sbatch_argv"] != submission["slurm"]["compute_sbatch_argv"]:
        _fail("scheduler candidate compute sbatch argv differs")
    if evidence["finalizer_sbatch_argv"] != submission["slurm"]["finalizer_sbatch_argv"]:
        _fail("scheduler candidate finalizer sbatch argv differs")

    submission_record = _exact_keys(
        candidate["submission"],
        ("bytes", "mode", "path", "sha256"),
        "scheduler candidate submission record",
    )
    if (
        _positive_int(submission_record["bytes"], "scheduler candidate submission bytes")
        != submission_read.size
    ):
        _fail("scheduler candidate submission byte count differs")
    if (
        _mode(submission_record["mode"], "scheduler candidate submission mode")
        != submission_read.mode
    ):
        _fail("scheduler candidate submission mode differs")
    if submission_record["path"] != os.fspath(submission_path):
        _fail("scheduler candidate submission path differs")
    if submission_record["sha256"] != submission_read.sha256:
        _fail("scheduler candidate submission SHA-256 differs")
    if os.fspath(candidate_path) != submission["scheduler_candidate_path"]:
        _fail("scheduler-candidate input path differs from the submission")

    attempt_identity = {
        "run_nonce": submission["run_nonce"],
        "cluster": submission["slurm"]["cluster"],
        "compute_job_id": submission["slurm"]["compute_job_id"],
        "finalizer_job_id": submission["slurm"]["finalizer_job_id"],
        "submission_sha256": submission_read.sha256,
        "compute_index_sha256": candidate_record["compute_index_sha256"],
        "semantic_candidate_sha256": candidate_record["semantic_candidate_sha256"],
        "scheduler_raw_sha256": scheduler["raw_sha256"],
        "compute_held_sha256": compute_held_read.sha256,
        "finalizer_held_sha256": finalizer_held_read.sha256,
    }
    expected_attempt_id = hashlib.sha256(canonical_json_bytes(attempt_identity)).hexdigest()
    if candidate["attempt_id"] != expected_attempt_id:
        _fail("scheduler candidate attempt ID differs from its bound evidence")
    _sha256(candidate_read.sha256, "scheduler candidate SHA-256")
    candidate.update(
        {
            "artifacts": artifacts,
            "candidate": candidate_record,
            "scheduler": scheduler,
            "submission_evidence": evidence,
            "submission": submission_record,
        }
    )
    return candidate


def _default_command_runner(argv: Sequence[str]) -> CommandOutput:
    if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
        _fail("scheduler execution requires Linux sealed memfd support")
    source = _stable_read_path(
        Path(argv[0]),
        MAX_EXECUTABLE_BYTES,
        "scheduler executable",
        require_nonwritable=False,
        require_executable=True,
    )
    flags = getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(
        os, "MFD_ALLOW_SEALING", 0x0002
    )
    descriptor = os.memfd_create("t11-authorizer-scheduler", flags)
    try:
        offset = 0
        while offset < len(source.data):
            written = os.write(descriptor, source.data[offset:])
            if written <= 0:
                _fail("short scheduler executable snapshot write")
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
            _fail("scheduler executable memfd lacks mandatory seals")
        completed = subprocess.run(
            list(argv),
            executable=f"/proc/self/fd/{descriptor}",
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            pass_fds=(descriptor,),
            timeout=30,
        )
    finally:
        os.close(descriptor)
    current = _stable_read_path(
        Path(argv[0]),
        MAX_EXECUTABLE_BYTES,
        "scheduler executable",
        require_nonwritable=False,
        require_executable=True,
    )
    if current != source:
        _fail("scheduler executable changed during sealed execution")
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


def _parse_sacct_row(
    raw: bytes, fields: Sequence[str], expected_id: str, context: str
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


def collect_finalizer_evidence(
    submission: Mapping[str, Any],
    runner: CommandRunner = _default_command_runner,
    *,
    sacct_bin: str = "/usr/bin/sacct",
) -> FinalizerEvidence:
    slurm = submission["slurm"]
    job_id = str(slurm["finalizer_job_id"])
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
        "--format=" + ",".join(FINALIZER_ALLOCATION_FIELDS),
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
        "--format=" + ",".join(FINALIZER_BATCH_FIELDS),
    )
    allocation_output = _run_scheduler_command(allocation_argv, runner)
    batch_output = _run_scheduler_command(batch_argv, runner)
    return FinalizerEvidence(
        allocation=_parse_sacct_row(
            allocation_output.stdout,
            FINALIZER_ALLOCATION_FIELDS,
            job_id,
            "finalizer allocation",
        ),
        batch=_parse_sacct_row(
            batch_output.stdout,
            FINALIZER_BATCH_FIELDS,
            f"{job_id}.batch",
            "finalizer batch",
        ),
        allocation_command=allocation_argv,
        batch_command=batch_argv,
        allocation_sha256=hashlib.sha256(allocation_output.stdout).hexdigest(),
        batch_sha256=hashlib.sha256(batch_output.stdout).hexdigest(),
    )


def _canonical_decimal(value: str, context: str, *, positive: bool = False) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
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
        if TRES_NAME_RE.fullmatch(key) is None or not raw or key in result:
            _fail(f"{context} contains a malformed or duplicate item")
        result[key] = raw
    allowed = {"billing", "cpu", "mem", "node"}
    if not {"cpu", "mem", "node"}.issubset(result) or not set(result).issubset(allowed):
        _fail(f"{context} contains an unexpected resource set")
    return result


def _parse_memory(value: str, cpus: int, nodes: int, context: str) -> int:
    match = MEMORY_RE.fullmatch(value)
    if match is None:
        _fail(f"{context} is not a canonical Slurm memory quantity")
    amount = int(match.group(1))
    unit = match.group(2)
    scope = match.group(3)
    multiplier = 1 if not unit else 1024 ** ("KMGTPE".index(unit) + 1)
    result = amount * multiplier
    if scope == "c":
        result *= cpus
    elif scope == "n":
        result *= nodes
    return result


def _validate_tres_contract(
    raw: str,
    *,
    cpus: int,
    nodes: int,
    memory_bytes: int,
    context: str,
) -> None:
    tres = _parse_tres(raw, context)
    if _canonical_decimal(tres["cpu"], f"{context} cpu", positive=True) != cpus:
        _fail(f"{context} CPU count differs")
    if _canonical_decimal(tres["node"], f"{context} node", positive=True) != nodes:
        _fail(f"{context} node count differs")
    if _parse_memory(tres["mem"], cpus, nodes, f"{context} memory") != memory_bytes:
        _fail(f"{context} memory differs")
    if "billing" in tres and _canonical_decimal(
        tres["billing"], f"{context} billing", positive=True
    ) != cpus:
        _fail(f"{context} billing count differs")


def validate_finalizer_evidence(
    evidence: FinalizerEvidence,
    submission: Mapping[str, Any],
    finalizer_held_record: Mapping[str, str],
) -> dict[str, Any]:
    allocation = dict(evidence.allocation)
    batch = dict(evidence.batch)
    slurm = submission["slurm"]
    if allocation["Cluster"] != slurm["cluster"]:
        _fail("finalizer allocation cluster differs from the submission")
    if batch["Cluster"] != slurm["cluster"]:
        _fail("finalizer batch cluster differs from the submission")
    allocation_db_index = _canonical_decimal(
        allocation["DBIndex"], "finalizer allocation DBIndex", positive=True
    )
    batch_db_index = _canonical_decimal(
        batch["DBIndex"], "finalizer batch DBIndex", positive=True
    )
    if allocation_db_index != batch_db_index:
        _fail("finalizer allocation and batch DBIndex differ")
    if allocation["JobName"] != slurm["finalizer_job_name"]:
        _fail("finalizer allocation job name differs from the submission")
    held_user = re.fullmatch(
        r"([^()]+)\(([0-9]+)\)", finalizer_held_record.get("UserId", "")
    )
    if held_user is None:
        _fail("finalizer held scheduler user identity is malformed")
    if allocation["User"] != held_user.group(1):
        _fail("finalizer allocation user differs from the held scheduler identity")
    if _canonical_decimal(allocation["UID"], "finalizer allocation UID") != slurm[
        "owner_uid"
    ]:
        _fail("finalizer allocation UID differs from the submission")
    if int(held_user.group(2)) != slurm["owner_uid"]:
        _fail("finalizer held scheduler UID differs from the submission")
    if allocation["Comment"] != slurm["finalizer_comment"]:
        _fail("finalizer allocation comment differs from the submission")
    finalizer_argv = slurm["finalizer_sbatch_argv"]
    if any(any(character.isspace() for character in argument) for argument in finalizer_argv):
        _fail("finalizer sbatch argv cannot be represented exactly by SubmitLine")
    if allocation["SubmitLine"] != " ".join(finalizer_argv):
        _fail("finalizer allocation SubmitLine differs from the exact submitted argv")
    if allocation["State"] != "COMPLETED" or batch["State"] != "COMPLETED":
        _fail("finalizer allocation and batch step must both be COMPLETED")
    if allocation["ExitCode"] != "0:0" or allocation["DerivedExitCode"] != "0:0":
        _fail("finalizer allocation exit and derived-exit codes must both be 0:0")
    if batch["JobName"] != "batch":
        _fail("finalizer batch step name differs")
    if batch["ExitCode"] != "0:0" or batch["DerivedExitCode"] not in ("", "0:0"):
        _fail("finalizer batch exit evidence is not successful")
    if allocation["Partition"] != slurm["partition"]:
        _fail("finalizer allocation partition differs from the submission")
    nodes = _canonical_decimal(allocation["NNodes"], "finalizer NNodes", positive=True)
    requested_cpus = _canonical_decimal(
        allocation["ReqCPUS"], "finalizer ReqCPUS", positive=True
    )
    allocated_cpus = _canonical_decimal(
        allocation["AllocCPUS"], "finalizer AllocCPUS", positive=True
    )
    if (
        nodes != slurm["finalizer_requested_nodes"]
        or requested_cpus != slurm["finalizer_requested_cpus"]
        or allocated_cpus != slurm["finalizer_requested_cpus"]
    ):
        _fail("finalizer CPU or node resources differ from the submission")
    memory_bytes = slurm["finalizer_requested_memory_bytes"]
    if (
        _parse_memory(allocation["ReqMem"], requested_cpus, nodes, "finalizer ReqMem")
        != memory_bytes
    ):
        _fail("finalizer requested memory differs from the submission")
    _validate_tres_contract(
        allocation["ReqTRES"],
        cpus=requested_cpus,
        nodes=nodes,
        memory_bytes=memory_bytes,
        context="finalizer requested TRES",
    )
    _validate_tres_contract(
        allocation["AllocTRES"],
        cpus=allocated_cpus,
        nodes=nodes,
        memory_bytes=memory_bytes,
        context="finalizer allocated TRES",
    )
    minutes = _canonical_decimal(
        allocation["TimelimitRaw"], "finalizer TimelimitRaw", positive=True
    )
    if minutes * 60 != slurm["finalizer_timelimit_seconds"]:
        _fail("finalizer time limit differs from the submission")
    for field, expected in (
        ("WorkDir", slurm["finalizer_work_dir"]),
        ("StdOut", slurm["finalizer_stdout_path"]),
        ("StdErr", slurm["finalizer_stderr_path"]),
    ):
        if allocation[field] != expected:
            _fail(f"finalizer allocation {field} differs from the submission")
    if not allocation["NodeList"] or allocation["NodeList"] in ("None", "Unknown"):
        _fail("finalizer allocation node list is absent")
    submit = _parse_timestamp(allocation["Submit"], "finalizer Submit")
    eligible = _parse_timestamp(allocation["Eligible"], "finalizer Eligible")
    start = _parse_timestamp(allocation["Start"], "finalizer Start")
    end = _parse_timestamp(allocation["End"], "finalizer End")
    try:
        monotone = submit <= eligible <= start <= end
    except TypeError:
        _fail("finalizer timestamps mix timezone-aware and naive forms")
    if not monotone:
        _fail("finalizer timestamps are not monotone")
    elapsed = _canonical_decimal(allocation["ElapsedRaw"], "finalizer ElapsedRaw")
    if elapsed != int((end - start).total_seconds()):
        _fail("finalizer elapsed time differs from its timestamps")

    batch_nodes = _canonical_decimal(
        batch["NNodes"], "finalizer batch NNodes", positive=True
    )
    batch_requested_cpus = _canonical_decimal(
        batch["ReqCPUS"], "finalizer batch ReqCPUS", positive=True
    )
    batch_allocated_cpus = _canonical_decimal(
        batch["AllocCPUS"], "finalizer batch AllocCPUS", positive=True
    )
    if (
        batch_nodes != nodes
        or batch_requested_cpus != requested_cpus
        or batch_allocated_cpus != allocated_cpus
    ):
        _fail("finalizer batch CPU or node resources differ from the allocation")
    if batch["NodeList"] != allocation["NodeList"]:
        _fail("finalizer batch node list differs from the allocation")
    _validate_tres_contract(
        batch["AllocTRES"],
        cpus=batch_allocated_cpus,
        nodes=batch_nodes,
        memory_bytes=memory_bytes,
        context="finalizer batch allocated TRES",
    )
    batch_submit = _parse_timestamp(batch["Submit"], "finalizer batch Submit")
    batch_start = _parse_timestamp(batch["Start"], "finalizer batch Start")
    batch_end = _parse_timestamp(batch["End"], "finalizer batch End")
    try:
        batch_monotone = submit <= batch_submit <= batch_start <= batch_end <= end
    except TypeError:
        _fail("finalizer batch timestamps mix timezone-aware and naive forms")
    if not batch_monotone:
        _fail("finalizer batch timestamps are not within the allocation interval")
    batch_elapsed = _canonical_decimal(
        batch["ElapsedRaw"], "finalizer batch ElapsedRaw"
    )
    if batch_elapsed != int((batch_end - batch_start).total_seconds()):
        _fail("finalizer batch elapsed time differs from its timestamps")
    return {
        "allocation": allocation,
        "batch": batch,
        "commands": {
            "allocation": list(evidence.allocation_command),
            "batch": list(evidence.batch_command),
        },
        "raw_sha256": {
            "allocation": evidence.allocation_sha256,
            "batch": evidence.batch_sha256,
        },
    }


def _authorizer_source_binding() -> BoundInput:
    try:
        source = Path(__file__).resolve(strict=True)
    except OSError as error:
        _fail(f"cannot resolve the authorizer source: {error}")
    return _bind_input(
        source,
        MAX_MODULE_BYTES,
        "authorizer module",
        require_nonwritable=True,
    )


def _prepare_authorization(
    submission_path: Path,
    scheduler_candidate_path: Path,
    *,
    submission_sha256: str,
    finalizer_module_path: Path,
    finalizer_module_sha256: str,
    command_runner: CommandRunner,
    sacct_bin: str,
    poll_attempts: int,
    poll_interval_seconds: float,
    sleeper: Sleeper,
    output_path: Path | None,
) -> PreparedAuthorization:
    submission_path = _canonical_absolute_path(os.fspath(submission_path), "submission path")
    scheduler_candidate_path = _canonical_absolute_path(
        os.fspath(scheduler_candidate_path), "scheduler-candidate path"
    )
    finalizer_module_path = _canonical_absolute_path(
        os.fspath(finalizer_module_path), "finalizer-module path"
    )
    sacct_path = _canonical_absolute_path(sacct_bin, "sacct path")
    module, module_binding = _load_finalizer_module(
        finalizer_module_path, finalizer_module_sha256
    )
    submission_binding = _bind_input(
        submission_path,
        MAX_JSON_BYTES,
        "submission record",
        require_nonwritable=True,
    )
    if submission_binding.initial.sha256 != _sha256(
        submission_sha256, "expected submission SHA-256"
    ):
        _fail("submission record SHA-256 differs from the caller binding")
    submission_json = decode_canonical_json(submission_binding.initial.data, "submission record")
    submission = _validate_submission_with_module(module, submission_json)
    if submission["control"]["finalizer_sha256"] != module_binding.initial.sha256:
        _fail("submission finalizer digest differs from the bound finalizer module")
    if scheduler_candidate_path != Path(submission["scheduler_candidate_path"]):
        _fail("scheduler-candidate argument differs from the submission")
    expected_output = Path(submission["final_decision_path"])
    if output_path is not None:
        output_path = _canonical_absolute_path(os.fspath(output_path), "output path")
        if output_path != expected_output:
            _fail("output path differs from the submission final-decision path")
    else:
        output_path = expected_output
    if submission["slurm"]["compute_job_id"] == submission["slurm"]["finalizer_job_id"]:
        _fail("submission reuses the compute job ID for the finalizer")
    if submission["slurm"]["owner_uid"] != os.getuid():
        _fail("authorizer process UID differs from the submission owner UID")
    authorizer_binding = _authorizer_source_binding()
    if authorizer_binding.initial.sha256 != submission["control"]["authorizer_sha256"]:
        _fail("authorizer module digest differs from the submission")
    sacct_binding = _bind_input(
        sacct_path,
        MAX_EXECUTABLE_BYTES,
        "sacct executable",
        require_nonwritable=False,
        require_executable=True,
    )
    if sacct_binding.initial.sha256 != submission["control"]["sacct_sha256"]:
        _fail("sacct executable digest differs from the submission")

    _, compute_held_binding = _validate_held_record(submission, "compute")
    finalizer_held_record, finalizer_held_binding = _validate_held_record(
        submission, "finalizer"
    )
    candidate_binding = _bind_input(
        scheduler_candidate_path,
        MAX_JSON_BYTES,
        "scheduler candidate",
        require_nonwritable=True,
    )
    candidate_json = decode_canonical_json(
        candidate_binding.initial.data, "scheduler candidate"
    )
    candidate = validate_scheduler_candidate(
        candidate_json,
        candidate_read=candidate_binding.initial,
        candidate_path=scheduler_candidate_path,
        submission=submission,
        submission_read=submission_binding.initial,
        submission_path=submission_path,
        compute_held_read=compute_held_binding.initial,
        finalizer_held_read=finalizer_held_binding.initial,
        module=module,
    )
    candidate_root = Path(submission["candidate_root"])
    root_mode, root_inventory, root_identity = module.inventory_run_root(candidate_root)
    if root_mode != candidate["candidate"]["root_mode"]:
        _fail("candidate-root mode differs from the scheduler candidate")
    if root_inventory != candidate["artifacts"]:
        _fail("candidate-root inventory differs from the scheduler candidate")
    root_inventory_sha256 = hashlib.sha256(
        canonical_json_bytes(root_inventory)
    ).hexdigest()

    def revalidate_candidate_root() -> None:
        current_mode, current_inventory, current_identity = module.inventory_run_root(
            candidate_root
        )
        if (
            current_mode != root_mode
            or current_inventory != root_inventory
            or current_identity != root_identity
        ):
            _fail("candidate root changed during authorization")
    if poll_attempts <= 0 or poll_interval_seconds < 0:
        _fail("scheduler polling parameters are invalid")
    terminal: dict[str, Any] | None = None
    last_pending: SchedulerPending | None = None
    for attempt in range(poll_attempts):
        try:
            terminal = validate_finalizer_evidence(
                collect_finalizer_evidence(
                    submission,
                    command_runner,
                    sacct_bin=os.fspath(sacct_path),
                ),
                submission,
                finalizer_held_record,
            )
            break
        except SchedulerPending as error:
            last_pending = error
            if attempt + 1 < poll_attempts:
                sleeper(poll_interval_seconds)
    if terminal is None:
        raise last_pending or SchedulerPending("finalizer accounting is unavailable")

    inputs = (
        submission_binding,
        candidate_binding,
        compute_held_binding,
        finalizer_held_binding,
        module_binding,
        authorizer_binding,
        sacct_binding,
    )
    _revalidate_inputs(inputs)
    revalidate_candidate_root()
    root_binding = {
        "device": root_identity[0],
        "inode": root_identity[1],
        "inventory_sha256": root_inventory_sha256,
        "mode": root_mode,
        "path": os.fspath(candidate_root),
    }
    identity = {
        "candidate_root": submission["candidate_root"],
        "candidate_root_binding": root_binding,
        "cluster": submission["slurm"]["cluster"],
        "finalizer_job_id": submission["slurm"]["finalizer_job_id"],
        "finalizer_scheduler_raw_sha256": terminal["raw_sha256"],
        "launch_manifest_sha256": submission["launch_manifest_sha256"],
        "revision": submission["revision"],
        "run_nonce": submission["run_nonce"],
        "scheduler_candidate_sha256": candidate_binding.initial.sha256,
        "submission_sha256": submission_binding.initial.sha256,
    }
    authorization_id = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    payload = {
        "authorization_id": authorization_id,
        "candidate_root": submission["candidate_root"],
        "candidate_root_binding": root_binding,
        "classification": candidate["classification"],
        "control": submission["control"],
        "decision": AUTHORIZATION_DECISION,
        "finalizer_scheduler": terminal,
        "launch_manifest_sha256": submission["launch_manifest_sha256"],
        "policy": candidate["policy"],
        "revision": submission["revision"],
        "run_nonce": submission["run_nonce"],
        "scheduler_candidate": {
            "attempt_id": candidate["attempt_id"],
            "bytes": candidate_binding.initial.size,
            "mode": candidate_binding.initial.mode,
            "path": os.fspath(scheduler_candidate_path),
            "sha256": candidate_binding.initial.sha256,
        },
        "schema": AUTHORIZATION_SCHEMA,
        "stage0b_authority": True,
        "status": "stage0b_authorized",
        "submission": {
            "bytes": submission_binding.initial.size,
            "mode": submission_binding.initial.mode,
            "path": os.fspath(submission_path),
            "sha256": submission_binding.initial.sha256,
        },
        "submission_evidence": {
            "compute_held_record": submission["slurm"]["compute_held_record"],
            "compute_sbatch_argv": submission["slurm"]["compute_sbatch_argv"],
            "finalizer_held_record": submission["slurm"]["finalizer_held_record"],
            "finalizer_sbatch_argv": submission["slurm"]["finalizer_sbatch_argv"],
            "owner_uid": submission["slurm"]["owner_uid"],
        },
    }
    canonical_json_bytes(payload)
    return PreparedAuthorization(
        payload=payload,
        output_path=output_path,
        inputs=inputs,
        revalidate_candidate_root=revalidate_candidate_root,
    )


def build_authorization_payload(
    submission_path: Path,
    scheduler_candidate_path: Path,
    *,
    submission_sha256: str,
    finalizer_module_path: Path,
    finalizer_module_sha256: str,
    command_runner: CommandRunner = _default_command_runner,
    sacct_bin: str = "/usr/bin/sacct",
    poll_attempts: int = 1,
    poll_interval_seconds: float = 0.0,
    sleeper: Sleeper = time.sleep,
    output_path: Path | None = None,
) -> dict[str, Any]:
    prepared = _prepare_authorization(
        submission_path,
        scheduler_candidate_path,
        submission_sha256=submission_sha256,
        finalizer_module_path=finalizer_module_path,
        finalizer_module_sha256=finalizer_module_sha256,
        command_runner=command_runner,
        sacct_bin=sacct_bin,
        poll_attempts=poll_attempts,
        poll_interval_seconds=poll_interval_seconds,
        sleeper=sleeper,
        output_path=output_path,
    )
    return dict(prepared.payload)


def _ensure_destination_fresh(path: Path) -> tuple[Path, str]:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        _fail("authorization output path must be an absolute file path")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        _fail(f"cannot resolve authorization output parent: {error}")
    if parent != path.parent:
        _fail("authorization output parent must contain no symbolic-link components")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        _fail(f"cannot inspect authorization output path: {error}")
    else:
        _fail("authorization output path must be fresh")
    return parent, path.name


def _validate_publishable_payload(payload: Mapping[str, Any]) -> None:
    expected = (
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
    _exact_keys(payload, expected, "authorization payload")
    if (
        payload.get("schema") != AUTHORIZATION_SCHEMA
        or payload.get("status") != "stage0b_authorized"
        or payload.get("decision") != AUTHORIZATION_DECISION
        or payload.get("stage0b_authority") is not True
    ):
        _fail("only an exact Stage 0B authorization payload may be published")
    _sha256(payload.get("authorization_id"), "authorization ID")
    root_binding = _exact_keys(
        payload.get("candidate_root_binding"),
        ("device", "inode", "inventory_sha256", "mode", "path"),
        "authorization candidate-root binding",
    )
    _nonnegative_int(root_binding["device"], "authorization candidate-root device")
    _positive_int(root_binding["inode"], "authorization candidate-root inode")
    _sha256(
        root_binding["inventory_sha256"],
        "authorization candidate-root inventory SHA-256",
    )
    _mode(root_binding["mode"], "authorization candidate-root mode")
    if root_binding["path"] != payload.get("candidate_root"):
        _fail("authorization candidate-root path binding differs")


def publish_authorization(
    path: Path,
    payload: Mapping[str, Any],
    *,
    before_link: Callable[[], None] | None = None,
) -> None:
    parent, name = _ensure_destination_fresh(path)
    _validate_publishable_payload(payload)
    if not sys.platform.startswith("linux") or not hasattr(os, "O_TMPFILE"):
        _fail("authorization publication requires Linux O_TMPFILE support")
    encoded = canonical_json_bytes(payload)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(parent, directory_flags)
    descriptor = -1
    try:
        parent_before = os.fstat(directory_fd)
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("authorization output path ceased to be fresh")
        descriptor = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                _fail("short authorization-payload write")
            offset += written
        os.fsync(descriptor)
        if os.pread(descriptor, len(encoded) + 1, 0) != encoded:
            _fail("staged authorization payload differs from the intended bytes")
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        if (
            not stat.S_ISREG(staged.st_mode)
            or staged.st_nlink != 0
            or staged.st_size != len(encoded)
            or stat.S_IMODE(staged.st_mode) != 0o400
        ):
            _fail("anonymous authorization inode violates the publication contract")
        if before_link is not None:
            before_link()
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("authorization output path ceased to be fresh")
        proc_path = f"/proc/self/fd/{descriptor}"
        proc_metadata = os.stat(proc_path)
        if (staged.st_dev, staged.st_ino) != (proc_metadata.st_dev, proc_metadata.st_ino):
            _fail("authorization proc descriptor does not bind the staging inode")
        try:
            os.link(
                proc_path,
                name,
                dst_dir_fd=directory_fd,
                follow_symlinks=True,
            )
        except FileExistsError:
            _fail("authorization output path ceased to be fresh")
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
                _fail("published authorization payload differs from the staging inode")
        finally:
            os.close(final_descriptor)
        parent_after = os.fstat(directory_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (
            parent_after.st_dev,
            parent_after.st_ino,
        ):
            _fail("authorization output parent identity changed during publication")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def authorize_and_publish(
    submission_path: Path,
    scheduler_candidate_path: Path,
    output_path: Path,
    *,
    submission_sha256: str,
    finalizer_module_path: Path,
    finalizer_module_sha256: str,
    command_runner: CommandRunner = _default_command_runner,
    sacct_bin: str = "/usr/bin/sacct",
    poll_attempts: int = 1,
    poll_interval_seconds: float = 0.0,
    sleeper: Sleeper = time.sleep,
    before_publish: Callable[[], None] | None = None,
) -> dict[str, Any]:
    _ensure_destination_fresh(output_path)
    prepared = _prepare_authorization(
        submission_path,
        scheduler_candidate_path,
        submission_sha256=submission_sha256,
        finalizer_module_path=finalizer_module_path,
        finalizer_module_sha256=finalizer_module_sha256,
        command_runner=command_runner,
        sacct_bin=sacct_bin,
        poll_attempts=poll_attempts,
        poll_interval_seconds=poll_interval_seconds,
        sleeper=sleeper,
        output_path=output_path,
    )
    def revalidate_before_link() -> None:
        if before_publish is not None:
            before_publish()
        _revalidate_inputs(prepared.inputs)
        prepared.revalidate_candidate_root()

    publish_authorization(
        prepared.output_path,
        prepared.payload,
        before_link=revalidate_before_link,
    )
    return dict(prepared.payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--submission-sha256", required=True)
    parser.add_argument("--scheduler-candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--finalizer-module", type=Path, required=True)
    parser.add_argument("--finalizer-module-sha256", required=True)
    parser.add_argument("--sacct-bin", default="/usr/bin/sacct")
    parser.add_argument("--poll-attempts", type=int, default=12)
    parser.add_argument("--poll-interval-seconds", type=float, default=5.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = authorize_and_publish(
            args.submission,
            args.scheduler_candidate,
            args.output,
            submission_sha256=args.submission_sha256,
            finalizer_module_path=args.finalizer_module,
            finalizer_module_sha256=args.finalizer_module_sha256,
            sacct_bin=args.sacct_bin,
            poll_attempts=args.poll_attempts,
            poll_interval_seconds=args.poll_interval_seconds,
        )
        encoded = canonical_json_bytes(payload)
        print(
            canonical_json_bytes(
                {
                    "authorization_id": payload["authorization_id"],
                    "output": os.fspath(args.output),
                    "output_sha256": hashlib.sha256(encoded).hexdigest(),
                    "status": payload["status"],
                }
            ).decode("ascii"),
            end="",
        )
        return 0
    except (AuthorizationError, OSError) as error:
        print(f"T11 Stage 0A authorization rejected: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
