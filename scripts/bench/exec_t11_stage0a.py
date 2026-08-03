#!/usr/bin/env python3
"""Execute a T11 Stage 0A command from immutable sealed memfd snapshots."""

from __future__ import annotations

import argparse
import dataclasses
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Iterable, Mapping, Sequence


SCHEMA = "euf-viper.t11-stage0a-exec.v1"
RUNTIME_SCHEMA = "euf-viper.t11-stage0a-exec.v2"
PROC_FD_ROOT = "/proc/self/fd"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_HELPER_BYTES = 4 * 1024 * 1024
MAX_INPUTS = 32
MAX_RUNTIME_FILES = 128
MAX_ARGV = 256
MAX_STRING_BYTES = 16 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
EXECUTABLE_SNAPSHOT_MODE = 0o500
INPUT_SNAPSHOT_MODE = 0o400

# Linux uapi value.  Older Python builds may not expose this constant even when
# the running kernel implements it, so support is probed by F_ADD_SEALS.
_F_SEAL_FUTURE_WRITE = getattr(fcntl, "F_SEAL_FUTURE_WRITE", 0x0010)

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PLACEHOLDER_RE = re.compile(r"@[A-Z][A-Z0-9_]{0,62}@\Z")
PLACEHOLDER_SEARCH_RE = re.compile(r"@[A-Z][A-Z0-9_]{0,62}@")
ARGV0_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
LOCALE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\Z")
TZ_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+./-]{0,127}\Z")

ALLOWED_ENVIRONMENT_KEYS = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "RUST_BACKTRACE",
        "TZ",
        "EUF_VIPER_T11_EQRES",
    }
)


class Stage0ExecError(RuntimeError):
    """A fail-closed request or execution preparation failure."""


@dataclasses.dataclass(frozen=True)
class FileSpec:
    path: str
    sha256: str


@dataclasses.dataclass(frozen=True)
class InputSpec:
    placeholder: str
    file: FileSpec


@dataclasses.dataclass(frozen=True)
class ExecRequest:
    executable: FileSpec
    inputs: tuple[InputSpec, ...]
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    runtime: tuple[FileSpec, ...] = ()


@dataclasses.dataclass(frozen=True)
class _SealedFile:
    role: str
    fd: int
    expected_sha256: str
    size: int
    mode: int
    seals: int
    identity: tuple[int, int, int, int, int, int]


@dataclasses.dataclass(frozen=True)
class _RetainedRuntime:
    spec: FileSpec
    fd: int
    identity: tuple[int, int, int, int, int, int]


def _fail(message: str) -> None:
    raise Stage0ExecError(message)


def _exact_keys(value: object, expected: Iterable[str], context: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    expected_set = set(expected)
    actual_set = set(value)
    if actual_set != expected_set:
        missing = sorted(expected_set - actual_set)
        extra = sorted(actual_set - expected_set)
        _fail(f"{context} keys differ: missing={missing}, extra={extra}")
    return value


def _duplicate_rejecting_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    _fail(f"non-finite JSON value is forbidden: {value}")


def _bounded_string(value: object, context: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        _fail(f"{context} must be a string")
    if not allow_empty and not value:
        _fail(f"{context} must not be empty")
    if "\x00" in value:
        _fail(f"{context} must not contain NUL")
    if len(value.encode("utf-8")) > MAX_STRING_BYTES:
        _fail(f"{context} is too long")
    return value


def _canonical_sha256(value: object, context: str) -> str:
    digest = _bounded_string(value, context)
    if SHA256_RE.fullmatch(digest) is None:
        _fail(f"{context} must be exactly 64 lowercase hexadecimal digits")
    return digest


def _descriptor_number(value: str) -> int:
    if re.fullmatch(r"(?:[3-9]|[1-9][0-9]+)", value) is None:
        raise argparse.ArgumentTypeError(
            "descriptor must be a canonical decimal integer greater than 2"
        )
    try:
        return int(value)
    except ValueError as error:  # pragma: no cover - guarded by the regular expression
        raise argparse.ArgumentTypeError("descriptor is outside the integer range") from error


def _absolute_path(value: object, context: str) -> str:
    path = _bounded_string(value, context)
    if not os.path.isabs(path):
        _fail(f"{context} must be an absolute path")
    return path


def _parse_file_spec(value: object, context: str) -> FileSpec:
    record = _exact_keys(value, ("path", "sha256"), context)
    return FileSpec(
        path=_absolute_path(record["path"], f"{context}.path"),
        sha256=_canonical_sha256(record["sha256"], f"{context}.sha256"),
    )


def _validate_environment(value: object) -> Mapping[str, str]:
    if type(value) is not dict:
        _fail("request.environment must be an object")
    environment: dict[str, str] = {}
    for key, raw_value in value.items():
        if key not in ALLOWED_ENVIRONMENT_KEYS:
            _fail(f"request.environment contains unsafe key: {key!r}")
        item = _bounded_string(
            raw_value, f"request.environment[{key!r}]", allow_empty=False
        )
        if key == "HOME":
            if not os.path.isabs(item):
                _fail("request.environment['HOME'] must be an absolute path")
        elif key == "PATH":
            components = item.split(os.pathsep)
            if any(not component or not os.path.isabs(component) for component in components):
                _fail("request.environment['PATH'] must contain only absolute components")
        elif key in {"LANG", "LC_ALL", "LC_CTYPE"}:
            if LOCALE_RE.fullmatch(item) is None:
                _fail(f"request.environment[{key!r}] is not a safe locale value")
        elif key == "RUST_BACKTRACE":
            if item not in {"0", "1", "full"}:
                _fail("request.environment['RUST_BACKTRACE'] must be 0, 1, or full")
        elif key == "EUF_VIPER_T11_EQRES":
            if item != "clique-er-auto":
                _fail(
                    "request.environment['EUF_VIPER_T11_EQRES'] must be "
                    "clique-er-auto"
                )
        elif key == "TZ" and TZ_RE.fullmatch(item) is None:
            _fail("request.environment['TZ'] is not a safe timezone value")
        environment[key] = item
    return environment


def parse_request(value: object) -> ExecRequest:
    if type(value) is not dict:
        _fail("request must be an object")
    schema = value.get("schema")
    if schema == SCHEMA:
        record = _exact_keys(
            value,
            ("schema", "executable", "inputs", "argv", "environment"),
            "request",
        )
        runtime: tuple[FileSpec, ...] = ()
    elif schema == RUNTIME_SCHEMA:
        record = _exact_keys(
            value,
            ("schema", "executable", "inputs", "argv", "environment", "runtime"),
            "request",
        )
        raw_runtime = record["runtime"]
        if type(raw_runtime) is not list:
            _fail("request.runtime must be an array")
        if not 1 <= len(raw_runtime) <= MAX_RUNTIME_FILES:
            _fail(
                f"request.runtime must contain between 1 and {MAX_RUNTIME_FILES} entries"
            )
        runtime = tuple(
            _parse_file_spec(item, f"request.runtime[{index}]")
            for index, item in enumerate(raw_runtime)
        )
        paths = [item.path for item in runtime]
        if len(paths) != len(set(paths)):
            _fail("request.runtime contains duplicate paths")
        if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
            _fail("request.runtime paths are not byte-sorted")
    else:
        _fail(f"request.schema must equal {SCHEMA!r} or {RUNTIME_SCHEMA!r}")

    executable = _parse_file_spec(record["executable"], "request.executable")

    raw_inputs = record["inputs"]
    if type(raw_inputs) is not list:
        _fail("request.inputs must be an array")
    if not 1 <= len(raw_inputs) <= MAX_INPUTS:
        _fail(f"request.inputs must contain between 1 and {MAX_INPUTS} entries")

    inputs: list[InputSpec] = []
    declared_placeholders: set[str] = set()
    for index, raw_input in enumerate(raw_inputs):
        context = f"request.inputs[{index}]"
        input_record = _exact_keys(raw_input, ("placeholder", "path", "sha256"), context)
        placeholder = _bounded_string(
            input_record["placeholder"], f"{context}.placeholder"
        )
        if PLACEHOLDER_RE.fullmatch(placeholder) is None:
            _fail(
                f"{context}.placeholder must match "
                "@[A-Z][A-Z0-9_]{0,62}@"
            )
        if placeholder in declared_placeholders:
            _fail(f"duplicate input placeholder: {placeholder}")
        declared_placeholders.add(placeholder)
        inputs.append(
            InputSpec(
                placeholder=placeholder,
                file=FileSpec(
                    path=_absolute_path(input_record["path"], f"{context}.path"),
                    sha256=_canonical_sha256(
                        input_record["sha256"], f"{context}.sha256"
                    ),
                ),
            )
        )

    raw_argv = record["argv"]
    if type(raw_argv) is not list:
        _fail("request.argv must be an array")
    if not 1 <= len(raw_argv) <= MAX_ARGV:
        _fail(f"request.argv must contain between 1 and {MAX_ARGV} entries")
    argv = tuple(
        _bounded_string(item, f"request.argv[{index}]")
        for index, item in enumerate(raw_argv)
    )
    if ARGV0_RE.fullmatch(argv[0]) is None:
        _fail("request.argv[0] must be a simple program name")

    occurrence_counts = dict.fromkeys(declared_placeholders, 0)
    for index, argument in enumerate(argv):
        if argument.startswith("/proc/self/fd/"):
            _fail(f"request.argv[{index}] must not supply a proc-fd path")
        if argument in occurrence_counts:
            occurrence_counts[argument] += 1
            continue
        embedded = PLACEHOLDER_SEARCH_RE.search(argument)
        if embedded is not None:
            _fail(
                f"request.argv[{index}] contains undeclared or embedded placeholder "
                f"{embedded.group(0)!r}"
            )
    for placeholder, count in occurrence_counts.items():
        if count < 1:
            _fail(
                f"input placeholder {placeholder} must occur in request.argv; "
                f"found {count}"
            )

    environment = _validate_environment(record["environment"])
    return ExecRequest(
        executable=executable,
        inputs=tuple(inputs),
        argv=argv,
        environment=environment,
        runtime=runtime,
    )


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_readonly_regular(path: str, role: str, *, executable: bool = False) -> int:
    flags = os.O_RDONLY
    for flag_name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, flag_name, 0)

    before_lstat: os.stat_result | None = None
    if not hasattr(os, "O_NOFOLLOW"):
        try:
            before_lstat = os.lstat(path)
        except OSError as error:
            _fail(f"cannot inspect {role} {path!r}: {error}")
        if stat.S_ISLNK(before_lstat.st_mode):
            _fail(f"{role} must not be a symlink: {path!r}")

    try:
        fd = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            _fail(f"{role} must not be a symlink: {path!r}")
        _fail(f"cannot open {role} {path!r}: {error}")

    try:
        os.set_inheritable(fd, False)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            _fail(f"{role} must be a regular file: {path!r}")
        if executable and metadata.st_mode & 0o111 == 0:
            _fail(f"{role} is not executable: {path!r}")
        if before_lstat is not None:
            after_lstat = os.lstat(path)
            if stat.S_ISLNK(after_lstat.st_mode):
                _fail(f"{role} became a symlink: {path!r}")
            if (after_lstat.st_dev, after_lstat.st_ino) != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                _fail(f"{role} changed while it was opened: {path!r}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_fd_bytes(fd: int, maximum_bytes: int, context: str) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(HASH_CHUNK_BYTES, maximum_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum_bytes:
            _fail(f"{context} exceeds {maximum_bytes} bytes")
    os.lseek(fd, 0, os.SEEK_SET)
    return b"".join(chunks)


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, HASH_CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _require_linux_memfd_sealing() -> None:
    if not sys.platform.startswith("linux"):
        _fail("sealed Stage 0A execution requires Linux")
    if PROC_FD_ROOT != "/proc/self/fd":
        _fail("sealed Stage 0A execution requires /proc/self/fd")
    if not callable(getattr(os, "memfd_create", None)):
        _fail("os.memfd_create is unavailable")
    for name in ("MFD_ALLOW_SEALING", "MFD_CLOEXEC"):
        if not hasattr(os, name):
            _fail(f"required memfd primitive os.{name} is unavailable")
    for name in (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_WRITE",
        "F_SEAL_GROW",
        "F_SEAL_SHRINK",
        "F_SEAL_SEAL",
    ):
        if not hasattr(fcntl, name):
            _fail(f"required sealing primitive fcntl.{name} is unavailable")


def _write_all(fd: int, data: bytes, context: str) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(fd, data[offset:])
        except InterruptedError:
            continue
        except OSError as error:
            _fail(f"cannot write {context}: {error}")
        if written <= 0:
            _fail(f"cannot write {context}: write made no progress")
        offset += written


def _copy_and_hash(source_fd: int, snapshot_fd: int, role: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    os.lseek(source_fd, 0, os.SEEK_SET)
    while True:
        try:
            chunk = os.read(source_fd, HASH_CHUNK_BYTES)
        except InterruptedError:
            continue
        except OSError as error:
            _fail(f"cannot read {role} while snapshotting: {error}")
        if not chunk:
            break
        digest.update(chunk)
        _write_all(snapshot_fd, chunk, f"{role} snapshot")
        size += len(chunk)
    return digest.hexdigest(), size


def _get_seals(fd: int, role: str) -> int:
    try:
        return int(fcntl.fcntl(fd, fcntl.F_GET_SEALS))
    except OSError as error:
        _fail(f"cannot inspect {role} seals: {error}")


def _required_memfd_seals() -> int:
    return (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )


def _seal_snapshot(fd: int, role: str) -> int:
    initial_seals = _get_seals(fd, role)
    if initial_seals != 0:
        _fail(f"new {role} snapshot unexpectedly has seals 0x{initial_seals:x}")

    base_seals = _required_memfd_seals()
    preferred_seals = base_seals | _F_SEAL_FUTURE_WRITE
    try:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, preferred_seals)
        expected_seals = preferred_seals
    except OSError as error:
        if error.errno not in {errno.EINVAL, getattr(errno, "EOPNOTSUPP", 95)}:
            _fail(f"cannot seal {role} snapshot: {error}")
        if _get_seals(fd, role) != 0:
            _fail(f"future-write probe partially sealed {role} snapshot")
        try:
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, base_seals)
        except OSError as base_error:
            _fail(f"cannot seal {role} snapshot: {base_error}")
        expected_seals = base_seals

    actual_seals = _get_seals(fd, role)
    if actual_seals != expected_seals:
        _fail(
            f"{role} snapshot seal mismatch: expected 0x{expected_seals:x}, "
            f"found 0x{actual_seals:x}"
        )
    return expected_seals


def _create_memfd(role: str) -> int:
    name = "euf-viper-t11-" + re.sub(r"[^a-zA-Z0-9_.-]", "-", role)
    flags = os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC
    try:
        fd = os.memfd_create(name, flags=flags)
    except (AttributeError, OSError) as error:
        _fail(f"cannot create sealed snapshot for {role}: {error}")
    try:
        os.set_inheritable(fd, False)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _snapshot_verified(
    spec: FileSpec,
    role: str,
    *,
    executable: bool = False,
) -> _SealedFile:
    source_fd = _open_readonly_regular(spec.path, role, executable=executable)
    snapshot_fd: int | None = None
    try:
        source_before = _stat_identity(os.fstat(source_fd))
        snapshot_fd = _create_memfd(role)
        actual_sha256, copied_size = _copy_and_hash(source_fd, snapshot_fd, role)
        source_after = _stat_identity(os.fstat(source_fd))
        if source_before != source_after:
            _fail(f"{role} changed while it was copied: {spec.path!r}")
        if copied_size != source_after[3]:
            _fail(
                f"{role} size changed while it was copied: expected "
                f"{source_after[3]}, copied {copied_size}"
            )
        if actual_sha256 != spec.sha256:
            _fail(
                f"{role} SHA-256 mismatch: expected {spec.sha256}, "
                f"found {actual_sha256}"
            )

        snapshot_mode = (
            EXECUTABLE_SNAPSHOT_MODE if executable else INPUT_SNAPSHOT_MODE
        )
        try:
            os.fchmod(snapshot_fd, snapshot_mode)
        except OSError as error:
            _fail(f"cannot set safe mode on {role} snapshot: {error}")
        seals = _seal_snapshot(snapshot_fd, role)

        sealed_sha256 = _sha256_fd(snapshot_fd)
        if sealed_sha256 != spec.sha256:
            _fail(
                f"sealed {role} SHA-256 mismatch: expected {spec.sha256}, "
                f"found {sealed_sha256}"
            )
        metadata = os.fstat(snapshot_fd)
        if not stat.S_ISREG(metadata.st_mode):
            _fail(f"sealed {role} snapshot is not a regular file")
        if metadata.st_size != copied_size:
            _fail(
                f"sealed {role} size mismatch: expected {copied_size}, "
                f"found {metadata.st_size}"
            )
        if stat.S_IMODE(metadata.st_mode) != snapshot_mode:
            _fail(
                f"sealed {role} mode mismatch: expected {snapshot_mode:#o}, "
                f"found {stat.S_IMODE(metadata.st_mode):#o}"
            )
        sealed = _SealedFile(
            role=role,
            fd=snapshot_fd,
            expected_sha256=spec.sha256,
            size=copied_size,
            mode=snapshot_mode,
            seals=seals,
            identity=_stat_identity(metadata),
        )
        snapshot_fd = None
        return sealed
    except BaseException:
        if snapshot_fd is not None:
            os.close(snapshot_fd)
        raise
    finally:
        os.close(source_fd)


def _require_runtime_path_immutable(path: str, role: str) -> None:
    canonical = os.path.realpath(path)
    if canonical != path:
        _fail(f"{role} path must be canonical and nonsymlinked: {path!r}")
    current = path
    while True:
        try:
            metadata = os.stat(current, follow_symlinks=False)
        except OSError as error:
            _fail(f"cannot inspect {role} path component {current!r}: {error}")
        if stat.S_ISLNK(metadata.st_mode):
            _fail(f"{role} path component must not be a symlink: {current!r}")
        try:
            writable = os.access(current, os.W_OK, effective_ids=True)
        except TypeError:  # pragma: no cover - effective_ids is present on Linux
            writable = os.access(current, os.W_OK)
        if writable:
            _fail(
                f"{role} path is writable by the executing identity: {current!r}"
            )
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent


def _open_retained_runtime(spec: FileSpec, index: int) -> _RetainedRuntime:
    role = f"runtime[{index}]"
    _require_runtime_path_immutable(spec.path, role)
    descriptor = _open_readonly_regular(spec.path, role)
    try:
        before = _stat_identity(os.fstat(descriptor))
        actual_sha256 = _sha256_fd(descriptor)
        after = _stat_identity(os.fstat(descriptor))
        if before != after:
            _fail(f"{role} changed while it was hashed")
        if actual_sha256 != spec.sha256:
            _fail(
                f"{role} SHA-256 mismatch: expected {spec.sha256}, "
                f"found {actual_sha256}"
            )
        path_metadata = os.stat(spec.path, follow_symlinks=False)
        if _stat_identity(path_metadata) != before:
            _fail(f"{role} path and retained descriptor identities differ")
        return _RetainedRuntime(
            spec=spec,
            fd=descriptor,
            identity=before,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _verify_retained_runtime(runtime: _RetainedRuntime, index: int) -> None:
    role = f"runtime[{index}]"
    _require_runtime_path_immutable(runtime.spec.path, role)
    descriptor_identity = _stat_identity(os.fstat(runtime.fd))
    if descriptor_identity != runtime.identity:
        _fail(f"retained {role} descriptor metadata changed during execution")
    if _sha256_fd(runtime.fd) != runtime.spec.sha256:
        _fail(f"retained {role} bytes changed during execution")
    path_identity = _stat_identity(
        os.stat(runtime.spec.path, follow_symlinks=False)
    )
    if path_identity != runtime.identity:
        _fail(f"{role} pathname identity changed during execution")


def _require_proc_fd_root() -> None:
    try:
        metadata = os.stat(PROC_FD_ROOT)
    except OSError as error:
        _fail(f"required proc-fd directory is unavailable: {PROC_FD_ROOT!r}: {error}")
    if not stat.S_ISDIR(metadata.st_mode):
        _fail(f"required proc-fd path is not a directory: {PROC_FD_ROOT!r}")


def _proc_path(fd: int) -> str:
    return f"{PROC_FD_ROOT}/{fd}"


def _verify_proc_binding(sealed: _SealedFile) -> None:
    path = _proc_path(sealed.fd)
    try:
        metadata = os.stat(path)
    except OSError as error:
        _fail(f"cannot resolve sealed {sealed.role} through {path!r}: {error}")
    if _stat_identity(metadata) != sealed.identity:
        _fail(f"proc-fd identity mismatch for sealed {sealed.role}: {path!r}")


def _verify_sealed_file_again(sealed: _SealedFile) -> None:
    metadata = os.fstat(sealed.fd)
    if _stat_identity(metadata) != sealed.identity:
        _fail(f"sealed {sealed.role} metadata changed before execution")
    if not stat.S_ISREG(metadata.st_mode):
        _fail(f"sealed {sealed.role} is no longer a regular file")
    if metadata.st_size != sealed.size:
        _fail(f"sealed {sealed.role} size changed before execution")
    if stat.S_IMODE(metadata.st_mode) != sealed.mode:
        _fail(f"sealed {sealed.role} mode changed before execution")
    if _get_seals(sealed.fd, sealed.role) != sealed.seals:
        _fail(f"sealed {sealed.role} seals changed before execution")
    actual_sha256 = _sha256_fd(sealed.fd)
    if actual_sha256 != sealed.expected_sha256:
        _fail(
            f"sealed {sealed.role} bytes changed before execution: "
            f"expected {sealed.expected_sha256}, found {actual_sha256}"
        )
    if _stat_identity(os.fstat(sealed.fd)) != sealed.identity:
        _fail(f"sealed {sealed.role} metadata changed during final verification")
    _verify_proc_binding(sealed)


def _verify_supplied_sealed_descriptor(
    fd: int,
    role: str,
    expected_sha256: str,
    expected_mode: int,
    maximum_bytes: int,
) -> _SealedFile:
    try:
        metadata = os.fstat(fd)
    except OSError as error:
        _fail(f"cannot inspect {role} descriptor {fd}: {error}")
    if not stat.S_ISREG(metadata.st_mode):
        _fail(f"{role} descriptor {fd} must be a regular file")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode != expected_mode:
        _fail(
            f"{role} descriptor {fd} mode mismatch: expected {expected_mode:#o}, "
            f"found {mode:#o}"
        )
    if metadata.st_size > maximum_bytes:
        _fail(f"{role} descriptor {fd} exceeds {maximum_bytes} bytes")

    seals = _get_seals(fd, f"{role} descriptor {fd}")
    required_seals = _required_memfd_seals()
    if seals & required_seals != required_seals:
        missing = required_seals & ~seals
        _fail(
            f"{role} descriptor {fd} is not fully sealed: "
            f"missing seals 0x{missing:x}"
        )

    identity = _stat_identity(metadata)
    sealed = _SealedFile(
        role=f"{role} descriptor",
        fd=fd,
        expected_sha256=expected_sha256,
        size=metadata.st_size,
        mode=expected_mode,
        seals=seals,
        identity=identity,
    )
    _verify_proc_binding(sealed)
    _verify_sealed_file_again(sealed)
    return sealed


def _inheritable_descriptors() -> set[int]:
    inherited: set[int] = set()
    try:
        entries = os.listdir(PROC_FD_ROOT)
    except OSError as error:
        _fail(f"cannot enumerate inherited descriptors: {error}")
    for entry in entries:
        if not entry.isdecimal():
            continue
        fd = int(entry)
        if fd <= 2:
            continue
        try:
            if os.get_inheritable(fd):
                inherited.add(fd)
        except OSError as error:
            if error.errno != errno.EBADF:
                _fail(f"cannot inspect descriptor {fd} inheritance: {error}")
    return inherited


def _require_exact_inherited_descriptors(required_fds: set[int]) -> None:
    inherited = _inheritable_descriptors()
    if inherited != required_fds:
        missing = sorted(required_fds - inherited)
        undeclared = sorted(inherited - required_fds)
        _fail(
            "inherited descriptor set differs from the declared bootstrap: "
            f"missing={missing}, undeclared={undeclared}"
        )


def _verify_running_helper_binding(self_descriptor: _SealedFile) -> None:
    expected_path = _proc_path(self_descriptor.fd)
    running_path = os.fspath(__file__)
    if running_path != expected_path:
        _fail(
            "running helper was not loaded from its declared descriptor: "
            f"expected {expected_path!r}, found {running_path!r}"
        )
    try:
        metadata = os.stat(running_path)
    except OSError as error:
        _fail(f"cannot inspect running helper path {running_path!r}: {error}")
    if _stat_identity(metadata) != self_descriptor.identity:
        _fail("running helper path does not identify the declared self descriptor")


def _set_only_required_inheritable(required_fds: set[int]) -> None:
    for entry in os.listdir(PROC_FD_ROOT):
        if not entry.isdecimal():
            continue
        fd = int(entry)
        if fd <= 2:
            continue
        try:
            os.set_inheritable(fd, False)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise

    for fd in required_fds:
        if fd <= 2:
            _fail("verified artifact unexpectedly occupied a standard file descriptor")
        os.set_inheritable(fd, True)
        if not os.get_inheritable(fd):
            _fail(f"failed to make required file descriptor {fd} inheritable")


def _parse_request_bytes(encoded: bytes, context: str) -> ExecRequest:
    try:
        text = encoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        _fail(f"{context} is not valid UTF-8: {error}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
        )
    except Stage0ExecError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        _fail(f"{context} is not strict JSON: {error}")
    return parse_request(value)


def load_request(path: str) -> ExecRequest:
    request_path = _absolute_path(path, "--request")
    fd = _open_readonly_regular(request_path, "request file")
    try:
        before = _stat_identity(os.fstat(fd))
        encoded = _read_fd_bytes(fd, MAX_REQUEST_BYTES, "request file")
        if _stat_identity(os.fstat(fd)) != before:
            _fail("request file changed while it was read")
    finally:
        os.close(fd)
    return _parse_request_bytes(encoded, "request file")


def load_request_from_descriptors(
    request_fd: int,
    request_sha256: str,
    self_fd: int,
    self_sha256: str,
) -> ExecRequest:
    _require_linux_memfd_sealing()
    _require_proc_fd_root()
    if request_fd == self_fd:
        _fail("request and self descriptors must be distinct")
    for fd, context in ((request_fd, "--request-fd"), (self_fd, "--self-fd")):
        if type(fd) is not int or fd <= 2:
            _fail(f"{context} must identify a descriptor greater than 2")

    expected_request_sha256 = _canonical_sha256(
        request_sha256, "--request-sha256"
    )
    expected_self_sha256 = _canonical_sha256(self_sha256, "--self-sha256")
    required_fds = {request_fd, self_fd}
    _require_exact_inherited_descriptors(required_fds)

    self_descriptor = _verify_supplied_sealed_descriptor(
        self_fd,
        "self",
        expected_self_sha256,
        EXECUTABLE_SNAPSHOT_MODE,
        MAX_HELPER_BYTES,
    )
    _verify_running_helper_binding(self_descriptor)
    request_descriptor = _verify_supplied_sealed_descriptor(
        request_fd,
        "request",
        expected_request_sha256,
        INPUT_SNAPSHOT_MODE,
        MAX_REQUEST_BYTES,
    )
    encoded = _read_fd_bytes(request_fd, MAX_REQUEST_BYTES, "request descriptor")

    # Recheck every bootstrap property after reading and immediately before JSON
    # parsing. The descriptors are sealed, so no pathname is reopened here.
    _verify_sealed_file_again(self_descriptor)
    _verify_running_helper_binding(self_descriptor)
    _verify_sealed_file_again(request_descriptor)
    _require_exact_inherited_descriptors(required_fds)
    return _parse_request_bytes(encoded, "request descriptor")


def execute_request(
    request: ExecRequest,
    *,
    execve: Callable[[str, Sequence[str], Mapping[str, str]], Any] = os.execve,
    popen: Callable[..., Any] = subprocess.Popen,
) -> int | None:
    _require_linux_memfd_sealing()
    _require_proc_fd_root()
    sealed_files: list[_SealedFile] = []
    retained_runtime: list[_RetainedRuntime] = []
    try:
        executable = _snapshot_verified(
            request.executable, "executable", executable=True
        )
        sealed_files.append(executable)

        placeholder_paths: dict[str, str] = {}
        for index, input_spec in enumerate(request.inputs):
            sealed = _snapshot_verified(input_spec.file, f"input[{index}]")
            sealed_files.append(sealed)
            placeholder_paths[input_spec.placeholder] = _proc_path(sealed.fd)

        for index, runtime_spec in enumerate(request.runtime):
            retained_runtime.append(
                _open_retained_runtime(runtime_spec, index)
            )

        argv = [placeholder_paths.get(argument, argument) for argument in request.argv]
        required_fds = {sealed.fd for sealed in sealed_files}
        _set_only_required_inheritable(required_fds)

        for sealed in sealed_files:
            _verify_sealed_file_again(sealed)

        for index, runtime in enumerate(retained_runtime):
            _verify_retained_runtime(runtime, index)

        if retained_runtime:
            process = popen(
                argv,
                executable=_proc_path(executable.fd),
                env=dict(request.environment),
                close_fds=True,
                pass_fds=tuple(sorted(required_fds)),
            )
            return_code = process.wait()
            for index, runtime in enumerate(retained_runtime):
                _verify_retained_runtime(runtime, index)
            for sealed in sealed_files:
                _verify_sealed_file_again(sealed)
            if return_code < 0:
                return 128 + min(-return_code, 127)
            return return_code

        execve(
            _proc_path(executable.fd),
            argv,
            dict(request.environment),
        )
        _fail("os.execve returned unexpectedly")
    finally:
        for runtime in reversed(retained_runtime):
            try:
                os.close(runtime.fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
        for sealed in reversed(sealed_files):
            try:
                os.close(sealed.fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute one T11 Stage 0A command from sealed memfd snapshots.",
        allow_abbrev=False,
    )
    request_source = parser.add_mutually_exclusive_group(required=True)
    request_source.add_argument(
        "--request", help="absolute strict JSON request path (compatibility mode)"
    )
    request_source.add_argument(
        "--request-fd",
        type=_descriptor_number,
        help="sealed inherited request descriptor (production mode)",
    )
    parser.add_argument("--request-sha256", help="SHA-256 of --request-fd bytes")
    parser.add_argument(
        "--self-fd",
        type=_descriptor_number,
        help="sealed inherited descriptor from which this helper was loaded",
    )
    parser.add_argument("--self-sha256", help="SHA-256 of --self-fd bytes")
    return parser


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    descriptor_fields = {
        "--request-sha256": arguments.request_sha256,
        "--self-fd": arguments.self_fd,
        "--self-sha256": arguments.self_sha256,
    }
    if arguments.request_fd is None:
        supplied = sorted(name for name, value in descriptor_fields.items() if value is not None)
        if supplied:
            parser.error(
                "descriptor verification options require --request-fd: "
                + ", ".join(supplied)
            )
    else:
        missing = sorted(name for name, value in descriptor_fields.items() if value is None)
        if missing:
            parser.error(
                "--request-fd requires descriptor verification options: "
                + ", ".join(missing)
            )
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_arguments(argv)
    try:
        if arguments.request_fd is None:
            request = load_request(arguments.request)
        else:
            request = load_request_from_descriptors(
                arguments.request_fd,
                arguments.request_sha256,
                arguments.self_fd,
                arguments.self_sha256,
            )
        result = execute_request(request)
        if result is not None:
            return result
    except (Stage0ExecError, OSError) as error:
        print(f"exec_t11_stage0a: rejected: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
