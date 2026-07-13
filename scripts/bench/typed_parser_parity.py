#!/usr/bin/env python3
"""Prepare, execute, and audit fail-closed typed parser parity campaigns."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, NamedTuple


PREPARE_SCHEMA = "euf-viper.typed-parser-parity-prepare.v3"
WORK_SCHEMA = "euf-viper.typed-parser-parity-work.v3"
RECORD_SCHEMA = "euf-viper.typed-parser-parity-record.v3"
PARSER_SCHEMA = "euf-viper.typed-parser-parity.v1"
AUDIT_SCHEMA = "euf-viper.typed-parser-parity-audit.v3"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MD5_RE = re.compile(r"[0-9a-f]{32}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")
FINGERPRINT_RE = re.compile(r"[0-9a-f]{16}")
PYTHON_VERSION_RE = re.compile(
    r"Python [0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?"
)
DIAGNOSTIC_LIMIT = 4096
BYTE_BINDING = "single-open-buffer.v1"
EXECUTABLE_BINDING = "inherited-descriptor.v1"
PRIVATE_COPY_BINDING = "private-byte-copy.v1"
PYTHON_PATH_ENV = "EUF_VIPER_PYTHON"
PYTHON_SHA256_ENV = "EUF_VIPER_PYTHON_SHA256"
PYTHON_VERSION_ENV = "EUF_VIPER_PYTHON_VERSION"
PARSER_ENVIRONMENT: dict[str, str | None] = {
    "EUF_VIPER_SCOPED_LET": "auto",
    "EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT": "1024",
    "EUF_VIPER_PROFILE": None,
}
PARSER_BOOLEAN_FIELDS = {
    "tree_well_sorted": True,
    "stream_well_sorted": True,
    "fallback": False,
}
PARSER_COUNT_FIELDS = (
    "symbols",
    "sorts",
    "functions",
    "terms",
    "applications",
    "assertions",
    "bool_data_terms",
    "unsupported_diagnostics",
)
PARSER_KEYS = frozenset(
    {
        "schema",
        "status",
        "snapshot_fnv1a64",
        *PARSER_BOOLEAN_FIELDS,
        *PARSER_COUNT_FIELDS,
    }
)
MANIFEST_KEYS = frozenset(
    {
        "archive_md5",
        "bytes",
        "id",
        "logic",
        "path",
        "relative_path",
        "sha256",
        "source_doi",
        "source_url",
        "status",
    }
)
PYTHON_IDENTITY_KEYS = frozenset({"path", "sha256", "version"})
FILE_BINDING_KEYS = frozenset({"path", "sha256"})
BINARY_BINDING_KEYS = frozenset({"path", "sha256", "bytes", "execution"})
PREFLIGHT_BINDING_KEYS = frozenset(
    {
        "path",
        "sha256",
        "source_path",
        "source_sha256",
        "source_bytes",
        "elapsed_seconds",
    }
)
PREPARE_KEYS = frozenset(
    {
        "schema",
        "byte_binding",
        "revision",
        "repository_root",
        "expected_sources",
        "source_count",
        "shard_count",
        "timeout_seconds",
        "parser_environment",
        "python",
        "manifest",
        "binary",
        "tool",
        "preflight",
        "workset",
    }
)
WORK_KEYS = frozenset(
    {
        "schema",
        "byte_binding",
        "sequence",
        "manifest_line",
        "relative_path",
        "source_path",
        "source_sha256",
        "source_bytes",
    }
)
RECORD_KEYS = frozenset(
    {
        "schema",
        "byte_binding",
        "sequence",
        "shard",
        "revision",
        "parser_environment",
        "python",
        "binary",
        "relative_path",
        "source_sha256",
        "opened_source_sha256",
        "opened_source_bytes",
        "status",
        "exit_code",
        "elapsed_seconds",
        "reason",
        "stdout_sha256",
        "stderr_sha256",
        "stdout_excerpt",
        "stderr_excerpt",
        "parser",
    }
)
AUDIT_KEYS = frozenset(
    {
        "schema",
        "byte_binding",
        "status",
        "revision",
        "source_count",
        "expected_sources",
        "shard_count",
        "parser_environment",
        "python",
        "binary",
        "counts",
        "gate",
        "artifacts",
    }
)
COUNT_KEYS = frozenset({"match", "fallback", "mismatch", "error"})
GATE_KEYS = frozenset(
    {
        "all_tree_parses_succeeded",
        "all_typed_snapshots_matched",
        "zero_fallbacks",
        "all_sources_covered",
        "passed",
    }
)
AUDIT_ARTIFACT_KEYS = frozenset(
    {"prepare_sha256", "workset_sha256", "records_sha256", "shard_sha256"}
)


class CampaignError(ValueError):
    """Raised when an input or artifact violates the parity contract."""


class CapturedArtifact(NamedTuple):
    path: Path
    content: bytes
    sha256: str


class PreparedCampaign(NamedTuple):
    metadata: dict[str, Any]
    prepare_artifact: CapturedArtifact
    workset: list[dict[str, Any]]
    workset_artifact: CapturedArtifact


class ExecutableFingerprint(NamedTuple):
    device: int
    inode: int
    size: int
    mode: int
    modified_ns: int


class OpenedExecutable(NamedTuple):
    descriptor: int
    path: Path
    execution_path: str
    binding: dict[str, Any]
    fingerprint: ExecutableFingerprint
    cleanup_directory: Path | None


class ParserExecution(NamedTuple):
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float
    timed_out: bool


def validate_parser_environment() -> dict[str, str | None]:
    for name, expected in PARSER_ENVIRONMENT.items():
        if expected is None:
            if name in os.environ:
                raise CampaignError(
                    f"parser environment drift: {name} must be unset"
                )
            continue
        actual = os.environ.get(name)
        if actual != expected:
            raise CampaignError(
                f"parser environment drift: {name} must be {expected!r}, "
                f"got {actual!r}"
            )
    return dict(PARSER_ENVIRONMENT)


def validate_python_identity() -> dict[str, str]:
    configured = os.environ.get(PYTHON_PATH_ENV)
    expected_sha256 = os.environ.get(PYTHON_SHA256_ENV)
    expected_version = os.environ.get(PYTHON_VERSION_ENV)
    if not configured:
        raise CampaignError(f"python identity drift: {PYTHON_PATH_ENV} must be set")
    configured_path = Path(configured)
    if not configured_path.is_absolute():
        raise CampaignError(
            f"python identity drift: {PYTHON_PATH_ENV} must be an absolute path"
        )
    if expected_sha256 is None or SHA256_RE.fullmatch(expected_sha256) is None:
        raise CampaignError(
            f"python identity drift: {PYTHON_SHA256_ENV} must be lowercase SHA-256"
        )
    if expected_version is None or PYTHON_VERSION_RE.fullmatch(expected_version) is None:
        raise CampaignError(
            f"python identity drift: {PYTHON_VERSION_ENV} is malformed"
        )
    try:
        configured_resolved = configured_path.resolve(strict=True)
        executing_resolved = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise CampaignError(
            f"python identity drift: cannot resolve interpreter: {error}"
        ) from error
    if configured_path != configured_resolved:
        raise CampaignError(
            "python identity drift: configured interpreter must be its canonical realpath"
        )
    if not configured_resolved.is_file() or not os.access(configured_resolved, os.X_OK):
        raise CampaignError(
            f"python identity drift: interpreter is not executable: {configured_path}"
        )
    if configured_resolved != executing_resolved:
        raise CampaignError(
            "python identity drift: configured interpreter does not execute the harness"
        )
    try:
        actual_sha256 = sha256_file(configured_resolved)
    except OSError as error:
        raise CampaignError(f"python identity drift: cannot hash interpreter: {error}") from error
    if actual_sha256 != expected_sha256:
        raise CampaignError(
            f"python identity drift: hash mismatch for {configured_resolved}"
        )
    actual_version = f"Python {platform.python_version()}"
    if actual_version != expected_version:
        raise CampaignError(
            "python identity drift: "
            f"version mismatch, expected {expected_version!r}, got {actual_version!r}"
        )
    return {
        "path": str(configured_resolved),
        "sha256": actual_sha256,
        "version": actual_version,
    }


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def reject_nonfinite_number(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


def strict_json(text: str, *, where: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_number,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise CampaignError(f"{where}: malformed JSON: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return (serialized + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CampaignError(f"cannot serialize strict JSON: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def executable_fingerprint(descriptor: int) -> ExecutableFingerprint:
    metadata = os.fstat(descriptor)
    return ExecutableFingerprint(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mode=metadata.st_mode,
        modified_ns=metadata.st_mtime_ns,
    )


def sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def assert_executable_unchanged(executable: OpenedExecutable) -> None:
    if executable_fingerprint(executable.descriptor) != executable.fingerprint:
        raise CampaignError("opened parser executable changed after validation")


def executable_binding_contract() -> str:
    if sys.platform.startswith("linux"):
        return EXECUTABLE_BINDING
    return PRIVATE_COPY_BINDING


def write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise CampaignError("short write while materializing parser executable")
        offset += written


def private_execution_copy(descriptor: int, size: int, digest: str) -> tuple[str, Path]:
    directory = Path(tempfile.mkdtemp(prefix="euf-viper-parser-exec-"))
    execution_path = directory / "parser"
    output = -1
    try:
        output = os.open(
            execution_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o500,
        )
        offset = 0
        copied_digest = hashlib.sha256()
        while offset < size:
            chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
            if not chunk:
                raise CampaignError("parser executable became short while copied")
            write_all(output, chunk)
            copied_digest.update(chunk)
            offset += len(chunk)
        if os.pread(descriptor, 1, size):
            raise CampaignError("parser executable grew while copied")
        os.fsync(output)
        os.close(output)
        output = -1
        execution_path.chmod(0o500)
        directory.chmod(0o500)
        if copied_digest.hexdigest() != digest:
            raise CampaignError("private parser execution copy hash mismatch")
        return str(execution_path), directory
    except BaseException:
        if output >= 0:
            os.close(output)
        directory.chmod(0o700)
        execution_path.unlink(missing_ok=True)
        directory.rmdir()
        raise


def descriptor_execution_path(
    descriptor: int, size: int, digest: str
) -> tuple[str, Path | None]:
    if sys.platform.startswith("linux"):
        return f"/proc/self/fd/{descriptor}", None
    return private_execution_copy(descriptor, size, digest)


@contextlib.contextmanager
def open_verified_executable(
    path: Path, expected: dict[str, Any] | None = None
) -> Iterator[OpenedExecutable]:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "pread"):
        raise CampaignError("platform lacks no-follow descriptor verification")
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"cannot resolve parser executable {path}: {error}") from error
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(canonical, flags)
    except OSError as error:
        raise CampaignError(f"cannot open parser executable {canonical}: {error}") from error
    try:
        before = executable_fingerprint(descriptor)
        if not stat.S_ISREG(before.mode):
            raise CampaignError("parser executable is not a regular file")
        if before.mode & 0o111 == 0:
            raise CampaignError("parser executable has no execute bit")
        digest = sha256_descriptor(descriptor)
        after = executable_fingerprint(descriptor)
        if before != after:
            raise CampaignError("parser executable changed while it was hashed")
        binding: dict[str, Any] = {
            "path": str(canonical),
            "sha256": digest,
            "bytes": before.size,
            "execution": executable_binding_contract(),
        }
        validate_binary_binding(binding, where="opened parser executable")
        if expected is not None:
            validate_binary_binding(expected, where="prepared parser executable")
            if binding != expected:
                raise CampaignError("prepared parser executable identity mismatch")
        execution_path, cleanup_directory = descriptor_execution_path(
            descriptor, before.size, digest
        )
        executable = OpenedExecutable(
            descriptor=descriptor,
            path=canonical,
            execution_path=execution_path,
            binding=binding,
            fingerprint=before,
            cleanup_directory=cleanup_directory,
        )
        yield executable
        assert_executable_unchanged(executable)
    finally:
        if "cleanup_directory" in locals() and cleanup_directory is not None:
            cleanup_directory.chmod(0o700)
            (cleanup_directory / "parser").unlink(missing_ok=True)
            cleanup_directory.rmdir()
        os.close(descriptor)


def execute_parser(
    executable: OpenedExecutable, source: bytes, timeout_seconds: int
) -> ParserExecution:
    assert_executable_unchanged(executable)
    started = time.monotonic_ns()
    timed_out = False
    try:
        completed = subprocess.run(
            [executable.execution_path, "parse-check", "-"],
            input=source,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            env={**os.environ, "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            pass_fds=(executable.descriptor,),
        )
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code: int | None = completed.returncode
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        exit_code = None
        timed_out = True
    except OSError as error:
        raise CampaignError(f"cannot execute opened parser descriptor: {error}") from error
    finally:
        elapsed_seconds = (time.monotonic_ns() - started) / 1_000_000_000.0
        assert_executable_unchanged(executable)
    if not math.isfinite(elapsed_seconds) or elapsed_seconds < 0:
        raise CampaignError("parser execution produced an invalid elapsed time")
    return ParserExecution(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_seconds=elapsed_seconds,
        timed_out=timed_out,
    )


def capture_artifact(path: Path) -> CapturedArtifact:
    try:
        content = path.read_bytes()
    except OSError as error:
        raise CampaignError(f"cannot read {path}: {error}") from error
    return CapturedArtifact(path=path, content=content, sha256=sha256_bytes(content))


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path: Path, value: Any) -> CapturedArtifact:
    content = canonical_bytes(value)
    atomic_write(path, content)
    return CapturedArtifact(path=path, content=content, sha256=sha256_bytes(content))


def atomic_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> CapturedArtifact:
    content = b"".join(canonical_bytes(row) for row in rows)
    atomic_write(path, content)
    return CapturedArtifact(path=path, content=content, sha256=sha256_bytes(content))


def positive_integer(value: str) -> int:
    if not value.isascii() or not value.isdigit() or value.startswith("0"):
        raise argparse.ArgumentTypeError("must be a canonical positive integer")
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def nonnegative_integer(value: str) -> int:
    if value == "0":
        return 0
    return positive_integer(value)


def require_revision(value: str) -> str:
    if REVISION_RE.fullmatch(value) is None:
        raise CampaignError("revision must be a lowercase 40-hex commit hash")
    return value


def require_exact_keys(
    value: dict[str, Any], expected: frozenset[str], *, where: str
) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise CampaignError(
            f"{where}: fields differ: missing={missing!r}, extra={extra!r}"
        )


def require_string(value: Any, *, where: str, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        raise CampaignError(f"{where}: expected a nonempty string")
    return value


def require_bool(value: Any, *, where: str) -> bool:
    if type(value) is not bool:
        raise CampaignError(f"{where}: expected a Boolean")
    return value


def require_integer(
    value: Any, *, where: str, minimum: int | None = None
) -> int:
    if type(value) is not int or (minimum is not None and value < minimum):
        qualifier = "" if minimum is None else f" >= {minimum}"
        raise CampaignError(f"{where}: expected an integer{qualifier}")
    return value


def require_optional_integer(value: Any, *, where: str) -> int | None:
    if value is None:
        return None
    return require_integer(value, where=where)


def require_nonnegative_float(value: Any, *, where: str) -> float:
    if type(value) is not float or not math.isfinite(value) or value < 0:
        raise CampaignError(f"{where}: expected a finite nonnegative float")
    return value


def require_optional_nonnegative_float(value: Any, *, where: str) -> float | None:
    if value is None:
        return None
    return require_nonnegative_float(value, where=where)


def require_sha256(value: Any, *, where: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise CampaignError(f"{where}: expected lowercase SHA-256")
    return value


def require_absolute_path(value: Any, *, where: str) -> str:
    text = require_string(value, where=where)
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise CampaignError(f"{where}: expected a normalized absolute path")
    return text


def validate_parser_environment_object(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, frozenset(PARSER_ENVIRONMENT), where=where)
    for name, expected in PARSER_ENVIRONMENT.items():
        if value[name] != expected or (
            expected is not None and type(value[name]) is not str
        ):
            raise CampaignError(f"{where}: invalid parser setting {name}")


def validate_python_binding(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, PYTHON_IDENTITY_KEYS, where=where)
    require_absolute_path(value["path"], where=f"{where}.path")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    version = require_string(value["version"], where=f"{where}.version")
    if PYTHON_VERSION_RE.fullmatch(version) is None:
        raise CampaignError(f"{where}.version: malformed Python version")


def validate_file_binding(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, FILE_BINDING_KEYS, where=where)
    require_absolute_path(value["path"], where=f"{where}.path")
    require_sha256(value["sha256"], where=f"{where}.sha256")


def validate_binary_binding(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, BINARY_BINDING_KEYS, where=where)
    require_absolute_path(value["path"], where=f"{where}.path")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    require_integer(value["bytes"], where=f"{where}.bytes", minimum=1)
    if value["execution"] != executable_binding_contract():
        raise CampaignError(f"{where}.execution: unexpected execution contract")


def validate_preflight_binding(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, PREFLIGHT_BINDING_KEYS, where=where)
    require_absolute_path(value["path"], where=f"{where}.path")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    require_absolute_path(value["source_path"], where=f"{where}.source_path")
    require_sha256(value["source_sha256"], where=f"{where}.source_sha256")
    require_integer(
        value["source_bytes"], where=f"{where}.source_bytes", minimum=0
    )
    require_nonnegative_float(
        value["elapsed_seconds"], where=f"{where}.elapsed_seconds"
    )


def validate_manifest_row(value: Any, *, where: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CampaignError(f"{where}: row is not an object")
    require_exact_keys(value, MANIFEST_KEYS, where=where)
    archive_md5 = require_string(value["archive_md5"], where=f"{where}.archive_md5")
    if MD5_RE.fullmatch(archive_md5) is None:
        raise CampaignError(f"{where}.archive_md5: expected lowercase MD5")
    require_integer(value["bytes"], where=f"{where}.bytes", minimum=0)
    require_integer(value["id"], where=f"{where}.id", minimum=0)
    if value["logic"] != "QF_UF":
        raise CampaignError(f"{where}.logic: expected QF_UF")
    require_string(value["path"], where=f"{where}.path")
    require_string(value["relative_path"], where=f"{where}.relative_path")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    require_string(value["source_doi"], where=f"{where}.source_doi")
    require_string(value["source_url"], where=f"{where}.source_url")
    if value["status"] not in {"sat", "unsat"} or type(value["status"]) is not str:
        raise CampaignError(f"{where}.status: expected sat or unsat")
    return value


def validate_parser_object(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, PARSER_KEYS, where=where)
    if value["schema"] != PARSER_SCHEMA or type(value["schema"]) is not str:
        raise CampaignError(f"{where}.schema: unexpected parser schema")
    if value["status"] != "match" or type(value["status"]) is not str:
        raise CampaignError(f"{where}.status: expected match")
    for key, expected in PARSER_BOOLEAN_FIELDS.items():
        if type(value[key]) is not bool or value[key] is not expected:
            raise CampaignError(f"{where}.{key}: expected {expected!r}")
    fingerprint = value["snapshot_fnv1a64"]
    if type(fingerprint) is not str or FINGERPRINT_RE.fullmatch(fingerprint) is None:
        raise CampaignError(f"{where}.snapshot_fnv1a64: malformed fingerprint")
    for key in PARSER_COUNT_FIELDS:
        require_integer(value[key], where=f"{where}.{key}", minimum=0)


def validate_prepare_object(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, PREPARE_KEYS, where=where)
    if value["schema"] != PREPARE_SCHEMA or type(value["schema"]) is not str:
        raise CampaignError(f"{where}.schema: unexpected schema")
    if value["byte_binding"] != BYTE_BINDING:
        raise CampaignError(f"{where}.byte_binding: unexpected contract")
    require_revision(require_string(value["revision"], where=f"{where}.revision"))
    require_absolute_path(value["repository_root"], where=f"{where}.repository_root")
    expected_sources = require_integer(
        value["expected_sources"], where=f"{where}.expected_sources", minimum=1
    )
    source_count = require_integer(
        value["source_count"], where=f"{where}.source_count", minimum=1
    )
    if source_count != expected_sources:
        raise CampaignError(f"{where}: prepared source counts differ")
    require_integer(value["shard_count"], where=f"{where}.shard_count", minimum=1)
    require_integer(
        value["timeout_seconds"], where=f"{where}.timeout_seconds", minimum=1
    )
    validate_parser_environment_object(
        value["parser_environment"], where=f"{where}.parser_environment"
    )
    validate_python_binding(value["python"], where=f"{where}.python")
    validate_file_binding(value["manifest"], where=f"{where}.manifest")
    validate_binary_binding(value["binary"], where=f"{where}.binary")
    validate_file_binding(value["tool"], where=f"{where}.tool")
    validate_preflight_binding(value["preflight"], where=f"{where}.preflight")
    validate_file_binding(value["workset"], where=f"{where}.workset")


def validate_work_row(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, WORK_KEYS, where=where)
    if value["schema"] != WORK_SCHEMA or type(value["schema"]) is not str:
        raise CampaignError(f"{where}.schema: unexpected schema")
    if value["byte_binding"] != BYTE_BINDING:
        raise CampaignError(f"{where}.byte_binding: unexpected contract")
    require_integer(value["sequence"], where=f"{where}.sequence", minimum=0)
    line = require_integer(
        value["manifest_line"], where=f"{where}.manifest_line", minimum=1
    )
    safe_relative_path(value["relative_path"], line=line)
    require_absolute_path(value["source_path"], where=f"{where}.source_path")
    require_sha256(value["source_sha256"], where=f"{where}.source_sha256")
    require_integer(value["source_bytes"], where=f"{where}.source_bytes", minimum=0)


def validate_optional_excerpt(value: Any, *, where: str) -> None:
    if value is None:
        return
    text = require_string(value, where=where, nonempty=True)
    if len(text) > DIAGNOSTIC_LIMIT:
        raise CampaignError(f"{where}: diagnostic exceeds limit")


def validate_record_row(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, RECORD_KEYS, where=where)
    if value["schema"] != RECORD_SCHEMA or type(value["schema"]) is not str:
        raise CampaignError(f"{where}.schema: unexpected schema")
    if value["byte_binding"] != BYTE_BINDING:
        raise CampaignError(f"{where}.byte_binding: unexpected contract")
    require_integer(value["sequence"], where=f"{where}.sequence", minimum=0)
    require_integer(value["shard"], where=f"{where}.shard", minimum=0)
    require_revision(require_string(value["revision"], where=f"{where}.revision"))
    validate_parser_environment_object(
        value["parser_environment"], where=f"{where}.parser_environment"
    )
    validate_python_binding(value["python"], where=f"{where}.python")
    validate_binary_binding(value["binary"], where=f"{where}.binary")
    require_string(value["relative_path"], where=f"{where}.relative_path")
    require_sha256(value["source_sha256"], where=f"{where}.source_sha256")
    opened_hash = value["opened_source_sha256"]
    opened_bytes = value["opened_source_bytes"]
    if (opened_hash is None) != (opened_bytes is None):
        raise CampaignError(f"{where}: incomplete opened-source binding")
    if opened_hash is not None:
        require_sha256(opened_hash, where=f"{where}.opened_source_sha256")
        require_integer(
            opened_bytes, where=f"{where}.opened_source_bytes", minimum=0
        )
    status_value = value["status"]
    if type(status_value) is not str or status_value not in COUNT_KEYS:
        raise CampaignError(f"{where}.status: unexpected status")
    exit_code = require_optional_integer(value["exit_code"], where=f"{where}.exit_code")
    elapsed = require_optional_nonnegative_float(
        value["elapsed_seconds"], where=f"{where}.elapsed_seconds"
    )
    reason = value["reason"]
    if reason is not None:
        require_string(reason, where=f"{where}.reason")
    require_sha256(value["stdout_sha256"], where=f"{where}.stdout_sha256")
    require_sha256(value["stderr_sha256"], where=f"{where}.stderr_sha256")
    validate_optional_excerpt(value["stdout_excerpt"], where=f"{where}.stdout_excerpt")
    validate_optional_excerpt(value["stderr_excerpt"], where=f"{where}.stderr_excerpt")
    if status_value == "match":
        if exit_code != 0 or elapsed is None or reason is not None:
            raise CampaignError(f"{where}: matching row has invalid execution fields")
        if opened_hash is None:
            raise CampaignError(f"{where}: matching row lacks opened-source binding")
        if value["stdout_excerpt"] is not None:
            raise CampaignError(f"{where}: matching row has a stdout diagnostic")
        validate_parser_object(value["parser"], where=f"{where}.parser")
    else:
        if type(reason) is not str or value["parser"] is not None:
            raise CampaignError(f"{where}: failing row has invalid diagnostic fields")
        if status_value in {"fallback", "mismatch"} and (
            opened_hash is None or elapsed is None
        ):
            raise CampaignError(
                f"{where}: parser-classified failure lacks execution binding"
            )
    if exit_code is not None and elapsed is None:
        raise CampaignError(f"{where}: exit code lacks execution timing")


def validate_audit_object(value: Any, *, where: str) -> None:
    if type(value) is not dict:
        raise CampaignError(f"{where}: expected an object")
    require_exact_keys(value, AUDIT_KEYS, where=where)
    if value["schema"] != AUDIT_SCHEMA or type(value["schema"]) is not str:
        raise CampaignError(f"{where}.schema: unexpected schema")
    if value["byte_binding"] != BYTE_BINDING:
        raise CampaignError(f"{where}.byte_binding: unexpected contract")
    status_value = value["status"]
    if type(status_value) is not str or status_value not in {"completed", "rejected"}:
        raise CampaignError(f"{where}.status: unexpected status")
    require_revision(require_string(value["revision"], where=f"{where}.revision"))
    source_count = require_integer(
        value["source_count"], where=f"{where}.source_count", minimum=1
    )
    expected_sources = require_integer(
        value["expected_sources"], where=f"{where}.expected_sources", minimum=1
    )
    shard_count = require_integer(
        value["shard_count"], where=f"{where}.shard_count", minimum=1
    )
    if source_count != expected_sources:
        raise CampaignError(f"{where}: audited source counts differ")
    validate_parser_environment_object(
        value["parser_environment"], where=f"{where}.parser_environment"
    )
    validate_python_binding(value["python"], where=f"{where}.python")
    validate_binary_binding(value["binary"], where=f"{where}.binary")
    counts = value["counts"]
    if type(counts) is not dict:
        raise CampaignError(f"{where}.counts: expected an object")
    require_exact_keys(counts, COUNT_KEYS, where=f"{where}.counts")
    for key in COUNT_KEYS:
        require_integer(counts[key], where=f"{where}.counts.{key}", minimum=0)
    if sum(counts.values()) != source_count:
        raise CampaignError(f"{where}: status counts do not cover all sources")
    gate = value["gate"]
    if type(gate) is not dict:
        raise CampaignError(f"{where}.gate: expected an object")
    require_exact_keys(gate, GATE_KEYS, where=f"{where}.gate")
    for key in GATE_KEYS:
        require_bool(gate[key], where=f"{where}.gate.{key}")
    expected_passed = counts == {
        "match": expected_sources,
        "fallback": 0,
        "mismatch": 0,
        "error": 0,
    }
    expected_gate = {
        "all_tree_parses_succeeded": counts["error"] == 0,
        "all_typed_snapshots_matched": counts["mismatch"] == 0,
        "zero_fallbacks": counts["fallback"] == 0,
        "all_sources_covered": source_count == expected_sources,
        "passed": expected_passed,
    }
    if gate != expected_gate:
        raise CampaignError(f"{where}: gate does not follow audited counts")
    if (status_value == "completed") is not expected_passed:
        raise CampaignError(f"{where}: status and gate disagree")
    artifacts = value["artifacts"]
    if type(artifacts) is not dict:
        raise CampaignError(f"{where}.artifacts: expected an object")
    require_exact_keys(artifacts, AUDIT_ARTIFACT_KEYS, where=f"{where}.artifacts")
    for key in ("prepare_sha256", "workset_sha256", "records_sha256"):
        require_sha256(artifacts[key], where=f"{where}.artifacts.{key}")
    shards = artifacts["shard_sha256"]
    if type(shards) is not dict:
        raise CampaignError(f"{where}.artifacts.shard_sha256: expected an object")
    expected_shard_keys = {f"{index:05d}" for index in range(shard_count)}
    if set(shards) != expected_shard_keys:
        raise CampaignError(
            f"{where}.artifacts.shard_sha256: shard set does not match shard_count"
        )
    for key, digest in shards.items():
        if type(key) is not str or re.fullmatch(r"[0-9]{5}", key) is None:
            raise CampaignError(f"{where}.artifacts.shard_sha256: malformed key")
        require_sha256(digest, where=f"{where}.artifacts.shard_sha256.{key}")


def validate_schema_object(value: Any, *, schema: str, where: str) -> None:
    if schema == PREPARE_SCHEMA:
        validate_prepare_object(value, where=where)
    elif schema == WORK_SCHEMA:
        validate_work_row(value, where=where)
    elif schema == RECORD_SCHEMA:
        validate_record_row(value, where=where)
    elif schema == AUDIT_SCHEMA:
        validate_audit_object(value, where=where)
    else:
        raise CampaignError(f"{where}: no strict validator for schema {schema!r}")


def safe_relative_path(value: Any, *, line: int) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CampaignError(f"manifest line {line}: invalid relative_path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise CampaignError(f"manifest line {line}: unsafe relative_path {value!r}")
    if pure.suffix.lower() != ".smt2":
        raise CampaignError(f"manifest line {line}: source is not an .smt2 file")
    return pure.as_posix()


def resolve_source(value: Any, repository_root: Path, *, line: int) -> Path:
    if not isinstance(value, str) or not value:
        raise CampaignError(f"manifest line {line}: path must be a nonempty string")
    path = Path(value)
    if not path.is_absolute():
        path = repository_root / path
    try:
        path = path.resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"manifest line {line}: cannot resolve {path}: {error}") from error
    if not path.is_file():
        raise CampaignError(f"manifest line {line}: source is not a file: {path}")
    return path


def load_manifest(
    manifest: Path, repository_root: Path
) -> tuple[list[dict[str, Any]], CapturedArtifact]:
    manifest_artifact = capture_artifact(manifest)
    try:
        text = manifest_artifact.content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CampaignError(f"cannot read UTF-8 manifest {manifest}: {error}") from error
    lines = text.splitlines()
    if not lines:
        raise CampaignError("manifest has no rows")

    rows: list[dict[str, Any]] = []
    seen_ids: set[int | str] = set()
    seen_paths: set[str] = set()
    seen_sources: set[Path] = set()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise CampaignError(f"manifest line {line_number}: blank JSONL row")
        value = strict_json(line, where=f"manifest line {line_number}")
        value = validate_manifest_row(value, where=f"manifest line {line_number}")
        record_id = value["id"]
        if record_id in seen_ids:
            raise CampaignError(f"manifest line {line_number}: duplicate id")
        seen_ids.add(record_id)

        relative = safe_relative_path(value["relative_path"], line=line_number)
        if relative in seen_paths:
            raise CampaignError(f"manifest line {line_number}: duplicate relative_path")
        seen_paths.add(relative)
        source = resolve_source(value["path"], repository_root, line=line_number)
        if source in seen_sources:
            raise CampaignError(f"manifest line {line_number}: duplicate source path")
        seen_sources.add(source)
        relative_parts = PurePosixPath(relative).parts
        if tuple(source.parts[-len(relative_parts) :]) != relative_parts:
            raise CampaignError(
                f"manifest line {line_number}: source path does not end in {relative!r}"
            )

        source_artifact = capture_artifact(source)
        try:
            source_artifact.content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CampaignError(
                f"manifest line {line_number}: source is not UTF-8: {error}"
            ) from error
        source_hash = source_artifact.sha256
        if value["sha256"] != source_hash:
            raise CampaignError(f"manifest line {line_number}: source hash mismatch")
        if value["bytes"] != len(source_artifact.content):
            raise CampaignError(f"manifest line {line_number}: byte count mismatch")
        rows.append(
            {
                "manifest_line": line_number,
                "relative_path": relative,
                "source_path": str(source),
                "source_sha256": source_hash,
                "source_bytes": len(source_artifact.content),
            }
        )
    rows.sort(key=lambda row: row["relative_path"])
    return rows, manifest_artifact


def prepare_campaign(args: argparse.Namespace) -> None:
    parser_environment = validate_parser_environment()
    python_identity = validate_python_identity()
    revision = require_revision(args.revision)
    repository_root = args.repository_root.resolve(strict=True)
    manifest = args.manifest.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    preflight_source = args.preflight_source.resolve(strict=True)
    tool = Path(__file__).resolve(strict=True)
    rows, manifest_artifact = load_manifest(manifest, repository_root)
    if len(rows) != args.expected_sources:
        raise CampaignError(
            f"source cardinality mismatch: expected {args.expected_sources}, got {len(rows)}"
        )
    work_rows = [
        {
            "schema": WORK_SCHEMA,
            "byte_binding": BYTE_BINDING,
            "sequence": sequence,
            **row,
        }
        for sequence, row in enumerate(rows)
    ]
    for sequence, row in enumerate(work_rows):
        validate_work_row(row, where=f"generated work row {sequence}")
    workset = args.output_root / "workset.jsonl"
    workset_artifact = atomic_jsonl(workset, work_rows)
    preflight_source_artifact = capture_artifact(preflight_source)
    try:
        preflight_source_artifact.content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CampaignError(f"preflight source is not UTF-8: {error}") from error
    with open_verified_executable(binary) as executable:
        execution = execute_parser(
            executable, preflight_source_artifact.content, args.timeout_seconds
        )
        if execution.timed_out:
            raise CampaignError("typed parser preflight timed out")
        if execution.exit_code != 0:
            raise CampaignError(
                f"typed parser preflight exited with status {execution.exit_code}"
            )
        _, payload_error = parser_payload(execution.stdout)
        if payload_error is not None:
            raise CampaignError(f"typed parser preflight failed: {payload_error}")
        preflight_path = args.output_root / "preflight.json"
        atomic_write(preflight_path, execution.stdout)
        preflight_artifact = CapturedArtifact(
            path=preflight_path,
            content=execution.stdout,
            sha256=sha256_bytes(execution.stdout),
        )
        prepare = {
            "schema": PREPARE_SCHEMA,
            "byte_binding": BYTE_BINDING,
            "revision": revision,
            "repository_root": str(repository_root),
            "expected_sources": args.expected_sources,
            "source_count": len(rows),
            "shard_count": args.shards,
            "timeout_seconds": args.timeout_seconds,
            "parser_environment": parser_environment,
            "python": python_identity,
            "manifest": {"path": str(manifest), "sha256": manifest_artifact.sha256},
            "binary": executable.binding,
            "tool": {"path": str(tool), "sha256": sha256_file(tool)},
            "preflight": {
                "path": str(preflight_path.resolve()),
                "sha256": preflight_artifact.sha256,
                "source_path": str(preflight_source),
                "source_sha256": preflight_source_artifact.sha256,
                "source_bytes": len(preflight_source_artifact.content),
                "elapsed_seconds": execution.elapsed_seconds,
            },
            "workset": {
                "path": str(workset.resolve()),
                "sha256": workset_artifact.sha256,
            },
        }
        validate_prepare_object(prepare, where="generated prepare artifact")
        atomic_json(args.output_root / "prepare.json", prepare)


def load_object(path: Path, *, schema: str) -> tuple[dict[str, Any], CapturedArtifact]:
    artifact = capture_artifact(path)
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{path}: artifact is not ASCII: {error}") from error
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        raise CampaignError(f"{path}: object is not exactly one LF-terminated line")
    value = strict_json(text[:-1], where=str(path))
    validate_schema_object(value, schema=schema, where=str(path))
    if canonical_bytes(value) != artifact.content:
        raise CampaignError(f"{path}: object is not canonically serialized")
    return value, artifact


def load_jsonl(
    path: Path, *, schema: str
) -> tuple[list[dict[str, Any]], CapturedArtifact]:
    artifact = capture_artifact(path)
    if not artifact.content:
        return [], artifact
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{path}: artifact is not ASCII: {error}") from error
    if not text.endswith("\n") or "\r" in text:
        raise CampaignError(f"{path}: JSONL is not LF-terminated")
    lines = text[:-1].split("\n")
    rows = []
    for line_number, line in enumerate(lines, 1):
        if not line:
            raise CampaignError(f"{path}:{line_number}: blank row")
        value = strict_json(line, where=f"{path}:{line_number}")
        validate_schema_object(
            value, schema=schema, where=f"{path}:{line_number}"
        )
        if canonical_bytes(value) != (line + "\n").encode("ascii"):
            raise CampaignError(f"{path}:{line_number}: row is not canonical JSON")
        rows.append(value)
    return rows, artifact


def load_prepared(root: Path, revision: str) -> PreparedCampaign:
    parser_environment = validate_parser_environment()
    python_identity = validate_python_identity()
    revision = require_revision(revision)
    prepare, prepare_artifact = load_object(
        root / "prepare.json", schema=PREPARE_SCHEMA
    )
    if prepare.get("revision") != revision:
        raise CampaignError("prepare revision does not match executing revision")
    if prepare.get("byte_binding") != BYTE_BINDING:
        raise CampaignError("prepared byte-binding contract mismatch")
    if prepare.get("parser_environment") != parser_environment:
        raise CampaignError("prepared parser environment contract mismatch")
    if prepare.get("python") != python_identity:
        raise CampaignError("prepared python identity contract mismatch")
    for name in ("manifest", "tool"):
        value = prepare.get(name)
        path = Path(value.get("path", ""))
        if not path.is_file() or sha256_file(path) != value.get("sha256"):
            raise CampaignError(f"prepared {name} hash mismatch")
    preflight_binding = prepare["preflight"]
    preflight_artifact = capture_artifact(Path(preflight_binding["path"]))
    if preflight_artifact.sha256 != preflight_binding["sha256"]:
        raise CampaignError("prepared preflight hash mismatch")
    _, preflight_error = parser_payload(preflight_artifact.content)
    if preflight_error is not None:
        raise CampaignError(f"prepared preflight violates parser contract: {preflight_error}")
    workset_binding = prepare.get("workset")
    workset_path = Path(workset_binding.get("path", ""))
    rows, workset_artifact = load_jsonl(workset_path, schema=WORK_SCHEMA)
    if workset_artifact.sha256 != workset_binding.get("sha256"):
        raise CampaignError("prepared workset hash mismatch")
    if len(rows) != prepare.get("source_count"):
        raise CampaignError("workset cardinality does not match prepare")
    if [row.get("sequence") for row in rows] != list(range(len(rows))):
        raise CampaignError("workset sequence is not contiguous")
    if any(row.get("byte_binding") != BYTE_BINDING for row in rows):
        raise CampaignError("workset byte-binding contract mismatch")
    return PreparedCampaign(
        metadata=prepare,
        prepare_artifact=prepare_artifact,
        workset=rows,
        workset_artifact=workset_artifact,
    )


def parser_payload(stdout: bytes) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = stdout.decode("ascii")
    except UnicodeDecodeError as error:
        return None, f"parser stdout is not ASCII: {error}"
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        return None, "parser stdout is not exactly one LF-terminated line"
    line = text[:-1]
    if not line:
        return None, "parser stdout line is empty"
    try:
        value = strict_json(line, where="parser stdout")
    except CampaignError as error:
        return None, str(error)
    try:
        validate_parser_object(value, where="parser stdout")
    except CampaignError as error:
        return None, str(error)
    return value, None


def classify_failure(exit_code: int | None, stderr: bytes, reason: str) -> str:
    diagnostic = stderr.decode("utf-8", errors="replace")
    if "semantic mismatch" in diagnostic:
        return "mismatch"
    if "fallback" in diagnostic or "fallback" in reason:
        return "fallback"
    return "error"


def diagnostic_excerpt(value: bytes) -> str | None:
    if not value:
        return None
    return value.decode("utf-8", errors="replace")[:DIAGNOSTIC_LIMIT]


def run_work_item(
    work: dict[str, Any],
    *,
    shard: int,
    prepare: dict[str, Any],
    executable: OpenedExecutable,
) -> dict[str, Any]:
    sequence = work["sequence"]
    source = Path(work["source_path"])
    source_artifact: CapturedArtifact | None = None
    stdout = b""
    stderr = b""
    exit_code: int | None = None
    elapsed_seconds: float | None = None
    parser: dict[str, Any] | None = None
    reason: str | None = None
    status = "match"
    try:
        source_artifact = capture_artifact(source)
    except CampaignError as error:
        status = "error"
        reason = str(error)
    if source_artifact is not None and (
        source_artifact.sha256 != work["source_sha256"]
        or len(source_artifact.content) != work["source_bytes"]
    ):
        status = "error"
        reason = "source hash changed after prepare"
    elif source_artifact is not None:
        execution = execute_parser(
            executable, source_artifact.content, prepare["timeout_seconds"]
        )
        stdout = execution.stdout
        stderr = execution.stderr
        exit_code = execution.exit_code
        elapsed_seconds = execution.elapsed_seconds
        if execution.timed_out:
            reason = f"parse-check exceeded {prepare['timeout_seconds']} seconds"
            status = "error"
        elif exit_code == 0:
            parser, reason = parser_payload(stdout)
            if reason is not None:
                status = classify_failure(exit_code, stderr, reason)
        else:
            reason = f"parse-check exited with status {exit_code}"
            status = classify_failure(exit_code, stderr, reason)
    record = {
        "schema": RECORD_SCHEMA,
        "byte_binding": BYTE_BINDING,
        "sequence": sequence,
        "shard": shard,
        "revision": prepare["revision"],
        "parser_environment": prepare["parser_environment"],
        "python": prepare["python"],
        "binary": executable.binding,
        "relative_path": work["relative_path"],
        "source_sha256": work["source_sha256"],
        "opened_source_sha256": (
            source_artifact.sha256 if source_artifact is not None else None
        ),
        "opened_source_bytes": (
            len(source_artifact.content) if source_artifact is not None else None
        ),
        "status": status,
        "exit_code": exit_code,
        "elapsed_seconds": elapsed_seconds,
        "reason": reason,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_excerpt": diagnostic_excerpt(stdout) if status != "match" else None,
        "stderr_excerpt": diagnostic_excerpt(stderr),
        "parser": parser,
    }
    validate_record_row(record, where=f"generated record {sequence}")
    return record


def run_shard(args: argparse.Namespace) -> None:
    root = args.root.resolve(strict=True)
    prepared = load_prepared(root, args.revision)
    prepare = prepared.metadata
    workset = prepared.workset
    shard_count = prepare["shard_count"]
    if args.shard >= shard_count:
        raise CampaignError(f"shard {args.shard} is outside [0, {shard_count})")
    records: list[dict[str, Any]] = []
    with open_verified_executable(
        Path(prepare["binary"]["path"]), expected=prepare["binary"]
    ) as executable:
        for work in workset:
            if work["sequence"] % shard_count != args.shard:
                continue
            records.append(
                run_work_item(
                    work,
                    shard=args.shard,
                    prepare=prepare,
                    executable=executable,
                )
            )
    expected = sum(
        1 for row in workset if row["sequence"] % shard_count == args.shard
    )
    if len(records) != expected:
        raise CampaignError("internal shard cardinality mismatch")
    atomic_jsonl(root / "shards" / f"shard-{args.shard:05d}.jsonl", records)


def audit_campaign(args: argparse.Namespace) -> bool:
    root = args.root.resolve(strict=True)
    prepared = load_prepared(root, args.revision)
    prepare = prepared.metadata
    workset = prepared.workset
    expected_sources = prepare["expected_sources"]
    if expected_sources != args.expected_sources or len(workset) != expected_sources:
        raise CampaignError("audit source cardinality does not match preregistration")
    shard_count = prepare["shard_count"]
    records: list[dict[str, Any]] = []
    shard_hashes: dict[str, str] = {}
    for shard in range(shard_count):
        path = root / "shards" / f"shard-{shard:05d}.jsonl"
        rows, shard_artifact = load_jsonl(path, schema=RECORD_SCHEMA)
        shard_hashes[f"{shard:05d}"] = shard_artifact.sha256
        for row in rows:
            if row.get("shard") != shard or row.get("revision") != prepare["revision"]:
                raise CampaignError(f"shard {shard}: row provenance mismatch")
            if row.get("byte_binding") != BYTE_BINDING:
                raise CampaignError(f"shard {shard}: byte-binding contract drift")
            if row.get("parser_environment") != prepare["parser_environment"]:
                raise CampaignError(f"shard {shard}: parser environment drift")
            if row.get("python") != prepare["python"]:
                raise CampaignError(f"shard {shard}: python identity drift")
            if row.get("binary") != prepare["binary"]:
                raise CampaignError(f"shard {shard}: parser executable identity drift")
            records.append(row)
    records.sort(key=lambda row: row["sequence"])
    if [row.get("sequence") for row in records] != list(range(expected_sources)):
        raise CampaignError("merged rows are missing, duplicated, or non-contiguous")

    counts = {"match": 0, "fallback": 0, "mismatch": 0, "error": 0}
    for work, record in zip(workset, records, strict=True):
        if (
            record.get("relative_path") != work["relative_path"]
            or record.get("source_sha256") != work["source_sha256"]
        ):
            raise CampaignError("merged row does not match its workset source")
        status = record.get("status")
        if status not in counts:
            raise CampaignError(f"unknown parity status {status!r}")
        opened_hash = record.get("opened_source_sha256")
        opened_bytes = record.get("opened_source_bytes")
        if (opened_hash is None) != (opened_bytes is None):
            raise CampaignError("merged row has incomplete opened source binding")
        if opened_hash is not None and (
            type(opened_hash) is not str or SHA256_RE.fullmatch(opened_hash) is None
        ):
            raise CampaignError("merged row has malformed opened source hash")
        if opened_bytes is not None and (
            type(opened_bytes) is not int or opened_bytes < 0
        ):
            raise CampaignError("merged row has malformed opened source byte count")
        if status == "match" and (
            opened_hash != work["source_sha256"]
            or opened_bytes != work["source_bytes"]
        ):
            raise CampaignError("matching row is not bound to its opened source bytes")
        counts[status] += 1
        if status == "match":
            parser = record.get("parser")
            if not isinstance(parser, dict):
                raise CampaignError("matching row has no parser payload")
            _, error = parser_payload(canonical_bytes(parser))
            if error is not None:
                raise CampaignError(f"matching row violates parser contract: {error}")

    records_path = root / "records.jsonl"
    records_artifact = atomic_jsonl(records_path, records)
    passed = counts == {
        "match": expected_sources,
        "fallback": 0,
        "mismatch": 0,
        "error": 0,
    }
    aggregate = {
        "schema": AUDIT_SCHEMA,
        "byte_binding": BYTE_BINDING,
        "status": "completed" if passed else "rejected",
        "revision": prepare["revision"],
        "source_count": len(records),
        "expected_sources": expected_sources,
        "shard_count": shard_count,
        "parser_environment": prepare["parser_environment"],
        "python": prepare["python"],
        "binary": prepare["binary"],
        "counts": counts,
        "gate": {
            "all_tree_parses_succeeded": counts["error"] == 0,
            "all_typed_snapshots_matched": counts["mismatch"] == 0,
            "zero_fallbacks": counts["fallback"] == 0,
            "all_sources_covered": len(records) == expected_sources,
            "passed": passed,
        },
        "artifacts": {
            "prepare_sha256": prepared.prepare_artifact.sha256,
            "workset_sha256": prepared.workset_artifact.sha256,
            "records_sha256": records_artifact.sha256,
            "shard_sha256": shard_hashes,
        },
    }
    validate_audit_object(aggregate, where="generated audit artifact")
    audit_artifact = atomic_json(root / "audit.json", aggregate)
    atomic_write(
        root / "audit-sha256.txt",
        f"{audit_artifact.sha256}  audit.json\n".encode("ascii"),
    )
    return passed


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--manifest", type=Path, required=True)
    prepare.add_argument("--repository-root", type=Path, required=True)
    prepare.add_argument("--binary", type=Path, required=True)
    prepare.add_argument("--preflight-source", type=Path, required=True)
    prepare.add_argument("--revision", required=True)
    prepare.add_argument("--expected-sources", type=positive_integer, default=7503)
    prepare.add_argument("--shards", type=positive_integer, default=128)
    prepare.add_argument("--timeout-seconds", type=positive_integer, default=60)
    prepare.add_argument("--output-root", type=Path, required=True)

    shard = subparsers.add_parser("run-shard")
    shard.add_argument("--root", type=Path, required=True)
    shard.add_argument("--revision", required=True)
    shard.add_argument("--shard", type=nonnegative_integer, required=True)

    audit = subparsers.add_parser("audit")
    audit.add_argument("--root", type=Path, required=True)
    audit.add_argument("--revision", required=True)
    audit.add_argument("--expected-sources", type=positive_integer, default=7503)

    subparsers.add_parser("validate-payload")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "prepare":
            prepare_campaign(args)
            return 0
        if args.command == "run-shard":
            run_shard(args)
            return 0
        if args.command == "audit":
            return 0 if audit_campaign(args) else 1
        if args.command == "validate-payload":
            validate_python_identity()
            _, error = parser_payload(sys.stdin.buffer.read())
            if error is not None:
                raise CampaignError(f"invalid typed parser payload: {error}")
            return 0
        raise AssertionError(args.command)
    except CampaignError as error:
        print(f"typed parser parity campaign error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
