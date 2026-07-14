#!/usr/bin/env python3
"""Prepare, execute, and audit the preregistered T1 parser timing gate."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import platform
import re
import resource
import selectors
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, NamedTuple


CONTRACT_SCHEMA = "euf-viper.typed-parser-timing-contract.v1"
PREPARE_SCHEMA = "euf-viper.typed-parser-timing-prepare.v1"
WORK_SCHEMA = "euf-viper.typed-parser-timing-work.v1"
BINARY_OBSERVATION_SCHEMA = "euf-viper.typed-parser-timing-observation.v1"
SEMANTIC_ATTESTATION_SCHEMA = "euf-viper.typed-parser-semantics.v1"
PREFLIGHT_SCHEMA = "euf-viper.typed-parser-timing-preflight.v1"
RECORD_SCHEMA = "euf-viper.typed-parser-timing-record.v1"
AUDIT_SCHEMA = "euf-viper.typed-parser-timing-audit.v1"
BYTE_BINDING = "single-open-descriptor-buffer-replay.v1"
EXECUTABLE_BINDING = "inherited-descriptor.v1"
PRIVATE_COPY_BINDING = "private-byte-copy.v1"
PROCESS_ISOLATION = "fresh-process-per-observation.v1"
ABBA_ORDER = ("tree", "stream", "stream", "tree")
PHASES = ("parse", "end_to_end")
LOCKED_SOURCE_COUNT = 7503
LOCKED_REPETITIONS = 128
LOCKED_MAX_PARALLEL = 32
LOCKED_WARMUP_ROUNDS = 1
LOCKED_MEASURED_ROUNDS = 5
LOCKED_TIMEOUT_SECONDS = 2
DECISIVE_RESULTS = frozenset({"sat", "unsat"})
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
PYTHON_VERSION_RE = re.compile(
    r"Python [0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?"
)
PYTHON_PATH_ENV = "EUF_VIPER_PYTHON"
PYTHON_SHA256_ENV = "EUF_VIPER_PYTHON_SHA256"
PYTHON_VERSION_ENV = "EUF_VIPER_PYTHON_VERSION"
BUILD_TOOL_ENVIRONMENT = {
    "cargo": ("EUF_VIPER_CARGO", "EUF_VIPER_CARGO_SHA256", "EUF_VIPER_CARGO_VERSION"),
    "rustc": ("EUF_VIPER_RUSTC", "EUF_VIPER_RUSTC_SHA256", "EUF_VIPER_RUSTC_VERSION"),
}
MAX_CAPTURE_BYTES = 1_048_576
DIAGNOSTIC_LIMIT = 4096
RUNTIME_ENVIRONMENT: dict[str, str | None] = {
    "EUF_VIPER_SCOPED_LET": "auto",
    "EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT": "1024",
    "EUF_VIPER_PROFILE": None,
    "OMP_NUM_THREADS": "1",
    "RAYON_NUM_THREADS": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "TMPDIR": "/tmp",
}

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
CONTRACT_KEYS = frozenset(
    {"schema", "name", "arms", "campaign", "execution", "gates", "measurement"}
)
WORK_KEYS = frozenset(
    {
        "schema",
        "byte_binding",
        "sequence",
        "manifest_line",
        "relative_path",
        "family",
        "expected_status",
        "source_path",
        "source_sha256",
        "source_bytes",
    }
)
BINARY_OBSERVATION_KEYS = frozenset(
    {
        "schema",
        "parser",
        "phase",
        "elapsed_ns",
        "source_bytes",
        "result",
        "result_sha256",
    }
)
SEMANTIC_ATTESTATION_KEYS = frozenset(
    {
        "schema",
        "parser",
        "source_bytes",
        "canonical_sha256",
        "symbols",
        "sorts",
        "sort_bindings",
        "functions",
        "terms",
        "applications",
        "interned_terms",
        "equalities",
        "disequalities",
        "assertions",
        "bool_data_terms",
        "unsupported_diagnostics",
        "contradiction",
    }
)
OBSERVATION_KEYS = frozenset(
    {
        "ordinal",
        "stage",
        "round",
        "phase",
        "position",
        "parser",
        "outcome",
        "exit_code",
        "external_elapsed_ns",
        "max_rss_kb",
        "stdout_sha256",
        "stderr_sha256",
        "diagnostic",
        "payload",
    }
)
RECORD_KEYS = frozenset(
    {
        "schema",
        "byte_binding",
        "process_isolation",
        "sequence",
        "shard",
        "revision",
        "prepare_sha256",
        "contract_sha256",
        "python",
        "binary",
        "runtime_environment",
        "worker",
        "relative_path",
        "family",
        "expected_status",
        "source_sha256",
        "opened_source_sha256",
        "opened_source_bytes",
        "semantic_attestations",
        "observations",
    }
)
PREPARE_KEYS = frozenset(
    {
        "schema",
        "revision",
        "repository_root",
        "expected_sources",
        "source_count",
        "shard_count",
        "runtime_environment",
        "python",
        "build_tools",
        "manifest",
        "binary",
        "tool",
        "contract",
        "preflight",
        "workset",
        "expected_contract_sha256",
        "expected_manifest_sha256",
        "checkout_receipt",
    }
)
AUDIT_KEYS = frozenset(
    {
        "schema",
        "status",
        "revision",
        "source_count",
        "expected_sources",
        "shard_count",
        "contract_sha256",
        "python",
        "build_tools",
        "binary",
        "runtime_environment",
        "counts",
        "metrics",
        "strata",
        "gates",
        "artifacts",
    }
)
PREFLIGHT_KEYS = frozenset(
    {
        "schema",
        "source",
        "measured_rounds",
        "warmup_rounds",
        "semantic_attestations",
        "observations",
    }
)


class CampaignError(ValueError):
    """Raised when an input or artifact violates the timing contract."""


class CapturedArtifact(NamedTuple):
    path: Path
    content: bytes
    sha256: str


class FileFingerprint(NamedTuple):
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
    fingerprint: FileFingerprint
    cleanup_directory: Path | None


class Execution(NamedTuple):
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    elapsed_ns: int
    max_rss_kb: int
    timed_out: bool


class PreparedCampaign(NamedTuple):
    metadata: dict[str, Any]
    prepare_artifact: CapturedArtifact
    contract: dict[str, Any]
    workset: list[dict[str, Any]]
    workset_artifact: CapturedArtifact


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def reject_nonfinite_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


def ensure_finite_json(value: Any, *, where: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise CampaignError(f"{where}: non-finite JSON number")
    if isinstance(value, list):
        for index, item in enumerate(value):
            ensure_finite_json(item, where=f"{where}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            ensure_finite_json(item, where=f"{where}.{key}")


def strict_json(text: str, *, where: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise CampaignError(f"{where}: malformed JSON: {error}") from error
    ensure_finite_json(value, where=where)
    return value


def canonical_bytes(value: Any) -> bytes:
    ensure_finite_json(value, where="serialization")
    try:
        serialized = json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return (serialized + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CampaignError(f"cannot serialize strict JSON: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_fingerprint(descriptor: int) -> FileFingerprint:
    metadata = os.fstat(descriptor)
    return FileFingerprint(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mode=metadata.st_mode,
        modified_ns=metadata.st_mtime_ns,
    )


def read_descriptor(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise CampaignError("opened file became short while read")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise CampaignError("opened file grew while read")
    return b"".join(chunks)


def open_regular_artifact(path: Path, *, executable: bool = False) -> CapturedArtifact:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "pread"):
        raise CampaignError("platform lacks no-follow descriptor verification")
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"cannot resolve {path}: {error}") from error
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(canonical, flags)
    except OSError as error:
        raise CampaignError(f"cannot open {canonical}: {error}") from error
    try:
        before = file_fingerprint(descriptor)
        if not stat.S_ISREG(before.mode):
            raise CampaignError(f"not a regular file: {canonical}")
        if executable and before.mode & 0o111 == 0:
            raise CampaignError(f"file has no execute bit: {canonical}")
        content = read_descriptor(descriptor, before.size)
        after = file_fingerprint(descriptor)
        if before != after:
            raise CampaignError(f"file changed while read: {canonical}")
        return CapturedArtifact(canonical, content, sha256_bytes(content))
    finally:
        os.close(descriptor)


def write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise CampaignError("short write while publishing artifact")
        offset += written


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_new(path: Path, content: bytes) -> CapturedArtifact:
    """Publish a fully written inode atomically without replacing an artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    linked = False
    try:
        write_all(descriptor, content)
        os.fsync(descriptor)
        if file_fingerprint(descriptor).size != len(content):
            raise CampaignError("published artifact byte count changed before link")
        if sha256_bytes(read_descriptor(descriptor, len(content))) != sha256_bytes(content):
            raise CampaignError("published artifact hash changed before link")
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise CampaignError(f"refusing to replace existing artifact {path}") from error
        linked = True
        fsync_directory(path.parent)
        published = open_regular_artifact(path)
        if published.content != content:
            raise CampaignError(f"published artifact verification failed: {path}")
        return published
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        if linked:
            fsync_directory(path.parent)


def publish_json(path: Path, value: Any) -> CapturedArtifact:
    return publish_new(path, canonical_bytes(value))


def publish_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> CapturedArtifact:
    return publish_new(path, b"".join(canonical_bytes(row) for row in rows))


def executable_binding_contract() -> str:
    return EXECUTABLE_BINDING if sys.platform.startswith("linux") else PRIVATE_COPY_BINDING


def private_execution_copy(descriptor: int, size: int, digest: str) -> tuple[str, Path]:
    directory = Path(tempfile.mkdtemp(prefix="euf-viper-t1-exec-"))
    execution_path = directory / "euf-viper"
    output = -1
    try:
        output = os.open(
            execution_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o500,
        )
        content = read_descriptor(descriptor, size)
        write_all(output, content)
        os.fsync(output)
        os.close(output)
        output = -1
        if sha256_bytes(content) != digest:
            raise CampaignError("private executable copy hash mismatch")
        execution_path.chmod(0o500)
        directory.chmod(0o500)
        return str(execution_path), directory
    except BaseException:
        if output >= 0:
            os.close(output)
        directory.chmod(0o700)
        execution_path.unlink(missing_ok=True)
        directory.rmdir()
        raise


@contextlib.contextmanager
def open_verified_executable(
    path: Path, expected: dict[str, Any] | None = None
) -> Iterator[OpenedExecutable]:
    canonical = path.resolve(strict=True)
    descriptor = os.open(canonical, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    cleanup_directory: Path | None = None
    try:
        before = file_fingerprint(descriptor)
        if not stat.S_ISREG(before.mode) or before.mode & 0o111 == 0:
            raise CampaignError("timing binary is not a regular executable")
        content = read_descriptor(descriptor, before.size)
        digest = sha256_bytes(content)
        if file_fingerprint(descriptor) != before:
            raise CampaignError("timing binary changed while hashed")
        binding = {
            "path": str(canonical),
            "sha256": digest,
            "bytes": before.size,
            "execution": executable_binding_contract(),
        }
        validate_binary_binding(binding, where="opened timing binary")
        if expected is not None:
            validate_binary_binding(expected, where="prepared timing binary")
            if binding != expected:
                raise CampaignError("prepared timing binary identity mismatch")
        if sys.platform.startswith("linux"):
            execution_path = f"/proc/self/fd/{descriptor}"
        else:
            execution_path, cleanup_directory = private_execution_copy(
                descriptor, before.size, digest
            )
        opened = OpenedExecutable(
            descriptor,
            canonical,
            execution_path,
            binding,
            before,
            cleanup_directory,
        )
        yield opened
        assert_executable_unchanged(opened)
    finally:
        if cleanup_directory is not None:
            cleanup_directory.chmod(0o700)
            (cleanup_directory / "euf-viper").unlink(missing_ok=True)
            cleanup_directory.rmdir()
        os.close(descriptor)


def assert_executable_unchanged(executable: OpenedExecutable) -> None:
    if file_fingerprint(executable.descriptor) != executable.fingerprint:
        raise CampaignError("opened timing binary changed after verification")


def assert_path_names_opened_inode(executable: OpenedExecutable) -> None:
    descriptor = os.open(
        executable.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        if file_fingerprint(descriptor) != executable.fingerprint:
            raise CampaignError("tool pathname no longer names the verified inode")
    finally:
        os.close(descriptor)


def child_environment() -> dict[str, str]:
    environment: dict[str, str] = {}
    for name, value in RUNTIME_ENVIRONMENT.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    return environment


def _close_quietly(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def execute_binary(
    executable: OpenedExecutable,
    source: bytes,
    *,
    arguments: list[str],
    timeout_seconds: int,
) -> Execution:
    """Execute one fresh process and collect its own wait4 RSS."""
    assert_executable_unchanged(executable)
    stdin_read, stdin_write = os.pipe()
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    started = time.monotonic_ns()
    pid = os.fork()
    if pid == 0:
        try:
            _close_quietly(stdin_write)
            _close_quietly(stdout_read)
            _close_quietly(stderr_read)
            os.dup2(stdin_read, 0)
            os.dup2(stdout_write, 1)
            os.dup2(stderr_write, 2)
            for descriptor in (stdin_read, stdout_write, stderr_write):
                if descriptor > 2:
                    _close_quietly(descriptor)
            os.set_inheritable(executable.descriptor, True)
            argv = [executable.execution_path, *arguments]
            os.execve(executable.execution_path, argv, child_environment())
        except BaseException as error:
            message = f"timing exec failed: {error}\n".encode("utf-8", errors="replace")
            try:
                os.write(2, message[:DIAGNOSTIC_LIMIT])
            except OSError:
                pass
            os._exit(127)

    _close_quietly(stdin_read)
    _close_quietly(stdout_write)
    _close_quietly(stderr_write)
    for descriptor in (stdin_write, stdout_read, stderr_read):
        os.set_blocking(descriptor, False)
    selector = selectors.DefaultSelector()
    selector.register(stdin_write, selectors.EVENT_WRITE, "stdin")
    selector.register(stdout_read, selectors.EVENT_READ, "stdout")
    selector.register(stderr_read, selectors.EVENT_READ, "stderr")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    input_offset = 0
    status: int | None = None
    usage: resource.struct_rusage | None = None
    timed_out = False
    capture_overflow = False
    deadline = started + timeout_seconds * 1_000_000_000
    try:
        while status is None or selector.get_map():
            now = time.monotonic_ns()
            if status is None and now >= deadline and not capture_overflow:
                timed_out = True
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            wait_seconds = 0.01
            if status is None and not timed_out:
                wait_seconds = min(wait_seconds, max(0.0, (deadline - now) / 1e9))
            for key, _ in selector.select(wait_seconds):
                descriptor = key.fd
                stream = key.data
                if stream == "stdin":
                    try:
                        written = os.write(descriptor, source[input_offset : input_offset + 65536])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = 0
                    input_offset += written
                    if input_offset == len(source) or written == 0:
                        selector.unregister(descriptor)
                        _close_quietly(descriptor)
                    continue
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    _close_quietly(descriptor)
                    continue
                streams[stream].extend(chunk)
                if len(streams[stream]) > MAX_CAPTURE_BYTES:
                    capture_overflow = True
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if status is None:
                waited, candidate_status, candidate_usage = os.wait4(pid, os.WNOHANG)
                if waited == pid:
                    status = candidate_status
                    usage = candidate_usage
                    for key in list(selector.get_map().values()):
                        if key.data == "stdin":
                            selector.unregister(key.fd)
                            _close_quietly(key.fd)
            if status is not None and not selector.get_map():
                break
        if status is None:
            _, status, usage = os.wait4(pid, 0)
    finally:
        for key in list(selector.get_map().values()):
            selector.unregister(key.fd)
            _close_quietly(key.fd)
        selector.close()
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status, usage = os.wait4(pid, 0)
    elapsed_ns = max(1, time.monotonic_ns() - started)
    if usage is None:
        raise CampaignError("wait4 returned no resource usage")
    max_rss_kb = int(usage.ru_maxrss)
    if sys.platform == "darwin":
        max_rss_kb = (max_rss_kb + 1023) // 1024
    assert_executable_unchanged(executable)
    exit_code = None if timed_out else os.waitstatus_to_exitcode(status)
    return Execution(
        exit_code,
        bytes(streams["stdout"][:MAX_CAPTURE_BYTES]),
        bytes(streams["stderr"][:MAX_CAPTURE_BYTES]),
        elapsed_ns,
        max_rss_kb,
        timed_out,
    )


def execute_observation(
    executable: OpenedExecutable,
    source: bytes,
    *,
    parser: str,
    phase: str,
    timeout_seconds: int,
) -> Execution:
    return execute_binary(
        executable,
        source,
        arguments=[
            "research-parser-timing",
            "--parser",
            parser,
            "--phase",
            "end-to-end" if phase == "end_to_end" else "parse",
            "-",
        ],
        timeout_seconds=timeout_seconds,
    )


def require_exact_keys(value: Any, expected: frozenset[str], *, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CampaignError(f"{where}: expected an object")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise CampaignError(f"{where}: key mismatch, missing={missing}, extra={extra}")
    return value


def require_string(value: Any, *, where: str, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise CampaignError(f"{where}: expected a nonempty string")
    return value


def require_integer(value: Any, *, where: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CampaignError(f"{where}: expected an integer >= {minimum}")
    return value


def require_number(value: Any, *, where: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CampaignError(f"{where}: expected a finite number")
    number = float(value)
    if not math.isfinite(number) or number < minimum:
        raise CampaignError(f"{where}: expected a finite number >= {minimum}")
    return number


def require_sha256(value: Any, *, where: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CampaignError(f"{where}: expected lowercase SHA-256")
    return value


def require_revision(value: Any) -> str:
    if not isinstance(value, str) or REVISION_RE.fullmatch(value) is None:
        raise CampaignError("revision must be a lowercase 40-character commit id")
    return value


def validate_file_binding(value: Any, *, where: str) -> None:
    value = require_exact_keys(value, frozenset({"path", "sha256", "bytes"}), where=where)
    path = require_string(value["path"], where=f"{where}.path")
    if not Path(path).is_absolute():
        raise CampaignError(f"{where}.path must be absolute")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    require_integer(value["bytes"], where=f"{where}.bytes")


def file_binding(artifact: CapturedArtifact) -> dict[str, Any]:
    return {
        "path": str(artifact.path),
        "sha256": artifact.sha256,
        "bytes": len(artifact.content),
    }


def validate_checkout_receipt(
    artifact: CapturedArtifact, *, repository_root: Path, revision: str, where: str
) -> None:
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{where}: checkout receipt is not ASCII") from error
    if not text.endswith("\n") or text.count("\n") != 1:
        raise CampaignError(f"{where}: checkout receipt is not one line")
    value = require_exact_keys(
        strict_json(text[:-1], where=where),
        frozenset(
            {
                "schema",
                "cargo_configs",
                "ignored_sha256",
                "published_ref",
                "repository",
                "revision",
                "runtime_blobs",
                "status_sha256",
                "tree",
            }
        ),
        where=where,
    )
    if canonical_bytes(value) != artifact.content:
        raise CampaignError(f"{where}: checkout receipt is not canonical JSON")
    if value["schema"] != "euf-viper.t1-clean-checkout-receipt.v1":
        raise CampaignError(f"{where}: checkout receipt schema drift")
    if value["repository"] != str(repository_root) or value["revision"] != revision:
        raise CampaignError(f"{where}: checkout receipt identity mismatch")
    if value["cargo_configs"] != []:
        raise CampaignError(f"{where}: checkout receipt admits Cargo configuration")
    if value["status_sha256"] != EMPTY_SHA256 or value["ignored_sha256"] != EMPTY_SHA256:
        raise CampaignError(f"{where}: checkout receipt admits mutable state")
    require_revision(value["tree"])
    require_string(value["published_ref"], where=f"{where}.published_ref")
    if not isinstance(value["runtime_blobs"], dict) or not value["runtime_blobs"]:
        raise CampaignError(f"{where}: checkout receipt has no runtime blobs")
    for path, binding in value["runtime_blobs"].items():
        require_string(path, where=f"{where}.runtime_blobs path")
        binding = require_exact_keys(
            binding, frozenset({"blob", "mode"}), where=f"{where}.runtime_blobs.{path}"
        )
        require_revision(binding["blob"])
        if binding["mode"] not in {"100644", "100755"}:
            raise CampaignError(f"{where}: unsupported runtime blob mode")


def validate_binary_binding(value: Any, *, where: str) -> None:
    value = require_exact_keys(
        value, frozenset({"path", "sha256", "bytes", "execution"}), where=where
    )
    path = require_string(value["path"], where=f"{where}.path")
    if not Path(path).is_absolute():
        raise CampaignError(f"{where}.path must be absolute")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    require_integer(value["bytes"], where=f"{where}.bytes", minimum=1)
    if value["execution"] not in {EXECUTABLE_BINDING, PRIVATE_COPY_BINDING}:
        raise CampaignError(f"{where}.execution is unsupported")


def validate_python_binding(value: Any, *, where: str) -> None:
    value = require_exact_keys(value, frozenset({"path", "sha256", "version"}), where=where)
    path = require_string(value["path"], where=f"{where}.path")
    if not Path(path).is_absolute():
        raise CampaignError(f"{where}.path must be absolute")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    version = require_string(value["version"], where=f"{where}.version")
    if PYTHON_VERSION_RE.fullmatch(version) is None:
        raise CampaignError(f"{where}.version is malformed")


def validate_build_tool_binding(value: Any, *, where: str) -> None:
    value = require_exact_keys(
        value, frozenset({"path", "sha256", "bytes", "version"}), where=where
    )
    path = require_string(value["path"], where=f"{where}.path")
    if not Path(path).is_absolute():
        raise CampaignError(f"{where}.path must be absolute")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    require_integer(value["bytes"], where=f"{where}.bytes", minimum=1)
    version = require_string(value["version"], where=f"{where}.version")
    if "\n" in version or "\r" in version or not version.isascii():
        raise CampaignError(f"{where}.version must be one ASCII line")


def validate_build_tools(value: Any, *, where: str) -> None:
    value = require_exact_keys(value, frozenset(BUILD_TOOL_ENVIRONMENT), where=where)
    for name in sorted(BUILD_TOOL_ENVIRONMENT):
        validate_build_tool_binding(value[name], where=f"{where}.{name}")


def validate_external_tool_identity(name: str) -> dict[str, Any]:
    path_env, sha_env, version_env = BUILD_TOOL_ENVIRONMENT[name]
    configured = os.environ.get(path_env)
    expected_sha256 = os.environ.get(sha_env)
    expected_version = os.environ.get(version_env)
    if not configured:
        raise CampaignError(f"{path_env} must be set")
    configured_path = Path(configured)
    if not configured_path.is_absolute():
        raise CampaignError(f"{path_env} must be absolute")
    canonical = configured_path.resolve(strict=True)
    if canonical != configured_path:
        raise CampaignError(f"{path_env} must be its canonical realpath")
    require_sha256(expected_sha256, where=sha_env)
    if not isinstance(expected_version, str) or not expected_version:
        raise CampaignError(f"{version_env} must be set")
    with open_verified_executable(canonical) as executable:
        if executable.binding["sha256"] != expected_sha256:
            raise CampaignError(f"{name} hash mismatch")
        actual_version = execute_tool_version(executable, name=name)
        if actual_version != expected_version:
            raise CampaignError(f"{name} version mismatch")
        value = {
            "path": str(canonical),
            "sha256": executable.binding["sha256"],
            "bytes": executable.binding["bytes"],
            "version": actual_version,
        }
    validate_build_tool_binding(value, where=name)
    return value


def verify_build_tool_binding(value: dict[str, Any], *, where: str) -> None:
    validate_build_tool_binding(value, where=where)
    with open_verified_executable(Path(value["path"])) as executable:
        if (
            executable.binding["sha256"] != value["sha256"]
            or executable.binding["bytes"] != value["bytes"]
            or execute_tool_version(executable, name=where) != value["version"]
        ):
            raise CampaignError(f"{where}: build tool identity mismatch")


def execute_tool_version(executable: OpenedExecutable, *, name: str) -> str:
    assert_path_names_opened_inode(executable)
    execution_path = (
        executable.execution_path
        if sys.platform.startswith("linux")
        else str(executable.path)
    )
    try:
        completed = subprocess.run(
            [str(executable.path), "--version"],
            executable=execution_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
            pass_fds=(executable.descriptor,),
            env=child_environment(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CampaignError(f"cannot execute pinned {name}: {error}") from error
    assert_executable_unchanged(executable)
    assert_path_names_opened_inode(executable)
    if completed.returncode != 0:
        raise CampaignError(f"pinned {name} --version exited {completed.returncode}")
    try:
        version = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise CampaignError(f"pinned {name} version is not ASCII") from error
    if not version or "\n" in version or "\r" in version:
        raise CampaignError(f"pinned {name} version is not exactly one line")
    return version


def validate_runtime_environment(value: Any, *, where: str) -> None:
    if value != RUNTIME_ENVIRONMENT:
        raise CampaignError(f"{where}: runtime environment contract drift")


def validate_worker(value: Any, *, where: str) -> None:
    value = require_exact_keys(
        value,
        frozenset({"hostname", "platform", "machine", "cpu_id", "affinity"}),
        where=where,
    )
    for key in ("hostname", "platform", "machine", "affinity"):
        text = require_string(value[key], where=f"{where}.{key}")
        if not text.isascii() or "\n" in text or "\r" in text:
            raise CampaignError(f"{where}.{key} must be one ASCII line")
    if value["cpu_id"] is not None:
        require_integer(value["cpu_id"], where=f"{where}.cpu_id")


def bind_worker(*, require_linux_affinity: bool) -> dict[str, Any]:
    cpu_id: int | None = None
    affinity = "unavailable-nonlinux"
    if hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"):
        allowed = sorted(os.sched_getaffinity(0))
        if not allowed:
            raise CampaignError("worker has no allowed CPUs")
        cpu_id = allowed[0]
        os.sched_setaffinity(0, {cpu_id})
        if os.sched_getaffinity(0) != {cpu_id}:
            raise CampaignError("worker CPU affinity did not become singleton")
        affinity = "sched_setaffinity-singleton.v1"
    elif require_linux_affinity:
        raise CampaignError("Linux singleton CPU affinity is required")
    worker = {
        "hostname": platform.node(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "cpu_id": cpu_id,
        "affinity": affinity,
    }
    validate_worker(worker, where="worker")
    return worker


def validate_contract(value: Any, *, where: str = "contract") -> dict[str, Any]:
    value = require_exact_keys(value, CONTRACT_KEYS, where=where)
    if value["schema"] != CONTRACT_SCHEMA:
        raise CampaignError(f"{where}: wrong schema")
    if value["name"] != "T1 typed stream parser causal timing gate":
        raise CampaignError(f"{where}: contract name drifted")

    arms = require_exact_keys(
        value["arms"], frozenset({"baseline", "candidate"}), where=f"{where}.arms"
    )
    if arms != {"baseline": "tree", "candidate": "stream"}:
        raise CampaignError(f"{where}: arm identities are not tree versus stream")

    campaign = require_exact_keys(
        value["campaign"],
        frozenset(
            {"expected_sources", "source_count", "shards", "repetitions", "max_parallel"}
        ),
        where=f"{where}.campaign",
    )
    locked_campaign = {
        "expected_sources": LOCKED_SOURCE_COUNT,
        "source_count": LOCKED_SOURCE_COUNT,
        "shards": LOCKED_REPETITIONS,
        "repetitions": LOCKED_REPETITIONS,
        "max_parallel": LOCKED_MAX_PARALLEL,
    }
    if campaign != locked_campaign:
        raise CampaignError(f"{where}: immutable campaign dimensions drifted")

    execution = require_exact_keys(
        value["execution"],
        frozenset(
            {
                "binary_command",
                "byte_binding",
                "executable_binding_linux",
                "measured_rounds",
                "order",
                "per_observation_timeout_seconds",
                "phases",
                "process_isolation",
                "semantic_command",
                "semantic_digest",
                "semantic_timing",
                "source_argument",
                "timed_path",
                "warmup_rounds",
            }
        ),
        where=f"{where}.execution",
    )
    expected_execution = {
        "binary_command": "research-parser-timing",
        "byte_binding": BYTE_BINDING,
        "executable_binding_linux": EXECUTABLE_BINDING,
        "order": list(ABBA_ORDER),
        "phases": list(PHASES),
        "process_isolation": PROCESS_ISOLATION,
        "semantic_command": "research-parser-semantics",
        "semantic_digest": "sha256-canonical-typed-snapshot-v1",
        "semantic_timing": "outside-timed-region-before-observations",
        "source_argument": "-",
        "timed_path": "production-problem-path-no-symbol-telemetry-v1",
    }
    for key, expected in expected_execution.items():
        if execution[key] != expected:
            raise CampaignError(f"{where}.execution.{key} drifted")
    if execution["measured_rounds"] != LOCKED_MEASURED_ROUNDS:
        raise CampaignError(f"{where}: measured rounds drifted")
    if execution["warmup_rounds"] != LOCKED_WARMUP_ROUNDS:
        raise CampaignError(f"{where}: warmup rounds drifted")
    if execution["per_observation_timeout_seconds"] != LOCKED_TIMEOUT_SECONDS:
        raise CampaignError(f"{where}: observation timeout drifted")

    gates = require_exact_keys(
        value["gates"],
        frozenset(
            {
                "aggregate_ratio_max_exclusive",
                "common_sources_required_per_phase",
                "exact_result_parity",
                "no_baseline_only_solve",
                "no_solved_count_regression",
                "p95_all_source_overhead_max_exclusive",
                "paired_geomean_ratio_max_exclusive",
                "phases_requiring_speedup",
                "semantic_parity_before_metrics",
                "zero_error_observations",
                "zero_incorrect_results",
                "zero_timeout_observations",
            }
        ),
        where=f"{where}.gates",
    )
    for key in (
        "exact_result_parity",
        "no_baseline_only_solve",
        "no_solved_count_regression",
        "semantic_parity_before_metrics",
        "zero_error_observations",
        "zero_incorrect_results",
        "zero_timeout_observations",
    ):
        if gates[key] is not True:
            raise CampaignError(f"{where}.gates.{key} must be true")
    if gates["common_sources_required_per_phase"] != LOCKED_SOURCE_COUNT:
        raise CampaignError(f"{where}: common-source gate drifted")
    if gates["phases_requiring_speedup"] != list(PHASES):
        raise CampaignError(f"{where}: both timing phases must require speedup")
    for key in ("aggregate_ratio_max_exclusive", "paired_geomean_ratio_max_exclusive"):
        threshold = require_number(gates[key], where=f"{where}.gates.{key}")
        if threshold != 1.0:
            raise CampaignError(f"{where}.gates.{key} must be exactly 1.0")
    p95 = require_number(
        gates["p95_all_source_overhead_max_exclusive"],
        where=f"{where}.gates.p95_all_source_overhead_max_exclusive",
    )
    if p95 != 0.01:
        raise CampaignError(f"{where}: p95 all-source overhead cap must be exactly 0.01")

    measurement = require_exact_keys(
        value["measurement"],
        frozenset(
            {
                "aggregate_unit",
                "overhead_definition",
                "p95_definition",
                "paired_unit",
                "reported_strata",
                "rss_unit_linux",
            }
        ),
        where=f"{where}.measurement",
    )
    expected_measurement = {
        "aggregate_unit": "sum-of-per-source-arm-medians",
        "overhead_definition": "max(candidate-median/baseline-median-minus-one,zero)-over-all-7503-sources",
        "p95_definition": "nearest-rank-ceiling",
        "paired_unit": "within-round-abba-neighbor-log-ratio",
        "reported_strata": ["expected_status", "family"],
        "rss_unit_linux": "KiB",
    }
    if measurement != expected_measurement:
        raise CampaignError(f"{where}: measurement definitions drifted")
    return value


def load_contract(path: Path) -> tuple[dict[str, Any], CapturedArtifact]:
    artifact = open_regular_artifact(path)
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"contract is not ASCII: {error}") from error
    contract = strict_json(text, where=str(path))
    return validate_contract(contract, where=str(path)), artifact


def validate_python_identity() -> dict[str, str]:
    configured = os.environ.get(PYTHON_PATH_ENV)
    expected_sha256 = os.environ.get(PYTHON_SHA256_ENV)
    expected_version = os.environ.get(PYTHON_VERSION_ENV)
    if not configured:
        raise CampaignError(f"{PYTHON_PATH_ENV} must be set")
    configured_path = Path(configured)
    if not configured_path.is_absolute():
        raise CampaignError(f"{PYTHON_PATH_ENV} must be absolute")
    require_sha256(expected_sha256, where=PYTHON_SHA256_ENV)
    if not isinstance(expected_version, str) or PYTHON_VERSION_RE.fullmatch(expected_version) is None:
        raise CampaignError(f"{PYTHON_VERSION_ENV} is malformed")
    try:
        configured_resolved = configured_path.resolve(strict=True)
        executing_resolved = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"cannot resolve Python interpreter: {error}") from error
    if configured_path != configured_resolved:
        raise CampaignError("configured Python must be its canonical realpath")
    if configured_resolved != executing_resolved:
        raise CampaignError("configured Python does not execute this harness")
    artifact = open_regular_artifact(configured_resolved, executable=True)
    if artifact.sha256 != expected_sha256:
        raise CampaignError("Python interpreter hash mismatch")
    actual_version = f"Python {platform.python_version()}"
    if actual_version != expected_version:
        raise CampaignError("Python interpreter version mismatch")
    value = {
        "path": str(configured_resolved),
        "sha256": artifact.sha256,
        "version": actual_version,
    }
    validate_python_binding(value, where="executing Python")
    return value


def validate_manifest_row(value: Any, *, where: str) -> dict[str, Any]:
    value = require_exact_keys(value, MANIFEST_KEYS, where=where)
    if not isinstance(value["id"], (str, int)) or isinstance(value["id"], bool):
        raise CampaignError(f"{where}.id is malformed")
    require_string(value["logic"], where=f"{where}.logic")
    if value["logic"] != "QF_UF":
        raise CampaignError(f"{where}: non-QF_UF row")
    require_string(value["path"], where=f"{where}.path")
    require_string(value["relative_path"], where=f"{where}.relative_path")
    require_sha256(value["sha256"], where=f"{where}.sha256")
    require_integer(value["bytes"], where=f"{where}.bytes")
    if value["status"] not in DECISIVE_RESULTS:
        raise CampaignError(f"{where}.status must be sat or unsat")
    for key in ("archive_md5", "source_doi", "source_url"):
        if value[key] is not None and not isinstance(value[key], str):
            raise CampaignError(f"{where}.{key} must be a string or null")
    return value


def safe_relative_path(value: Any, *, where: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CampaignError(f"{where}: invalid relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise CampaignError(f"{where}: unsafe relative path")
    if pure.suffix.lower() != ".smt2":
        raise CampaignError(f"{where}: source is not .smt2")
    return pure.as_posix()


def family_name(relative_path: str) -> str:
    parts = PurePosixPath(relative_path).parts
    if len(parts) >= 2 and parts[0] == "QF_UF":
        return parts[1]
    return parts[0] if parts else "unknown"


def load_manifest(
    manifest: Path, repository_root: Path
) -> tuple[list[dict[str, Any]], CapturedArtifact]:
    artifact = open_regular_artifact(manifest)
    try:
        text = artifact.content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CampaignError(f"manifest is not UTF-8: {error}") from error
    lines = text.splitlines()
    if not lines:
        raise CampaignError("manifest has no rows")
    rows: list[dict[str, Any]] = []
    seen_ids: set[int | str] = set()
    seen_relative: set[str] = set()
    seen_sources: set[Path] = set()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise CampaignError(f"manifest line {line_number}: blank row")
        row = validate_manifest_row(
            strict_json(line, where=f"manifest line {line_number}"),
            where=f"manifest line {line_number}",
        )
        if row["id"] in seen_ids:
            raise CampaignError(f"manifest line {line_number}: duplicate id")
        seen_ids.add(row["id"])
        relative = safe_relative_path(
            row["relative_path"], where=f"manifest line {line_number}"
        )
        if relative in seen_relative:
            raise CampaignError(f"manifest line {line_number}: duplicate relative path")
        seen_relative.add(relative)
        source_path = Path(row["path"])
        if not source_path.is_absolute():
            source_path = repository_root / source_path
        source = open_regular_artifact(source_path)
        if source.path in seen_sources:
            raise CampaignError(f"manifest line {line_number}: duplicate source inode path")
        seen_sources.add(source.path)
        relative_parts = PurePosixPath(relative).parts
        if tuple(source.path.parts[-len(relative_parts) :]) != relative_parts:
            raise CampaignError(
                f"manifest line {line_number}: source path suffix does not match relative path"
            )
        try:
            source.content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CampaignError(
                f"manifest line {line_number}: source is not UTF-8: {error}"
            ) from error
        if source.sha256 != row["sha256"]:
            raise CampaignError(f"manifest line {line_number}: source hash mismatch")
        if len(source.content) != row["bytes"]:
            raise CampaignError(f"manifest line {line_number}: source byte count mismatch")
        rows.append(
            {
                "manifest_line": line_number,
                "relative_path": relative,
                "family": family_name(relative),
                "expected_status": row["status"],
                "source_path": str(source.path),
                "source_sha256": source.sha256,
                "source_bytes": len(source.content),
            }
        )
    rows.sort(key=lambda item: item["relative_path"])
    return rows, artifact


def expected_schedule(
    contract: dict[str, Any], *, measured_rounds: int | None = None, warmup_rounds: int | None = None
) -> list[dict[str, Any]]:
    execution = contract["execution"]
    measured = execution["measured_rounds"] if measured_rounds is None else measured_rounds
    warmups = execution["warmup_rounds"] if warmup_rounds is None else warmup_rounds
    schedule: list[dict[str, Any]] = []
    for stage, rounds in (("warmup", warmups), ("measure", measured)):
        for round_index in range(rounds):
            for phase in PHASES:
                for position, parser in enumerate(ABBA_ORDER):
                    schedule.append(
                        {
                            "ordinal": len(schedule),
                            "stage": stage,
                            "round": round_index,
                            "phase": phase,
                            "position": position,
                            "parser": parser,
                        }
                    )
    return schedule


def validate_binary_observation(
    value: Any,
    *,
    parser: str,
    phase: str,
    source_bytes: int,
    where: str,
) -> dict[str, Any]:
    value = require_exact_keys(value, BINARY_OBSERVATION_KEYS, where=where)
    if value["schema"] != BINARY_OBSERVATION_SCHEMA:
        raise CampaignError(f"{where}: wrong observation schema")
    if value["parser"] != parser or value["phase"] != phase:
        raise CampaignError(f"{where}: parser or phase identity mismatch")
    require_integer(value["elapsed_ns"], where=f"{where}.elapsed_ns", minimum=1)
    if value["source_bytes"] != source_bytes:
        raise CampaignError(f"{where}: source byte count mismatch")
    result = value["result"]
    if phase == "parse":
        if result != "parsed":
            raise CampaignError(f"{where}: parse observation did not report parsed")
        if value["result_sha256"] is not None:
            raise CampaignError(f"{where}: parse observation has result digest")
    else:
        if result not in DECISIVE_RESULTS | {"unsupported"}:
            raise CampaignError(f"{where}: malformed solve result")
        require_sha256(value["result_sha256"], where=f"{where}.result_sha256")
    return value


def validate_semantic_attestation(
    value: Any, *, parser: str, source_bytes: int, where: str
) -> dict[str, Any]:
    value = require_exact_keys(value, SEMANTIC_ATTESTATION_KEYS, where=where)
    if value["schema"] != SEMANTIC_ATTESTATION_SCHEMA or value["parser"] != parser:
        raise CampaignError(f"{where}: semantic schema or parser mismatch")
    if value["source_bytes"] != source_bytes:
        raise CampaignError(f"{where}: semantic source byte count mismatch")
    require_sha256(value["canonical_sha256"], where=f"{where}.canonical_sha256")
    for key in SEMANTIC_ATTESTATION_KEYS - {
        "schema",
        "parser",
        "source_bytes",
        "canonical_sha256",
        "contradiction",
    }:
        require_integer(value[key], where=f"{where}.{key}")
    if type(value["contradiction"]) is not bool:
        raise CampaignError(f"{where}.contradiction must be Boolean")
    return value


def semantic_signature(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "parser"}


def parse_binary_stdout(
    stdout: bytes, *, parser: str, phase: str, source_bytes: int
) -> dict[str, Any]:
    try:
        text = stdout.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"binary stdout is not ASCII: {error}") from error
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        raise CampaignError("binary stdout is not exactly one LF-terminated line")
    value = validate_binary_observation(
        strict_json(text[:-1], where="binary stdout"),
        parser=parser,
        phase=phase,
        source_bytes=source_bytes,
        where="binary stdout",
    )
    if canonical_bytes(value) != stdout:
        raise CampaignError("binary stdout is not canonical JSON")
    return value


def parse_semantic_stdout(
    stdout: bytes, *, parser: str, source_bytes: int
) -> dict[str, Any]:
    try:
        text = stdout.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"semantic stdout is not ASCII: {error}") from error
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        raise CampaignError("semantic stdout is not exactly one LF-terminated line")
    value = validate_semantic_attestation(
        strict_json(text[:-1], where="semantic stdout"),
        parser=parser,
        source_bytes=source_bytes,
        where="semantic stdout",
    )
    if canonical_bytes(value) != stdout:
        raise CampaignError("semantic stdout is not canonical JSON")
    return value


def execute_semantic_attestation(
    executable: OpenedExecutable,
    source: bytes,
    *,
    parser: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    execution = execute_binary(
        executable,
        source,
        arguments=["research-parser-semantics", "--parser", parser, "-"],
        timeout_seconds=timeout_seconds,
    )
    if execution.timed_out:
        raise CampaignError(f"{parser} semantic attestation timed out")
    if execution.exit_code != 0 or execution.stderr:
        diagnostic = diagnostic_excerpt(execution.stderr) or f"exit {execution.exit_code}"
        raise CampaignError(f"{parser} semantic attestation failed: {diagnostic}")
    return parse_semantic_stdout(
        execution.stdout, parser=parser, source_bytes=len(source)
    )


def collect_semantic_attestations(
    executable: OpenedExecutable, source: bytes, *, timeout_seconds: int
) -> dict[str, dict[str, Any]]:
    values = {
        parser: execute_semantic_attestation(
            executable,
            source,
            parser=parser,
            timeout_seconds=timeout_seconds,
        )
        for parser in ("tree", "stream")
    }
    if semantic_signature(values["tree"]) != semantic_signature(values["stream"]):
        raise CampaignError("tree and stream semantic attestations differ")
    return values


def diagnostic_excerpt(value: bytes) -> str | None:
    if not value:
        return None
    return value.decode("utf-8", errors="replace")[:DIAGNOSTIC_LIMIT]


def execute_scheduled_observation(
    executable: OpenedExecutable,
    source: bytes,
    schedule: dict[str, Any],
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    execution = execute_observation(
        executable,
        source,
        parser=schedule["parser"],
        phase=schedule["phase"],
        timeout_seconds=timeout_seconds,
    )
    payload = None
    diagnostic = diagnostic_excerpt(execution.stderr)
    if execution.timed_out:
        outcome = "timeout"
    elif execution.exit_code != 0:
        outcome = "error"
        if diagnostic is None:
            diagnostic = f"timing binary exited with status {execution.exit_code}"
    elif execution.stderr:
        outcome = "error"
        diagnostic = diagnostic or "timing binary wrote unexpected stderr"
    else:
        try:
            payload = parse_binary_stdout(
                execution.stdout,
                parser=schedule["parser"],
                phase=schedule["phase"],
                source_bytes=len(source),
            )
            outcome = "ok"
        except CampaignError as error:
            outcome = "error"
            diagnostic = str(error)[:DIAGNOSTIC_LIMIT]
    observation = {
        **schedule,
        "outcome": outcome,
        "exit_code": execution.exit_code,
        "external_elapsed_ns": execution.elapsed_ns,
        "max_rss_kb": execution.max_rss_kb,
        "stdout_sha256": sha256_bytes(execution.stdout),
        "stderr_sha256": sha256_bytes(execution.stderr),
        "diagnostic": diagnostic,
        "payload": payload,
    }
    validate_observation(observation, schedule=schedule, source_bytes=len(source), where="generated observation")
    return observation


def validate_observation(
    value: Any,
    *,
    schedule: dict[str, Any],
    source_bytes: int,
    where: str,
) -> None:
    value = require_exact_keys(value, OBSERVATION_KEYS, where=where)
    for key in ("ordinal", "stage", "round", "phase", "position", "parser"):
        if value[key] != schedule[key]:
            raise CampaignError(f"{where}: immutable ABBA coordinate {key} mismatch")
    if value["outcome"] not in {"ok", "timeout", "error"}:
        raise CampaignError(f"{where}: invalid outcome")
    if value["exit_code"] is not None and type(value["exit_code"]) is not int:
        raise CampaignError(f"{where}: invalid exit code")
    require_integer(value["external_elapsed_ns"], where=f"{where}.external_elapsed_ns", minimum=1)
    require_integer(value["max_rss_kb"], where=f"{where}.max_rss_kb")
    require_sha256(value["stdout_sha256"], where=f"{where}.stdout_sha256")
    require_sha256(value["stderr_sha256"], where=f"{where}.stderr_sha256")
    if value["diagnostic"] is not None and not isinstance(value["diagnostic"], str):
        raise CampaignError(f"{where}: diagnostic must be a string or null")
    if value["outcome"] == "ok":
        if value["exit_code"] != 0 or value["diagnostic"] is not None:
            raise CampaignError(f"{where}: successful observation has diagnostics")
        validate_binary_observation(
            value["payload"],
            parser=schedule["parser"],
            phase=schedule["phase"],
            source_bytes=source_bytes,
            where=f"{where}.payload",
        )
    elif value["payload"] is not None:
        raise CampaignError(f"{where}: failed observation has a payload")


def validate_schedule(
    observations: Any,
    *,
    contract: dict[str, Any],
    source_bytes: int,
    where: str,
    measured_rounds: int | None = None,
    warmup_rounds: int | None = None,
) -> None:
    if not isinstance(observations, list):
        raise CampaignError(f"{where}: observations must be a list")
    schedule = expected_schedule(
        contract, measured_rounds=measured_rounds, warmup_rounds=warmup_rounds
    )
    if len(observations) != len(schedule):
        raise CampaignError(f"{where}: missing or duplicate observations")
    seen: set[tuple[Any, ...]] = set()
    for index, (observation, expected) in enumerate(zip(observations, schedule, strict=True)):
        coordinate = tuple(
            observation.get(key) if isinstance(observation, dict) else None
            for key in ("stage", "round", "phase", "position", "parser")
        )
        if coordinate in seen:
            raise CampaignError(f"{where}: duplicate ABBA observation coordinate")
        seen.add(coordinate)
        validate_observation(
            observation,
            schedule=expected,
            source_bytes=source_bytes,
            where=f"{where}[{index}]",
        )


def validate_work_row(value: Any, *, where: str) -> None:
    value = require_exact_keys(value, WORK_KEYS, where=where)
    if value["schema"] != WORK_SCHEMA or value["byte_binding"] != BYTE_BINDING:
        raise CampaignError(f"{where}: work schema or byte binding mismatch")
    require_integer(value["sequence"], where=f"{where}.sequence")
    require_integer(value["manifest_line"], where=f"{where}.manifest_line", minimum=1)
    safe_relative_path(value["relative_path"], where=f"{where}.relative_path")
    require_string(value["family"], where=f"{where}.family")
    if value["expected_status"] not in DECISIVE_RESULTS:
        raise CampaignError(f"{where}: expected status is not decisive")
    source_path = require_string(value["source_path"], where=f"{where}.source_path")
    if not Path(source_path).is_absolute():
        raise CampaignError(f"{where}: source path is not absolute")
    require_sha256(value["source_sha256"], where=f"{where}.source_sha256")
    require_integer(value["source_bytes"], where=f"{where}.source_bytes")


def validate_preflight(value: Any, *, contract: dict[str, Any], where: str) -> None:
    value = require_exact_keys(value, PREFLIGHT_KEYS, where=where)
    if value["schema"] != PREFLIGHT_SCHEMA:
        raise CampaignError(f"{where}: wrong preflight schema")
    validate_file_binding(value["source"], where=f"{where}.source")
    if value["measured_rounds"] != 1 or value["warmup_rounds"] != 0:
        raise CampaignError(f"{where}: preflight schedule drift")
    validate_semantic_pair(
        value["semantic_attestations"],
        source_bytes=value["source"]["bytes"],
        where=f"{where}.semantic_attestations",
    )
    validate_schedule(
        value["observations"],
        contract=contract,
        source_bytes=value["source"]["bytes"],
        where=f"{where}.observations",
        measured_rounds=1,
        warmup_rounds=0,
    )
    if any(observation["outcome"] != "ok" for observation in value["observations"]):
        raise CampaignError(f"{where}: preflight contains a failed observation")
    assert_exact_observation_parity(
        value["observations"], expected_status=None, where=f"{where}.observations"
    )


def validate_prepare(value: Any, *, contract: dict[str, Any], where: str) -> None:
    value = require_exact_keys(value, PREPARE_KEYS, where=where)
    if value["schema"] != PREPARE_SCHEMA:
        raise CampaignError(f"{where}: wrong prepare schema")
    require_revision(value["revision"])
    repository_root = require_string(
        value["repository_root"], where=f"{where}.repository_root"
    )
    if not Path(repository_root).is_absolute():
        raise CampaignError(f"{where}: repository root is not absolute")
    expected_sources = require_integer(
        value["expected_sources"], where=f"{where}.expected_sources", minimum=1
    )
    source_count = require_integer(
        value["source_count"], where=f"{where}.source_count", minimum=1
    )
    if expected_sources != source_count or expected_sources != contract["campaign"]["expected_sources"]:
        raise CampaignError(f"{where}: source cardinality violates contract")
    if value["shard_count"] != contract["campaign"]["shards"]:
        raise CampaignError(f"{where}: shard count violates contract")
    if value["expected_contract_sha256"] != value["contract"]["sha256"]:
        raise CampaignError(f"{where}: expected contract hash binding differs")
    if value["expected_manifest_sha256"] != value["manifest"]["sha256"]:
        raise CampaignError(f"{where}: expected manifest hash binding differs")
    require_sha256(
        value["expected_contract_sha256"],
        where=f"{where}.expected_contract_sha256",
    )
    require_sha256(
        value["expected_manifest_sha256"],
        where=f"{where}.expected_manifest_sha256",
    )
    validate_runtime_environment(value["runtime_environment"], where=f"{where}.runtime_environment")
    validate_python_binding(value["python"], where=f"{where}.python")
    validate_build_tools(value["build_tools"], where=f"{where}.build_tools")
    validate_binary_binding(value["binary"], where=f"{where}.binary")
    for key in (
        "manifest",
        "tool",
        "contract",
        "preflight",
        "workset",
        "checkout_receipt",
    ):
        validate_file_binding(value[key], where=f"{where}.{key}")


def validate_record(value: Any, *, contract: dict[str, Any], where: str) -> None:
    value = require_exact_keys(value, RECORD_KEYS, where=where)
    if value["schema"] != RECORD_SCHEMA:
        raise CampaignError(f"{where}: wrong record schema")
    if value["byte_binding"] != BYTE_BINDING or value["process_isolation"] != PROCESS_ISOLATION:
        raise CampaignError(f"{where}: execution binding drift")
    require_integer(value["sequence"], where=f"{where}.sequence")
    require_integer(value["shard"], where=f"{where}.shard")
    require_revision(value["revision"])
    require_sha256(value["prepare_sha256"], where=f"{where}.prepare_sha256")
    require_sha256(value["contract_sha256"], where=f"{where}.contract_sha256")
    validate_python_binding(value["python"], where=f"{where}.python")
    validate_binary_binding(value["binary"], where=f"{where}.binary")
    validate_runtime_environment(value["runtime_environment"], where=f"{where}.runtime_environment")
    validate_worker(value["worker"], where=f"{where}.worker")
    safe_relative_path(value["relative_path"], where=f"{where}.relative_path")
    require_string(value["family"], where=f"{where}.family")
    if value["expected_status"] not in DECISIVE_RESULTS:
        raise CampaignError(f"{where}: expected status is not decisive")
    require_sha256(value["source_sha256"], where=f"{where}.source_sha256")
    require_sha256(value["opened_source_sha256"], where=f"{where}.opened_source_sha256")
    source_bytes = require_integer(value["opened_source_bytes"], where=f"{where}.opened_source_bytes")
    validate_semantic_pair(
        value["semantic_attestations"],
        source_bytes=source_bytes,
        where=f"{where}.semantic_attestations",
    )
    validate_schedule(
        value["observations"],
        contract=contract,
        source_bytes=source_bytes,
        where=f"{where}.observations",
    )


def load_object(path: Path) -> tuple[dict[str, Any], CapturedArtifact]:
    artifact = open_regular_artifact(path)
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{path}: object is not ASCII: {error}") from error
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        raise CampaignError(f"{path}: object is not one LF-terminated line")
    value = strict_json(text[:-1], where=str(path))
    if canonical_bytes(value) != artifact.content:
        raise CampaignError(f"{path}: object is not canonical JSON")
    if not isinstance(value, dict):
        raise CampaignError(f"{path}: expected an object")
    return value, artifact


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], CapturedArtifact]:
    artifact = open_regular_artifact(path)
    if not artifact.content:
        return [], artifact
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{path}: JSONL is not ASCII: {error}") from error
    if not text.endswith("\n") or "\r" in text:
        raise CampaignError(f"{path}: JSONL is not LF-terminated")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text[:-1].split("\n"), 1):
        if not line:
            raise CampaignError(f"{path}:{line_number}: blank row")
        value = strict_json(line, where=f"{path}:{line_number}")
        if not isinstance(value, dict):
            raise CampaignError(f"{path}:{line_number}: expected an object")
        if canonical_bytes(value) != (line + "\n").encode("ascii"):
            raise CampaignError(f"{path}:{line_number}: row is not canonical JSON")
        rows.append(value)
    return rows, artifact


def verify_file_binding(value: dict[str, Any], *, where: str) -> CapturedArtifact:
    validate_file_binding(value, where=where)
    artifact = open_regular_artifact(Path(value["path"]))
    if file_binding(artifact) != value:
        raise CampaignError(f"{where}: file identity mismatch")
    return artifact


def assert_exact_observation_parity(
    observations: list[dict[str, Any]], *, expected_status: str | None, where: str
) -> None:
    by_phase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        if observation["stage"] != "measure" or observation["outcome"] != "ok":
            continue
        by_phase[observation["phase"]].append(observation)
    if len(by_phase["parse"]) == 0:
        raise CampaignError(f"{where}: no successful parse observations")
    solve_signatures = {
        (
            observation["payload"]["result"],
            observation["payload"]["result_sha256"],
        )
        for observation in by_phase["end_to_end"]
    }
    if len(solve_signatures) != 1:
        raise CampaignError(f"{where}: tree and stream solve outputs differ")
    if expected_status is not None and solve_signatures:
        result, _ = next(iter(solve_signatures))
        if result != expected_status:
            raise CampaignError(f"{where}: solve result differs from manifest status")


def validate_semantic_pair(value: Any, *, source_bytes: int, where: str) -> None:
    value = require_exact_keys(value, frozenset({"tree", "stream"}), where=where)
    for parser in ("tree", "stream"):
        validate_semantic_attestation(
            value[parser],
            parser=parser,
            source_bytes=source_bytes,
            where=f"{where}.{parser}",
        )
    if semantic_signature(value["tree"]) != semantic_signature(value["stream"]):
        raise CampaignError(f"{where}: exact semantic attestations differ")


def prepare_campaign(args: argparse.Namespace) -> None:
    revision = require_revision(args.revision)
    python_identity = validate_python_identity()
    build_tools = {
        name: validate_external_tool_identity(name)
        for name in sorted(BUILD_TOOL_ENVIRONMENT)
    }
    repository_root = args.repository_root.resolve(strict=True)
    contract, contract_artifact = load_contract(args.contract)
    expected_contract_sha256 = require_sha256(
        args.expected_contract_sha256, where="expected contract SHA-256"
    )
    if contract_artifact.sha256 != expected_contract_sha256:
        raise CampaignError("contract hash differs from submitted expectation")
    expected_sources = contract["campaign"]["expected_sources"]
    source_root = args.source_root.resolve(strict=True)
    rows, manifest_artifact = load_manifest(args.manifest, source_root)
    expected_manifest_sha256 = require_sha256(
        args.expected_manifest_sha256, where="expected manifest SHA-256"
    )
    if manifest_artifact.sha256 != expected_manifest_sha256:
        raise CampaignError("manifest hash differs from submitted expectation")
    checkout_receipt = open_regular_artifact(args.checkout_receipt)
    expected_checkout_receipt_sha256 = require_sha256(
        args.expected_checkout_receipt_sha256,
        where="expected checkout receipt SHA-256",
    )
    if checkout_receipt.sha256 != expected_checkout_receipt_sha256:
        raise CampaignError("checkout receipt hash differs from submitted expectation")
    validate_checkout_receipt(
        checkout_receipt,
        repository_root=repository_root,
        revision=revision,
        where="checkout receipt",
    )
    if len(rows) != expected_sources:
        raise CampaignError(
            f"source cardinality mismatch: expected {expected_sources}, got {len(rows)}"
        )
    if args.output_root.exists():
        raise CampaignError(f"campaign root already exists: {args.output_root}")
    args.output_root.mkdir(mode=0o700, parents=True)
    fsync_directory(args.output_root.parent)
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
    workset_artifact = publish_jsonl(args.output_root / "workset.jsonl", work_rows)
    (args.output_root / "shards").mkdir(mode=0o700)
    fsync_directory(args.output_root)

    preflight_source = open_regular_artifact(args.preflight_source)
    try:
        preflight_source.content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CampaignError(f"preflight source is not UTF-8: {error}") from error
    tool_artifact = open_regular_artifact(Path(__file__))
    with open_verified_executable(args.binary) as executable:
        semantic_attestations = collect_semantic_attestations(
            executable,
            preflight_source.content,
            timeout_seconds=contract["execution"]["per_observation_timeout_seconds"],
        )
        observations = [
            execute_scheduled_observation(
                executable,
                preflight_source.content,
                schedule,
                timeout_seconds=contract["execution"]["per_observation_timeout_seconds"],
            )
            for schedule in expected_schedule(contract, measured_rounds=1, warmup_rounds=0)
        ]
        preflight = {
            "schema": PREFLIGHT_SCHEMA,
            "source": file_binding(preflight_source),
            "measured_rounds": 1,
            "warmup_rounds": 0,
            "semantic_attestations": semantic_attestations,
            "observations": observations,
        }
        validate_preflight(preflight, contract=contract, where="generated preflight")
        preflight_artifact = publish_json(args.output_root / "preflight.json", preflight)
        prepare = {
            "schema": PREPARE_SCHEMA,
            "revision": revision,
            "repository_root": str(repository_root),
            "expected_sources": expected_sources,
            "source_count": len(rows),
            "shard_count": contract["campaign"]["shards"],
            "runtime_environment": RUNTIME_ENVIRONMENT,
            "python": python_identity,
            "build_tools": build_tools,
            "manifest": file_binding(manifest_artifact),
            "binary": executable.binding,
            "tool": file_binding(tool_artifact),
            "contract": file_binding(contract_artifact),
            "preflight": file_binding(preflight_artifact),
            "workset": file_binding(workset_artifact),
            "expected_contract_sha256": expected_contract_sha256,
            "expected_manifest_sha256": expected_manifest_sha256,
            "checkout_receipt": file_binding(checkout_receipt),
        }
        validate_prepare(prepare, contract=contract, where="generated prepare")
        publish_json(args.output_root / "prepare.json", prepare)


def load_prepared(
    root: Path,
    revision: str,
    *,
    expected_contract_sha256: str,
    expected_manifest_sha256: str,
    expected_checkout_receipt_sha256: str,
) -> PreparedCampaign:
    revision = require_revision(revision)
    root = root.resolve(strict=True)
    prepare, prepare_artifact = load_object(root / "prepare.json")
    contract_binding = prepare.get("contract")
    if not isinstance(contract_binding, dict):
        raise CampaignError("prepare has no contract binding")
    contract_artifact = verify_file_binding(contract_binding, where="prepared contract")
    try:
        contract_text = contract_artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"prepared contract is not ASCII: {error}") from error
    contract = validate_contract(
        strict_json(contract_text, where="prepared contract"), where="prepared contract"
    )
    validate_prepare(prepare, contract=contract, where="prepare")
    for label, supplied, recorded in (
        ("contract", expected_contract_sha256, prepare["expected_contract_sha256"]),
        ("manifest", expected_manifest_sha256, prepare["expected_manifest_sha256"]),
        (
            "checkout receipt",
            expected_checkout_receipt_sha256,
            prepare["checkout_receipt"]["sha256"],
        ),
    ):
        if require_sha256(supplied, where=f"expected {label} SHA-256") != recorded:
            raise CampaignError(f"prepared {label} hash differs from submitted expectation")
    if prepare["revision"] != revision:
        raise CampaignError("prepare revision differs from executing revision")
    if prepare["python"] != validate_python_identity():
        raise CampaignError("prepared Python identity drift")
    for name, binding in prepare["build_tools"].items():
        verify_build_tool_binding(binding, where=f"prepared {name}")
    if prepare["runtime_environment"] != RUNTIME_ENVIRONMENT:
        raise CampaignError("prepared runtime environment drift")
    for name in ("manifest", "tool"):
        verify_file_binding(prepare[name], where=f"prepared {name}")
    checkout_receipt = verify_file_binding(
        prepare["checkout_receipt"], where="prepared checkout receipt"
    )
    validate_checkout_receipt(
        checkout_receipt,
        repository_root=Path(prepare["repository_root"]),
        revision=revision,
        where="prepared checkout receipt",
    )
    preflight, preflight_artifact = load_object(Path(prepare["preflight"]["path"]))
    if file_binding(preflight_artifact) != prepare["preflight"]:
        raise CampaignError("prepared preflight identity mismatch")
    validate_preflight(preflight, contract=contract, where="prepared preflight")
    work_rows, workset_artifact = load_jsonl(Path(prepare["workset"]["path"]))
    if file_binding(workset_artifact) != prepare["workset"]:
        raise CampaignError("prepared workset identity mismatch")
    if len(work_rows) != prepare["source_count"]:
        raise CampaignError("prepared workset cardinality mismatch")
    for sequence, row in enumerate(work_rows):
        validate_work_row(row, where=f"workset row {sequence}")
        if row["sequence"] != sequence:
            raise CampaignError("workset sequence is missing, duplicated, or reordered")
    return PreparedCampaign(prepare, prepare_artifact, contract, work_rows, workset_artifact)


def run_work_item(
    work: dict[str, Any],
    *,
    shard: int,
    prepared: PreparedCampaign,
    executable: OpenedExecutable,
    worker: dict[str, Any],
) -> dict[str, Any]:
    source = open_regular_artifact(Path(work["source_path"]))
    if source.sha256 != work["source_sha256"] or len(source.content) != work["source_bytes"]:
        raise CampaignError(f"source bytes changed after prepare: {work['relative_path']}")
    try:
        source.content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CampaignError(f"source is no longer UTF-8: {work['relative_path']}") from error
    timeout_seconds = prepared.contract["execution"]["per_observation_timeout_seconds"]
    semantic_attestations = collect_semantic_attestations(
        executable, source.content, timeout_seconds=timeout_seconds
    )
    observations = [
        execute_scheduled_observation(
            executable,
            source.content,
            schedule,
            timeout_seconds=timeout_seconds,
        )
        for schedule in expected_schedule(prepared.contract)
    ]
    record = {
        "schema": RECORD_SCHEMA,
        "byte_binding": BYTE_BINDING,
        "process_isolation": PROCESS_ISOLATION,
        "sequence": work["sequence"],
        "shard": shard,
        "revision": prepared.metadata["revision"],
        "prepare_sha256": prepared.prepare_artifact.sha256,
        "contract_sha256": prepared.metadata["contract"]["sha256"],
        "python": prepared.metadata["python"],
        "binary": executable.binding,
        "runtime_environment": RUNTIME_ENVIRONMENT,
        "worker": worker,
        "relative_path": work["relative_path"],
        "family": work["family"],
        "expected_status": work["expected_status"],
        "source_sha256": work["source_sha256"],
        "opened_source_sha256": source.sha256,
        "opened_source_bytes": len(source.content),
        "semantic_attestations": semantic_attestations,
        "observations": observations,
    }
    validate_record(
        record,
        contract=prepared.contract,
        where=f"generated record {work['sequence']}",
    )
    return record


def run_shard(args: argparse.Namespace) -> None:
    root = args.root.resolve(strict=True)
    prepared = load_prepared(
        root,
        args.revision,
        expected_contract_sha256=args.expected_contract_sha256,
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_checkout_receipt_sha256=args.expected_checkout_receipt_sha256,
    )
    shard_count = prepared.metadata["shard_count"]
    if args.shard >= shard_count:
        raise CampaignError(f"shard {args.shard} is outside [0, {shard_count})")
    output = root / "shards" / f"shard-{args.shard:05d}.jsonl"
    if output.exists():
        raise CampaignError(f"refusing to replace shard artifact {output}")
    records: list[dict[str, Any]] = []
    worker = bind_worker(require_linux_affinity=args.require_linux_affinity)
    with open_verified_executable(
        Path(prepared.metadata["binary"]["path"]), expected=prepared.metadata["binary"]
    ) as executable:
        for work in prepared.workset:
            if work["sequence"] % shard_count != args.shard:
                continue
            records.append(
                run_work_item(
                    work,
                    shard=args.shard,
                    prepared=prepared,
                    executable=executable,
                    worker=worker,
                )
            )
    expected = sum(
        work["sequence"] % shard_count == args.shard for work in prepared.workset
    )
    if len(records) != expected:
        raise CampaignError("internal shard cardinality mismatch")
    publish_jsonl(output, records)


def nearest_rank_p95(values: list[float]) -> float:
    if not values:
        raise CampaignError("p95 population must not be empty")
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def _measured_observations(record: dict[str, Any], phase: str) -> list[dict[str, Any]]:
    return [
        observation
        for observation in record["observations"]
        if observation["stage"] == "measure" and observation["phase"] == phase
    ]


def analyze_source(record: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    rounds = contract["execution"]["measured_rounds"]
    expected_per_arm = rounds * 2
    parse_observations = _measured_observations(record, "parse")
    solve_observations = _measured_observations(record, "end_to_end")
    all_solve_observations = [
        item for item in record["observations"] if item["phase"] == "end_to_end"
    ]

    semantic_values = record["semantic_attestations"]
    parse_parity = semantic_signature(semantic_values["tree"]) == semantic_signature(
        semantic_values["stream"]
    )

    solve_ok = [item for item in all_solve_observations if item["outcome"] == "ok"]
    solve_signatures = {
        (item["payload"]["result"], item["payload"]["result_sha256"])
        for item in solve_ok
    }
    incorrect = sum(
        item["payload"]["result"] in DECISIVE_RESULTS
        and item["payload"]["result"] != record["expected_status"]
        for item in solve_ok
    )
    result_parity = (
        len(solve_ok)
        == (contract["execution"]["warmup_rounds"] + rounds) * len(ABBA_ORDER)
        and incorrect == 0
        and len(solve_signatures) == 1
    )
    solved: dict[str, bool] = {}
    for parser in ("tree", "stream"):
        arm = [item for item in solve_observations if item["parser"] == parser]
        solved[parser] = len(arm) == expected_per_arm and all(
            item["outcome"] == "ok"
            and item["payload"]["result"] == record["expected_status"]
            for item in arm
        )

    phase_metrics: dict[str, dict[str, Any] | None] = {}
    for phase, observations in (("parse", parse_observations), ("end_to_end", solve_observations)):
        complete = parse_parity and len(observations) == expected_per_arm * 2 and all(
            item["outcome"] == "ok" for item in observations
        )
        if phase == "end_to_end":
            complete = complete and result_parity and all(
                item["payload"]["result"] == record["expected_status"]
                for item in observations
            )
        if not complete:
            phase_metrics[phase] = None
            continue
        by_coordinate = {
            (item["round"], item["position"]): item for item in observations
        }
        baseline_times = [
            item["payload"]["elapsed_ns"] for item in observations if item["parser"] == "tree"
        ]
        candidate_times = [
            item["payload"]["elapsed_ns"] for item in observations if item["parser"] == "stream"
        ]
        baseline_rss = [item["max_rss_kb"] for item in observations if item["parser"] == "tree"]
        candidate_rss = [item["max_rss_kb"] for item in observations if item["parser"] == "stream"]
        paired_ratios: list[float] = []
        for round_index in range(rounds):
            paired_ratios.append(
                by_coordinate[(round_index, 1)]["payload"]["elapsed_ns"]
                / by_coordinate[(round_index, 0)]["payload"]["elapsed_ns"]
            )
            paired_ratios.append(
                by_coordinate[(round_index, 2)]["payload"]["elapsed_ns"]
                / by_coordinate[(round_index, 3)]["payload"]["elapsed_ns"]
            )
        phase_metrics[phase] = {
            "baseline_median_ns": statistics.median(baseline_times),
            "candidate_median_ns": statistics.median(candidate_times),
            "baseline_median_rss_kb": statistics.median(baseline_rss),
            "candidate_median_rss_kb": statistics.median(candidate_rss),
            "paired_ratios": paired_ratios,
        }

    outcome_counts = {"ok": 0, "timeout": 0, "error": 0}
    for observation in record["observations"]:
        outcome_counts[observation["outcome"]] += 1
    return {
        "relative_path": record["relative_path"],
        "family": record["family"],
        "expected_status": record["expected_status"],
        "parse_parity": parse_parity,
        "result_parity": result_parity,
        "incorrect_results": incorrect,
        "solved": solved,
        "baseline_only_solve": solved["tree"] and not solved["stream"],
        "outcomes": outcome_counts,
        "phase_metrics": phase_metrics,
    }


def summarize_phase(rows: list[dict[str, Any]], phase: str) -> dict[str, Any]:
    complete = [row["phase_metrics"][phase] for row in rows if row["phase_metrics"][phase] is not None]
    if not complete:
        return {
            "common_sources": 0,
            "baseline_aggregate_ns": 0.0,
            "candidate_aggregate_ns": 0.0,
            "aggregate_ratio": None,
            "paired_geomean_ratio": None,
            "paired_comparisons": 0,
            "wins": 0,
            "ties": 0,
            "losses": 0,
            "overhead_population_sources": 0,
            "p95_all_source_overhead": None,
            "baseline_aggregate_rss_kb": 0.0,
            "candidate_aggregate_rss_kb": 0.0,
            "rss_aggregate_ratio": None,
        }
    baseline = [float(item["baseline_median_ns"]) for item in complete]
    candidate = [float(item["candidate_median_ns"]) for item in complete]
    baseline_sum = math.fsum(baseline)
    candidate_sum = math.fsum(candidate)
    paired = [ratio for item in complete for ratio in item["paired_ratios"]]
    geomean = math.exp(math.fsum(math.log(ratio) for ratio in paired) / len(paired))
    overheads = [
        max(candidate_time / baseline_time - 1.0, 0.0)
        for baseline_time, candidate_time in zip(baseline, candidate, strict=True)
    ]
    baseline_rss = math.fsum(float(item["baseline_median_rss_kb"]) for item in complete)
    candidate_rss = math.fsum(float(item["candidate_median_rss_kb"]) for item in complete)
    return {
        "common_sources": len(complete),
        "baseline_aggregate_ns": baseline_sum,
        "candidate_aggregate_ns": candidate_sum,
        "aggregate_ratio": candidate_sum / baseline_sum,
        "paired_geomean_ratio": geomean,
        "paired_comparisons": len(paired),
        "wins": sum(candidate_time < baseline_time for baseline_time, candidate_time in zip(baseline, candidate, strict=True)),
        "ties": sum(candidate_time == baseline_time for baseline_time, candidate_time in zip(baseline, candidate, strict=True)),
        "losses": sum(candidate_time > baseline_time for baseline_time, candidate_time in zip(baseline, candidate, strict=True)),
        "overhead_population_sources": len(overheads),
        "p95_all_source_overhead": nearest_rank_p95(overheads),
        "baseline_aggregate_rss_kb": baseline_rss,
        "candidate_aggregate_rss_kb": candidate_rss,
        "rss_aggregate_ratio": candidate_rss / baseline_rss if baseline_rss > 0 else None,
    }


def summarize_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(rows),
        "solved": {
            "tree": sum(row["solved"]["tree"] for row in rows),
            "stream": sum(row["solved"]["stream"] for row in rows),
        },
        "parse": summarize_phase(rows, "parse"),
        "end_to_end": summarize_phase(rows, "end_to_end"),
    }


def build_strata(rows: list[dict[str, Any]]) -> dict[str, Any]:
    status_groups = {
        status: [row for row in rows if row["expected_status"] == status]
        for status in sorted(DECISIVE_RESULTS)
    }
    families = sorted({row["family"] for row in rows})
    family_groups = {
        family: [row for row in rows if row["family"] == family] for family in families
    }
    return {
        "expected_status": {
            status: summarize_group(group) for status, group in status_groups.items()
        },
        "family": {family: summarize_group(group) for family, group in family_groups.items()},
    }


def evaluate_gates(
    rows: list[dict[str, Any]], metrics: dict[str, Any], contract: dict[str, Any]
) -> dict[str, bool]:
    thresholds = contract["gates"]
    solved_tree = sum(row["solved"]["tree"] for row in rows)
    solved_stream = sum(row["solved"]["stream"] for row in rows)
    gates: dict[str, bool] = {
        "all_sources_accounted": len(rows) == contract["campaign"]["expected_sources"],
        "exact_semantic_parity": all(row["parse_parity"] for row in rows),
        "exact_result_parity": all(row["result_parity"] for row in rows),
        "zero_incorrect_results": sum(row["incorrect_results"] for row in rows) == 0,
        "no_solved_count_regression": solved_stream == solved_tree,
        "no_baseline_only_solve": not any(row["baseline_only_solve"] for row in rows),
        "zero_observation_errors": sum(row["outcomes"]["error"] for row in rows) == 0,
        "zero_observation_timeouts": sum(row["outcomes"]["timeout"] for row in rows) == 0,
    }
    for phase in PHASES:
        phase_metrics = metrics[phase]
        gates[f"{phase}_full_common_population"] = (
            phase_metrics["common_sources"]
            == thresholds["common_sources_required_per_phase"]
            and phase_metrics["overhead_population_sources"]
            == thresholds["common_sources_required_per_phase"]
        )
        gates[f"{phase}_aggregate_improved"] = (
            phase_metrics["aggregate_ratio"] is not None
            and phase_metrics["aggregate_ratio"]
            < thresholds["aggregate_ratio_max_exclusive"]
        )
        gates[f"{phase}_paired_improved"] = (
            phase_metrics["paired_geomean_ratio"] is not None
            and phase_metrics["paired_geomean_ratio"]
            < thresholds["paired_geomean_ratio_max_exclusive"]
        )
        gates[f"{phase}_p95_all_source_overhead_below_one_percent"] = (
            phase_metrics["p95_all_source_overhead"] is not None
            and phase_metrics["p95_all_source_overhead"]
            < thresholds["p95_all_source_overhead_max_exclusive"]
        )
    gates["passed"] = all(gates.values())
    return gates


def validate_audit(value: Any, *, where: str) -> None:
    value = require_exact_keys(value, AUDIT_KEYS, where=where)
    if value["schema"] != AUDIT_SCHEMA or value["status"] not in {"accepted", "rejected"}:
        raise CampaignError(f"{where}: audit schema or status mismatch")
    require_revision(value["revision"])
    require_integer(value["source_count"], where=f"{where}.source_count")
    require_integer(value["expected_sources"], where=f"{where}.expected_sources", minimum=1)
    require_integer(value["shard_count"], where=f"{where}.shard_count", minimum=1)
    require_sha256(value["contract_sha256"], where=f"{where}.contract_sha256")
    validate_python_binding(value["python"], where=f"{where}.python")
    validate_build_tools(value["build_tools"], where=f"{where}.build_tools")
    validate_binary_binding(value["binary"], where=f"{where}.binary")
    validate_runtime_environment(value["runtime_environment"], where=f"{where}.runtime_environment")
    for key in ("counts", "metrics", "strata", "gates", "artifacts"):
        if not isinstance(value[key], dict):
            raise CampaignError(f"{where}.{key} must be an object")
    ensure_finite_json(value, where=where)
    if value["status"] == "accepted" and value["gates"].get("passed") is not True:
        raise CampaignError(f"{where}: accepted audit did not pass")
    if value["status"] == "rejected" and value["gates"].get("passed") is not False:
        raise CampaignError(f"{where}: rejected audit claims pass")


def audit_campaign(args: argparse.Namespace) -> bool:
    root = args.root.resolve(strict=True)
    prepared = load_prepared(
        root,
        args.revision,
        expected_contract_sha256=args.expected_contract_sha256,
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_checkout_receipt_sha256=args.expected_checkout_receipt_sha256,
    )
    prepare = prepared.metadata
    shard_count = prepare["shard_count"]
    records: list[dict[str, Any]] = []
    shard_hashes: dict[str, str] = {}
    shard_workers: dict[str, dict[str, Any]] = {}
    for shard in range(shard_count):
        path = root / "shards" / f"shard-{shard:05d}.jsonl"
        shard_rows, artifact = load_jsonl(path)
        shard_hashes[f"{shard:05d}"] = artifact.sha256
        for index, record in enumerate(shard_rows):
            validate_record(
                record,
                contract=prepared.contract,
                where=f"shard {shard} row {index}",
            )
            if record["shard"] != shard:
                raise CampaignError(f"shard {shard}: embedded shard mismatch")
            if record["revision"] != prepare["revision"]:
                raise CampaignError(f"shard {shard}: revision mismatch")
            if record["prepare_sha256"] != prepared.prepare_artifact.sha256:
                raise CampaignError(f"shard {shard}: prepare binding mismatch")
            if record["contract_sha256"] != prepare["contract"]["sha256"]:
                raise CampaignError(f"shard {shard}: contract binding mismatch")
            if record["python"] != prepare["python"] or record["binary"] != prepare["binary"]:
                raise CampaignError(f"shard {shard}: executable identity mismatch")
            shard_key = f"{shard:05d}"
            prior_worker = shard_workers.setdefault(shard_key, record["worker"])
            if prior_worker != record["worker"]:
                raise CampaignError(f"shard {shard}: worker identity changed within shard")
            records.append(record)
    records.sort(key=lambda row: row["sequence"])
    if [row["sequence"] for row in records] != list(range(len(prepared.workset))):
        raise CampaignError("merged records are missing, duplicated, or non-contiguous")
    for work, record in zip(prepared.workset, records, strict=True):
        for key in (
            "relative_path",
            "family",
            "expected_status",
            "source_sha256",
        ):
            if record[key] != work[key]:
                raise CampaignError(f"record/workset {key} mismatch")
        if (
            record["opened_source_sha256"] != work["source_sha256"]
            or record["opened_source_bytes"] != work["source_bytes"]
        ):
            raise CampaignError("record is not bound to prepared source bytes")

    analyzed = [analyze_source(record, prepared.contract) for record in records]
    metrics = {phase: summarize_phase(analyzed, phase) for phase in PHASES}
    strata = build_strata(analyzed)
    gates = evaluate_gates(analyzed, metrics, prepared.contract)
    outcome_counts = {"ok": 0, "timeout": 0, "error": 0}
    for row in analyzed:
        for outcome in outcome_counts:
            outcome_counts[outcome] += row["outcomes"][outcome]
    counts = {
        "parse_parity_sources": sum(row["parse_parity"] for row in analyzed),
        "result_parity_sources": sum(row["result_parity"] for row in analyzed),
        "incorrect_results": sum(row["incorrect_results"] for row in analyzed),
        "solved_tree": sum(row["solved"]["tree"] for row in analyzed),
        "solved_stream": sum(row["solved"]["stream"] for row in analyzed),
        "observation_outcomes": outcome_counts,
        "workers": shard_workers,
    }
    records_artifact = publish_jsonl(root / "records.jsonl", records)
    audit = {
        "schema": AUDIT_SCHEMA,
        "status": "accepted" if gates["passed"] else "rejected",
        "revision": prepare["revision"],
        "source_count": len(records),
        "expected_sources": prepare["expected_sources"],
        "shard_count": shard_count,
        "contract_sha256": prepare["contract"]["sha256"],
        "python": prepare["python"],
        "build_tools": prepare["build_tools"],
        "binary": prepare["binary"],
        "runtime_environment": prepare["runtime_environment"],
        "counts": counts,
        "metrics": metrics,
        "strata": strata,
        "gates": gates,
        "artifacts": {
            "prepare_sha256": prepared.prepare_artifact.sha256,
            "contract_sha256": prepare["contract"]["sha256"],
            "manifest_sha256": prepare["manifest"]["sha256"],
            "checkout_receipt_sha256": prepare["checkout_receipt"]["sha256"],
            "workset_sha256": prepared.workset_artifact.sha256,
            "records_sha256": records_artifact.sha256,
            "shard_sha256": shard_hashes,
        },
    }
    validate_audit(audit, where="generated audit")
    audit_artifact = publish_json(root / "audit.json", audit)
    publish_new(
        root / "audit-sha256.txt",
        f"{audit_artifact.sha256}  audit.json\n".encode("ascii"),
    )
    return gates["passed"]


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


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--manifest", type=Path, required=True)
    prepare.add_argument("--repository-root", type=Path, required=True)
    prepare.add_argument("--source-root", type=Path, required=True)
    prepare.add_argument("--binary", type=Path, required=True)
    prepare.add_argument("--preflight-source", type=Path, required=True)
    prepare.add_argument("--contract", type=Path, required=True)
    prepare.add_argument("--revision", required=True)
    prepare.add_argument("--output-root", type=Path, required=True)
    prepare.add_argument("--checkout-receipt", type=Path, required=True)
    prepare.add_argument("--expected-checkout-receipt-sha256", required=True)
    prepare.add_argument("--expected-contract-sha256", required=True)
    prepare.add_argument("--expected-manifest-sha256", required=True)

    shard = commands.add_parser("run-shard")
    shard.add_argument("--root", type=Path, required=True)
    shard.add_argument("--revision", required=True)
    shard.add_argument("--shard", type=nonnegative_integer, required=True)
    shard.add_argument("--require-linux-affinity", action="store_true")
    shard.add_argument("--expected-checkout-receipt-sha256", required=True)
    shard.add_argument("--expected-contract-sha256", required=True)
    shard.add_argument("--expected-manifest-sha256", required=True)

    audit = commands.add_parser("audit")
    audit.add_argument("--root", type=Path, required=True)
    audit.add_argument("--revision", required=True)
    audit.add_argument("--expected-checkout-receipt-sha256", required=True)
    audit.add_argument("--expected-contract-sha256", required=True)
    audit.add_argument("--expected-manifest-sha256", required=True)
    return parser


def main() -> int:
    args = argument_parser().parse_args()
    try:
        if args.command == "prepare":
            prepare_campaign(args)
            return 0
        if args.command == "run-shard":
            run_shard(args)
            return 0
        if args.command == "audit":
            return 0 if audit_campaign(args) else 1
        raise AssertionError(args.command)
    except (CampaignError, OSError) as error:
        print(f"T1 typed parser timing campaign error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
