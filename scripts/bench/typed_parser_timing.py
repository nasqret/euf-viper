#!/usr/bin/env python3
"""Prepare, execute, and audit the preregistered T1 parser timing gate."""

from __future__ import annotations

import argparse
import base64
import binascii
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
import struct
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, NamedTuple


CONTRACT_SCHEMA = "euf-viper.typed-parser-timing-contract.v3"
PREPARE_SCHEMA = "euf-viper.typed-parser-timing-prepare.v2"
WORK_SCHEMA = "euf-viper.typed-parser-timing-work.v2"
BINARY_OBSERVATION_SCHEMA = "euf-viper.typed-parser-timing-observation.v1"
SEMANTIC_ATTESTATION_SCHEMA = "euf-viper.typed-parser-semantics.v1"
PREFLIGHT_SCHEMA = "euf-viper.typed-parser-timing-preflight.v2"
RECORD_SCHEMA = "euf-viper.typed-parser-timing-record.v2"
SHARD_RECEIPT_SCHEMA = "euf-viper.typed-parser-timing-shard-receipt.v1"
SHARD_SET_RECEIPT_SCHEMA = "euf-viper.typed-parser-timing-shard-set-receipt.v1"
HASH_CHAIN_SCHEMA = "euf-viper.sha256-record-chain.v1"
BUILD_RECEIPT_SCHEMA = "euf-viper.t1-guarded-release-build.v3"
AUDIT_SCHEMA = "euf-viper.typed-parser-timing-audit.v2"
BYTE_BINDING = "single-open-descriptor-buffer-replay.v1"
EXECUTABLE_BINDING = "inherited-descriptor-static-elf.v1"
PRIVATE_COPY_BINDING = "private-byte-copy.v1"
PROCESS_ISOLATION = "fresh-process-per-observation.v1"
ABBA_ORDER = ("tree", "stream", "stream", "tree")
PHASES = ("parse", "end_to_end")
LOCKED_SOURCE_COUNT = 7503
LOCKED_SHARDS = 128
LOCKED_MAX_PARALLEL = 1
LOCKED_WARMUP_ROUNDS = 1
LOCKED_MEASURED_ROUNDS = 5
LOCKED_TIMEOUT_SECONDS = 2
ACCEPTED_MANIFEST_SHA256 = "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
ACCEPTED_PARITY_RECEIPT_SHA256 = "c0c9c1879c9ac2da524c69f07affa991626c326ac0837f8f8066fde708d8482c"
ACCEPTED_WORKSET_SHA256 = "35127766939028747b170b2dc26ca74b78a89c39833c37cd6961146b09cbb7a3"
ACCEPTED_PARITY_RECEIPT_PATH = "results/wmi/typed-parser-parity-146510/receipt.json"
ACCEPTED_PARITY_LOCAL_ARTIFACTS = {
    "audit_json_sha256": "audit.json",
    "independent_json_sha256": "typed-parser-parity-20260713T221314Z-66099-independent.json",
    "prepare_json_sha256": "prepare.json",
    "preflight_json_sha256": "preflight.json",
    "submission_json_sha256": "submission.json",
}
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
    "ar": ("EUF_VIPER_AR", "EUF_VIPER_AR_SHA256", "EUF_VIPER_AR_VERSION"),
    "cargo": ("EUF_VIPER_CARGO", "EUF_VIPER_CARGO_SHA256", "EUF_VIPER_CARGO_VERSION"),
    "cc": ("EUF_VIPER_CC", "EUF_VIPER_CC_SHA256", "EUF_VIPER_CC_VERSION"),
    "ld": ("EUF_VIPER_LD", "EUF_VIPER_LD_SHA256", "EUF_VIPER_LD_VERSION"),
    "rustc": ("EUF_VIPER_RUSTC", "EUF_VIPER_RUSTC_SHA256", "EUF_VIPER_RUSTC_VERSION"),
}
MAX_CAPTURE_BYTES = 1_048_576
DIAGNOSTIC_LIMIT = 4096
RUNTIME_ENVIRONMENT: dict[str, str | None] = {
    "EUF_VIPER_SCOPED_LET": "auto",
    "EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT": "1024",
    "EUF_VIPER_PROFILE": None,
    "EUF_VIPER_BACKEND": "auto",
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
    {
        "schema",
        "name",
        "arms",
        "campaign",
        "corpus",
        "execution",
        "gates",
        "measurement",
        "timing_environment",
    }
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
        "stdout_base64",
        "stdout_sha256",
        "stderr_base64",
        "stderr_sha256",
        "diagnostic",
        "payload",
    }
)
CAPTURED_PAYLOAD_KEYS = frozenset(
    {
        "exit_code",
        "external_elapsed_ns",
        "max_rss_kb",
        "stdout_base64",
        "stdout_sha256",
        "stderr_base64",
        "stderr_sha256",
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
        "timing_environment",
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
        "accepted_parity_receipt",
        "checkout_receipt",
        "build_receipt",
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
        "timing_environment",
        "promotable",
        "promotion_reasons",
        "counts",
        "metrics",
        "strata",
        "gates",
        "artifacts",
    }
)
SHARD_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "status",
        "shard",
        "revision",
        "prepare_sha256",
        "contract_sha256",
        "record_count",
        "records",
        "records_chain",
        "worker_sha256",
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
    static_elf: dict[str, Any] | None


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


def encode_raw(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_raw(value: Any, *, where: str) -> bytes:
    text = require_string(value, where=where, nonempty=False)
    if not text.isascii():
        raise CampaignError(f"{where}: base64 must be ASCII")
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise CampaignError(f"{where}: malformed base64") from error
    if encode_raw(decoded) != text:
        raise CampaignError(f"{where}: noncanonical base64")
    if len(decoded) > MAX_CAPTURE_BYTES:
        raise CampaignError(f"{where}: decoded capture exceeds limit")
    return decoded


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


def open_inherited_artifact(path: Path, descriptor: int) -> CapturedArtifact:
    if not sys.platform.startswith("linux"):
        raise CampaignError("inherited artifact descriptors require Linux procfs")
    canonical = path.resolve(strict=True)
    try:
        duplicate = os.dup(descriptor)
    except OSError as error:
        raise CampaignError(f"cannot duplicate inherited artifact descriptor: {error}") from error
    try:
        target = Path(f"/proc/self/fd/{duplicate}").resolve(strict=True)
        if target != canonical:
            raise CampaignError("inherited artifact descriptor does not name its supplied path")
        before = file_fingerprint(duplicate)
        if not stat.S_ISREG(before.mode):
            raise CampaignError("inherited artifact descriptor is not regular")
        content = read_descriptor(duplicate, before.size)
        if file_fingerprint(duplicate) != before:
            raise CampaignError("inherited artifact descriptor changed while read")
        return CapturedArtifact(canonical, content, sha256_bytes(content))
    finally:
        os.close(duplicate)


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


def publish_new(path: Path, content: bytes, *, mode: int = 0o400) -> CapturedArtifact:
    """Publish a fully written inode atomically without replacing an artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    linked = False
    try:
        write_all(descriptor, content)
        os.fchmod(descriptor, mode)
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
        if stat.S_IMODE(path.stat().st_mode) != mode:
            raise CampaignError(f"published artifact mode verification failed: {path}")
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


def record_hash_chain(content: bytes) -> dict[str, Any]:
    if content and not content.endswith(b"\n"):
        raise CampaignError("record chain input is not LF-terminated")
    lines = [] if not content else content.splitlines(keepends=True)
    head = hashlib.sha256(b"euf-viper.t1-record-chain.v1\0").digest()
    for line in lines:
        head = hashlib.sha256(
            b"euf-viper.t1-record-chain.v1\0"
            + head
            + len(line).to_bytes(8, "big")
            + line
        ).digest()
    return {
        "schema": HASH_CHAIN_SCHEMA,
        "algorithm": "sha256",
        "domain": "euf-viper.t1-record-chain.v1",
        "records": len(lines),
        "head": head.hex(),
    }


def executable_binding_contract() -> str:
    return EXECUTABLE_BINDING if sys.platform.startswith("linux") else PRIVATE_COPY_BINDING


def inspect_static_linux_elf(content: bytes, *, digest: str) -> dict[str, Any]:
    if not sys.platform.startswith("linux"):
        raise CampaignError("static guarded release verification requires Linux")
    if len(content) < 64 or content[:4] != b"\x7fELF":
        raise CampaignError("guarded release is not an ELF image")
    identity = content[:16]
    if identity[4:7] != b"\x02\x01\x01":
        raise CampaignError("guarded release is not little-endian ELF64 version 1")
    (
        elf_type,
        machine,
        version,
        _entry,
        program_offset,
        _section_offset,
        _flags,
        header_size,
        program_entry_size,
        program_count,
        _section_entry_size,
        _section_count,
        _section_names,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", content, 16)
    if (
        elf_type not in {2, 3}
        or machine not in {62, 183}
        or version != 1
        or header_size != 64
        or program_entry_size != 56
        or program_count < 1
        or program_count > 4096
        or program_offset + program_entry_size * program_count > len(content)
    ):
        raise CampaignError("guarded release ELF identity or program table is unsupported")
    interpreter_count = 0
    dynamic_segments: list[tuple[int, int]] = []
    for index in range(program_count):
        segment_type, _segment_flags, offset, _vaddr, _paddr, file_size, memory_size, _align = (
            struct.unpack_from("<IIQQQQQQ", content, program_offset + index * program_entry_size)
        )
        if file_size > memory_size or offset + file_size > len(content):
            raise CampaignError("guarded release ELF has an invalid program segment")
        if segment_type == 3:
            interpreter_count += 1
        elif segment_type == 2:
            dynamic_segments.append((offset, file_size))
    if interpreter_count != 0:
        raise CampaignError("guarded release must not contain PT_INTERP")
    if len(dynamic_segments) > 1:
        raise CampaignError("guarded release has multiple PT_DYNAMIC segments")
    needed_count = 0
    if dynamic_segments:
        offset, size = dynamic_segments[0]
        if size % 16:
            raise CampaignError("guarded release has a misaligned PT_DYNAMIC segment")
        terminated = False
        for entry in range(offset, offset + size, 16):
            tag, _value = struct.unpack_from("<qQ", content, entry)
            if tag == 0:
                terminated = True
                break
            if tag == 1:
                needed_count += 1
        if not terminated:
            raise CampaignError("guarded release has an unterminated PT_DYNAMIC segment")
    if needed_count:
        raise CampaignError("guarded release must not contain DT_NEEDED entries")
    return {
        "schema": "euf-viper.t1-static-linux-elf.v1",
        "binary_sha256": digest,
        "binary_bytes": len(content),
        "class": "ELF64",
        "endianness": "little",
        "machine": {62: "x86_64", 183: "aarch64"}[machine],
        "type": {2: "executable", 3: "shared-or-pie"}[elf_type],
        "pt_interp_count": 0,
        "dt_needed_count": 0,
        "native_runtime": "no-pt-interp-zero-dt-needed.v1",
    }


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
    path: Path,
    expected: dict[str, Any] | None = None,
    *,
    inherited_descriptor: int | None = None,
    require_static_linux_elf: bool = False,
) -> Iterator[OpenedExecutable]:
    canonical = path.resolve(strict=True)
    if inherited_descriptor is None:
        descriptor = os.open(canonical, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    else:
        try:
            descriptor = os.dup(inherited_descriptor)
        except OSError as error:
            raise CampaignError(f"cannot duplicate inherited timing binary: {error}") from error
        if sys.platform.startswith("linux"):
            try:
                descriptor_target = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
            except OSError as error:
                os.close(descriptor)
                raise CampaignError(
                    f"cannot resolve inherited timing descriptor: {error}"
                ) from error
            if descriptor_target != canonical:
                os.close(descriptor)
                raise CampaignError(
                    "inherited timing descriptor does not name the supplied binary path"
                )
    cleanup_directory: Path | None = None
    try:
        before = file_fingerprint(descriptor)
        if not stat.S_ISREG(before.mode) or before.mode & 0o111 == 0:
            raise CampaignError("timing binary is not a regular executable")
        content = read_descriptor(descriptor, before.size)
        digest = sha256_bytes(content)
        static_elf = (
            inspect_static_linux_elf(content, digest=digest)
            if require_static_linux_elf
            else None
        )
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
            static_elf,
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
    if capture_overflow:
        raise CampaignError(
            "process output exceeded the exact-capture limit; refusing truncated evidence"
        )
    exit_code = None if timed_out else os.waitstatus_to_exitcode(status)
    return Execution(
        exit_code,
        bytes(streams["stdout"]),
        bytes(streams["stderr"]),
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


def validate_embedded_json_artifact(
    value: Any, *, where: str, verify_path: bool = True
) -> dict[str, Any]:
    value = require_exact_keys(value, frozenset({"path", "sha256", "payload"}), where=where)
    path = Path(require_string(value["path"], where=f"{where}.path"))
    if not path.is_absolute():
        raise CampaignError(f"{where}.path must be absolute")
    expected = require_sha256(value["sha256"], where=f"{where}.sha256")
    if not verify_path:
        parsed = value["payload"]
        if not isinstance(parsed, dict) or sha256_bytes(canonical_bytes(parsed)) != expected:
            raise CampaignError(f"{where}: descriptor-sealed embedded payload mismatch")
        return parsed
    artifact = open_regular_artifact(path)
    if stat.S_IMODE(path.stat().st_mode) != 0o400:
        raise CampaignError(f"{where}: embedded artifact is not sealed mode 0400")
    if artifact.sha256 != expected:
        raise CampaignError(f"{where}: embedded artifact hash mismatch")
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{where}: embedded artifact is not ASCII") from error
    parsed = strict_json(text, where=where)
    if canonical_bytes(parsed) != artifact.content or parsed != value["payload"]:
        raise CampaignError(f"{where}: embedded artifact payload mismatch")
    if not isinstance(parsed, dict):
        raise CampaignError(f"{where}: embedded payload is not an object")
    return parsed


def validate_clean_mutation_monitor(
    value: Any, *, expected_root: Path, where: str, verify_paths: bool = True
) -> dict[str, Any]:
    monitor = validate_embedded_json_artifact(value, where=where, verify_path=verify_paths)
    monitor = require_exact_keys(
        monitor,
        frozenset(
            {
                "schema",
                "control",
                "monitor_pid",
                "parent_pid",
                "poll_cycles",
                "snapshot",
                "watched_directories",
                "watch_mask",
                "event_count",
                "ready",
                "events",
                "status",
            }
        ),
        where=f"{where}.payload",
    )
    if (
        monitor["schema"] != "euf-viper.t1-mutation-monitor-receipt.v3"
        or monitor["control"] != "parent-owned-pipe-eof.v1"
        or require_integer(monitor["monitor_pid"], where=f"{where}.monitor_pid", minimum=2)
        < 2
        or require_integer(monitor["parent_pid"], where=f"{where}.parent_pid", minimum=2)
        < 2
        or require_integer(monitor["poll_cycles"], where=f"{where}.poll_cycles", minimum=1)
        < 1
        or monitor["status"] != "clean"
        or monitor["event_count"] != 0
        or monitor["snapshot"] != str(expected_root)
        or require_integer(
            monitor["watched_directories"],
            where=f"{where}.watched_directories",
            minimum=1,
        )
        < 1
        or require_integer(monitor["watch_mask"], where=f"{where}.watch_mask", minimum=1)
        < 1
    ):
        raise CampaignError(f"{where}: mutation monitor is not clean and root-bound")
    ready = require_exact_keys(
        monitor["ready"],
        frozenset({"path", "sha256", "bytes"}),
        where=f"{where}.ready",
    )
    ready_path = Path(require_string(ready["path"], where=f"{where}.ready.path"))
    if not ready_path.is_absolute():
        raise CampaignError(f"{where}: mutation readiness path is not absolute")
    expected_ready_sha = require_sha256(
        ready["sha256"], where=f"{where}.ready.sha256"
    )
    expected_ready_bytes = require_integer(
        ready["bytes"], where=f"{where}.ready.bytes", minimum=1
    )
    if verify_paths:
        ready_artifact = open_regular_artifact(ready_path)
        if stat.S_IMODE(ready_path.stat().st_mode) != 0o400:
            raise CampaignError(f"{where}: mutation readiness is not sealed mode 0400")
        try:
            ready_payload = strict_json(
                ready_artifact.content.decode("ascii"), where=f"{where}.ready"
            )
        except UnicodeDecodeError as error:
            raise CampaignError(f"{where}: mutation readiness is not ASCII") from error
        expected_ready = {
            "schema": "euf-viper.t1-mutation-monitor-ready.v3",
            "control": monitor["control"],
            "monitor_pid": monitor["monitor_pid"],
            "parent_pid": monitor["parent_pid"],
            "snapshot": monitor["snapshot"],
            "watch_setup_complete": True,
            "watched_directories": monitor["watched_directories"],
            "watch_mask": monitor["watch_mask"],
        }
        if (
            ready_artifact.sha256 != expected_ready_sha
            or len(ready_artifact.content) != expected_ready_bytes
            or canonical_bytes(ready_payload) != ready_artifact.content
            or ready_payload != expected_ready
        ):
            raise CampaignError(f"{where}: mutation readiness binding is invalid")
    elif expected_ready_bytes < 1:
        raise CampaignError(f"{where}: descriptor-sealed readiness evidence is empty")
    events = require_exact_keys(
        monitor["events"],
        frozenset({"path", "sha256", "bytes"}),
        where=f"{where}.events",
    )
    events_path = Path(require_string(events["path"], where=f"{where}.events.path"))
    if not events_path.is_absolute():
        raise CampaignError(f"{where}: mutation event log path is not absolute")
    expected_event_sha = require_sha256(
        events["sha256"], where=f"{where}.events.sha256"
    )
    expected_event_bytes = require_integer(
        events["bytes"], where=f"{where}.events.bytes"
    )
    if verify_paths:
        event_artifact = open_regular_artifact(events_path)
        if stat.S_IMODE(events_path.stat().st_mode) != 0o400:
            raise CampaignError(f"{where}: mutation event log is not sealed mode 0400")
        if (
            event_artifact.sha256 != expected_event_sha
            or len(event_artifact.content) != expected_event_bytes
            or event_artifact.content != b""
        ):
            raise CampaignError(f"{where}: clean mutation event log is not empty and bound")
    elif expected_event_sha != EMPTY_SHA256 or expected_event_bytes != 0:
        raise CampaignError(f"{where}: descriptor-sealed clean event binding is not empty")
    return monitor


def validate_static_elf_attestation(
    value: Any, *, binary: dict[str, Any], where: str
) -> dict[str, Any]:
    value = require_exact_keys(
        value,
        frozenset(
            {
                "schema",
                "binary_sha256",
                "binary_bytes",
                "class",
                "endianness",
                "machine",
                "type",
                "pt_interp_count",
                "dt_needed_count",
                "native_runtime",
            }
        ),
        where=where,
    )
    if (
        value["schema"] != "euf-viper.t1-static-linux-elf.v1"
        or value["binary_sha256"] != binary["sha256"]
        or value["binary_bytes"] != binary["bytes"]
        or value["class"] != "ELF64"
        or value["endianness"] != "little"
        or value["machine"] not in {"x86_64", "aarch64"}
        or value["type"] not in {"executable", "shared-or-pie"}
        or value["pt_interp_count"] != 0
        or value["dt_needed_count"] != 0
        or value["native_runtime"] != "no-pt-interp-zero-dt-needed.v1"
    ):
        raise CampaignError(
            f"{where}: release is not a bound static ELF without PT_INTERP or DT_NEEDED"
        )
    return value


def validate_build_receipt(
    artifact: CapturedArtifact,
    *,
    revision: str,
    binary: dict[str, Any],
    python_identity: dict[str, Any],
    build_tools: dict[str, Any],
    where: str,
    verify_embedded_paths: bool = True,
) -> dict[str, Any]:
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{where}: build receipt is not ASCII") from error
    value = require_exact_keys(
        strict_json(text, where=where),
        frozenset(
            {
                "schema",
                "status",
                "revision",
                "source_snapshot",
                "pre_inventory",
                "post_inventory",
                "mutation_monitor",
                "dependency_pre_inventory",
                "dependency_post_inventory",
                "dependency_mutation_monitor",
                "binary",
                "static_elf",
                "linker_selection",
                "python",
                "tools",
                "build",
            }
        ),
        where=where,
    )
    if canonical_bytes(value) != artifact.content:
        raise CampaignError(f"{where}: build receipt is not canonical JSON")
    if value["schema"] != BUILD_RECEIPT_SCHEMA or value["status"] != "clean":
        raise CampaignError(f"{where}: guarded build did not close cleanly")
    if value["revision"] != revision:
        raise CampaignError(f"{where}: build revision mismatch")
    snapshot = Path(require_string(value["source_snapshot"], where=f"{where}.source_snapshot"))
    if not snapshot.is_absolute():
        raise CampaignError(f"{where}: source snapshot is not absolute")
    if verify_embedded_paths:
        resolved_snapshot = snapshot.resolve(strict=True)
        if snapshot != resolved_snapshot or snapshot.is_symlink() or not snapshot.is_dir():
            raise CampaignError(f"{where}: source snapshot is not a canonical directory")
        snapshot = resolved_snapshot
    elif Path(os.path.normpath(str(snapshot))) != snapshot or ".." in snapshot.parts:
        raise CampaignError(f"{where}: source snapshot path is not lexically canonical")
    pre = validate_embedded_json_artifact(
        value["pre_inventory"],
        where=f"{where}.pre_inventory",
        verify_path=verify_embedded_paths,
    )
    post = validate_embedded_json_artifact(
        value["post_inventory"],
        where=f"{where}.post_inventory",
        verify_path=verify_embedded_paths,
    )
    if pre != post or pre.get("revision") != revision or pre.get("snapshot") != str(snapshot):
        raise CampaignError(f"{where}: pre/post source inventory mismatch")
    validate_clean_mutation_monitor(
        value["mutation_monitor"],
        expected_root=snapshot,
        where=f"{where}.mutation_monitor",
        verify_paths=verify_embedded_paths,
    )
    dependency_pre = validate_embedded_json_artifact(
        value["dependency_pre_inventory"],
        where=f"{where}.dependency_pre_inventory",
        verify_path=verify_embedded_paths,
    )
    dependency_post = validate_embedded_json_artifact(
        value["dependency_post_inventory"],
        where=f"{where}.dependency_post_inventory",
        verify_path=verify_embedded_paths,
    )
    if dependency_pre != dependency_post:
        raise CampaignError(f"{where}: dependency inventory changed during offline build")
    dependency_pre = require_exact_keys(
        dependency_pre,
        frozenset(
            {
                "schema",
                "root",
                "directories",
                "files",
                "bytes",
                "entries_sha256",
            }
        ),
        where=f"{where}.dependency_inventory.payload",
    )
    if dependency_pre["schema"] != "euf-viper.t1-external-dependency-inventory.v1":
        raise CampaignError(f"{where}: dependency inventory schema drifted")
    dependency_root = Path(
        require_string(dependency_pre["root"], where=f"{where}.dependency_inventory.root")
    )
    if not dependency_root.is_absolute():
        raise CampaignError(f"{where}: dependency inventory root is not canonical")
    if verify_embedded_paths:
        if dependency_root != dependency_root.resolve(strict=True):
            raise CampaignError(f"{where}: dependency inventory root is not canonical")
    elif Path(os.path.normpath(str(dependency_root))) != dependency_root or ".." in dependency_root.parts:
        raise CampaignError(f"{where}: dependency inventory root is not lexically canonical")
    validate_clean_mutation_monitor(
        value["dependency_mutation_monitor"],
        expected_root=dependency_root,
        where=f"{where}.dependency_mutation_monitor",
        verify_paths=verify_embedded_paths,
    )
    require_integer(
        dependency_pre["directories"],
        where=f"{where}.dependency_inventory.directories",
        minimum=1,
    )
    require_integer(
        dependency_pre["files"], where=f"{where}.dependency_inventory.files", minimum=1
    )
    require_integer(dependency_pre["bytes"], where=f"{where}.dependency_inventory.bytes")
    require_sha256(
        dependency_pre["entries_sha256"],
        where=f"{where}.dependency_inventory.entries_sha256",
    )
    build_binary = require_exact_keys(
        value["binary"],
        frozenset({"path", "sha256", "bytes", "attestation"}),
        where=f"{where}.binary",
    )
    if build_binary["attestation"] != "inherited-open-descriptor.v1":
        raise CampaignError(f"{where}: release binary was not descriptor-attested")
    if {key: build_binary[key] for key in ("path", "sha256", "bytes")} != {
        key: binary[key] for key in ("path", "sha256", "bytes")
    }:
        raise CampaignError(f"{where}: release binary identity mismatch")
    validate_static_elf_attestation(
        value["static_elf"],
        binary=build_binary,
        where=f"{where}.static_elf",
    )
    build_python = require_exact_keys(
        value["python"],
        frozenset({"path", "sha256", "bytes", "version"}),
        where=f"{where}.python",
    )
    if {key: build_python[key] for key in ("path", "sha256", "version")} != python_identity:
        raise CampaignError(f"{where}: Python identity mismatch")
    validate_build_tools(value["tools"], where=f"{where}.tools")
    if value["tools"] != build_tools:
        raise CampaignError(f"{where}: compiler or linker identity mismatch")
    linker_selection = require_exact_keys(
        value["linker_selection"],
        frozenset(
            {
                "driver_path",
                "driver_sha256",
                "request",
                "resolved_path",
                "resolved_sha256",
            }
        ),
        where=f"{where}.linker_selection",
    )
    if linker_selection != {
        "driver_path": build_tools["cc"]["path"],
        "driver_sha256": build_tools["cc"]["sha256"],
        "request": "-fuse-ld=bfd",
        "resolved_path": build_tools["ld"]["path"],
        "resolved_sha256": build_tools["ld"]["sha256"],
    }:
        raise CampaignError(f"{where}: selected linker is not the pinned linker")
    build = require_exact_keys(
        value["build"],
        frozenset(
            {
                "allocator",
                "backend",
                "cargo_home",
                "cargo_profile",
                "dependency_mode",
                "features",
                "fetch_cargo_home",
                "locked",
                "native_linkage",
                "offline",
                "rustflags",
                "target_dir",
                "vendor_dir",
            }
        ),
        where=f"{where}.build",
    )
    if (
        build["allocator"] != "rust-system-allocator-static-runtime"
        or build["backend"] != "auto"
        or build["cargo_profile"] != "release"
        or build["dependency_mode"] != "locked-vendor-offline-v1"
        or build["features"] != ["finite-symmetry"]
        or build["locked"] is not True
        or build["native_linkage"] != "crt-static-no-interpreter-no-needed.v1"
        or build["offline"] is not True
        or not Path(build["cargo_home"]).is_absolute()
        or not Path(build["fetch_cargo_home"]).is_absolute()
        or not Path(build["target_dir"]).is_absolute()
        or not Path(build["vendor_dir"]).is_absolute()
    ):
        raise CampaignError(f"{where}: locked release configuration drifted")
    cargo_home_path = Path(build["cargo_home"])
    fetch_cargo_home_path = Path(build["fetch_cargo_home"])
    target_dir_path = Path(build["target_dir"])
    vendor_dir_path = Path(build["vendor_dir"])
    if verify_embedded_paths:
        cargo_home = cargo_home_path.resolve(strict=True)
        fetch_cargo_home = fetch_cargo_home_path.resolve(strict=True)
        target_dir = target_dir_path.resolve(strict=True)
        vendor_dir = vendor_dir_path.resolve(strict=True)
    else:
        cargo_home = Path(os.path.normpath(str(cargo_home_path)))
        fetch_cargo_home = Path(os.path.normpath(str(fetch_cargo_home_path)))
        target_dir = Path(os.path.normpath(str(target_dir_path)))
        vendor_dir = Path(os.path.normpath(str(vendor_dir_path)))
    if (
        cargo_home_path != cargo_home
        or fetch_cargo_home_path != fetch_cargo_home
        or target_dir_path != target_dir
        or vendor_dir_path != vendor_dir
    ):
        raise CampaignError(f"{where}: build output paths are not canonical")
    if any(
        path.is_relative_to(snapshot)
        for path in (cargo_home, fetch_cargo_home, target_dir, vendor_dir)
    ):
        raise CampaignError(f"{where}: build output is inside the watched source snapshot")
    if vendor_dir != dependency_root / "vendor":
        raise CampaignError(f"{where}: offline vendor directory is not dependency-bound")
    expected_rustflags = (
        f"-C linker={build_tools['cc']['path']} -C link-arg=-fuse-ld=bfd "
        "-C target-feature=+crt-static"
    )
    if build["rustflags"] != expected_rustflags:
        raise CampaignError(f"{where}: linker flags drifted")
    return value


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
        output = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise CampaignError(f"pinned {name} version is not ASCII") from error
    if not output:
        raise CampaignError(f"pinned {name} version is empty")
    version = output.splitlines()[0]
    if not version or "\r" in version:
        raise CampaignError(f"pinned {name} version first line is malformed")
    return version


def validate_runtime_environment(value: Any, *, where: str) -> None:
    if value != RUNTIME_ENVIRONMENT:
        raise CampaignError(f"{where}: runtime environment contract drift")


def validate_worker(value: Any, *, where: str) -> None:
    value = require_exact_keys(
        value,
        frozenset(
            {
                "hostname",
                "platform",
                "machine",
                "cpu_id",
                "affinity",
                "cpu_model",
                "microcode",
                "physical_package_id",
                "core_id",
                "thread_siblings_list",
                "numa_node",
                "scaling_governor",
                "scaling_driver",
                "scaling_min_khz",
                "scaling_max_khz",
                "scaling_current_khz",
                "turbo_state",
                "slurm_partition",
                "slurm_nodelist",
                "slurm_cpus_per_task",
                "slurm_cpu_bind",
                "slurm_mem_bind",
                "slurm_threads_per_core",
                "slurm_job_cpus_per_node",
                "slurm_job_num_nodes",
                "slurm_cpu_freq_req",
                "physical_cores_on_node",
                "submission_mode",
                "placement_contract",
                "governor_control",
                "exclusive_control",
                "libc",
                "allocator",
                "backend",
            }
        ),
        where=where,
    )
    for key in (
        "hostname",
        "platform",
        "machine",
        "affinity",
        "cpu_model",
        "microcode",
        "thread_siblings_list",
        "scaling_governor",
        "scaling_driver",
        "turbo_state",
        "slurm_partition",
        "slurm_nodelist",
        "slurm_cpu_bind",
        "slurm_mem_bind",
        "slurm_cpu_freq_req",
        "submission_mode",
        "placement_contract",
        "allocator",
        "backend",
    ):
        text = require_string(value[key], where=f"{where}.{key}")
        if not text.isascii() or "\n" in text or "\r" in text:
            raise CampaignError(f"{where}.{key} must be one ASCII line")
    for key in (
        "cpu_id",
        "physical_package_id",
        "core_id",
        "numa_node",
        "scaling_min_khz",
        "scaling_max_khz",
        "scaling_current_khz",
        "slurm_cpus_per_task",
        "slurm_threads_per_core",
        "slurm_job_cpus_per_node",
        "slurm_job_num_nodes",
        "physical_cores_on_node",
    ):
        require_integer(value[key], where=f"{where}.{key}")
    for key in ("governor_control", "exclusive_control"):
        if type(value[key]) is not bool:
            raise CampaignError(f"{where}.{key} must be Boolean")
    expected_placement = {
        "full": "slurm-serial-exclusive-core-local-high-userspace.v1",
        "canary": "bounded-canary-uncontrolled.v1",
    }
    if (
        value["submission_mode"] not in expected_placement
        or value["placement_contract"]
        != expected_placement[value["submission_mode"]]
    ):
        raise CampaignError(f"{where}: submission mode and placement contract differ")
    for key in (
        "cpu_model",
        "microcode",
        "thread_siblings_list",
        "scaling_governor",
        "scaling_driver",
        "turbo_state",
    ):
        if value[key] == "unavailable":
            raise CampaignError(f"{where}.{key} identity is unavailable")
    for key in ("scaling_min_khz", "scaling_max_khz", "scaling_current_khz"):
        if value[key] == 0:
            raise CampaignError(f"{where}.{key} identity is unavailable")
    if value["scaling_min_khz"] > value["scaling_max_khz"]:
        raise CampaignError(f"{where}: scaling frequency bounds are inconsistent")
    if not (
        value["scaling_min_khz"]
        <= value["scaling_current_khz"]
        <= value["scaling_max_khz"]
    ):
        raise CampaignError(f"{where}: current frequency is outside recorded bounds")
    libc = require_exact_keys(
        value["libc"],
        frozenset({"path", "sha256", "bytes", "name", "version"}),
        where=f"{where}.libc",
    )
    if not Path(require_string(libc["path"], where=f"{where}.libc.path")).is_absolute():
        raise CampaignError(f"{where}.libc.path must be absolute")
    require_sha256(libc["sha256"], where=f"{where}.libc.sha256")
    require_integer(libc["bytes"], where=f"{where}.libc.bytes", minimum=1)
    require_string(libc["name"], where=f"{where}.libc.name")
    require_string(libc["version"], where=f"{where}.libc.version")


def _read_one_line(path: Path, *, unavailable: str = "unavailable") -> str:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError:
        return unavailable
    if not value or "\n" in value or "\r" in value:
        return unavailable
    return value


def _read_integer(path: Path) -> int:
    value = _read_one_line(path, unavailable="0")
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def _cpuinfo_fields(cpu_id: int) -> dict[str, str]:
    try:
        sections = Path("/proc/cpuinfo").read_text(encoding="ascii").split("\n\n")
    except OSError:
        return {"model name": "unavailable", "microcode": "unavailable"}
    for section in sections:
        fields = {
            key.strip(): value.strip()
            for line in section.splitlines()
            if ":" in line
            for key, value in [line.split(":", 1)]
        }
        if fields.get("processor") == str(cpu_id):
            return fields
    return {"model name": "unavailable", "microcode": "unavailable"}


def _environment_integer(name: str) -> int:
    value = os.environ.get(name, "0")
    if not value.isascii() or not value.isdigit() or (len(value) > 1 and value.startswith("0")):
        raise CampaignError(f"{name} is not a canonical nonnegative integer")
    return int(value)


def _slurm_single_node_cpu_count() -> int:
    value = os.environ.get("SLURM_JOB_CPUS_PER_NODE", "0")
    match = re.fullmatch(r"([1-9][0-9]*)(?:\(x1\))?", value)
    return int(match.group(1)) if match else 0


def _physical_core_count() -> int:
    cores: set[tuple[int, int]] = set()
    for cpu in Path("/sys/devices/system/cpu").glob("cpu[0-9]*"):
        package = _read_integer(cpu / "topology/physical_package_id")
        core = _read_integer(cpu / "topology/core_id")
        if (cpu / "topology/physical_package_id").is_file() and (
            cpu / "topology/core_id"
        ).is_file():
            cores.add((package, core))
    return len(cores)


def loaded_libc_identity() -> dict[str, Any]:
    candidates: set[Path] = set()
    maps = Path("/proc/self/maps")
    if maps.is_file():
        for line in maps.read_text(encoding="ascii").splitlines():
            fields = line.split()
            if fields and fields[-1].startswith("/") and "libc.so" in fields[-1]:
                candidates.add(Path(fields[-1]).resolve(strict=True))
    if len(candidates) != 1:
        raise CampaignError("cannot identify exactly one loaded libc")
    path = next(iter(candidates))
    artifact = open_regular_artifact(path)
    name, version = platform.libc_ver()
    if not name or not version:
        raise CampaignError("cannot identify libc name and version")
    return {
        "path": str(path),
        "sha256": artifact.sha256,
        "bytes": len(artifact.content),
        "name": name,
        "version": version,
    }


def worker_homogeneous_identity(worker: dict[str, Any]) -> dict[str, Any]:
    return {
        key: worker[key]
        for key in (
            "hostname",
            "platform",
            "machine",
            "cpu_model",
            "microcode",
            "physical_package_id",
            "numa_node",
            "scaling_governor",
            "scaling_driver",
            "scaling_min_khz",
            "scaling_max_khz",
            "turbo_state",
            "slurm_partition",
            "slurm_nodelist",
            "slurm_cpus_per_task",
            "slurm_cpu_bind",
            "slurm_mem_bind",
            "slurm_threads_per_core",
            "slurm_job_cpus_per_node",
            "slurm_job_num_nodes",
            "slurm_cpu_freq_req",
            "physical_cores_on_node",
            "submission_mode",
            "placement_contract",
            "governor_control",
            "exclusive_control",
            "libc",
            "allocator",
            "backend",
        )
    }


def require_homogeneous_workers(workers: Iterable[dict[str, Any]]) -> None:
    identities = {
        sha256_bytes(canonical_bytes(worker_homogeneous_identity(worker)))
        for worker in workers
    }
    if len(identities) != 1:
        raise CampaignError("timing shards have mixed hardware or runtime identities")


def bind_worker(
    *,
    contract: dict[str, Any],
    require_linux_affinity: bool,
    submission_mode: str,
    require_placement_controls: bool,
) -> dict[str, Any]:
    cpu_id = 0
    affinity = "unavailable-nonlinux"
    if hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"):
        allowed = sorted(os.sched_getaffinity(0))
        if not allowed:
            raise CampaignError("worker has no allowed CPUs")
        if require_linux_affinity and len(allowed) != 1:
            raise CampaignError("SLURM affinity is not exactly one pinned logical CPU")
        cpu_id = allowed[0]
        os.sched_setaffinity(0, {cpu_id})
        if os.sched_getaffinity(0) != {cpu_id}:
            raise CampaignError("worker CPU affinity did not become singleton")
        affinity = "sched_setaffinity-singleton.v1"
    elif require_linux_affinity:
        raise CampaignError("Linux singleton CPU affinity is required")
    if not sys.platform.startswith("linux"):
        raise CampaignError("worker identity collection requires Linux")
    hostname = platform.node()
    if require_linux_affinity and hostname not in contract["timing_environment"]["allowed_hostnames"]:
        raise CampaignError(f"worker hostname is outside the preregistered node set: {hostname}")
    cpu_root = Path(f"/sys/devices/system/cpu/cpu{cpu_id}")
    topology = cpu_root / "topology"
    cpufreq = cpu_root / "cpufreq"
    cpuinfo = _cpuinfo_fields(cpu_id)
    numa_nodes = sorted(
        int(path.name[4:])
        for path in cpu_root.glob("node[0-9]*")
        if path.name[4:].isdigit()
    )
    if require_linux_affinity and len(numa_nodes) != 1:
        raise CampaignError("pinned CPU does not identify exactly one NUMA node")
    siblings = _read_one_line(topology / "thread_siblings_list")
    governor = _read_one_line(cpufreq / "scaling_governor")
    minimum = _read_integer(cpufreq / "scaling_min_freq")
    maximum = _read_integer(cpufreq / "scaling_max_freq")
    current = _read_integer(cpufreq / "scaling_cur_freq")
    turbo = _read_one_line(Path("/sys/devices/system/cpu/intel_pstate/no_turbo"))
    if turbo == "unavailable":
        turbo = _read_one_line(Path("/sys/devices/system/cpu/cpufreq/boost"))
    job_cpus_per_node = _slurm_single_node_cpu_count()
    job_num_nodes = _environment_integer("SLURM_JOB_NUM_NODES")
    physical_cores = _physical_core_count()
    frequency_request = os.environ.get("SLURM_CPU_FREQ_REQ", "unavailable")
    if (
        not frequency_request
        or not frequency_request.isascii()
        or "\n" in frequency_request
        or "\r" in frequency_request
    ):
        frequency_request = "unavailable"
    fixed_frequency = (
        governor.lower() == "userspace" and minimum > 0 and minimum == maximum
    )
    exclusive = (
        submission_mode == "full"
        and job_num_nodes == 1
        and physical_cores > 0
        and job_cpus_per_node == physical_cores
    )
    worker = {
        "hostname": hostname,
        "platform": platform.system(),
        "machine": platform.machine(),
        "cpu_id": cpu_id,
        "affinity": affinity,
        "cpu_model": cpuinfo.get("model name", "unavailable"),
        "microcode": cpuinfo.get("microcode", "unavailable"),
        "physical_package_id": _read_integer(topology / "physical_package_id"),
        "core_id": _read_integer(topology / "core_id"),
        "thread_siblings_list": siblings,
        "numa_node": numa_nodes[0] if numa_nodes else 0,
        "scaling_governor": governor,
        "scaling_driver": _read_one_line(cpufreq / "scaling_driver"),
        "scaling_min_khz": minimum,
        "scaling_max_khz": maximum,
        "scaling_current_khz": current,
        "turbo_state": turbo,
        "slurm_partition": os.environ.get("SLURM_JOB_PARTITION", "unavailable"),
        "slurm_nodelist": os.environ.get("SLURM_JOB_NODELIST", "unavailable"),
        "slurm_cpus_per_task": _environment_integer("SLURM_CPUS_PER_TASK"),
        "slurm_cpu_bind": os.environ.get(
            "SLURM_CPU_BIND_TYPE", os.environ.get("SLURM_CPU_BIND", "unavailable")
        ),
        "slurm_mem_bind": os.environ.get(
            "SLURM_MEM_BIND_TYPE", os.environ.get("SLURM_MEM_BIND", "unavailable")
        ),
        "slurm_threads_per_core": _environment_integer("SLURM_THREADS_PER_CORE"),
        "slurm_job_cpus_per_node": job_cpus_per_node,
        "slurm_job_num_nodes": job_num_nodes,
        "slurm_cpu_freq_req": frequency_request,
        "physical_cores_on_node": physical_cores,
        "submission_mode": submission_mode,
        "placement_contract": (
            "slurm-serial-exclusive-core-local-high-userspace.v1"
            if submission_mode == "full"
            else "bounded-canary-uncontrolled.v1"
        ),
        "governor_control": fixed_frequency,
        "exclusive_control": exclusive,
        "libc": loaded_libc_identity(),
        "allocator": "rust-system-allocator-static-runtime",
        "backend": "auto",
    }
    if require_linux_affinity:
        if any(
            worker[key] == "unavailable"
            for key in ("cpu_model", "microcode", "thread_siblings_list")
        ):
            raise CampaignError("required CPU identity metadata is unavailable")
        timing = contract["timing_environment"]
        if worker["slurm_partition"] != timing["partition"]:
            raise CampaignError("SLURM partition differs from the timing contract")
        if worker["slurm_nodelist"] != timing["slurm_nodelist"]:
            raise CampaignError("SLURM node allocation differs from the timing contract")
        if worker["slurm_cpus_per_task"] != 1 or worker["slurm_threads_per_core"] != 1:
            raise CampaignError("SLURM did not allocate one physical core per timing task")
        if "cores" not in worker["slurm_cpu_bind"].split(","):
            raise CampaignError("SLURM did not report core binding")
        if "local" not in worker["slurm_mem_bind"].split(","):
            raise CampaignError("SLURM did not report local NUMA memory binding")
    if require_placement_controls:
        if submission_mode != "full":
            raise CampaignError("placement controls can only be required for a full campaign")
        if frequency_request == "unavailable":
            raise CampaignError("SLURM did not propagate the frequency request")
        if not worker["exclusive_control"]:
            raise CampaignError("SLURM allocation does not prove exclusive node control")
        if not worker["governor_control"]:
            raise CampaignError("SLURM frequency request did not produce fixed userspace control")
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
        frozenset({"expected_sources", "source_count", "shards", "max_parallel"}),
        where=f"{where}.campaign",
    )
    locked_campaign = {
        "expected_sources": LOCKED_SOURCE_COUNT,
        "source_count": LOCKED_SOURCE_COUNT,
        "shards": LOCKED_SHARDS,
        "max_parallel": LOCKED_MAX_PARALLEL,
    }
    if campaign != locked_campaign:
        raise CampaignError(f"{where}: immutable campaign dimensions drifted")

    corpus = require_exact_keys(
        value["corpus"],
        frozenset(
            {
                "accepted_manifest_sha256",
                "accepted_parity_receipt_path",
                "accepted_parity_receipt_sha256",
                "accepted_workset_sha256",
                "source_count",
            }
        ),
        where=f"{where}.corpus",
    )
    if corpus != {
        "accepted_manifest_sha256": ACCEPTED_MANIFEST_SHA256,
        "accepted_parity_receipt_path": ACCEPTED_PARITY_RECEIPT_PATH,
        "accepted_parity_receipt_sha256": ACCEPTED_PARITY_RECEIPT_SHA256,
        "accepted_workset_sha256": ACCEPTED_WORKSET_SHA256,
        "source_count": LOCKED_SOURCE_COUNT,
    }:
        raise CampaignError(f"{where}: accepted corpus evidence drifted")

    execution = require_exact_keys(
        value["execution"],
        frozenset(
            {
                "binary_command",
                "byte_binding",
                "executable_binding_linux",
                "measured_rounds",
                "native_runtime",
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
        "native_runtime": "no-pt-interp-zero-dt-needed.v1",
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

    timing_environment = require_exact_keys(
        value["timing_environment"],
        frozenset(
            {
                "allowed_hostnames",
                "canary_shards",
                "core_binding",
                "exclusive_allocation",
                "exclusive_control_required_for_promotion",
                "frequency_control",
                "governor_control_required_for_promotion",
                "max_parallel",
                "memory_binding",
                "partition",
                "promotion_eligibility",
                "slurm_nodelist",
                "threads_per_core",
            }
        ),
        where=f"{where}.timing_environment",
    )
    expected_timing_environment = {
        "allowed_hostnames": ["c1n1.cluster.wmi.amu.edu.pl"],
        "canary_shards": 1,
        "core_binding": "slurm-cpu-bind-cores-singleton.v1",
        "exclusive_allocation": "serial-slurm-exclusive-node-runtime-verified.v1",
        "exclusive_control_required_for_promotion": True,
        "frequency_control": "slurm-srun-high-userspace-runtime-verified.v1",
        "governor_control_required_for_promotion": True,
        "max_parallel": LOCKED_MAX_PARALLEL,
        "memory_binding": "slurm-mem-bind-local.v1",
        "partition": "cpu_idle",
        "promotion_eligibility": "permanently-nonpromotable-research-only",
        "slurm_nodelist": "c1n1",
        "threads_per_core": 1,
    }
    if timing_environment != expected_timing_environment:
        raise CampaignError(f"{where}: immutable timing environment drifted")
    return value


def load_contract(path: Path) -> tuple[dict[str, Any], CapturedArtifact]:
    artifact = open_regular_artifact(path)
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"contract is not ASCII: {error}") from error
    contract = strict_json(text, where=str(path))
    return validate_contract(contract, where=str(path)), artifact


def validate_accepted_parity_receipt(
    artifact: CapturedArtifact, *, contract: dict[str, Any], where: str
) -> dict[str, Any]:
    corpus = contract["corpus"]
    if artifact.sha256 != corpus["accepted_parity_receipt_sha256"]:
        raise CampaignError(f"{where}: accepted parity receipt hash mismatch")
    try:
        text = artifact.content.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{where}: accepted parity receipt is not ASCII") from error
    value = require_exact_keys(
        strict_json(text, where=where),
        frozenset(
            {
                "schema",
                "status",
                "research_revision",
                "evidence_integration_commit",
                "source_integration_commit",
                "jobs",
                "counts",
                "identities",
                "remote_artifacts",
                "local_artifacts",
                "scope",
                "independent_review",
            }
        ),
        where=where,
    )
    if (
        value["schema"] != "euf-viper.typed-parser-parity-decision.v1"
        or value["status"] != "accepted_for_parser_parity_only"
        or value["independent_review"] != "go_for_parity_only"
    ):
        raise CampaignError(f"{where}: parity decision is not accepted")
    counts = require_exact_keys(
        value["counts"],
        frozenset(
            {
                "sources",
                "shards",
                "match",
                "fallback",
                "mismatch",
                "error",
                "other",
                "source_bytes",
            }
        ),
        where=f"{where}.counts",
    )
    if (
        counts["sources"] != LOCKED_SOURCE_COUNT
        or counts["shards"] != LOCKED_SHARDS
        or counts["match"] != LOCKED_SOURCE_COUNT
        or any(counts[key] != 0 for key in ("fallback", "mismatch", "error", "other"))
    ):
        raise CampaignError(f"{where}: parity decision counts drifted")
    remote = require_exact_keys(
        value["remote_artifacts"],
        frozenset(
            {
                "manifest_sha256",
                "prepare_sha256",
                "workset_sha256",
                "preflight_sha256",
                "records_sha256",
                "audit_sha256",
                "shard_set_sha256",
                "independent_sha256",
            }
        ),
        where=f"{where}.remote_artifacts",
    )
    for key, digest in remote.items():
        require_sha256(digest, where=f"{where}.remote_artifacts.{key}")
    if remote["manifest_sha256"] != corpus["accepted_manifest_sha256"]:
        raise CampaignError(f"{where}: accepted manifest digest mismatch")
    if remote["workset_sha256"] != corpus["accepted_workset_sha256"]:
        raise CampaignError(f"{where}: accepted workset digest mismatch")
    local = require_exact_keys(
        value["local_artifacts"],
        frozenset(ACCEPTED_PARITY_LOCAL_ARTIFACTS),
        where=f"{where}.local_artifacts",
    )
    for key, filename in ACCEPTED_PARITY_LOCAL_ARTIFACTS.items():
        expected = require_sha256(local[key], where=f"{where}.local_artifacts.{key}")
        frozen = open_regular_artifact(artifact.path.parent / filename)
        if frozen.sha256 != expected:
            raise CampaignError(f"{where}: frozen local artifact hash mismatch: {filename}")
    for local_key, remote_key in (
        ("audit_json_sha256", "audit_sha256"),
        ("independent_json_sha256", "independent_sha256"),
        ("prepare_json_sha256", "prepare_sha256"),
        ("preflight_json_sha256", "preflight_sha256"),
    ):
        if local[local_key] != remote[remote_key]:
            raise CampaignError(f"{where}: local and remote frozen evidence differ")
    return value


def load_accepted_parity_receipt(
    path: Path, *, contract: dict[str, Any], where: str
) -> CapturedArtifact:
    artifact = open_regular_artifact(path)
    validate_accepted_parity_receipt(artifact, contract=contract, where=where)
    return artifact


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
    payload = value["payload"]
    return {key: item for key, item in payload.items() if key != "parser"}


def captured_execution(execution: Execution, payload: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "exit_code": execution.exit_code,
        "external_elapsed_ns": execution.elapsed_ns,
        "max_rss_kb": execution.max_rss_kb,
        "stdout_base64": encode_raw(execution.stdout),
        "stdout_sha256": sha256_bytes(execution.stdout),
        "stderr_base64": encode_raw(execution.stderr),
        "stderr_sha256": sha256_bytes(execution.stderr),
        "payload": payload,
    }


def validate_capture_bytes(value: dict[str, Any], *, where: str) -> tuple[bytes, bytes]:
    stdout = decode_raw(value["stdout_base64"], where=f"{where}.stdout_base64")
    stderr = decode_raw(value["stderr_base64"], where=f"{where}.stderr_base64")
    if sha256_bytes(stdout) != require_sha256(
        value["stdout_sha256"], where=f"{where}.stdout_sha256"
    ):
        raise CampaignError(f"{where}: stdout SHA-256 does not bind captured bytes")
    if sha256_bytes(stderr) != require_sha256(
        value["stderr_sha256"], where=f"{where}.stderr_sha256"
    ):
        raise CampaignError(f"{where}: stderr SHA-256 does not bind captured bytes")
    return stdout, stderr


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
    payload = parse_semantic_stdout(
        execution.stdout, parser=parser, source_bytes=len(source)
    )
    captured = captured_execution(execution, payload)
    validate_captured_semantic(
        captured,
        parser=parser,
        source_bytes=len(source),
        where=f"generated {parser} semantic attestation",
    )
    return captured


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


def validate_captured_semantic(
    value: Any, *, parser: str, source_bytes: int, where: str
) -> dict[str, Any]:
    value = require_exact_keys(value, CAPTURED_PAYLOAD_KEYS, where=where)
    if value["exit_code"] != 0:
        raise CampaignError(f"{where}: semantic command did not exit zero")
    require_integer(
        value["external_elapsed_ns"], where=f"{where}.external_elapsed_ns", minimum=1
    )
    require_integer(value["max_rss_kb"], where=f"{where}.max_rss_kb")
    stdout, stderr = validate_capture_bytes(value, where=where)
    if stderr:
        raise CampaignError(f"{where}: semantic command wrote stderr")
    parsed = parse_semantic_stdout(stdout, parser=parser, source_bytes=source_bytes)
    if parsed != value["payload"]:
        raise CampaignError(f"{where}: stored semantic payload differs from captured stdout")
    return value


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
        **captured_execution(execution, payload),
        "diagnostic": diagnostic,
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
    stdout, stderr = validate_capture_bytes(value, where=where)
    if value["diagnostic"] is not None and not isinstance(value["diagnostic"], str):
        raise CampaignError(f"{where}: diagnostic must be a string or null")
    if value["outcome"] == "ok":
        if value["exit_code"] != 0 or value["diagnostic"] is not None:
            raise CampaignError(f"{where}: successful observation has diagnostics")
        if stderr:
            raise CampaignError(f"{where}: successful observation captured stderr")
        parsed = parse_binary_stdout(
            stdout,
            parser=schedule["parser"],
            phase=schedule["phase"],
            source_bytes=source_bytes,
        )
        if parsed != value["payload"]:
            raise CampaignError(f"{where}: stored payload differs from captured stdout")
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
    if value["expected_manifest_sha256"] != contract["corpus"]["accepted_manifest_sha256"]:
        raise CampaignError(f"{where}: manifest is not the accepted parity corpus")
    require_sha256(
        value["expected_contract_sha256"],
        where=f"{where}.expected_contract_sha256",
    )
    require_sha256(
        value["expected_manifest_sha256"],
        where=f"{where}.expected_manifest_sha256",
    )
    validate_runtime_environment(value["runtime_environment"], where=f"{where}.runtime_environment")
    if value["timing_environment"] != contract["timing_environment"]:
        raise CampaignError(f"{where}: timing environment contract drift")
    validate_python_binding(value["python"], where=f"{where}.python")
    validate_build_tools(value["build_tools"], where=f"{where}.build_tools")
    validate_binary_binding(value["binary"], where=f"{where}.binary")
    for key in (
        "manifest",
        "tool",
        "contract",
        "preflight",
        "workset",
        "accepted_parity_receipt",
        "checkout_receipt",
        "build_receipt",
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


def validate_record_chain(value: Any, *, content: bytes, where: str) -> None:
    value = require_exact_keys(
        value,
        frozenset({"schema", "algorithm", "domain", "records", "head"}),
        where=where,
    )
    expected = record_hash_chain(content)
    if value != expected:
        raise CampaignError(f"{where}: record hash chain mismatch")


def shard_directory(root: Path, shard: int) -> Path:
    return root / "shards" / f"shard-{shard:05d}"


def publish_sealed_shard(
    *,
    root: Path,
    shard: int,
    records: list[dict[str, Any]],
    prepared: PreparedCampaign,
    worker: dict[str, Any],
) -> tuple[CapturedArtifact, CapturedArtifact]:
    directory = shard_directory(root, shard)
    records_path = directory / "records.jsonl"
    receipt_path = directory / "receipt.json"
    if directory.exists():
        raise CampaignError(f"refusing to replace sealed shard {shard}")
    directory.mkdir(mode=0o700)
    fsync_directory(directory.parent)
    records_artifact = publish_jsonl(records_path, records)
    rebound = open_regular_artifact(records_path)
    if rebound.content != records_artifact.content:
        raise CampaignError(f"shard {shard}: records changed before receipt close")
    receipt = {
        "schema": SHARD_RECEIPT_SCHEMA,
        "status": "sealed",
        "shard": shard,
        "revision": prepared.metadata["revision"],
        "prepare_sha256": prepared.prepare_artifact.sha256,
        "contract_sha256": prepared.metadata["contract"]["sha256"],
        "record_count": len(records),
        "records": file_binding(rebound),
        "records_chain": record_hash_chain(rebound.content),
        "worker_sha256": sha256_bytes(canonical_bytes(worker)),
    }
    receipt_artifact = publish_json(receipt_path, receipt)
    directory.chmod(0o500)
    fsync_directory(directory.parent)
    if stat.S_IMODE(directory.stat().st_mode) != 0o500:
        raise CampaignError(f"shard {shard}: publication directory did not seal")
    return rebound, receipt_artifact


def load_sealed_shard(
    *, root: Path, shard: int, prepared: PreparedCampaign
) -> tuple[list[dict[str, Any]], CapturedArtifact, CapturedArtifact, dict[str, Any]]:
    directory = shard_directory(root, shard)
    if directory.is_symlink() or stat.S_IMODE(directory.stat().st_mode) != 0o500:
        raise CampaignError(f"shard {shard}: publication directory is not sealed")
    if {entry.name for entry in directory.iterdir()} != {"records.jsonl", "receipt.json"}:
        raise CampaignError(f"shard {shard}: sealed publication inventory mismatch")
    receipt_path = directory / "receipt.json"
    records_path = directory / "records.jsonl"
    for path in (receipt_path, records_path):
        if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o400:
            raise CampaignError(f"shard {shard}: sealed artifact mode mismatch")
    receipt, receipt_artifact = load_object(receipt_path)
    receipt = require_exact_keys(receipt, SHARD_RECEIPT_KEYS, where=f"shard {shard} receipt")
    if receipt["schema"] != SHARD_RECEIPT_SCHEMA or receipt["status"] != "sealed":
        raise CampaignError(f"shard {shard}: receipt is not sealed")
    if receipt["shard"] != shard:
        raise CampaignError(f"shard {shard}: receipt shard mismatch")
    if (
        receipt["revision"] != prepared.metadata["revision"]
        or receipt["prepare_sha256"] != prepared.prepare_artifact.sha256
        or receipt["contract_sha256"] != prepared.metadata["contract"]["sha256"]
    ):
        raise CampaignError(f"shard {shard}: receipt campaign binding mismatch")
    records_binding = receipt["records"]
    validate_file_binding(records_binding, where=f"shard {shard} receipt records")
    expected_path = records_path.resolve(strict=True)
    if Path(records_binding["path"]) != expected_path:
        raise CampaignError(f"shard {shard}: receipt names an unexpected records path")
    records_artifact = verify_file_binding(
        records_binding, where=f"shard {shard} sealed records"
    )
    validate_record_chain(
        receipt["records_chain"],
        content=records_artifact.content,
        where=f"shard {shard} receipt chain",
    )
    rows, reread = load_jsonl(expected_path)
    if reread.content != records_artifact.content:
        raise CampaignError(f"shard {shard}: records changed during audit")
    if receipt["record_count"] != len(rows):
        raise CampaignError(f"shard {shard}: sealed record count mismatch")
    require_sha256(receipt["worker_sha256"], where=f"shard {shard}.worker_sha256")
    return rows, records_artifact, receipt_artifact, receipt


def shard_set_entry(
    records_artifact: CapturedArtifact,
    receipt_artifact: CapturedArtifact,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    return {
        "record_count": receipt["record_count"],
        "records_chain_head": receipt["records_chain"]["head"],
        "records_sha256": records_artifact.sha256,
        "receipt_sha256": receipt_artifact.sha256,
        "worker_sha256": receipt["worker_sha256"],
    }


def validate_shard_set_receipt(
    value: Any, *, prepared: PreparedCampaign, where: str
) -> dict[str, Any]:
    value = require_exact_keys(
        value,
        frozenset(
            {
                "schema",
                "status",
                "revision",
                "prepare_sha256",
                "contract_sha256",
                "shard_count",
                "shards",
            }
        ),
        where=where,
    )
    if value["schema"] != SHARD_SET_RECEIPT_SCHEMA or value["status"] != "sealed":
        raise CampaignError(f"{where}: shard-set receipt is not sealed")
    if (
        value["revision"] != prepared.metadata["revision"]
        or value["prepare_sha256"] != prepared.prepare_artifact.sha256
        or value["contract_sha256"] != prepared.metadata["contract"]["sha256"]
    ):
        raise CampaignError(f"{where}: shard-set campaign binding mismatch")
    shard_count = require_integer(
        value["shard_count"], where=f"{where}.shard_count", minimum=1
    )
    if shard_count != prepared.metadata["shard_count"]:
        raise CampaignError(f"{where}: shard-set cardinality mismatch")
    shards = value["shards"]
    if not isinstance(shards, dict) or set(shards) != {
        f"{shard:05d}" for shard in range(shard_count)
    }:
        raise CampaignError(f"{where}: shard-set inventory mismatch")
    for key, entry in shards.items():
        entry = require_exact_keys(
            entry,
            frozenset(
                {
                    "record_count",
                    "records_chain_head",
                    "records_sha256",
                    "receipt_sha256",
                    "worker_sha256",
                }
            ),
            where=f"{where}.shards.{key}",
        )
        require_integer(
            entry["record_count"], where=f"{where}.shards.{key}.record_count", minimum=1
        )
        for digest_key in (
            "records_chain_head",
            "records_sha256",
            "receipt_sha256",
            "worker_sha256",
        ):
            require_sha256(entry[digest_key], where=f"{where}.shards.{key}.{digest_key}")
    return value


def publish_shard_set_receipt(
    *, root: Path, prepared: PreparedCampaign, shards: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], CapturedArtifact]:
    receipt = {
        "schema": SHARD_SET_RECEIPT_SCHEMA,
        "status": "sealed",
        "revision": prepared.metadata["revision"],
        "prepare_sha256": prepared.prepare_artifact.sha256,
        "contract_sha256": prepared.metadata["contract"]["sha256"],
        "shard_count": prepared.metadata["shard_count"],
        "shards": shards,
    }
    validate_shard_set_receipt(receipt, prepared=prepared, where="generated shard-set receipt")
    artifact = publish_json(root / "shard-set-receipt.json", receipt)
    return receipt, artifact


def revalidate_shard_set(
    *,
    root: Path,
    prepared: PreparedCampaign,
    expected: dict[str, Any],
    expected_artifact: CapturedArtifact,
    where: str,
) -> None:
    current, current_artifact = load_object(root / "shard-set-receipt.json")
    validate_shard_set_receipt(current, prepared=prepared, where=f"{where}.receipt")
    if current != expected or current_artifact.sha256 != expected_artifact.sha256:
        raise CampaignError(f"{where}: shard-set receipt changed after close")
    for shard in range(prepared.metadata["shard_count"]):
        _, records_artifact, receipt_artifact, receipt = load_sealed_shard(
            root=root, shard=shard, prepared=prepared
        )
        key = f"{shard:05d}"
        if shard_set_entry(records_artifact, receipt_artifact, receipt) != expected["shards"][key]:
            raise CampaignError(f"{where}: shard {shard} changed after close")


def assert_complete_record_sequences(records: list[dict[str, Any]], expected: int) -> None:
    sequences = [record.get("sequence") for record in records]
    if (
        any(type(sequence) is not int for sequence in sequences)
        or len(sequences) != expected
        or sorted(sequences) != list(range(expected))
    ):
        raise CampaignError("merged records are missing, duplicated, or non-contiguous")


def seal_shard_directory(root: Path, shard_count: int) -> None:
    directory = root / "shards"
    expected = {f"shard-{shard:05d}" for shard in range(shard_count)}
    actual = {entry.name for entry in directory.iterdir()}
    if actual != expected:
        raise CampaignError(
            "shard publication inventory is missing, duplicated, or contains extra artifacts"
        )
    for shard in range(shard_count):
        child = shard_directory(root, shard)
        if (
            child.is_symlink()
            or not child.is_dir()
            or stat.S_IMODE(child.stat().st_mode) != 0o500
            or {entry.name for entry in child.iterdir()} != {"records.jsonl", "receipt.json"}
        ):
            raise CampaignError(f"shard {shard}: publication boundary is not sealed")
    directory.chmod(0o500)
    fsync_directory(root)
    if stat.S_IMODE(directory.stat().st_mode) != 0o500:
        raise CampaignError("shard publication directory did not seal read-only")


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
        validate_captured_semantic(
            value[parser],
            parser=parser,
            source_bytes=source_bytes,
            where=f"{where}.{parser}",
        )
    if semantic_signature(value["tree"]) != semantic_signature(value["stream"]):
        raise CampaignError(f"{where}: exact semantic attestations differ")


def verify_corpus_command(args: argparse.Namespace) -> None:
    contract, contract_artifact = load_contract(args.contract)
    expected_contract_sha256 = require_sha256(
        args.expected_contract_sha256, where="expected contract SHA-256"
    )
    if contract_artifact.sha256 != expected_contract_sha256:
        raise CampaignError("contract hash differs from submitted expectation")
    receipt = load_accepted_parity_receipt(
        args.accepted_parity_receipt,
        contract=contract,
        where="accepted parity receipt",
    )
    expected_receipt_sha256 = require_sha256(
        args.expected_accepted_parity_receipt_sha256,
        where="expected accepted parity receipt SHA-256",
    )
    if receipt.sha256 != expected_receipt_sha256:
        raise CampaignError("accepted parity receipt differs from submitted expectation")
    source_root = args.source_root.resolve(strict=True)
    rows, manifest = load_manifest(args.manifest, source_root)
    expected_manifest = contract["corpus"]["accepted_manifest_sha256"]
    if manifest.sha256 != expected_manifest:
        raise CampaignError("manifest differs from preregistered accepted parity digest")
    if len(rows) != contract["corpus"]["source_count"]:
        raise CampaignError("accepted corpus source cardinality mismatch")
    summary = {
        "schema": "euf-viper.typed-parser-timing-corpus-verification.v1",
        "source_count": len(rows),
        "source_bytes": sum(row["source_bytes"] for row in rows),
        "manifest_sha256": manifest.sha256,
        "accepted_parity_receipt_sha256": receipt.sha256,
    }
    sys.stdout.buffer.write(canonical_bytes(summary))


def verify_evidence_command(args: argparse.Namespace) -> None:
    contract, contract_artifact = load_contract(args.contract)
    expected_contract_sha256 = require_sha256(
        args.expected_contract_sha256, where="expected contract SHA-256"
    )
    if contract_artifact.sha256 != expected_contract_sha256:
        raise CampaignError("contract hash differs from submitted expectation")
    receipt = load_accepted_parity_receipt(
        args.accepted_parity_receipt,
        contract=contract,
        where="accepted parity receipt",
    )
    if receipt.sha256 != contract["corpus"]["accepted_parity_receipt_sha256"]:
        raise CampaignError("accepted parity receipt differs from immutable contract")
    supplied_dimensions = {
        "shards": args.expected_shards,
        "max_parallel": args.expected_max_parallel,
        "warmup_rounds": args.expected_warmup_rounds,
        "measured_rounds": args.expected_measured_rounds,
        "timeout_seconds": args.expected_timeout_seconds,
    }
    locked_dimensions = {
        "shards": contract["campaign"]["shards"],
        "max_parallel": contract["campaign"]["max_parallel"],
        "warmup_rounds": contract["execution"]["warmup_rounds"],
        "measured_rounds": contract["execution"]["measured_rounds"],
        "timeout_seconds": contract["execution"]["per_observation_timeout_seconds"],
    }
    if supplied_dimensions != locked_dimensions:
        raise CampaignError("submitter dimensions differ from the immutable contract")
    summary = {
        "schema": "euf-viper.typed-parser-timing-evidence-verification.v1",
        "source_count": contract["corpus"]["source_count"],
        "manifest_sha256": contract["corpus"]["accepted_manifest_sha256"],
        "accepted_parity_receipt_sha256": receipt.sha256,
        "dimensions": supplied_dimensions,
    }
    sys.stdout.buffer.write(canonical_bytes(summary))


def verify_build_receipt_command(args: argparse.Namespace) -> None:
    revision = require_revision(args.revision)
    python_identity = validate_python_identity()
    build_tools = {
        name: validate_external_tool_identity(name)
        for name in sorted(BUILD_TOOL_ENVIRONMENT)
    }
    artifact = (
        open_inherited_artifact(args.build_receipt, args.build_receipt_fd)
        if args.build_receipt_fd is not None
        else open_regular_artifact(args.build_receipt)
    )
    with open_verified_executable(
        args.binary,
        inherited_descriptor=args.binary_fd,
        require_static_linux_elf=True,
    ) as executable:
        value = validate_build_receipt(
            artifact,
            revision=revision,
            binary=executable.binding,
            python_identity=python_identity,
            build_tools=build_tools,
            where="guarded release build receipt",
            verify_embedded_paths=args.build_receipt_fd is None,
        )
        if executable.static_elf != value["static_elf"]:
            raise CampaignError("guarded release static ELF attestation differs from bytes")
    summary = {
        "schema": "euf-viper.t1-guarded-release-build-verification.v1",
        "revision": revision,
        "build_receipt_sha256": artifact.sha256,
        "binary_sha256": value["binary"]["sha256"],
    }
    sys.stdout.buffer.write(canonical_bytes(summary))


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
    accepted_receipt = load_accepted_parity_receipt(
        args.accepted_parity_receipt,
        contract=contract,
        where="accepted parity receipt",
    )
    expected_accepted_receipt_sha256 = require_sha256(
        args.expected_accepted_parity_receipt_sha256,
        where="expected accepted parity receipt SHA-256",
    )
    if accepted_receipt.sha256 != expected_accepted_receipt_sha256:
        raise CampaignError("accepted parity receipt differs from submitted expectation")
    expected_sources = contract["campaign"]["expected_sources"]
    source_root = args.source_root.resolve(strict=True)
    rows, manifest_artifact = load_manifest(args.manifest, source_root)
    expected_manifest_sha256 = require_sha256(
        args.expected_manifest_sha256, where="expected manifest SHA-256"
    )
    if expected_manifest_sha256 != contract["corpus"]["accepted_manifest_sha256"]:
        raise CampaignError("submitted manifest hash is not the preregistered accepted digest")
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
    build_receipt = (
        open_inherited_artifact(args.build_receipt, args.build_receipt_fd)
        if args.build_receipt_fd is not None
        else open_regular_artifact(args.build_receipt)
    )
    with open_verified_executable(
        args.binary,
        inherited_descriptor=args.binary_fd,
        require_static_linux_elf=True,
    ) as executable:
        build_value = validate_build_receipt(
            build_receipt,
            revision=revision,
            binary=executable.binding,
            python_identity=python_identity,
            build_tools=build_tools,
            where="guarded release build receipt",
            verify_embedded_paths=args.build_receipt_fd is None,
        )
        if executable.static_elf != build_value["static_elf"]:
            raise CampaignError("guarded release static ELF attestation differs from bytes")
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
            "timing_environment": contract["timing_environment"],
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
            "accepted_parity_receipt": file_binding(accepted_receipt),
            "checkout_receipt": file_binding(checkout_receipt),
            "build_receipt": file_binding(build_receipt),
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
    if prepare["timing_environment"] != contract["timing_environment"]:
        raise CampaignError("prepared timing environment drift")
    for name in ("manifest", "tool"):
        verify_file_binding(prepare[name], where=f"prepared {name}")
    build_receipt = verify_file_binding(
        prepare["build_receipt"], where="prepared build receipt"
    )
    validate_build_receipt(
        build_receipt,
        revision=revision,
        binary=prepare["binary"],
        python_identity=prepare["python"],
        build_tools=prepare["build_tools"],
        where="prepared build receipt",
    )
    accepted_receipt = verify_file_binding(
        prepare["accepted_parity_receipt"], where="prepared accepted parity receipt"
    )
    validate_accepted_parity_receipt(
        accepted_receipt,
        contract=contract,
        where="prepared accepted parity receipt",
    )
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
    output = shard_directory(root, args.shard)
    if output.exists():
        raise CampaignError(f"refusing to replace shard artifact {output}")
    records: list[dict[str, Any]] = []
    worker = bind_worker(
        contract=prepared.contract,
        require_linux_affinity=args.require_linux_affinity,
        submission_mode=args.submission_mode,
        require_placement_controls=args.require_placement_controls,
    )
    with open_verified_executable(
        Path(prepared.metadata["binary"]["path"]),
        expected=prepared.metadata["binary"],
        require_static_linux_elf=True,
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
    publish_sealed_shard(
        root=root,
        shard=args.shard,
        records=records,
        prepared=prepared,
        worker=worker,
    )


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
    if value["schema"] != AUDIT_SCHEMA or value["status"] not in {
        "research_only_pass",
        "rejected",
    }:
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
    if not isinstance(value["timing_environment"], dict):
        raise CampaignError(f"{where}.timing_environment must be an object")
    if value["promotable"] is not False:
        raise CampaignError(f"{where}: first timing campaign must be nonpromotable")
    if not isinstance(value["promotion_reasons"], list) or not value["promotion_reasons"]:
        raise CampaignError(f"{where}: nonpromotion reasons are missing")
    for reason in value["promotion_reasons"]:
        require_string(reason, where=f"{where}.promotion_reasons")
    for key in ("counts", "metrics", "strata", "gates", "artifacts"):
        if not isinstance(value[key], dict):
            raise CampaignError(f"{where}.{key} must be an object")
    ensure_finite_json(value, where=where)
    if value["status"] == "research_only_pass" and value["gates"].get("passed") is not True:
        raise CampaignError(f"{where}: research-only audit did not pass")
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
    with open_verified_executable(
        Path(prepare["binary"]["path"]),
        expected=prepare["binary"],
        require_static_linux_elf=True,
    ):
        pass
    shard_count = prepare["shard_count"]
    seal_shard_directory(root, shard_count)
    records: list[dict[str, Any]] = []
    shard_hashes: dict[str, str] = {}
    shard_receipt_hashes: dict[str, str] = {}
    shard_set_entries: dict[str, dict[str, Any]] = {}
    shard_workers: dict[str, dict[str, Any]] = {}
    for shard in range(shard_count):
        shard_rows, artifact, receipt_artifact, receipt = load_sealed_shard(
            root=root,
            shard=shard,
            prepared=prepared,
        )
        shard_hashes[f"{shard:05d}"] = receipt["records"]["sha256"]
        shard_receipt_hashes[f"{shard:05d}"] = receipt_artifact.sha256
        shard_set_entries[f"{shard:05d}"] = shard_set_entry(
            artifact, receipt_artifact, receipt
        )
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
        worker = shard_workers.get(f"{shard:05d}")
        if worker is None:
            raise CampaignError(f"shard {shard}: sealed shard has no worker-bound records")
        if sha256_bytes(canonical_bytes(worker)) != receipt["worker_sha256"]:
            raise CampaignError(f"shard {shard}: worker identity differs from close receipt")
    require_homogeneous_workers(shard_workers.values())
    build_receipt, _ = load_object(Path(prepare["build_receipt"]["path"]))
    for worker in shard_workers.values():
        if (
            worker["allocator"] != build_receipt["build"]["allocator"]
            or worker["backend"] != build_receipt["build"]["backend"]
        ):
            raise CampaignError("timing worker allocator or backend identity drifted")
    assert_complete_record_sequences(records, len(prepared.workset))
    records.sort(key=lambda row: row["sequence"])
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

    shard_set_receipt, shard_set_artifact = publish_shard_set_receipt(
        root=root, prepared=prepared, shards=shard_set_entries
    )
    revalidate_shard_set(
        root=root,
        prepared=prepared,
        expected=shard_set_receipt,
        expected_artifact=shard_set_artifact,
        where="pre-metrics shard-set validation",
    )

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
    revalidate_shard_set(
        root=root,
        prepared=prepared,
        expected=shard_set_receipt,
        expected_artifact=shard_set_artifact,
        where="post-analysis shard-set validation",
    )
    promotion_reasons = ["first campaign is preregistered research-only"]
    if not all(worker["governor_control"] for worker in shard_workers.values()):
        promotion_reasons.append("governor and fixed-frequency control were not enforced")
    if not all(worker["exclusive_control"] for worker in shard_workers.values()):
        promotion_reasons.append("exclusive-node control was not enforced")
    if any(
        worker["scaling_driver"] == "unavailable"
        or worker["turbo_state"] == "unavailable"
        or worker["scaling_current_khz"] == 0
        for worker in shard_workers.values()
    ):
        promotion_reasons.append("complete frequency and turbo state was unavailable")
    audit = {
        "schema": AUDIT_SCHEMA,
        "status": "research_only_pass" if gates["passed"] else "rejected",
        "revision": prepare["revision"],
        "source_count": len(records),
        "expected_sources": prepare["expected_sources"],
        "shard_count": shard_count,
        "contract_sha256": prepare["contract"]["sha256"],
        "python": prepare["python"],
        "build_tools": prepare["build_tools"],
        "binary": prepare["binary"],
        "runtime_environment": prepare["runtime_environment"],
        "timing_environment": prepare["timing_environment"],
        "promotable": False,
        "promotion_reasons": promotion_reasons,
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
            "shard_set_receipt_sha256": shard_set_artifact.sha256,
            "shard_sha256": shard_hashes,
            "shard_receipt_sha256": shard_receipt_hashes,
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

    verify_evidence = commands.add_parser("verify-evidence")
    verify_evidence.add_argument("--contract", type=Path, required=True)
    verify_evidence.add_argument("--accepted-parity-receipt", type=Path, required=True)
    verify_evidence.add_argument("--expected-contract-sha256", required=True)
    verify_evidence.add_argument("--expected-shards", type=positive_integer, required=True)
    verify_evidence.add_argument("--expected-max-parallel", type=positive_integer, required=True)
    verify_evidence.add_argument("--expected-warmup-rounds", type=positive_integer, required=True)
    verify_evidence.add_argument("--expected-measured-rounds", type=positive_integer, required=True)
    verify_evidence.add_argument("--expected-timeout-seconds", type=positive_integer, required=True)

    verify_build = commands.add_parser("verify-build-receipt")
    verify_build.add_argument("--build-receipt", type=Path, required=True)
    verify_build.add_argument("--build-receipt-fd", type=nonnegative_integer)
    verify_build.add_argument("--binary", type=Path, required=True)
    verify_build.add_argument("--binary-fd", type=nonnegative_integer)
    verify_build.add_argument("--revision", required=True)

    verify_corpus = commands.add_parser("verify-corpus")
    verify_corpus.add_argument("--manifest", type=Path, required=True)
    verify_corpus.add_argument("--source-root", type=Path, required=True)
    verify_corpus.add_argument("--contract", type=Path, required=True)
    verify_corpus.add_argument("--accepted-parity-receipt", type=Path, required=True)
    verify_corpus.add_argument("--expected-accepted-parity-receipt-sha256", required=True)
    verify_corpus.add_argument("--expected-contract-sha256", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--manifest", type=Path, required=True)
    prepare.add_argument("--repository-root", type=Path, required=True)
    prepare.add_argument("--source-root", type=Path, required=True)
    prepare.add_argument("--binary", type=Path, required=True)
    prepare.add_argument("--binary-fd", type=nonnegative_integer)
    prepare.add_argument("--preflight-source", type=Path, required=True)
    prepare.add_argument("--contract", type=Path, required=True)
    prepare.add_argument("--revision", required=True)
    prepare.add_argument("--output-root", type=Path, required=True)
    prepare.add_argument("--checkout-receipt", type=Path, required=True)
    prepare.add_argument("--accepted-parity-receipt", type=Path, required=True)
    prepare.add_argument("--expected-accepted-parity-receipt-sha256", required=True)
    prepare.add_argument("--build-receipt", type=Path, required=True)
    prepare.add_argument("--build-receipt-fd", type=nonnegative_integer)
    prepare.add_argument("--expected-checkout-receipt-sha256", required=True)
    prepare.add_argument("--expected-contract-sha256", required=True)
    prepare.add_argument("--expected-manifest-sha256", required=True)

    shard = commands.add_parser("run-shard")
    shard.add_argument("--root", type=Path, required=True)
    shard.add_argument("--revision", required=True)
    shard.add_argument("--shard", type=nonnegative_integer, required=True)
    shard.add_argument("--require-linux-affinity", action="store_true")
    shard.add_argument("--submission-mode", choices=("canary", "full"), required=True)
    shard.add_argument("--require-placement-controls", action="store_true")
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
        if args.command == "verify-evidence":
            verify_evidence_command(args)
            return 0
        if args.command == "verify-build-receipt":
            verify_build_receipt_command(args)
            return 0
        if args.command == "verify-corpus":
            verify_corpus_command(args)
            return 0
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
