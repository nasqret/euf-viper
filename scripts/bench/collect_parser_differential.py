#!/usr/bin/env python3
"""Run fail-closed parse-only checks over an exact SMT-LIB manifest."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import tempfile
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Mapping, NamedTuple, Sequence


SCHEMA_VERSION = 3
PARSER_MODES = ("tree", "shadow", "stream")
DIAGNOSTIC_KEYS = (
    "parse_status",
    "parser_mode",
    "parser_route",
    "fallback_reason",
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
OUTPUT_LIMIT = 8192


class HarnessError(ValueError):
    """Raised for malformed inputs, incomplete evidence, or diagnostics."""


class ManifestSnapshot(NamedTuple):
    path: Path
    raw_bytes: bytes
    sha256: str
    entries: list[dict]


class PinnedFile(NamedTuple):
    path: Path
    fd: int
    fd_path: str
    size_bytes: int
    sha256: str
    device: int
    inode: int


class ExecutableBinding(NamedTuple):
    original: PinnedFile
    consumed: PinnedFile
    command_path: str
    inherited_fds: tuple[int, ...]
    consumed_via: str


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_identity_fd(fd: int) -> tuple[int, str]:
    if os.name != "posix" or not hasattr(os, "pread"):
        raise HarnessError("descriptor-bound campaigns require POSIX pread support")
    size = 0
    offset = 0
    digest = hashlib.sha256()
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        size += len(chunk)
        offset += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def _fd_path(fd: int) -> str:
    for root in (Path("/proc/self/fd"), Path("/dev/fd")):
        if root.is_dir():
            return str(root / str(fd))
    raise HarnessError("cannot expose inherited descriptors through /proc/self/fd or /dev/fd")


@contextlib.contextmanager
def open_pinned_file(
    path: Path, *, require_executable: bool = False
) -> Iterator[PinnedFile]:
    resolved = path.expanduser().resolve()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(resolved, flags)
    except OSError as error:
        raise HarnessError(f"cannot open {resolved}: {error}") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise HarnessError(f"not a regular file: {resolved}")
        if require_executable and metadata.st_mode & 0o111 == 0:
            raise HarnessError(f"binary is not executable: {resolved}")
        size_bytes, digest = file_identity_fd(fd)
        yield PinnedFile(
            path=resolved,
            fd=fd,
            fd_path=_fd_path(fd),
            size_bytes=size_bytes,
            sha256=digest,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
    finally:
        os.close(fd)


def _copy_pinned_bytes(source: PinnedFile, destination: Path) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o700,
    )
    try:
        offset = 0
        while offset < source.size_bytes:
            chunk = os.pread(source.fd, min(1024 * 1024, source.size_bytes - offset), offset)
            if not chunk:
                raise HarnessError("pinned executable changed size while staging")
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            offset += len(chunk)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(destination, 0o500)


@contextlib.contextmanager
def bind_executable(binary: PinnedFile) -> Iterator[ExecutableBinding]:
    if Path("/proc/self/fd").is_dir():
        yield ExecutableBinding(
            original=binary,
            consumed=binary,
            command_path=binary.fd_path,
            inherited_fds=(binary.fd,),
            consumed_via="inherited-posix-fd",
        )
        return

    with tempfile.TemporaryDirectory(prefix="euf-viper-pinned-binary-") as temp_dir:
        stage_root = Path(temp_dir)
        os.chmod(stage_root, 0o700)
        staged_path = stage_root / "euf-viper"
        _copy_pinned_bytes(binary, staged_path)
        with open_pinned_file(staged_path, require_executable=True) as staged:
            if (
                staged.size_bytes != binary.size_bytes
                or staged.sha256 != binary.sha256
            ):
                raise HarnessError("private executable stage does not match pinned bytes")
            yield ExecutableBinding(
                original=binary,
                consumed=staged,
                command_path=str(staged.path),
                inherited_fds=(),
                consumed_via="private-immutable-stage-from-pinned-fd",
            )


def parse_diagnostic(output: str) -> dict[str, str]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise HarnessError("parse-check must emit exactly one non-empty stdout line")
    fields: dict[str, str] = {}
    for item in lines[0].split():
        if "=" not in item:
            raise HarnessError(f"malformed parse-check field: {item!r}")
        key, value = item.split("=", 1)
        if key in fields:
            raise HarnessError(f"duplicate parse-check field: {key}")
        fields[key] = value
    if tuple(fields) != DIAGNOSTIC_KEYS:
        raise HarnessError(
            f"parse-check fields must be {DIAGNOSTIC_KEYS}, observed {tuple(fields)}"
        )

    status = fields["parse_status"]
    mode = fields["parser_mode"]
    route = fields["parser_route"]
    fallback = fields["fallback_reason"]
    if status not in {"ok", "fallback"}:
        raise HarnessError(f"invalid parse status: {status!r}")
    if mode not in PARSER_MODES:
        raise HarnessError(f"invalid parser mode: {mode!r}")

    direct_route = {"tree": "tree", "shadow": "shadow-match", "stream": "stream"}
    if status == "ok":
        if route != direct_route[mode] or fallback != "none":
            raise HarnessError(
                "parse_status=ok requires the mode's direct route and "
                "fallback_reason=none"
            )
    elif mode == "tree" or route != "tree-fallback" or fallback == "none":
        raise HarnessError(
            "parse_status=fallback requires a non-tree mode, tree-fallback, "
            "and a reason"
        )
    return fields


def _manifest_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise HarnessError(f"{context}: sha256 must be 64 lowercase hex digits")
    return value


def _manifest_bytes(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HarnessError(f"{context}: bytes must be a non-negative integer")
    return value


def _relative_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HarnessError(f"{context}: relative_path must be a non-empty string")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative == PurePosixPath(".")
        or ".." in relative.parts
    ):
        raise HarnessError(f"{context}: relative_path must stay below the benchmark root")
    if relative.as_posix() != value:
        raise HarnessError(f"{context}: relative_path must be normalized POSIX syntax")
    return value


def parse_manifest_bytes(raw_bytes: bytes, path: Path) -> list[dict]:
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HarnessError(f"{path}: manifest is not valid UTF-8: {error}") from error

    entries: list[dict] = []
    seen: dict[str, int] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        context = f"{path}:{line_number}"
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise HarnessError(f"{context}: invalid JSON: {error.msg}") from error
        if not isinstance(entry, dict):
            raise HarnessError(f"{context}: row must be an object")
        relative_path = _relative_path(entry.get("relative_path"), context)
        if relative_path in seen:
            raise HarnessError(
                f"{context}: duplicate {relative_path!r}; first seen on line "
                f"{seen[relative_path]}"
            )
        seen[relative_path] = line_number
        expected_bytes = _manifest_bytes(entry.get("bytes"), context)
        expected_sha256 = _manifest_sha256(entry.get("sha256"), context)
        entries.append(
            {
                **entry,
                "relative_path": relative_path,
                "bytes": expected_bytes,
                "sha256": expected_sha256,
                "manifest_line": line_number,
            }
        )
    if not entries:
        raise HarnessError("manifest selection is empty")
    return entries


def load_manifest_snapshot(path: Path) -> ManifestSnapshot:
    resolved = path.expanduser().resolve()
    try:
        with resolved.open("rb") as handle:
            raw_bytes = handle.read()
    except OSError as error:
        raise HarnessError(f"cannot read manifest {resolved}: {error}") from error
    return ManifestSnapshot(
        path=resolved,
        raw_bytes=raw_bytes,
        sha256=sha256_bytes(raw_bytes),
        entries=parse_manifest_bytes(raw_bytes, resolved),
    )


def read_manifest(path: Path) -> list[dict]:
    return load_manifest_snapshot(path).entries


def resolve_input_path(entry: dict, benchmark_root: Path) -> Path:
    root = benchmark_root.expanduser().resolve()
    relative = PurePosixPath(entry["relative_path"])
    source = root.joinpath(*relative.parts).resolve()
    try:
        source.relative_to(root)
    except ValueError as error:
        raise HarnessError(
            f"resolved input escapes benchmark root: {entry['relative_path']!r}"
        ) from error
    return source


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _path_identity(path: Path) -> tuple[int, int] | None:
    try:
        metadata = path.stat()
    except OSError:
        return None
    return metadata.st_dev, metadata.st_ino


def validate_artifact_paths(
    artifacts: Mapping[str, Path],
    *,
    benchmark_root: Path,
    protected_paths: Sequence[Path],
    protected_identities: Sequence[tuple[int, int]] = (),
) -> dict[str, Path]:
    root = benchmark_root.expanduser().resolve()
    resolved = {
        name: path.expanduser().resolve() for name, path in artifacts.items()
    }
    by_path: dict[Path, str] = {}
    output_identities: dict[tuple[int, int], str] = {}
    protected_resolved = {path.expanduser().resolve() for path in protected_paths}
    protected_inodes = set(protected_identities)
    protected_inodes.update(
        identity
        for path in protected_resolved
        if (identity := _path_identity(path)) is not None
    )

    for name, path in resolved.items():
        if path in by_path:
            raise HarnessError(
                f"{name} aliases {by_path[path]} after path resolution: {path}"
            )
        by_path[path] = name
        if _is_within(path, root):
            raise HarnessError(f"{name} must not resolve inside benchmark root: {path}")
        if path in protected_resolved:
            raise HarnessError(f"{name} aliases a protected input path: {path}")
        identity = _path_identity(path)
        if identity is not None:
            if identity in protected_inodes:
                raise HarnessError(f"{name} aliases a protected input inode: {path}")
            if identity in output_identities:
                raise HarnessError(
                    f"{name} hard-links {output_identities[identity]}: {path}"
                )
            output_identities[identity] = name
        if path.exists():
            raise HarnessError(f"{name} already exists; refusing stale evidence: {path}")
    return resolved


def failure_record(
    base: dict,
    kind: str,
    message: str,
    exit_code: int | None,
    *,
    wall_time_ns: int = 0,
    stdout: str | bytes | None = None,
    stderr: str | bytes | None = None,
) -> dict:
    record = {
        **base,
        "status": "timeout" if kind == "timeout" else "error",
        "failure_kind": kind,
        "message": message,
        "exit_code": exit_code,
        "wall_time_ns": wall_time_ns,
    }
    normalized_stdout = normalized_output(stdout)
    normalized_stderr = normalized_output(stderr)
    if normalized_stdout:
        record["stdout"] = normalized_stdout
    if normalized_stderr:
        record["stderr"] = normalized_stderr
    return record


def normalized_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode(encoding="utf-8", errors="replace")
    value = value.strip()
    if len(value) <= OUTPUT_LIMIT:
        return value
    return value[:OUTPUT_LIMIT] + "\n...[truncated]"


def _base_record(
    entry: dict,
    source: Path,
    candidate_parser_mode: str,
    binary: ExecutableBinding,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "id": entry.get("id", entry["manifest_line"]),
        "manifest_line": entry["manifest_line"],
        "relative_path": entry["relative_path"],
        "resolved_path": str(source),
        "expected_status": entry.get("status", "unknown"),
        "candidate_parser_mode": candidate_parser_mode,
        "source_expected_bytes": entry["bytes"],
        "source_expected_sha256": entry["sha256"],
        "binary_consumed_sha256": binary.consumed.sha256,
        "binary_consumed_bytes": binary.consumed.size_bytes,
        "binary_consumed_via": binary.consumed_via,
        "binary_consumed_device": binary.consumed.device,
        "binary_consumed_inode": binary.consumed.inode,
        "binary_original_sha256": binary.original.sha256,
    }


def _run_entry_with_binary(
    entry: dict,
    binary: ExecutableBinding,
    candidate_parser_mode: str,
    timeout_s: float,
    benchmark_root: Path,
) -> dict:
    try:
        source = resolve_input_path(entry, benchmark_root)
    except (HarnessError, OSError, RuntimeError) as error:
        unresolved = benchmark_root.joinpath(*PurePosixPath(entry["relative_path"]).parts)
        base = _base_record(entry, unresolved, candidate_parser_mode, binary)
        base["corpus_verified"] = False
        return failure_record(base, "path_error", str(error), 66)

    base = _base_record(entry, source, candidate_parser_mode, binary)
    try:
        with open_pinned_file(source) as pinned_source:
            base.update(
                {
                    "source_actual_bytes": pinned_source.size_bytes,
                    "source_actual_sha256": pinned_source.sha256,
                    "source_consumed_via": "inherited-posix-fd",
                    "source_consumed_device": pinned_source.device,
                    "source_consumed_inode": pinned_source.inode,
                }
            )
            mismatches = []
            if pinned_source.size_bytes != entry["bytes"]:
                mismatches.append(
                    f"bytes expected {entry['bytes']} actual {pinned_source.size_bytes}"
                )
            if pinned_source.sha256 != entry["sha256"]:
                mismatches.append(
                    f"sha256 expected {entry['sha256']} actual {pinned_source.sha256}"
                )
            if mismatches:
                base["corpus_verified"] = False
                return failure_record(
                    base,
                    "source_identity_mismatch",
                    "; ".join(mismatches),
                    65,
                )
            base["corpus_verified"] = True

            environment = os.environ.copy()
            environment.pop("EUF_VIPER_PARSER", None)
            environment["EUF_VIPER_PARSER_MODE"] = candidate_parser_mode
            started = time.monotonic_ns()
            try:
                process = subprocess.run(
                    [binary.command_path, "parse-check", pinned_source.fd_path],
                    env=environment,
                    pass_fds=(*binary.inherited_fds, pinned_source.fd),
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_s,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                return failure_record(
                    base,
                    "timeout",
                    f"parse-check exceeded timeout of {timeout_s:g}s",
                    124,
                    wall_time_ns=time.monotonic_ns() - started,
                    stdout=error.stdout,
                    stderr=error.stderr,
                )
            except OSError as error:
                return failure_record(
                    base,
                    "spawn_error",
                    f"cannot execute parse-check: {error}",
                    None,
                    wall_time_ns=time.monotonic_ns() - started,
                    stderr=str(error),
                )
            final_source_bytes, final_source_sha256 = file_identity_fd(
                pinned_source.fd
            )
            if (
                final_source_bytes != pinned_source.size_bytes
                or final_source_sha256 != pinned_source.sha256
            ):
                base["corpus_verified"] = False
                base["source_post_parse_bytes"] = final_source_bytes
                base["source_post_parse_sha256"] = final_source_sha256
                return failure_record(
                    base,
                    "source_changed_during_parse",
                    "pinned source bytes changed while parse-check was running",
                    65,
                    wall_time_ns=time.monotonic_ns() - started,
                    stdout=process.stdout,
                    stderr=process.stderr,
                )
    except HarnessError as error:
        base["corpus_verified"] = False
        return failure_record(base, "input_open_error", str(error), 66)

    wall_time_ns = time.monotonic_ns() - started
    if process.returncode != 0:
        stderr = normalized_output(process.stderr)
        return failure_record(
            base,
            "parse_error",
            stderr or f"parse-check exited {process.returncode}",
            process.returncode,
            wall_time_ns=wall_time_ns,
            stdout=process.stdout,
            stderr=process.stderr,
        )
    try:
        diagnostic = parse_diagnostic(process.stdout)
    except HarnessError as error:
        return failure_record(
            base,
            "diagnostic_error",
            str(error),
            65,
            wall_time_ns=wall_time_ns,
            stdout=process.stdout,
            stderr=process.stderr,
        )
    if diagnostic["parser_mode"] != candidate_parser_mode:
        return failure_record(
            base,
            "mode_mismatch",
            "parse-check reported "
            f"{diagnostic['parser_mode']!r}, expected {candidate_parser_mode!r}",
            65,
            wall_time_ns=wall_time_ns,
            stderr=process.stderr,
        )
    return {
        **base,
        "status": "ok",
        "exit_code": 0,
        "wall_time_ns": wall_time_ns,
        **diagnostic,
    }


def run_entry(
    entry: dict,
    manifest: Path,
    binary: Path | PinnedFile | ExecutableBinding,
    candidate_parser_mode: str,
    timeout_s: float,
    benchmark_root: Path,
) -> dict:
    del manifest
    if isinstance(binary, ExecutableBinding):
        return _run_entry_with_binary(
            entry, binary, candidate_parser_mode, timeout_s, benchmark_root
        )
    if isinstance(binary, PinnedFile):
        with bind_executable(binary) as binding:
            return _run_entry_with_binary(
                entry, binding, candidate_parser_mode, timeout_s, benchmark_root
            )
    with open_pinned_file(binary, require_executable=True) as pinned_binary:
        with bind_executable(pinned_binary) as binding:
            return _run_entry_with_binary(
                entry, binding, candidate_parser_mode, timeout_s, benchmark_root
            )


def summarize(
    records: Sequence[dict],
    candidate_parser_mode: str,
    *,
    expected_instances: int | None = None,
    max_fallbacks: int = 0,
    fallback_limit_explicit: bool = False,
) -> dict:
    if expected_instances is None:
        expected_instances = len(records)
    successful = [record for record in records if record["status"] == "ok"]
    failures = [record for record in records if record["status"] != "ok"]
    routes = Counter(record["parser_route"] for record in successful)
    fallbacks = routes["tree-fallback"]
    direct_parses = len(successful) - fallbacks
    unique_paths = len({record["relative_path"] for record in records})
    row_count_verified = len(records) == expected_instances
    unique_paths_verified = unique_paths == len(records)
    fallback_gate_passed = fallbacks <= max_fallbacks
    direct_route_gate_passed = candidate_parser_mode == "tree" or direct_parses > 0
    corpus_verified = sum(record.get("corpus_verified") is True for record in records)
    corpus_verification_failed = sum(
        record.get("corpus_verified") is False for record in records
    )
    gate_passed = (
        row_count_verified
        and unique_paths_verified
        and len(successful) == expected_instances
        and corpus_verified == expected_instances
        and fallback_gate_passed
        and direct_route_gate_passed
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_parser_mode": candidate_parser_mode,
        "expected_instances": expected_instances,
        "instances": len(records),
        "successful": len(successful),
        "direct_parses": direct_parses,
        "direct_shadow_matches": routes["shadow-match"],
        "direct_stream_parses": routes["stream"],
        "direct_tree_parses": routes["tree"],
        "fallbacks": fallbacks,
        "tree_fallbacks": fallbacks,
        "errors": sum(record["status"] == "error" for record in failures),
        "timeouts": sum(record["status"] == "timeout" for record in failures),
        "routes": dict(sorted(routes.items())),
        "fallback_reasons": dict(
            sorted(
                Counter(
                    record["fallback_reason"]
                    for record in successful
                    if record["parse_status"] == "fallback"
                ).items()
            )
        ),
        "corpus_verification": {
            "completed": corpus_verified + corpus_verification_failed,
            "verified": corpus_verified,
            "failed": corpus_verification_failed,
            "pending": max(
                0,
                expected_instances - corpus_verified - corpus_verification_failed,
            ),
        },
        "evidence_integrity": {
            "row_count_verified": row_count_verified,
            "unique_paths_verified": unique_paths_verified,
            "unique_paths": unique_paths,
        },
        "fallback_gate": {
            "explicit_limit": fallback_limit_explicit,
            "max_fallbacks": max_fallbacks,
            "observed_fallbacks": fallbacks,
            "direct_route_required": candidate_parser_mode != "tree",
            "direct_route_observed": direct_parses > 0,
            "passed": fallback_gate_passed and direct_route_gate_passed,
        },
        "gate_passed": gate_passed,
        "failure_examples": [
            {
                "relative_path": record["relative_path"],
                "failure_kind": record["failure_kind"],
                "message": record["message"],
            }
            for record in failures[:25]
        ],
    }


def json_bytes(payload: object) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def jsonl_bytes(records: Sequence[dict]) -> bytes:
    return "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    ).encode("utf-8")


def durable_atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_write_jsonl(path: Path, records: Sequence[dict]) -> None:
    durable_atomic_write(path, jsonl_bytes(records))


def atomic_write_json(path: Path, payload: dict) -> None:
    durable_atomic_write(path, json_bytes(payload))


def build_checkpoint_bundle(
    records: Sequence[dict],
    summary: dict,
    progress: dict,
    *,
    generation: int,
    expected_instances: int,
    success_checkpoint_interval: int,
) -> dict:
    encoded_records = jsonl_bytes(records)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "parser-differential-checkpoint",
        "campaign_status": "running",
        "generation": generation,
        "generated_at_unix_ns": time.time_ns(),
        "completion": {
            "completed_instances": len(records),
            "expected_instances": expected_instances,
            "completed_manifest_lines": [
                record["manifest_line"] for record in records
            ],
            "record_order": "manifest-order-subset",
            "contiguous_prefix_guaranteed": False,
        },
        "durability_policy": {
            "errors_checkpoint_immediately": True,
            "success_checkpoint_interval": success_checkpoint_interval,
            "maximum_uncheckpointed_successes": success_checkpoint_interval - 1,
        },
        "records_encoding": "canonical-jsonl",
        "records_sha256": sha256_bytes(encoded_records),
        "records": list(records),
        "summary": summary,
        "progress": progress,
    }


Checkpoint = Callable[[Sequence[dict], int, int], None]


def _internal_failure_record(
    entry: dict,
    benchmark_root: Path,
    candidate_parser_mode: str,
    binary: ExecutableBinding,
    error: Exception,
) -> dict:
    source = benchmark_root.joinpath(*PurePosixPath(entry["relative_path"]).parts)
    base = _base_record(entry, source, candidate_parser_mode, binary)
    base["corpus_verified"] = False
    return failure_record(
        base,
        "internal_error",
        f"unhandled collector error: {type(error).__name__}: {error}",
        70,
    )


def _collect_with_pinned_binary(
    manifest: Path,
    binary: ExecutableBinding,
    candidate_parser_mode: str,
    timeout_s: float,
    jobs: int,
    benchmark_root: Path,
    *,
    entries: Sequence[dict],
    checkpoint: Checkpoint | None,
    checkpoint_every: int,
) -> tuple[list[dict], dict]:
    records: list[dict | None] = [None] * len(entries)

    def run_one(entry: dict) -> dict:
        return run_entry(
            entry,
            manifest,
            binary,
            candidate_parser_mode,
            timeout_s,
            benchmark_root,
        )

    futures: dict[Future[dict], int] = {}
    executor = ThreadPoolExecutor(max_workers=jobs)
    interrupted = True
    successes_since_checkpoint = 0
    try:
        futures = {
            executor.submit(run_one, entry): index
            for index, entry in enumerate(entries)
        }
        completed = 0
        for future in as_completed(futures):
            index = futures[future]
            try:
                record = future.result()
            except Exception as error:  # Preserve a row even for a collector bug.
                record = _internal_failure_record(
                    entries[index],
                    benchmark_root,
                    candidate_parser_mode,
                    binary,
                    error,
                )
            records[index] = record
            completed += 1
            if record["status"] == "ok":
                successes_since_checkpoint += 1
            should_checkpoint = (
                record["status"] != "ok"
                or successes_since_checkpoint >= checkpoint_every
                or completed == len(entries)
            )
            if checkpoint is not None and should_checkpoint:
                checkpoint(
                    [item for item in records if item is not None],
                    completed,
                    len(entries),
                )
                successes_since_checkpoint = 0
        interrupted = False
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    complete_records = [record for record in records if record is not None]
    validate_complete_records(entries, complete_records)
    return complete_records, summarize(complete_records, candidate_parser_mode)


def collect_manifest(
    manifest: Path,
    binary: Path | PinnedFile | ExecutableBinding,
    candidate_parser_mode: str,
    timeout_s: float,
    jobs: int,
    benchmark_root: Path,
    *,
    entries: Sequence[dict] | None = None,
    checkpoint: Checkpoint | None = None,
    checkpoint_every: int = 25,
) -> tuple[list[dict], dict]:
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise HarnessError("timeout must be a finite number greater than zero")
    if jobs < 1:
        raise HarnessError("jobs must be at least one")
    if checkpoint_every < 1:
        raise HarnessError("checkpoint_every must be at least one")
    selected = list(entries) if entries is not None else read_manifest(manifest)
    if isinstance(binary, ExecutableBinding):
        return _collect_with_pinned_binary(
            manifest,
            binary,
            candidate_parser_mode,
            timeout_s,
            jobs,
            benchmark_root,
            entries=selected,
            checkpoint=checkpoint,
            checkpoint_every=checkpoint_every,
        )
    if isinstance(binary, PinnedFile):
        with bind_executable(binary) as binding:
            return _collect_with_pinned_binary(
                manifest,
                binding,
                candidate_parser_mode,
                timeout_s,
                jobs,
                benchmark_root,
                entries=selected,
                checkpoint=checkpoint,
                checkpoint_every=checkpoint_every,
            )
    with open_pinned_file(binary, require_executable=True) as pinned_binary:
        with bind_executable(pinned_binary) as binding:
            return _collect_with_pinned_binary(
                manifest,
                binding,
                candidate_parser_mode,
                timeout_s,
                jobs,
                benchmark_root,
                entries=selected,
                checkpoint=checkpoint,
                checkpoint_every=checkpoint_every,
            )


def validate_complete_records(entries: Sequence[dict], records: Sequence[dict]) -> None:
    if len(records) != len(entries):
        raise HarnessError(
            f"incomplete evidence: expected {len(entries)} rows, observed {len(records)}"
        )
    observed_paths = [record.get("relative_path") for record in records]
    if len(set(observed_paths)) != len(observed_paths):
        raise HarnessError("evidence contains duplicate relative_path values")
    expected_paths = [entry["relative_path"] for entry in entries]
    if observed_paths != expected_paths:
        raise HarnessError("evidence paths or ordering do not match the manifest")


def _sha256_argument(value: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be 64 lowercase hex digits")
    return value


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _campaign_summary(
    records: Sequence[dict],
    *,
    candidate_parser_mode: str,
    expected_instances: int,
    max_fallbacks: int,
    fallback_limit_explicit: bool,
    campaign_status: str,
    manifest: ManifestSnapshot,
    expected_manifest_sha256: str,
    benchmark_root: Path,
    binary: ExecutableBinding,
    expected_binary_sha256: str,
) -> dict:
    summary = summarize(
        records,
        candidate_parser_mode,
        expected_instances=expected_instances,
        max_fallbacks=max_fallbacks,
        fallback_limit_explicit=fallback_limit_explicit,
    )
    summary.update(
        {
            "campaign_status": campaign_status,
            "manifest": str(manifest.path),
            "expected_manifest_sha256": expected_manifest_sha256,
            "manifest_sha256": manifest.sha256,
            "manifest_snapshot_bytes": len(manifest.raw_bytes),
            "benchmark_root": str(benchmark_root),
            "binary": str(binary.original.path),
            "expected_binary_sha256": expected_binary_sha256,
            "binary_sha256": binary.consumed.sha256,
            "provenance": {
                "manifest": {
                    "path": str(manifest.path),
                    "expected_sha256": expected_manifest_sha256,
                    "sha256": manifest.sha256,
                    "snapshot_bytes": len(manifest.raw_bytes),
                    "expected_instances": expected_instances,
                    "parsed_from_single_snapshot": True,
                    "sha256_verified": (
                        manifest.sha256 == expected_manifest_sha256
                    ),
                },
                "corpus": {"benchmark_root": str(benchmark_root)},
                "binary": {
                    "path": str(binary.original.path),
                    "expected_sha256": expected_binary_sha256,
                    "actual_sha256": binary.consumed.sha256,
                    "size_bytes": binary.consumed.size_bytes,
                    "device": binary.consumed.device,
                    "inode": binary.consumed.inode,
                    "sha256_verified": (
                        binary.consumed.sha256 == expected_binary_sha256
                        and binary.consumed.sha256 == binary.original.sha256
                    ),
                    "consumed_via": binary.consumed_via,
                    "staged_from_verified_open_fd": (
                        binary.consumed_via
                        == "private-immutable-stage-from-pinned-fd"
                    ),
                },
            },
        }
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run exact tree/shadow/stream parse checks over a JSONL manifest."
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", type=_sha256_argument, required=True)
    parser.add_argument("--expected-manifest-sha256", type=_sha256_argument, required=True)
    parser.add_argument("--expected-instances", type=_positive_int, required=True)
    parser.add_argument(
        "--candidate-parser-mode",
        choices=PARSER_MODES,
        required=True,
    )
    parser.add_argument(
        "--benchmark-root",
        type=Path,
        required=True,
        help="the exact root passed to make_manifest.py",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--jobs", type=_positive_int, default=1)
    parser.add_argument(
        "--max-fallbacks",
        type=_nonnegative_int,
        help="explicit fallback allowance; omitted means zero",
    )
    parser.add_argument("--checkpoint-every", type=_positive_int, default=25)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--progress", type=Path, required=True)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite number greater than zero")

    benchmark_root = args.benchmark_root.expanduser().resolve()
    if not benchmark_root.is_dir():
        parser.error(f"benchmark root must be a directory: {benchmark_root}")
    try:
        manifest = load_manifest_snapshot(args.manifest)
    except HarnessError as error:
        parser.error(str(error))
    if manifest.sha256 != args.expected_manifest_sha256:
        parser.error(
            "manifest SHA256 mismatch: "
            f"expected {args.expected_manifest_sha256}, actual {manifest.sha256}"
        )
    if len(manifest.entries) != args.expected_instances:
        parser.error(
            "manifest instance count mismatch: "
            f"expected {args.expected_instances}, actual {len(manifest.entries)}"
        )

    fallback_limit_explicit = args.max_fallbacks is not None
    max_fallbacks = args.max_fallbacks if args.max_fallbacks is not None else 0
    if max_fallbacks >= args.expected_instances:
        parser.error(
            "--max-fallbacks must be less than --expected-instances so an "
            "all-fallback campaign cannot pass"
        )

    try:
        with open_pinned_file(args.binary, require_executable=True) as pinned_binary:
            if pinned_binary.sha256 != args.expected_binary_sha256:
                parser.error(
                    "binary SHA256 mismatch: "
                    f"expected {args.expected_binary_sha256}, "
                    f"actual {pinned_binary.sha256}"
                )
            with bind_executable(pinned_binary) as binary:
                source_paths = [
                    resolve_input_path(entry, benchmark_root)
                    for entry in manifest.entries
                ]
                artifacts = validate_artifact_paths(
                    {
                        "checkpoint": args.checkpoint,
                        "out": args.out,
                        "summary": args.summary,
                        "progress": args.progress,
                    },
                    benchmark_root=benchmark_root,
                    protected_paths=[
                        manifest.path,
                        binary.original.path,
                        binary.consumed.path,
                        *source_paths,
                    ],
                    protected_identities=[
                        (binary.original.device, binary.original.inode),
                        (binary.consumed.device, binary.consumed.inode),
                    ],
                )

                generation = 0

                def write_checkpoint(
                    records: Sequence[dict], completed: int, expected: int
                ) -> None:
                    nonlocal generation
                    generation += 1
                    checkpoint_summary = _campaign_summary(
                        records,
                        candidate_parser_mode=args.candidate_parser_mode,
                        expected_instances=args.expected_instances,
                        max_fallbacks=max_fallbacks,
                        fallback_limit_explicit=fallback_limit_explicit,
                        campaign_status="running",
                        manifest=manifest,
                        expected_manifest_sha256=args.expected_manifest_sha256,
                        benchmark_root=benchmark_root,
                        binary=binary,
                        expected_binary_sha256=args.expected_binary_sha256,
                    )
                    checkpoint_progress = {
                        "schema_version": SCHEMA_VERSION,
                        "campaign_status": "running",
                        "generation": generation,
                        "completed_instances": completed,
                        "expected_instances": expected,
                        "remaining_instances": expected - completed,
                        "expected_manifest_sha256": args.expected_manifest_sha256,
                        "manifest_sha256": manifest.sha256,
                        "binary_sha256": binary.consumed.sha256,
                    }
                    bundle = build_checkpoint_bundle(
                        records,
                        checkpoint_summary,
                        checkpoint_progress,
                        generation=generation,
                        expected_instances=expected,
                        success_checkpoint_interval=args.checkpoint_every,
                    )
                    durable_atomic_write(artifacts["checkpoint"], json_bytes(bundle))

                write_checkpoint([], 0, args.expected_instances)
                records, _ = collect_manifest(
                    manifest.path,
                    binary,
                    args.candidate_parser_mode,
                    args.timeout,
                    args.jobs,
                    benchmark_root,
                    entries=manifest.entries,
                    checkpoint=write_checkpoint,
                    checkpoint_every=args.checkpoint_every,
                )
                validate_complete_records(manifest.entries, records)
                final_binary_bytes, final_binary_sha256 = file_identity_fd(
                    binary.consumed.fd
                )
                if (
                    final_binary_bytes != binary.consumed.size_bytes
                    or final_binary_sha256 != binary.consumed.sha256
                ):
                    raise HarnessError(
                        "pinned binary bytes changed during the campaign"
                    )

                summary = _campaign_summary(
                    records,
                    candidate_parser_mode=args.candidate_parser_mode,
                    expected_instances=args.expected_instances,
                    max_fallbacks=max_fallbacks,
                    fallback_limit_explicit=fallback_limit_explicit,
                    campaign_status="finalized",
                    manifest=manifest,
                    expected_manifest_sha256=args.expected_manifest_sha256,
                    benchmark_root=benchmark_root,
                    binary=binary,
                    expected_binary_sha256=args.expected_binary_sha256,
                )
                encoded_records = jsonl_bytes(records)
                encoded_summary = json_bytes(summary)
                durable_atomic_write(artifacts["out"], encoded_records)
                durable_atomic_write(artifacts["summary"], encoded_summary)

                progress = {
                    "schema_version": SCHEMA_VERSION,
                    "campaign_status": "complete",
                    "publication_generation": generation + 1,
                    "completed_instances": len(records),
                    "expected_instances": args.expected_instances,
                    "remaining_instances": 0,
                    "expected_manifest_sha256": args.expected_manifest_sha256,
                    "manifest_sha256": manifest.sha256,
                    "binary_sha256": binary.consumed.sha256,
                    "gate_passed": summary["gate_passed"],
                    "artifacts": {
                        "records": {
                            "path": str(artifacts["out"]),
                            "size_bytes": len(encoded_records),
                            "sha256": sha256_bytes(encoded_records),
                        },
                        "summary": {
                            "path": str(artifacts["summary"]),
                            "size_bytes": len(encoded_summary),
                            "sha256": sha256_bytes(encoded_summary),
                        },
                    },
                    "published_last": True,
                    "updated_at_unix_ns": time.time_ns(),
                }
                durable_atomic_write(artifacts["progress"], json_bytes(progress))
    except (HarnessError, OSError) as error:
        parser.error(str(error))

    print(
        f"parser_mode={args.candidate_parser_mode} "
        f"instances={summary['instances']} successful={summary['successful']} "
        f"direct={summary['direct_parses']} fallbacks={summary['fallbacks']} "
        f"errors={summary['errors']} timeouts={summary['timeouts']} "
        f"gate_passed={str(summary['gate_passed']).lower()}"
    )
    return 0 if summary["gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
