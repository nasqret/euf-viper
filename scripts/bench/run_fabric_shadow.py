#!/usr/bin/env python3
"""Run the Viper Fabric semantic shadow over an exact JSONL manifest."""

from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, Iterator, Sequence


SCHEMA_VERSION = 1
MODE = "fabric_shadow"
RECORD_TYPE = "fabric_shadow_receipt"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DOCUMENTED_CORPUS_LAYOUT = Path("benchmarks/smtlib-2025/QF_UF")
HEX64 = frozenset("0123456789abcdef")

RECEIPT_INTEGER_FIELDS = (
    "source_bytes",
    "parse_ns",
    "projection_ns",
    "terms",
    "applications",
    "atoms",
    "assertions",
    "root_literals",
    "components",
    "max_component_terms",
    "cross_component_boolean_nodes",
    "unsupported_fragments",
)
RECEIPT_FIELDS = {
    "schema_version",
    "mode",
    "solver_result_emitted",
    *RECEIPT_INTEGER_FIELDS,
    "contradiction",
}
COMPONENT_TOTAL_FIELDS = (
    "source_bytes",
    "terms",
    "applications",
    "atoms",
    "assertions",
    "root_literals",
    "components",
    "cross_component_boolean_nodes",
    "unsupported_fragments",
)
OUTPUT_RECORD_FIELDS = {
    *RECEIPT_FIELDS,
    "record_type",
    "manifest_index",
    "manifest_line",
    "id",
    "path",
    "relative_path",
    "resolved_path",
    "resolution_rule",
    "expected_status",
    "manifest_sha256",
    "input_binding_sha256",
    "input_sha256",
    "solver_path",
    "solver_sha256",
    "timeout_s",
    "wall_time_ns",
}


class FabricShadowError(RuntimeError):
    """Base class for failures that must stop the corpus run."""

    kind = "runner_error"

    def __init__(self, message: str, row: ManifestRow | None = None) -> None:
        super().__init__(message)
        self.row = row


class ManifestError(FabricShadowError):
    kind = "manifest_error"


class InputError(FabricShadowError):
    kind = "input_error"


class SolverError(FabricShadowError):
    kind = "solver_error"


class SolverDriftError(SolverError):
    kind = "solver_hash_drift"


class ExecutionError(FabricShadowError):
    kind = "execution_error"


class ReceiptError(FabricShadowError):
    kind = "receipt_error"


class ResumeError(FabricShadowError):
    kind = "resume_incompatible"


class OutputError(FabricShadowError):
    kind = "output_error"


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class ManifestRow:
    ordinal: int
    line_number: int
    identifier: str | int
    declared_path: str | None
    relative_path: str
    expected_status: str
    declared_sha256: str
    declared_bytes: int | None


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    sha256: str
    size: int
    fingerprint: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class BoundRow:
    row: ManifestRow
    source: FileSnapshot
    resolution_rule: str


@dataclass(frozen=True)
class Attempt:
    row: ManifestRow
    record: dict[str, Any] | None = None
    error: FabricShadowError | None = None


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least one")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _parse_json(text: str, context: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, _DuplicateKeyError, ValueError) as exc:
        raise ValueError(f"{context}: invalid JSON: {exc}") from exc


def _canonical_json_line(value: Any) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in HEX64 for character in value)
    )


def _safe_relative_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ManifestError(f"{context}: relative_path must be a non-empty string")
    if "\\" in value:
        raise ManifestError(f"{context}: relative_path must use POSIX separators")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ManifestError(
            f"{context}: relative_path must be normalized and cannot traverse"
        )
    relative = PurePosixPath(value)
    if relative.is_absolute() or relative.as_posix() != value:
        raise ManifestError(
            f"{context}: relative_path must be normalized and relative"
        )
    return value


def read_manifest(path: Path) -> tuple[list[ManifestRow], str]:
    """Read a strict manifest without reordering its rows."""
    try:
        manifest_path = path.expanduser().resolve(strict=True)
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    if not stat.S_ISREG(manifest_path.stat().st_mode):
        raise ManifestError(f"manifest is not a regular file: {manifest_path}")
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"manifest is not UTF-8: {manifest_path}: {exc}") from exc
    if not text:
        raise ManifestError(f"manifest is empty: {manifest_path}")

    rows: list[ManifestRow] = []
    seen_ids: dict[str, int] = {}
    seen_paths: dict[str, int] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        context = f"{manifest_path}:{line_number}"
        if not line.strip():
            raise ManifestError(f"{context}: blank manifest rows are forbidden")
        try:
            value = _parse_json(line, context)
        except ValueError as exc:
            raise ManifestError(str(exc)) from exc
        if not isinstance(value, dict):
            raise ManifestError(f"{context}: manifest row must be a JSON object")

        identifier = value.get("id")
        if (
            isinstance(identifier, bool)
            or not isinstance(identifier, (str, int))
            or (isinstance(identifier, str) and not identifier)
        ):
            raise ManifestError(f"{context}: id must be a non-empty string or integer")
        identity_key = str(identifier)
        if identity_key in seen_ids:
            raise ManifestError(
                f"{context}: duplicate id {identifier!r}; first seen on line "
                f"{seen_ids[identity_key]}"
            )

        relative_path = _safe_relative_path(value.get("relative_path"), context)
        if relative_path in seen_paths:
            raise ManifestError(
                f"{context}: duplicate relative_path {relative_path!r}; first seen "
                f"on line {seen_paths[relative_path]}"
            )

        if "path" in value:
            declared_path = value["path"]
            if (
                not isinstance(declared_path, str)
                or not declared_path
                or "\x00" in declared_path
            ):
                raise ManifestError(
                    f"{context}: path must be a non-empty string when present"
                )
        else:
            declared_path = None

        expected_status = value.get("status")
        if not isinstance(expected_status, str) or not expected_status:
            raise ManifestError(f"{context}: status must be a non-empty string")
        declared_sha256 = value.get("sha256")
        if not _is_sha256(declared_sha256):
            raise ManifestError(f"{context}: sha256 must be 64 lowercase hex digits")

        declared_bytes = value.get("bytes")
        if declared_bytes is not None and (
            isinstance(declared_bytes, bool)
            or not isinstance(declared_bytes, int)
            or declared_bytes < 0
        ):
            raise ManifestError(
                f"{context}: bytes must be a non-negative integer when present"
            )

        rows.append(
            ManifestRow(
                ordinal=len(rows),
                line_number=line_number,
                identifier=identifier,
                declared_path=declared_path,
                relative_path=relative_path,
                expected_status=expected_status,
                declared_sha256=declared_sha256,
                declared_bytes=declared_bytes,
            )
        )
        seen_ids[identity_key] = line_number
        seen_paths[relative_path] = line_number

    if not rows:
        raise ManifestError(f"manifest has no rows: {manifest_path}")
    return rows, manifest_sha256


def _fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _snapshot_file(
    path: Path,
    *,
    context: str,
    error_type: type[FabricShadowError],
    executable: bool = False,
) -> FileSnapshot:
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise error_type(f"{context} is not a regular file: {path}")
        if executable and not os.access(path, os.X_OK):
            raise error_type(f"{context} is not executable: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        after = path.stat()
    except FabricShadowError:
        raise
    except OSError as exc:
        raise error_type(f"cannot read {context} {path}: {exc}") from exc
    if _fingerprint(before) != _fingerprint(after):
        raise error_type(f"{context} changed while it was hashed: {path}")
    return FileSnapshot(path, digest.hexdigest(), after.st_size, _fingerprint(after))


def _verify_snapshot_metadata(
    snapshot: FileSnapshot,
    *,
    context: str,
    error_type: type[FabricShadowError],
) -> None:
    try:
        current = snapshot.path.stat()
    except OSError as exc:
        raise error_type(f"cannot stat {context} {snapshot.path}: {exc}") from exc
    if _fingerprint(current) != snapshot.fingerprint:
        raise error_type(f"{context} changed after preflight: {snapshot.path}")


def resolve_solver(value: str) -> FileSnapshot:
    candidate = Path(value).expanduser()
    has_separator = os.sep in value or (os.altsep is not None and os.altsep in value)
    if candidate.exists() or has_separator:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise SolverError(f"cannot resolve solver {value!r}: {exc}") from exc
    else:
        found = shutil.which(value)
        if found is None:
            raise SolverError(f"cannot find solver executable: {value}")
        resolved = Path(found).resolve(strict=True)
    return _snapshot_file(
        resolved, context="solver", error_type=SolverError, executable=True
    )


def _contained_candidate(
    base: Path, relative_path: str, row: ManifestRow
) -> Path | None:
    relative = PurePosixPath(relative_path)
    lexical = base.joinpath(*relative.parts)
    try:
        resolved_base = base.resolve(strict=True)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InputError(f"cannot resolve corpus base {base}: {exc}", row) from exc
    if not resolved_base.is_dir():
        raise InputError(f"corpus base is not a directory: {resolved_base}", row)
    try:
        resolved = lexical.resolve(strict=True)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InputError(f"cannot resolve input {lexical}: {exc}", row) from exc
    try:
        resolved.relative_to(resolved_base)
    except ValueError as exc:
        raise InputError(
            f"resolved input escapes corpus root: {lexical} -> {resolved}", row
        ) from exc
    if not resolved.is_file():
        raise InputError(f"resolved input is not a file: {resolved}", row)
    return resolved


def resolve_input_path(
    row: ManifestRow,
    corpus_root: Path | None,
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> tuple[Path, str]:
    """Resolve one row by exactly one documented rule."""
    if corpus_root is None:
        if row.declared_path is None:
            raise InputError(
                f"manifest line {row.line_number} has no path; --corpus-root is required",
                row,
            )
        declared = Path(row.declared_path).expanduser()
        rule = (
            "declared_path_absolute"
            if declared.is_absolute()
            else "declared_path_invocation_cwd_relative"
        )
        candidate = declared if declared.is_absolute() else Path.cwd() / declared
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise InputError(
                f"cannot resolve declared input path {row.declared_path!r}: {exc}", row
            ) from exc
        if not resolved.is_file():
            raise InputError(f"resolved input is not a file: {resolved}", row)
        return resolved, rule

    try:
        root = corpus_root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise InputError(f"cannot resolve --corpus-root {corpus_root}: {exc}", row) from exc
    if not root.is_dir():
        raise InputError(f"--corpus-root is not a directory: {root}", row)
    candidates: list[tuple[Path, str]] = []
    direct = _contained_candidate(root, row.relative_path, row)
    if direct is not None:
        candidates.append((direct, "corpus_root_relative_path"))

    try:
        resolved_repository_root = repository_root.resolve(strict=True)
    except OSError as exc:
        raise InputError(f"cannot resolve repository root {repository_root}: {exc}", row) from exc
    if root == resolved_repository_root:
        documented_base = root / DOCUMENTED_CORPUS_LAYOUT
        documented = _contained_candidate(documented_base, row.relative_path, row)
        if documented is not None:
            candidates.append((documented, "repository_corpus_layout_relative_path"))

    if not candidates:
        locations = [str(root / Path(row.relative_path))]
        if root == resolved_repository_root:
            locations.append(
                str(root / DOCUMENTED_CORPUS_LAYOUT / Path(row.relative_path))
            )
        raise InputError(
            f"cannot resolve {row.relative_path!r} below --corpus-root; tried: "
            + ", ".join(locations),
            row,
        )
    if len(candidates) != 1:
        raise InputError(
            f"ambiguous corpus-root resolution for {row.relative_path!r}: "
            + ", ".join(str(path) for path, _ in candidates),
            row,
        )
    return candidates[0]


def bind_inputs(
    rows: Sequence[ManifestRow],
    corpus_root: Path | None,
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> list[BoundRow]:
    bound: list[BoundRow] = []
    seen_paths: dict[Path, ManifestRow] = {}
    seen_inodes: dict[tuple[int, int], ManifestRow] = {}
    for row in rows:
        path, rule = resolve_input_path(
            row, corpus_root, repository_root=repository_root
        )
        source = _snapshot_file(path, context="input", error_type=InputError)
        if source.sha256 != row.declared_sha256:
            raise InputError(
                f"input SHA-256 drift for {row.relative_path!r}: expected "
                f"{row.declared_sha256}, got {source.sha256}",
                row,
            )
        if row.declared_bytes is not None and source.size != row.declared_bytes:
            raise InputError(
                f"input byte-count drift for {row.relative_path!r}: expected "
                f"{row.declared_bytes}, got {source.size}",
                row,
            )
        previous = seen_paths.get(source.path)
        if previous is not None:
            raise InputError(
                f"duplicate resolved input identity for {row.relative_path!r}; "
                f"already used by {previous.relative_path!r}",
                row,
            )
        inode = (source.fingerprint[0], source.fingerprint[1])
        previous = seen_inodes.get(inode)
        if previous is not None:
            raise InputError(
                f"duplicate physical input identity for {row.relative_path!r}; "
                f"already used by {previous.relative_path!r}",
                row,
            )
        seen_paths[source.path] = row
        seen_inodes[inode] = row
        bound.append(BoundRow(row, source, rule))
    return bound


def input_binding_sha256(rows: Sequence[BoundRow]) -> str:
    digest = hashlib.sha256()
    for bound in rows:
        row = bound.row
        binding = {
            "manifest_index": row.ordinal,
            "manifest_line": row.line_number,
            "id": row.identifier,
            "path": row.declared_path,
            "relative_path": row.relative_path,
            "resolved_path": str(bound.source.path),
            "resolution_rule": bound.resolution_rule,
            "expected_status": row.expected_status,
            "input_sha256": bound.source.sha256,
            "source_bytes": bound.source.size,
        }
        digest.update(_canonical_json_line(binding).encode("ascii"))
    return digest.hexdigest()


def resolution_metadata(
    corpus_root: Path | None,
    rows: Sequence[BoundRow],
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    if corpus_root is None:
        root = None
        repository_layout_enabled = False
        rule = "declared_path_only_absolute_or_invocation_cwd_relative"
        declared_paths = "used"
    else:
        root_path = corpus_root.expanduser().resolve(strict=True)
        root = str(root_path)
        repository_layout_enabled = root_path == repository_root.resolve(strict=True)
        rule = (
            "corpus_root_plus_relative_path_and_repository_layout_when_repo_root"
        )
        declared_paths = "preserved_but_ignored"
    return {
        "rule": rule,
        "corpus_root": root,
        "invocation_cwd": (
            str(Path.cwd().resolve())
            if any(
                bound.resolution_rule == "declared_path_invocation_cwd_relative"
                for bound in rows
            )
            else None
        ),
        "declared_paths": declared_paths,
        "repository_root": str(repository_root.resolve(strict=True)),
        "repository_layout": DOCUMENTED_CORPUS_LAYOUT.as_posix(),
        "repository_layout_enabled": repository_layout_enabled,
        "resolved_by_rule": dict(
            sorted(Counter(bound.resolution_rule for bound in rows).items())
        ),
        "ambiguity_policy": "reject",
        "traversal_policy": "normalized_relative_and_resolved_containment",
    }


def _require_nonnegative_int(value: object, field: str, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReceiptError(f"{context}: {field} must be a non-negative integer")
    return value


def validate_receipt(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptError(f"{context}: receipt must be a JSON object")
    if set(value) != RECEIPT_FIELDS:
        missing = sorted(RECEIPT_FIELDS - set(value))
        extra = sorted(set(value) - RECEIPT_FIELDS)
        raise ReceiptError(
            f"{context}: receipt fields differ; missing={missing}, extra={extra}"
        )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ReceiptError(f"{context}: schema_version must be integer 1")
    if value["mode"] != MODE or not isinstance(value["mode"], str):
        raise ReceiptError(f"{context}: mode must be {MODE!r}")
    if type(value["solver_result_emitted"]) is not bool:
        raise ReceiptError(f"{context}: solver_result_emitted must be Boolean false")
    if value["solver_result_emitted"] is not False:
        raise ReceiptError(f"{context}: solver_result_emitted must be false")
    for field in RECEIPT_INTEGER_FIELDS:
        _require_nonnegative_int(value[field], field, context)
    if type(value["contradiction"]) is not bool:
        raise ReceiptError(f"{context}: contradiction must be a Boolean")
    return value


def parse_receipt(stdout: bytes, context: str) -> dict[str, Any]:
    try:
        text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReceiptError(f"{context}: stdout is not UTF-8: {exc}") from exc
    if "\r" in text:
        raise ReceiptError(f"{context}: stdout must use one LF-terminated JSON line")
    if text.endswith("\n"):
        body = text[:-1]
    else:
        body = text
    if not body or "\n" in body:
        raise ReceiptError(f"{context}: stdout must contain exactly one JSON line")
    try:
        value = _parse_json(body, context)
    except ValueError as exc:
        raise ReceiptError(str(exc)) from exc
    return validate_receipt(value, context)


def run_instance(
    bound: BoundRow,
    solver: FileSnapshot,
    manifest_sha256: str,
    binding_sha256: str,
    timeout_s: float,
) -> Attempt:
    row = bound.row
    context = f"manifest line {row.line_number} ({row.relative_path})"
    try:
        _verify_snapshot_metadata(
            solver, context="solver", error_type=SolverDriftError
        )
        _verify_snapshot_metadata(
            bound.source, context="input", error_type=InputError
        )
        started_ns = time.perf_counter_ns()
        try:
            completed = subprocess.run(
                [str(solver.path), "fabric-shadow", str(bound.source.path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            _verify_snapshot_metadata(
                solver, context="solver", error_type=SolverDriftError
            )
            _verify_snapshot_metadata(
                bound.source, context="input", error_type=InputError
            )
            raise ExecutionError(
                f"{context}: solver exceeded timeout of {timeout_s:g}s", row
            ) from exc
        except OSError as exc:
            raise SolverError(f"{context}: failed to execute solver: {exc}", row) from exc
        wall_time_ns = time.perf_counter_ns() - started_ns
        _verify_snapshot_metadata(
            solver, context="solver", error_type=SolverDriftError
        )
        _verify_snapshot_metadata(
            bound.source, context="input", error_type=InputError
        )
        if completed.returncode != 0:
            raise ReceiptError(
                f"{context}: solver exited with code {completed.returncode}", row
            )
        if completed.stderr != b"":
            raise ReceiptError(
                f"{context}: solver wrote {len(completed.stderr)} bytes to stderr", row
            )
        receipt = parse_receipt(completed.stdout, context)
        if receipt["source_bytes"] != bound.source.size:
            raise ReceiptError(
                f"{context}: receipt source_bytes={receipt['source_bytes']} does not "
                f"match bound input bytes={bound.source.size}",
                row,
            )

        record: dict[str, Any] = {
            "record_type": RECORD_TYPE,
            "manifest_index": row.ordinal,
            "manifest_line": row.line_number,
            "id": row.identifier,
            "path": row.declared_path,
            "relative_path": row.relative_path,
            "resolved_path": str(bound.source.path),
            "resolution_rule": bound.resolution_rule,
            "expected_status": row.expected_status,
            "manifest_sha256": manifest_sha256,
            "input_binding_sha256": binding_sha256,
            "input_sha256": bound.source.sha256,
            "solver_path": str(solver.path),
            "solver_sha256": solver.sha256,
            "timeout_s": timeout_s,
            "wall_time_ns": wall_time_ns,
        }
        record.update(receipt)
        return Attempt(row=row, record=record)
    except FabricShadowError as exc:
        if exc.row is None:
            exc.row = row
        return Attempt(row=row, error=exc)
    except Exception as exc:  # pragma: no cover - defensive conversion.
        return Attempt(
            row=row,
            error=FabricShadowError(f"{context}: unexpected runner failure: {exc}", row),
        )


def _ordered_attempts(
    function: Callable[[BoundRow], Attempt],
    rows: Sequence[BoundRow],
    jobs: int,
) -> Iterator[Attempt]:
    if jobs == 1:
        for row in rows:
            yield function(row)
        return

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)
    pending: dict[int, concurrent.futures.Future[Attempt]] = {}
    next_submit = 0
    next_yield = 0
    try:
        while next_submit < len(rows) and len(pending) < jobs:
            pending[next_submit] = executor.submit(function, rows[next_submit])
            next_submit += 1
        while next_yield < len(rows):
            future = pending.pop(next_yield)
            try:
                attempt = future.result()
            except Exception as exc:  # pragma: no cover - run_instance contains errors.
                attempt = Attempt(
                    row=rows[next_yield].row,
                    error=FabricShadowError(
                        f"manifest line {rows[next_yield].row.line_number}: "
                        f"worker failed: {exc}",
                        rows[next_yield].row,
                    ),
                )
            yield attempt
            next_yield += 1
            if next_submit < len(rows):
                pending[next_submit] = executor.submit(function, rows[next_submit])
                next_submit += 1
    finally:
        for future in pending.values():
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)


def _same_identity(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def validate_output_record(
    value: object,
    bound: BoundRow,
    *,
    manifest_sha256: str,
    binding_sha256: str,
    solver: FileSnapshot,
    timeout_s: float,
    context: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResumeError(f"{context}: output row must be a JSON object")
    if set(value) != OUTPUT_RECORD_FIELDS:
        missing = sorted(OUTPUT_RECORD_FIELDS - set(value))
        extra = sorted(set(value) - OUTPUT_RECORD_FIELDS)
        raise ResumeError(
            f"{context}: output fields differ; missing={missing}, extra={extra}"
        )
    try:
        validate_receipt({key: value[key] for key in RECEIPT_FIELDS}, context)
        _require_nonnegative_int(value["wall_time_ns"], "wall_time_ns", context)
    except ReceiptError as exc:
        raise ResumeError(str(exc)) from exc
    if (
        isinstance(value["timeout_s"], bool)
        or not isinstance(value["timeout_s"], (int, float))
        or not math.isfinite(value["timeout_s"])
        or value["timeout_s"] <= 0
    ):
        raise ResumeError(f"{context}: timeout_s must be finite and positive")

    row = bound.row
    expected: dict[str, Any] = {
        "manifest_sha256": manifest_sha256,
        "input_binding_sha256": binding_sha256,
        "solver_path": str(solver.path),
        "solver_sha256": solver.sha256,
        "timeout_s": timeout_s,
        "record_type": RECORD_TYPE,
        "manifest_index": row.ordinal,
        "manifest_line": row.line_number,
        "id": row.identifier,
        "path": row.declared_path,
        "relative_path": row.relative_path,
        "resolved_path": str(bound.source.path),
        "resolution_rule": bound.resolution_rule,
        "expected_status": row.expected_status,
        "input_sha256": bound.source.sha256,
    }
    for field, expected_value in expected.items():
        if not _same_identity(value[field], expected_value):
            raise ResumeError(
                f"{context}: incompatible {field}: expected {expected_value!r}, "
                f"got {value[field]!r}"
            )
    if value["source_bytes"] != bound.source.size:
        raise ResumeError(f"{context}: source_bytes no longer matches the input")
    return value


def read_resume_records(
    handle: BinaryIO,
    rows: Sequence[BoundRow],
    *,
    manifest_sha256: str,
    binding_sha256: str,
    solver: FileSnapshot,
    timeout_s: float,
    output_path: Path,
) -> list[dict[str, Any]]:
    handle.seek(0)
    raw = handle.read()
    if raw and not raw.endswith(b"\n"):
        raise ResumeError(f"resume JSONL ends with a partial record: {output_path}")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ResumeError(f"resume JSONL is not deterministic ASCII: {exc}") from exc
    lines = text.splitlines()
    if len(lines) > len(rows):
        raise ResumeError(
            f"resume JSONL has {len(lines)} rows for a {len(rows)}-row manifest"
        )
    records: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        context = f"{output_path}:{index + 1}"
        if not line:
            raise ResumeError(f"{context}: blank output rows are forbidden")
        try:
            value = _parse_json(line, context)
        except ValueError as exc:
            raise ResumeError(str(exc)) from exc
        records.append(
            validate_output_record(
                value,
                rows[index],
                manifest_sha256=manifest_sha256,
                binding_sha256=binding_sha256,
                solver=solver,
                timeout_s=timeout_s,
                context=context,
            )
        )
    handle.seek(0, os.SEEK_END)
    return records


def _quantiles(values: Sequence[int]) -> dict[str, int | None]:
    if not values:
        return {
            "count": 0,
            "total": 0,
            "min": None,
            "p50": None,
            "p90": None,
            "p95": None,
            "p99": None,
            "max": None,
        }
    ordered = sorted(values)

    def nearest_rank(percentile: int) -> int:
        index = max(0, math.ceil((percentile / 100) * len(ordered)) - 1)
        return ordered[index]

    return {
        "count": len(ordered),
        "total": sum(ordered),
        "min": ordered[0],
        "p50": nearest_rank(50),
        "p90": nearest_rank(90),
        "p95": nearest_rank(95),
        "p99": nearest_rank(99),
        "max": ordered[-1],
    }


def _error_payload(error: FabricShadowError | None) -> dict[str, Any] | None:
    if error is None:
        return None
    payload: dict[str, Any] = {"kind": error.kind, "message": str(error)}
    if error.row is not None:
        payload.update(
            {
                "manifest_index": error.row.ordinal,
                "manifest_line": error.row.line_number,
                "id": error.row.identifier,
                "path": error.row.declared_path,
                "relative_path": error.row.relative_path,
                "expected_status": error.row.expected_status,
            }
        )
    return payload


def build_summary(
    *,
    status: str,
    manifest_path: Path,
    manifest_sha256: str,
    rows: Sequence[BoundRow],
    binding_sha256: str,
    solver: FileSnapshot,
    output_path: Path,
    output_sha256: str,
    resolution: dict[str, Any],
    jobs: int,
    timeout_s: float,
    resume: bool,
    preexisting_rows: int,
    selected_rows: int,
    attempted_rows: int,
    records: Sequence[dict[str, Any]],
    error: FabricShadowError | None,
) -> dict[str, Any]:
    aggregate = {
        field: sum(record[field] for record in records)
        for field in COMPONENT_TOTAL_FIELDS
    }
    aggregate["max_component_terms"] = max(
        (record["max_component_terms"] for record in records), default=0
    )
    aggregate["contradiction_instances"] = sum(
        int(record["contradiction"]) for record in records
    )
    remaining = len(rows) - len(records)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "input_binding_sha256": binding_sha256,
        "input_bytes": sum(bound.source.size for bound in rows),
        "solver_path": str(solver.path),
        "solver_sha256": solver.sha256,
        "out_jsonl_path": str(output_path),
        "out_jsonl_sha256": output_sha256,
        "resolution": resolution,
        "parameters": {"jobs": jobs, "timeout_s": timeout_s, "resume": resume},
        "counts": {
            "manifest_rows": len(rows),
            "preexisting_rows": preexisting_rows,
            "selected_rows": selected_rows,
            "attempted_rows": attempted_rows,
            "completed_rows": len(records),
            "error_rows": int(error is not None),
            "remaining_rows": remaining,
        },
        "aggregate_component_metrics": aggregate,
        "timing_quantiles_ns": {
            "wall_time_ns": _quantiles([record["wall_time_ns"] for record in records]),
            "parse_ns": _quantiles([record["parse_ns"] for record in records]),
            "projection_ns": _quantiles(
                [record["projection_ns"] for record in records]
            ),
        },
        "error": _error_payload(error),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    except OSError as exc:
        raise OutputError(f"cannot atomically write summary {path}: {exc}") from exc
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def _validate_output_paths(args: argparse.Namespace, solver: FileSnapshot) -> None:
    output = args.out_jsonl.expanduser().resolve()
    summary = args.summary.expanduser().resolve()
    manifest = args.manifest.expanduser().resolve()
    if output == summary:
        raise OutputError("--out-jsonl and --summary must be different paths")
    if output == manifest or summary == manifest:
        raise OutputError("outputs must not overwrite the input manifest")
    if output == solver.path or summary == solver.path:
        raise OutputError("outputs must not overwrite the solver executable")


def _validate_resume_summary(
    path: Path,
    *,
    manifest_path: Path,
    manifest_sha256: str,
    binding_sha256: str,
    solver: FileSnapshot,
    timeout_s: float,
    output_path: Path,
    resolution: dict[str, Any],
    records: Sequence[dict[str, Any]],
    manifest_rows: int,
) -> None:
    if not path.exists():
        return
    try:
        raw = path.read_bytes()
        text = raw.decode("ascii", errors="strict")
        value = _parse_json(text, str(path))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ResumeError(f"cannot read compatible resume summary {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ResumeError(f"resume summary must be a JSON object: {path}")
    expected = {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "input_binding_sha256": binding_sha256,
        "solver_path": str(solver.path),
        "solver_sha256": solver.sha256,
        "out_jsonl_path": str(output_path),
        "resolution": resolution,
    }
    for field, expected_value in expected.items():
        if field not in value or not _same_identity(value[field], expected_value):
            raise ResumeError(
                f"resume summary has incompatible {field}: "
                f"expected {expected_value!r}, got {value.get(field)!r}"
            )
    status = value.get("status")
    if status not in {"complete", "error"}:
        raise ResumeError(f"resume summary has invalid status {status!r}")
    parameters = value.get("parameters")
    if (
        not isinstance(parameters, dict)
        or not _same_identity(parameters.get("timeout_s"), timeout_s)
    ):
        raise ResumeError(
            f"resume summary has incompatible timeout_s: expected {timeout_s!r}"
        )
    counts = value.get("counts")
    if not isinstance(counts, dict) or counts.get("manifest_rows") != manifest_rows:
        raise ResumeError("resume summary has incompatible manifest row count")
    if status == "complete":
        if len(records) != manifest_rows:
            raise ResumeError("complete resume summary accompanies incomplete JSONL")
        if counts.get("completed_rows") != manifest_rows:
            raise ResumeError("complete resume summary has incompatible completed count")
        if value.get("out_jsonl_sha256") != _sha256_file(output_path):
            raise ResumeError("complete resume summary has JSONL hash drift")


def _open_locked_output(path: Path, resume: bool) -> BinaryIO:
    path.parent.mkdir(parents=True, exist_ok=True)
    if resume:
        if not path.is_file():
            raise ResumeError(f"--resume requires an existing JSONL file: {path}")
        mode = "r+b"
    else:
        if path.exists():
            raise OutputError(
                f"output JSONL already exists; use --resume or choose another path: {path}"
            )
        mode = "x+b"
    try:
        handle = path.open(mode)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        try:
            handle.close()
        except UnboundLocalError:
            pass
        raise OutputError(f"output JSONL is locked by another runner: {path}") from exc
    except OSError as exc:
        raise OutputError(f"cannot open output JSONL {path}: {exc}") from exc
    return handle


def _append_record(handle: BinaryIO, record: dict[str, Any], path: Path) -> None:
    data = _canonical_json_line(record).encode("ascii")
    start = handle.tell()
    try:
        written = handle.write(data)
        if written != len(data):
            raise OSError(f"short write: {written}/{len(data)} bytes")
        handle.flush()
        os.fsync(handle.fileno())
    except OSError as exc:
        try:
            handle.seek(start)
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
        except OSError:
            pass
        raise OutputError(f"cannot append output record to {path}: {exc}") from exc


def run(args: argparse.Namespace) -> int:
    manifest_path = args.manifest.expanduser().resolve()
    output_path = args.out_jsonl.expanduser().resolve()
    summary_path = args.summary.expanduser().resolve()

    rows, manifest_sha256 = read_manifest(args.manifest)
    solver = resolve_solver(args.solver)
    _validate_output_paths(args, solver)
    bound_rows = bind_inputs(rows, args.corpus_root)
    for bound in bound_rows:
        if output_path == bound.source.path or summary_path == bound.source.path:
            raise OutputError("outputs must not overwrite a manifest input")
    binding_sha256 = input_binding_sha256(bound_rows)
    resolution = resolution_metadata(args.corpus_root, bound_rows)

    if not args.resume and summary_path.exists():
        raise OutputError(
            f"summary already exists; use --resume or choose another path: {summary_path}"
        )

    records: list[dict[str, Any]] = []
    attempted_rows = 0
    run_error: FabricShadowError | None = None
    handle = _open_locked_output(output_path, args.resume)
    try:
        if args.resume:
            records = read_resume_records(
                handle,
                bound_rows,
                manifest_sha256=manifest_sha256,
                binding_sha256=binding_sha256,
                solver=solver,
                timeout_s=args.timeout_s,
                output_path=output_path,
            )
            _validate_resume_summary(
                summary_path,
                manifest_path=manifest_path,
                manifest_sha256=manifest_sha256,
                binding_sha256=binding_sha256,
                solver=solver,
                timeout_s=args.timeout_s,
                output_path=output_path,
                resolution=resolution,
                records=records,
                manifest_rows=len(bound_rows),
            )

        preexisting_rows = len(records)
        selected = bound_rows[preexisting_rows:]
        attempts = _ordered_attempts(
            lambda bound: run_instance(
                bound,
                solver,
                manifest_sha256,
                binding_sha256,
                args.timeout_s,
            ),
            selected,
            args.jobs,
        )
        try:
            for attempt in attempts:
                attempted_rows += 1
                if attempt.error is not None:
                    run_error = attempt.error
                    break
                assert attempt.record is not None
                _append_record(handle, attempt.record, output_path)
                records.append(attempt.record)
        except KeyboardInterrupt:
            run_error = FabricShadowError("run interrupted by user")
        except FabricShadowError as exc:
            run_error = exc
        finally:
            attempts.close()

        try:
            final_solver = _snapshot_file(
                solver.path,
                context="solver",
                error_type=SolverDriftError,
                executable=True,
            )
            if final_solver.sha256 != solver.sha256:
                raise SolverDriftError(
                    f"solver SHA-256 drift: expected {solver.sha256}, "
                    f"got {final_solver.sha256}"
                )
        except SolverDriftError as exc:
            run_error = exc
        handle.flush()
        os.fsync(handle.fileno())
        output_sha256 = _sha256_file(output_path)
        status = "complete" if run_error is None else "error"
        summary = build_summary(
            status=status,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            rows=bound_rows,
            binding_sha256=binding_sha256,
            solver=solver,
            output_path=output_path,
            output_sha256=output_sha256,
            resolution=resolution,
            jobs=args.jobs,
            timeout_s=args.timeout_s,
            resume=args.resume,
            preexisting_rows=preexisting_rows,
            selected_rows=len(selected),
            attempted_rows=attempted_rows,
            records=records,
            error=run_error,
        )
        _atomic_write_json(summary_path, summary)
    finally:
        handle.close()

    counts = summary["counts"]
    print(
        f"status={summary['status']} manifest_rows={counts['manifest_rows']} "
        f"completed_rows={counts['completed_rows']} "
        f"remaining_rows={counts['remaining_rows']}"
    )
    if run_error is not None:
        print(f"error: {run_error}", file=sys.stderr)
        return 130 if str(run_error) == "run interrupted by user" else 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--solver", required=True)
    parser.add_argument("--out-jsonl", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--jobs", type=_positive_int, default=1)
    parser.add_argument(
        "--timeout-s",
        type=_positive_float,
        default=60.0,
        help="strict per-instance wall timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="validate and continue an existing deterministic JSONL prefix",
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        help=(
            "resolve safe relative_path values below ROOT, ignoring host-local "
            "manifest path values"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except FabricShadowError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
