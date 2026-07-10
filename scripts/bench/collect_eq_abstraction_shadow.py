#!/usr/bin/env python3
"""Collect and merge corpus-wide equality-abstraction shadow telemetry."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Sequence


SCHEMA_VERSION = 1
RESULTS = {"sat", "unsat"}
CAP_REASONS = {"none", "work", "entries", "star_edges", "arithmetic"}
PROFILE_LABELS = (
    "eq_abstraction",
    "eq_abstraction_nodes",
    "eq_abstraction_memo_entries",
    "eq_abstraction_memo_hits",
    "eq_abstraction_work",
    "eq_abstraction_classes",
    "eq_abstraction_partition_terms",
)
COUNT_FIELDS = {
    "eq_abstraction": "star_edges",
    "eq_abstraction_nodes": "nodes",
    "eq_abstraction_memo_entries": "memo_entries",
    "eq_abstraction_memo_hits": "memo_hits",
    "eq_abstraction_work": "work",
    "eq_abstraction_classes": "classes",
    "eq_abstraction_partition_terms": "partition_terms",
}
AGGREGATE_FIELDS = (
    "star_edges",
    "nodes",
    "memo_entries",
    "memo_hits",
    "work",
    "classes",
    "partition_terms",
)
MEASUREMENT_RE = re.compile(
    r"^profile_([a-z][a-z0-9_]*)_ns=(0|[1-9][0-9]*) "
    r"count=(0|[1-9][0-9]*)$"
)
MODE_RE = re.compile(
    r"^profile_eq_abstraction_mode=([a-z][a-z0-9_-]*) "
    r"cap_reason=([a-z][a-z0-9_]*) infeasible=([01])$"
)
ELAPSED_RE = re.compile(r"^elapsed_ns=(0|[1-9][0-9]*)$")


class CollectorError(ValueError):
    """Base class for invalid collector inputs or output."""


class ManifestError(CollectorError):
    """Raised when a benchmark manifest is malformed."""


class ProfileOutputError(CollectorError):
    """Raised when solver profile output is incomplete or malformed."""


class TelemetryError(CollectorError):
    """Raised when a telemetry shard is malformed or incomplete."""


def _safe_relative_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CollectorError(f"{context}: relative_path must be a non-empty string")
    relative = PurePosixPath(value)
    if relative.is_absolute() or value == "." or ".." in relative.parts:
        raise CollectorError(
            f"{context}: relative_path must stay below the benchmark root"
        )
    return value


def read_manifest(path: Path) -> list[dict]:
    """Read, validate, and lexically order a JSONL benchmark manifest."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc

    entries: list[dict] = []
    seen: dict[str, int] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ManifestError(
                f"{path}:{line_number}: invalid JSON: {exc.msg}"
            ) from exc
        if not isinstance(row, dict):
            raise ManifestError(f"{path}:{line_number}: row must be a JSON object")
        try:
            relative_path = _safe_relative_path(
                row.get("relative_path"), f"{path}:{line_number}"
            )
        except CollectorError as exc:
            raise ManifestError(str(exc)) from exc
        if relative_path in seen:
            raise ManifestError(
                f"{path}:{line_number}: duplicate relative_path {relative_path!r}; "
                f"first seen on line {seen[relative_path]}"
            )
        seen[relative_path] = line_number

        raw_path = row.get("path")
        if raw_path is not None and (
            not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path
        ):
            raise ManifestError(
                f"{path}:{line_number}: path must be a non-empty string when present"
            )
        expected_status = row.get("status")
        if expected_status is not None and not isinstance(expected_status, str):
            raise ManifestError(
                f"{path}:{line_number}: status must be a string when present"
            )
        entries.append(
            {
                "id": row.get("id"),
                "line_number": line_number,
                "path": raw_path,
                "relative_path": relative_path,
                "expected_status": expected_status,
            }
        )

    entries.sort(key=lambda entry: entry["relative_path"])
    return entries


def parse_profile(stderr: str) -> dict:
    """Parse one complete c958c9e profile or a fast-path no-op record."""
    measurements: dict[str, tuple[int, int]] = {}
    mode_record: tuple[str, str, bool] | None = None
    solver_elapsed_ns: int | None = None
    saw_eq_abstraction_profile = False

    for line_number, raw_line in enumerate(stderr.splitlines(), start=1):
        line = raw_line.strip()
        if line.startswith("profile_eq_abstraction"):
            saw_eq_abstraction_profile = True
        if line.startswith("profile_eq_abstraction_mode"):
            match = MODE_RE.fullmatch(line)
            if match is None:
                raise ProfileOutputError(
                    f"malformed equality-abstraction mode record on stderr line "
                    f"{line_number}: {line!r}"
                )
            if mode_record is not None:
                raise ProfileOutputError(
                    "duplicate equality-abstraction mode record on stderr"
                )
            mode, cap_reason, raw_infeasible = match.groups()
            mode_record = (mode, cap_reason, raw_infeasible == "1")
            continue

        if line.startswith("profile_eq_abstraction"):
            match = MEASUREMENT_RE.fullmatch(line)
            if match is None:
                raise ProfileOutputError(
                    f"malformed equality-abstraction measurement on stderr line "
                    f"{line_number}: {line!r}"
                )
            label, raw_elapsed, raw_count = match.groups()
            if label not in PROFILE_LABELS:
                raise ProfileOutputError(
                    f"unknown equality-abstraction measurement {label!r}"
                )
            if label in measurements:
                raise ProfileOutputError(
                    f"duplicate equality-abstraction measurement {label!r}"
                )
            elapsed_ns = int(raw_elapsed)
            count = int(raw_count)
            if label != "eq_abstraction" and elapsed_ns != 0:
                raise ProfileOutputError(
                    f"counter-only measurement {label!r} has nonzero timing"
                )
            measurements[label] = (elapsed_ns, count)
            continue

        if line.startswith("elapsed_ns="):
            match = ELAPSED_RE.fullmatch(line)
            if match is None:
                raise ProfileOutputError(
                    f"malformed solver elapsed_ns record on stderr line {line_number}"
                )
            if solver_elapsed_ns is not None:
                raise ProfileOutputError("duplicate solver elapsed_ns record on stderr")
            solver_elapsed_ns = int(match.group(1))

    if solver_elapsed_ns is None:
        raise ProfileOutputError("missing solver elapsed_ns record; run solve with --stats")
    if not saw_eq_abstraction_profile:
        parsed = {
            "applicable": False,
            "eq_abstraction_ns": 0,
            "solver_elapsed_ns": solver_elapsed_ns,
        }
        parsed.update({field: 0 for field in AGGREGATE_FIELDS})
        parsed["cap_reason"] = "none"
        parsed["infeasible"] = False
        return parsed

    missing = [label for label in PROFILE_LABELS if label not in measurements]
    if missing:
        raise ProfileOutputError(
            "missing equality-abstraction measurements: " + ", ".join(missing)
        )
    if mode_record is None:
        raise ProfileOutputError("missing equality-abstraction mode record")
    mode, cap_reason, infeasible = mode_record
    if mode != "shadow":
        raise ProfileOutputError(
            f"expected equality-abstraction mode 'shadow', observed {mode!r}"
        )
    if cap_reason not in CAP_REASONS:
        raise ProfileOutputError(f"unknown equality-abstraction cap reason {cap_reason!r}")

    primary_elapsed, _ = measurements["eq_abstraction"]
    parsed = {
        "applicable": True,
        "eq_abstraction_ns": primary_elapsed,
        "solver_elapsed_ns": solver_elapsed_ns,
    }
    for label in PROFILE_LABELS:
        parsed[COUNT_FIELDS[label]] = measurements[label][1]
    parsed["cap_reason"] = cap_reason
    parsed["infeasible"] = infeasible
    return parsed


def parse_solver_result(stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1 or lines[0] not in RESULTS:
        raise ProfileOutputError(
            "expected exactly one solver result line containing 'sat' or 'unsat'"
        )
    return lines[0]


def resolve_executable(value: str) -> str:
    candidate = Path(value).expanduser()
    contains_separator = os.sep in value or (os.altsep is not None and os.altsep in value)
    if contains_separator or candidate.exists():
        resolved = candidate.resolve()
        if not resolved.is_file():
            raise CollectorError(f"euf-viper binary is not a file: {resolved}")
        if not os.access(resolved, os.X_OK):
            raise CollectorError(f"euf-viper binary is not executable: {resolved}")
        return str(resolved)
    found = shutil.which(value)
    if found is None:
        raise CollectorError(f"cannot find euf-viper binary: {value}")
    return str(Path(found).resolve())


def resolve_input_path(
    entry: dict, manifest: Path, benchmark_root: Path | None
) -> Path:
    if benchmark_root is not None:
        relative = PurePosixPath(entry["relative_path"])
        return benchmark_root.joinpath(*relative.parts).expanduser().resolve()
    raw_path = entry["path"]
    if raw_path is not None:
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = manifest.parent / candidate
        return candidate.resolve()
    relative = PurePosixPath(entry["relative_path"])
    return manifest.parent.joinpath(*relative.parts).resolve()


def _identity(entry: dict, resolved_path: Path) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "id": entry["id"],
        "manifest_line": entry["line_number"],
        "relative_path": entry["relative_path"],
        "resolved_path": str(resolved_path),
        "expected_status": entry["expected_status"],
    }


def _excerpt(value: str | bytes | None, limit: int = 2_000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode(encoding="utf-8", errors="replace")
    value = value.strip()
    return value if len(value) <= limit else value[:limit] + "..."


def _failure_record(
    identity: dict,
    kind: str,
    message: str,
    *,
    wall_time_ns: int = 0,
    exit_code: int | None = None,
    stdout: str | bytes | None = None,
    stderr: str | bytes | None = None,
) -> dict:
    record = dict(identity)
    record.update(
        {
            "status": "timeout" if kind == "timeout" else "failure",
            "failure_kind": kind,
            "message": message,
            "wall_time_ns": wall_time_ns,
        }
    )
    if exit_code is not None:
        record["exit_code"] = exit_code
    stdout_excerpt = _excerpt(stdout)
    stderr_excerpt = _excerpt(stderr)
    if stdout_excerpt:
        record["stdout"] = stdout_excerpt
    if stderr_excerpt:
        record["stderr"] = stderr_excerpt
    return record


def collect_instance(
    entry: dict,
    manifest: Path,
    executable: str,
    timeout_s: float,
    benchmark_root: Path | None,
) -> dict:
    """Run one shadow solve and return a normalized telemetry record."""
    try:
        resolved_path = resolve_input_path(entry, manifest, benchmark_root)
    except (OSError, RuntimeError, ValueError) as exc:
        fallback = Path(entry["relative_path"])
        return _failure_record(
            _identity(entry, fallback), "path_error", f"cannot resolve input path: {exc}"
        )

    identity = _identity(entry, resolved_path)
    if not resolved_path.is_file():
        return _failure_record(
            identity,
            "missing_input",
            f"resolved benchmark path is not a file: {resolved_path}",
        )

    environment = os.environ.copy()
    environment["EUF_VIPER_EQ_ABSTRACTION"] = "shadow"
    environment["EUF_VIPER_PROFILE"] = "1"
    command = [executable, "solve", "--stats", str(resolved_path)]
    started_ns = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        wall_time_ns = time.perf_counter_ns() - started_ns
        return _failure_record(
            identity,
            "timeout",
            f"solve command exceeded timeout of {timeout_s:g}s",
            wall_time_ns=wall_time_ns,
            exit_code=124,
            stdout=exc.stdout,
            stderr=exc.stderr,
        )
    except OSError as exc:
        wall_time_ns = time.perf_counter_ns() - started_ns
        return _failure_record(
            identity,
            "process_error",
            f"failed to execute euf-viper: {exc}",
            wall_time_ns=wall_time_ns,
        )

    wall_time_ns = time.perf_counter_ns() - started_ns
    if completed.returncode != 0:
        return _failure_record(
            identity,
            "nonzero_exit",
            f"solve command exited with code {completed.returncode}",
            wall_time_ns=wall_time_ns,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    try:
        solver_result = parse_solver_result(completed.stdout)
        profile = parse_profile(completed.stderr)
    except ProfileOutputError as exc:
        return _failure_record(
            identity,
            "malformed_profile",
            str(exc),
            wall_time_ns=wall_time_ns,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    record = dict(identity)
    record.update(
        {
            "status": "ok",
            "solver_result": solver_result,
            "exit_code": completed.returncode,
            "wall_time_ns": wall_time_ns,
        }
    )
    record.update(profile)
    return record


def _bounded_ordered_map(
    function: Callable[[dict], dict], entries: Sequence[dict], jobs: int
) -> Iterator[dict]:
    """Preserve input order while keeping at most 2 * jobs tasks in flight."""
    if jobs == 1:
        for entry in entries:
            yield function(entry)
        return

    pending: dict[int, concurrent.futures.Future[dict]] = {}
    next_submit = 0
    next_yield = 0
    max_pending = jobs * 2
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        while next_yield < len(entries):
            while next_submit < len(entries) and len(pending) < max_pending:
                pending[next_submit] = executor.submit(function, entries[next_submit])
                next_submit += 1
            future = pending.pop(next_yield)
            yield future.result()
            next_yield += 1


def collect_manifest(
    manifest: Path,
    executable: str,
    timeout_s: float,
    benchmark_root: Path | None,
    jobs: int,
) -> list[dict]:
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise CollectorError("timeout must be a finite number greater than zero")
    if jobs < 1:
        raise CollectorError("jobs must be at least one")
    entries = read_manifest(manifest)
    inspect = lambda entry: collect_instance(
        entry, manifest, executable, timeout_s, benchmark_root
    )
    return list(_bounded_ordered_map(inspect, entries, jobs))


def _require_nonnegative_int(record: dict, field: str, context: str) -> int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TelemetryError(f"{context}: {field} must be a non-negative integer")
    return value


def validate_telemetry_record(record: object, context: str) -> dict:
    if not isinstance(record, dict):
        raise TelemetryError(f"{context}: telemetry row must be a JSON object")
    if record.get("schema_version") != SCHEMA_VERSION:
        raise TelemetryError(
            f"{context}: unsupported schema_version {record.get('schema_version')!r}"
        )
    try:
        _safe_relative_path(record.get("relative_path"), context)
    except CollectorError as exc:
        raise TelemetryError(str(exc)) from exc
    if not isinstance(record.get("resolved_path"), str) or not record["resolved_path"]:
        raise TelemetryError(f"{context}: resolved_path must be a non-empty string")
    _require_nonnegative_int(record, "manifest_line", context)
    _require_nonnegative_int(record, "wall_time_ns", context)

    status = record.get("status")
    if status not in {"ok", "timeout", "failure"}:
        raise TelemetryError(f"{context}: invalid status {status!r}")
    if status == "ok":
        if record.get("solver_result") not in RESULTS:
            raise TelemetryError(f"{context}: invalid solver_result")
        if record.get("exit_code") != 0:
            raise TelemetryError(f"{context}: successful row must have exit_code 0")
        applicable = record.get("applicable")
        if not isinstance(applicable, bool):
            raise TelemetryError(f"{context}: applicable must be a boolean")
        _require_nonnegative_int(record, "eq_abstraction_ns", context)
        _require_nonnegative_int(record, "solver_elapsed_ns", context)
        for field in AGGREGATE_FIELDS:
            _require_nonnegative_int(record, field, context)
        cap_reason = record.get("cap_reason")
        if cap_reason not in CAP_REASONS:
            raise TelemetryError(f"{context}: invalid cap_reason {cap_reason!r}")
        if not isinstance(record.get("infeasible"), bool):
            raise TelemetryError(f"{context}: infeasible must be a boolean")
        if not applicable:
            nonzero_fields = [
                field
                for field in ("eq_abstraction_ns", *AGGREGATE_FIELDS)
                if record[field] != 0
            ]
            if nonzero_fields:
                raise TelemetryError(
                    f"{context}: non-applicable row has nonzero metrics: "
                    + ", ".join(nonzero_fields)
                )
            if cap_reason != "none":
                raise TelemetryError(
                    f"{context}: non-applicable row must have cap_reason 'none'"
                )
            if record["infeasible"]:
                raise TelemetryError(
                    f"{context}: non-applicable row cannot be infeasible"
                )
    else:
        kind = record.get("failure_kind")
        if not isinstance(kind, str) or not kind:
            raise TelemetryError(f"{context}: failure_kind must be a non-empty string")
        if status == "timeout" and kind != "timeout":
            raise TelemetryError(f"{context}: timeout row must have failure_kind timeout")
        if status == "failure" and kind == "timeout":
            raise TelemetryError(f"{context}: timeout failure must use status timeout")
        if not isinstance(record.get("message"), str) or not record["message"]:
            raise TelemetryError(f"{context}: failure message must be a non-empty string")
    return record


def read_telemetry(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TelemetryError(f"cannot read telemetry shard {path}: {exc}") from exc
    records = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        context = f"{path}:{line_number}"
        try:
            raw_record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TelemetryError(f"{context}: invalid JSON: {exc.msg}") from exc
        records.append(validate_telemetry_record(raw_record, context))
    return records


def merge_shards(manifest: Path, inputs: Sequence[Path]) -> list[dict]:
    entries = read_manifest(manifest)
    entries_by_path = {entry["relative_path"]: entry for entry in entries}
    records_by_path: dict[str, dict] = {}
    source_by_path: dict[str, str] = {}

    for shard in inputs:
        for record in read_telemetry(shard):
            relative_path = record["relative_path"]
            if relative_path not in entries_by_path:
                raise TelemetryError(
                    f"{shard}: path is not in merge manifest: {relative_path!r}"
                )
            if relative_path in records_by_path:
                raise TelemetryError(
                    f"duplicate telemetry path {relative_path!r} in {shard}; "
                    f"first seen in {source_by_path[relative_path]}"
                )
            entry = entries_by_path[relative_path]
            if record.get("id") != entry["id"]:
                raise TelemetryError(f"{shard}: id mismatch for {relative_path!r}")
            if record.get("expected_status") != entry["expected_status"]:
                raise TelemetryError(
                    f"{shard}: expected_status mismatch for {relative_path!r}"
                )
            normalized = dict(record)
            normalized["manifest_line"] = entry["line_number"]
            records_by_path[relative_path] = normalized
            source_by_path[relative_path] = str(shard)

    missing = [
        entry["relative_path"]
        for entry in entries
        if entry["relative_path"] not in records_by_path
    ]
    if missing:
        raise TelemetryError(
            f"incomplete telemetry merge: rows={len(records_by_path)}/{len(entries)}; "
            f"first_missing={missing[:10]}"
        )
    return [records_by_path[entry["relative_path"]] for entry in entries]


def build_summary(records: Sequence[dict], source: dict) -> dict:
    """Build a deterministic compact summary from normalized records."""
    ordered = sorted(records, key=lambda record: record["relative_path"])
    seen: set[str] = set()
    for index, record in enumerate(ordered, start=1):
        validate_telemetry_record(record, f"summary record {index}")
        relative_path = record["relative_path"]
        if relative_path in seen:
            raise TelemetryError(f"duplicate summary path {relative_path!r}")
        seen.add(relative_path)

    successful = [record for record in ordered if record["status"] == "ok"]
    failed = [record for record in ordered if record["status"] != "ok"]
    applicable = [record for record in successful if record["applicable"]]
    non_applicable = [record for record in successful if not record["applicable"]]
    hits = [record for record in successful if record["star_edges"] > 0]
    capped = [record for record in successful if record["cap_reason"] != "none"]
    infeasible = [record for record in successful if record["infeasible"]]

    cap_counts = Counter(record["cap_reason"] for record in capped)
    cap_paths: dict[str, list[str]] = defaultdict(list)
    for record in capped:
        cap_paths[record["cap_reason"]].append(record["relative_path"])
    failure_counts = Counter(record["failure_kind"] for record in failed)
    failure_paths: dict[str, list[str]] = defaultdict(list)
    for record in failed:
        failure_paths[record["failure_kind"]].append(record["relative_path"])

    eq_abstraction_ns = sum(record["eq_abstraction_ns"] for record in successful)
    solver_elapsed_ns = sum(record["solver_elapsed_ns"] for record in successful)
    wall_time_ns = sum(record["wall_time_ns"] for record in successful)
    metric_totals = {
        field: sum(record[field] for record in successful)
        for field in AGGREGATE_FIELDS
    }

    payload = {
        "schema_version": SCHEMA_VERSION,
        **source,
        "counts": {
            "manifest_instances": len(ordered),
            "successful_instances": len(successful),
            "failed_instances": len(failed),
            "applicable_instances": len(applicable),
            "non_applicable_instances": len(non_applicable),
            "timeout_instances": failure_counts.get("timeout", 0),
            "star_edge_hit_instances": len(hits),
            "capped_instances": len(capped),
            "infeasible_instances": len(infeasible),
        },
        "solver_results": dict(
            sorted(Counter(record["solver_result"] for record in successful).items())
        ),
        "metric_totals": metric_totals,
        "star_edges": {
            "total": metric_totals["star_edges"],
            "hit_paths": [record["relative_path"] for record in hits],
            "hits": [
                {
                    "relative_path": record["relative_path"],
                    "resolved_path": record["resolved_path"],
                    "star_edges": record["star_edges"],
                }
                for record in hits
            ],
        },
        "caps": {
            "counts": dict(sorted(cap_counts.items())),
            "paths_by_reason": {
                reason: cap_paths[reason] for reason in sorted(cap_paths)
            },
        },
        "failures": {
            "counts": dict(sorted(failure_counts.items())),
            "paths_by_kind": {
                kind: failure_paths[kind] for kind in sorted(failure_paths)
            },
        },
        "aggregate_overhead": {
            "eq_abstraction_ns": eq_abstraction_ns,
            "solver_elapsed_ns": solver_elapsed_ns,
            "wall_time_ns": wall_time_ns,
            "eq_abstraction_fraction_of_solver_elapsed": (
                eq_abstraction_ns / solver_elapsed_ns if solver_elapsed_ns else None
            ),
        },
    }
    return payload


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_jsonl(path: Path, records: Sequence[dict]) -> None:
    ordered = sorted(records, key=lambda record: record["relative_path"])
    content = "".join(json.dumps(record, sort_keys=True) + "\n" for record in ordered)
    _atomic_write(path, content)


def write_json(path: Path, payload: dict) -> None:
    _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least one")
    return parsed


def _same_path(first: Path, second: Path) -> bool:
    return first.resolve() == second.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    collect = subparsers.add_parser("collect", help="collect one manifest shard")
    collect.add_argument("manifest", type=Path)
    collect.add_argument("--binary", "--viper", dest="binary", required=True)
    collect.add_argument("--timeout", type=_positive_float, default=10.0)
    collect.add_argument("--jobs", type=_positive_int, default=1)
    collect.add_argument(
        "--benchmark-root",
        "--corpus-root",
        dest="benchmark_root",
        type=Path,
        help="resolve relative_path below this root instead of using manifest path",
    )
    collect.add_argument("--out", type=Path, required=True)
    collect.add_argument("--summary", type=Path, required=True)

    merge = subparsers.add_parser("merge", help="strictly merge complete JSONL shards")
    merge.add_argument("manifest", type=Path)
    merge.add_argument("inputs", nargs="+", type=Path)
    merge.add_argument("--out", type=Path, required=True)
    merge.add_argument("--summary", type=Path, required=True)
    return parser


def _validate_output_paths(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if _same_path(args.out, args.summary):
        parser.error("--out and --summary must be different paths")
    if _same_path(args.out, args.manifest) or _same_path(args.summary, args.manifest):
        parser.error("output paths must not overwrite the input manifest")
    if args.mode == "merge":
        for input_path in args.inputs:
            if _same_path(args.out, input_path) or _same_path(args.summary, input_path):
                parser.error("output paths must not overwrite telemetry inputs")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_output_paths(parser, args)

    try:
        if args.mode == "collect":
            executable = resolve_executable(args.binary)
            records = collect_manifest(
                args.manifest,
                executable,
                args.timeout,
                args.benchmark_root,
                args.jobs,
            )
            source = {
                "mode": "collect",
                "manifest": str(args.manifest),
                "binary": executable,
                "parameters": {
                    "benchmark_root": (
                        str(args.benchmark_root)
                        if args.benchmark_root is not None
                        else None
                    ),
                    "jobs": args.jobs,
                    "timeout_s": args.timeout,
                },
            }
        else:
            records = merge_shards(args.manifest, args.inputs)
            source = {
                "mode": "merge",
                "manifest": str(args.manifest),
                "inputs": sorted(str(path) for path in args.inputs),
            }

        summary = build_summary(records, source)
        write_jsonl(args.out, records)
        write_json(args.summary, summary)
    except (CollectorError, OSError) as exc:
        parser.error(str(exc))

    counts = summary["counts"]
    print(
        f"instances={counts['manifest_instances']} "
        f"successful={counts['successful_instances']} "
        f"failed={counts['failed_instances']} "
        f"timeouts={counts['timeout_instances']} "
        f"star_edge_hits={counts['star_edge_hit_instances']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
