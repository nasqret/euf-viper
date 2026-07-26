#!/usr/bin/env python3
"""Import paired fast-cycle ledgers into the strict EUF dashboard registry.

The importer deliberately treats a fast-cycle directory as evidence, not as a
trusted database.  It cross-checks the ledger, run summary, and measured CSV;
preserves each candidate/comparator pair as its own ``solver_ids`` subset; and
fails before writing if observations cannot be classified unambiguously.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import statistics
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


REGISTRY_SCHEMA_VERSION = "euf-viper.dashboard-evidence.v1"
LEDGER_SCHEMA_VERSION = 2
SUMMARY_SCHEMA_VERSION = 1
DECISIVE_RESULTS = frozenset({"sat", "unsat"})
EXPECTED_RESULTS = frozenset({"sat", "unsat", "unknown"})
MEASURED_RESULTS = frozenset(
    {"sat", "unsat", "unknown", "timeout", "invalid-output"}
)
EVIDENCE_STATUSES = frozenset(
    {"verified", "provisional", "incomplete", "rejected", "superseded"}
)
ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
REVISION_PATTERN = re.compile(r"[0-9a-f]{7,64}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
INTEGER_PATTERN = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")

CSV_FIELDS = (
    "sequence",
    "row_index",
    "id",
    "relative_path",
    "expected_status",
    "label",
    "repeat",
    "order_in_repeat",
    "result",
    "time_s",
    "exit_code",
    "process_returncode",
    "timed_out",
    "error_kind",
    "stdout",
    "stderr",
    "argv_json",
)

LEDGER_KEYS = {
    "campaign_id",
    "finished_at",
    "preflight",
    "reference_binary",
    "repository",
    "runs",
    "schema_version",
    "selected_comparators",
    "selected_stages",
    "spec",
    "started_at",
    "status",
}
REPOSITORY_KEYS = {"clean", "revision"}
SPEC_KEYS = {"path", "sha256"}
RUN_KEYS = {
    "blocking_performance",
    "command_returncode",
    "common_aggregate_speedup",
    "common_geometric_speedup",
    "comparator",
    "coverage_delta",
    "coverage_dominance",
    "csv",
    "failures",
    "kind",
    "passed",
    "performance_target_failures",
    "performance_target_met",
    "stage",
    "stderr_tail",
    "stdout_tail",
    "summary",
}

COMPARATORS: dict[str, dict[str, object]] = {
    "cvc5": {"label": "cvc5", "executables": frozenset({"cvc5"})},
    "yices2": {
        "label": "Yices2",
        "executables": frozenset({"yices-smt2", "yices2"}),
    },
    "z3": {"label": "Z3", "executables": frozenset({"z3"})},
}
KNOWN_STAGE_FAMILIES = {
    "Q2NF": ("neq", "NEQ"),
    "Q2PF": ("peq", "PEQ"),
    "Q2SF": ("seq", "SEQ"),
}


class FastCycleImportError(ValueError):
    """Raised when fast-cycle evidence is incomplete or inconsistent."""


def _reject_json_constant(token: str) -> None:
    raise FastCycleImportError(f"non-finite JSON number {token!r} is forbidden")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FastCycleImportError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_file(path: Path, context: str) -> tuple[Path, bytes]:
    try:
        resolved = path.expanduser().resolve(strict=True)
        if not resolved.is_file():
            raise FastCycleImportError(f"{context} is not a regular file: {path}")
        payload = resolved.read_bytes()
    except FastCycleImportError:
        raise
    except OSError as error:
        raise FastCycleImportError(f"cannot read {context} {path}: {error}") from error
    return resolved, payload


def _load_json_bytes(payload: bytes, context: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FastCycleImportError(f"{context} is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise FastCycleImportError(
            f"{context}:{error.lineno}:{error.colno}: invalid JSON: {error.msg}"
        ) from error
    if type(value) is not dict:
        raise FastCycleImportError(f"{context} must contain a JSON object")
    return value


def _require_exact_keys(
    value: object, expected: set[str], context: str
) -> dict[str, Any]:
    if type(value) is not dict:
        raise FastCycleImportError(f"{context} must be an object")
    if not all(type(key) is str for key in value):
        raise FastCycleImportError(f"{context} keys must be strings")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing keys {missing!r}")
        if extra:
            details.append(f"unexpected keys {extra!r}")
        raise FastCycleImportError(f"{context}: {'; '.join(details)}")
    return value


def _require_mapping(value: object, context: str) -> dict[str, Any]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise FastCycleImportError(f"{context} must be an object with string keys")
    return value


def _require_list(value: object, context: str, *, nonempty: bool = True) -> list[Any]:
    if type(value) is not list:
        raise FastCycleImportError(f"{context} must be an array")
    if nonempty and not value:
        raise FastCycleImportError(f"{context} must not be empty")
    return value


def _require_text(value: object, context: str, *, maximum: int = 2048) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise FastCycleImportError(f"{context} must be a non-empty trimmed string")
    if len(value) > maximum:
        raise FastCycleImportError(f"{context} exceeds {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise FastCycleImportError(f"{context} contains a control character")
    return value


def _require_id(value: object, context: str) -> str:
    result = _require_text(value, context, maximum=128)
    if ID_PATTERN.fullmatch(result) is None:
        raise FastCycleImportError(f"{context} is not a dashboard-safe ID")
    return result


def _require_bool(value: object, context: str) -> bool:
    if type(value) is not bool:
        raise FastCycleImportError(f"{context} must be a boolean")
    return value


def _require_int(value: object, context: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise FastCycleImportError(f"{context} must be an integer")
    if minimum is not None and value < minimum:
        raise FastCycleImportError(f"{context} must be at least {minimum}")
    return value


def _require_number(value: object, context: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FastCycleImportError(f"{context} must be a number")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0.0):
        qualifier = "finite and positive" if positive else "finite"
        raise FastCycleImportError(f"{context} must be {qualifier}")
    return result


def _parse_timestamp(value: object, context: str) -> datetime:
    text = _require_text(value, context, maximum=64)
    if text.endswith("Z"):
        parsed_text = text[:-1] + "+00:00"
    else:
        parsed_text = text
    try:
        parsed = datetime.fromisoformat(parsed_text)
    except ValueError as error:
        raise FastCycleImportError(f"{context} is not an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise FastCycleImportError(f"{context} must use UTC")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _resolve_pointer(raw: object, ledger_dir: Path, context: str) -> Path:
    text = _require_text(raw, context)
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = ledger_dir / path
    resolved, _ = _read_file(path, context)
    return resolved


def _canonical_source_path(path: Path) -> str:
    repository = Path(__file__).resolve().parents[2]
    try:
        return path.relative_to(repository).as_posix()
    except ValueError:
        return path.as_posix()


def _slug(value: str, context: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")[:128]
    result = result.rstrip("-")
    if not result or ID_PATTERN.fullmatch(result) is None:
        raise FastCycleImportError(f"cannot derive a dashboard ID for {context}")
    return result


def _parse_csv_int(value: str, context: str, *, minimum: int | None = None) -> int:
    if INTEGER_PATTERN.fullmatch(value) is None:
        raise FastCycleImportError(f"{context} must be a canonical integer")
    result = int(value)
    if minimum is not None and result < minimum:
        raise FastCycleImportError(f"{context} must be at least {minimum}")
    return result


def _parse_csv_time(value: str, context: str) -> float:
    try:
        result = float(value)
    except ValueError as error:
        raise FastCycleImportError(f"{context} must be a floating-point number") from error
    if not math.isfinite(result) or result <= 0.0:
        raise FastCycleImportError(f"{context} must be finite and positive")
    return result


def _parse_argv(value: str, context: str) -> list[str]:
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise FastCycleImportError(f"{context} is not valid JSON") from error
    argv = _require_list(parsed, context)
    if not all(type(token) is str and token and "\x00" not in token for token in argv):
        raise FastCycleImportError(f"{context} must be an array of non-empty strings")
    return argv


def _validate_relative_path(value: str, context: str) -> str:
    result = _require_text(value, context, maximum=1024)
    path = PurePosixPath(result)
    if path.is_absolute() or path.as_posix() != result or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise FastCycleImportError(f"{context} must be a normalized relative POSIX path")
    return result


def _require_command(value: object, context: str) -> list[str]:
    command = _require_list(value, context)
    if not all(type(token) is str and token and "\x00" not in token for token in command):
        raise FastCycleImportError(f"{context} must contain non-empty string arguments")
    if command.count("{input}") != 1:
        raise FastCycleImportError(f"{context} must contain exactly one {{input}} token")
    return command


def _validate_command_identity(
    candidate: Sequence[str], baseline: Sequence[str], comparator: str, context: str
) -> None:
    if Path(candidate[0]).name != "euf-viper":
        raise FastCycleImportError(
            f"{context}: candidate executable must identify euf-viper"
        )
    metadata = COMPARATORS.get(comparator)
    if metadata is None:
        raise FastCycleImportError(f"{context}: unsupported comparator ID {comparator!r}")
    executable = Path(baseline[0]).name
    if executable not in metadata["executables"]:
        raise FastCycleImportError(
            f"{context}: comparator {comparator!r} does not match baseline "
            f"executable {executable!r}"
        )


def _validate_expanded_command(
    argv: Sequence[str], template: Sequence[str], relative_path: str, context: str
) -> None:
    if len(argv) != len(template):
        raise FastCycleImportError(f"{context} does not match its command template")
    input_index = template.index("{input}")
    input_argument = argv[input_index]
    suffix = "/" + relative_path
    normalized_input = input_argument.replace("\\", "/")
    if normalized_input != relative_path and not normalized_input.endswith(suffix):
        raise FastCycleImportError(
            f"{context} input argument does not match {relative_path!r}"
        )
    expected = list(template)
    expected[input_index] = input_argument
    if list(argv) != expected:
        raise FastCycleImportError(f"{context} does not match its command template")


def _classify_row(row: Mapping[str, Any], context: str) -> str:
    result = row["result"]
    expected = row["expected_status"]
    timed_out = row["timed_out"]
    error_kind = row["error_kind"]
    exit_code = row["exit_code"]
    process_returncode = row["process_returncode"]

    if timed_out:
        if result != "timeout" or error_kind != "timeout":
            raise FastCycleImportError(
                f"{context}: timeout rows must use result/error_kind 'timeout'"
            )
        return "timeout"
    if result == "timeout":
        raise FastCycleImportError(f"{context}: timeout result lacks timed_out=1")
    if exit_code != process_returncode:
        raise FastCycleImportError(
            f"{context}: non-timeout exit codes must agree"
        )
    if error_kind or exit_code != 0:
        return "error"
    if result == "invalid-output":
        raise FastCycleImportError(
            f"{context}: invalid-output must carry an execution error"
        )
    if result in DECISIVE_RESULTS:
        if expected in DECISIVE_RESULTS:
            return "solved" if result == expected else "wrong-answer"
        return "unknown"
    if result == "unknown":
        return "unknown"
    raise FastCycleImportError(f"{context}: cannot classify result {result!r}")


def _read_csv(
    path: Path,
    payload: bytes,
    *,
    candidate_command: Sequence[str],
    baseline_command: Sequence[str],
    repeats: int,
    timeout_s: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FastCycleImportError(f"CSV {path} is not valid UTF-8") from error
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        if tuple(reader.fieldnames or ()) != CSV_FIELDS:
            raise FastCycleImportError(
                f"CSV {path} has unexpected columns {reader.fieldnames!r}"
            )
        raw_rows = list(reader)
    except csv.Error as error:
        raise FastCycleImportError(f"CSV {path} is malformed: {error}") from error
    if not raw_rows:
        raise FastCycleImportError(f"CSV {path} contains no measurements")

    rows: list[dict[str, Any]] = []
    for line_index, raw in enumerate(raw_rows, start=2):
        context = f"{path}:{line_index}"
        if None in raw or set(raw) != set(CSV_FIELDS):
            raise FastCycleImportError(f"{context} has a malformed column count")
        if any(value is None for value in raw.values()):
            raise FastCycleImportError(f"{context} has a missing column")
        label = raw["label"]
        if label not in {"candidate", "baseline"}:
            raise FastCycleImportError(f"{context}.label must be candidate or baseline")
        expected = raw["expected_status"]
        if expected not in EXPECTED_RESULTS:
            raise FastCycleImportError(f"{context}.expected_status is invalid")
        result = raw["result"]
        if result not in MEASURED_RESULTS:
            raise FastCycleImportError(f"{context}.result is invalid")
        timed_out_raw = raw["timed_out"]
        if timed_out_raw not in {"0", "1"}:
            raise FastCycleImportError(f"{context}.timed_out must be 0 or 1")
        error_kind = raw["error_kind"]
        if error_kind != error_kind.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in error_kind
        ):
            raise FastCycleImportError(f"{context}.error_kind is malformed")
        relative_path = _validate_relative_path(
            raw["relative_path"], f"{context}.relative_path"
        )
        parsed = {
            "sequence": _parse_csv_int(raw["sequence"], f"{context}.sequence", minimum=0),
            "row_index": _parse_csv_int(
                raw["row_index"], f"{context}.row_index", minimum=0
            ),
            "id": raw["id"],
            "relative_path": relative_path,
            "expected_status": expected,
            "label": label,
            "repeat": _parse_csv_int(raw["repeat"], f"{context}.repeat", minimum=0),
            "order_in_repeat": _parse_csv_int(
                raw["order_in_repeat"], f"{context}.order_in_repeat", minimum=0
            ),
            "result": result,
            "time_s": _parse_csv_time(raw["time_s"], f"{context}.time_s"),
            "exit_code": _parse_csv_int(raw["exit_code"], f"{context}.exit_code"),
            "process_returncode": _parse_csv_int(
                raw["process_returncode"], f"{context}.process_returncode"
            ),
            "timed_out": timed_out_raw == "1",
            "error_kind": error_kind,
            "argv": _parse_argv(raw["argv_json"], f"{context}.argv_json"),
        }
        if parsed["repeat"] >= repeats:
            raise FastCycleImportError(f"{context}.repeat exceeds summary repeats")
        if parsed["order_in_repeat"] not in {0, 1}:
            raise FastCycleImportError(f"{context}.order_in_repeat must be 0 or 1")
        template = candidate_command if label == "candidate" else baseline_command
        _validate_expanded_command(
            parsed["argv"], template, relative_path, f"{context}.argv_json"
        )
        parsed["status"] = _classify_row(parsed, context)
        rows.append(parsed)

    sequences = [row["sequence"] for row in rows]
    if sequences != list(range(len(rows))):
        raise FastCycleImportError(f"CSV {path} sequences must be contiguous and ordered")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["relative_path"]].append(row)
    row_indices = sorted({row["row_index"] for row in rows})
    if row_indices != list(range(len(grouped))):
        raise FastCycleImportError(f"CSV {path} row_index values must be contiguous")

    instances: list[dict[str, Any]] = []
    for relative_path, observations in sorted(grouped.items()):
        identities = {
            (row["row_index"], row["id"], row["expected_status"])
            for row in observations
        }
        if len(identities) != 1:
            raise FastCycleImportError(
                f"CSV {path}: mismatched instance metadata for {relative_path!r}"
            )
        by_pair: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for row in observations:
            by_pair[(row["label"], row["repeat"])].append(row)
        expected_pairs = {
            (label, repeat)
            for label in ("candidate", "baseline")
            for repeat in range(repeats)
        }
        if set(by_pair) != expected_pairs or any(len(items) != 1 for items in by_pair.values()):
            raise FastCycleImportError(
                f"CSV {path}: candidate/baseline instances do not match for "
                f"{relative_path!r}"
            )
        for repeat in range(repeats):
            pair = sorted(
                (by_pair[("candidate", repeat)][0], by_pair[("baseline", repeat)][0]),
                key=lambda row: row["sequence"],
            )
            if [row["order_in_repeat"] for row in pair] != [0, 1]:
                raise FastCycleImportError(
                    f"CSV {path}: invalid paired order for {relative_path!r} repeat {repeat}"
                )
            if pair[1]["sequence"] != pair[0]["sequence"] + 1:
                raise FastCycleImportError(
                    f"CSV {path}: non-contiguous pair for {relative_path!r} repeat {repeat}"
                )

        results: dict[str, dict[str, Any]] = {}
        for label in ("candidate", "baseline"):
            label_rows = [by_pair[(label, repeat)][0] for repeat in range(repeats)]
            statuses = [row["status"] for row in label_rows]
            if all(status == "solved" for status in statuses):
                status = "solved"
                time_s: float | None = statistics.median(
                    row["time_s"] for row in label_rows
                )
            else:
                precedence = ("wrong-answer", "error", "timeout", "unknown")
                status = next(item for item in precedence if item in statuses)
                time_s = None
            results[label] = {"status": status, "time_s": time_s}
        row_index, identifier, expected = next(iter(identities))
        instances.append(
            {
                "id": relative_path,
                "row_index": row_index,
                "source_id": identifier,
                "expected_status": expected,
                "results": results,
                "rows": observations,
            }
        )
    return rows, instances


def _validate_summary(
    summary: Mapping[str, Any],
    *,
    path: Path,
    csv_path: Path,
    csv_payload: bytes,
    comparator: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], str, str]:
    required = {
        "artifacts",
        "baseline",
        "baseline_correct",
        "baseline_sha256",
        "candidate",
        "candidate_correct",
        "candidate_sha256",
        "host",
        "instances",
        "measured_runs",
        "paths",
        "repeats",
        "schema_version",
        "status",
        "timeout_s",
        "warmups",
    }
    missing = sorted(required - set(summary))
    if missing:
        raise FastCycleImportError(f"summary {path} is missing keys {missing!r}")
    if summary["schema_version"] != SUMMARY_SCHEMA_VERSION:
        raise FastCycleImportError(f"summary {path} has an unsupported schema version")
    if summary["status"] != "complete":
        raise FastCycleImportError(f"summary {path} is not complete")
    timeout_s = _require_number(summary["timeout_s"], f"summary {path}.timeout_s", positive=True)
    repeats = _require_int(summary["repeats"], f"summary {path}.repeats", minimum=1)
    _require_int(summary["warmups"], f"summary {path}.warmups", minimum=0)
    candidate = _require_command(summary["candidate"], f"summary {path}.candidate")
    baseline = _require_command(summary["baseline"], f"summary {path}.baseline")
    _validate_command_identity(candidate, baseline, comparator, f"summary {path}")

    artifacts = _require_mapping(summary["artifacts"], f"summary {path}.artifacts")
    results_csv = _require_mapping(
        artifacts.get("results_csv"), f"summary {path}.artifacts.results_csv"
    )
    declared_digest = _require_text(
        results_csv.get("sha256"),
        f"summary {path}.artifacts.results_csv.sha256",
        maximum=64,
    )
    if SHA256_PATTERN.fullmatch(declared_digest) is None:
        raise FastCycleImportError(f"summary {path} has an invalid CSV SHA-256")
    actual_digest = _sha256(csv_payload)
    if declared_digest != actual_digest:
        raise FastCycleImportError(f"CSV SHA-256 mismatch for {csv_path}")
    declared_size = _require_int(
        results_csv.get("size_bytes"),
        f"summary {path}.artifacts.results_csv.size_bytes",
        minimum=0,
    )
    if declared_size != len(csv_payload):
        raise FastCycleImportError(f"CSV size mismatch for {csv_path}")
    if tuple(_require_list(
        results_csv.get("fieldnames"),
        f"summary {path}.artifacts.results_csv.fieldnames",
    )) != CSV_FIELDS:
        raise FastCycleImportError(f"summary {path} declares unexpected CSV columns")
    recorded_csv = Path(
        _require_text(
            results_csv.get("resolved_path", results_csv.get("path")),
            f"summary {path}.artifacts.results_csv.resolved_path",
        )
    ).expanduser()
    try:
        if recorded_csv.resolve(strict=True) != csv_path:
            raise FastCycleImportError(f"summary {path} points to a different CSV")
    except OSError as error:
        raise FastCycleImportError(f"summary {path} CSV pointer is invalid: {error}") from error

    rows, instances = _read_csv(
        csv_path,
        csv_payload,
        candidate_command=candidate,
        baseline_command=baseline,
        repeats=repeats,
        timeout_s=timeout_s,
    )
    if _require_int(summary["instances"], f"summary {path}.instances", minimum=1) != len(instances):
        raise FastCycleImportError(f"summary {path} instance count does not match CSV")
    if (
        _require_int(
            summary["measured_runs"],
            f"summary {path}.measured_runs",
            minimum=1,
        )
        != len(rows)
    ):
        raise FastCycleImportError(f"summary {path} measured run count does not match CSV")
    expected_coverage = {
        label: sum(instance["results"][label]["status"] == "solved" for instance in instances)
        for label in ("candidate", "baseline")
    }
    for label in ("candidate", "baseline"):
        declared = _require_int(
            summary[f"{label}_correct"], f"summary {path}.{label}_correct", minimum=0
        )
        if declared != expected_coverage[label]:
            raise FastCycleImportError(f"summary {path} {label} coverage does not match CSV")

    summary_paths = _require_list(summary["paths"], f"summary {path}.paths")
    by_relative_path: dict[str, Mapping[str, Any]] = {}
    for index, value in enumerate(summary_paths):
        item = _require_mapping(value, f"summary {path}.paths[{index}]")
        relative_path = _validate_relative_path(
            item.get("relative_path"), f"summary {path}.paths[{index}].relative_path"
        )
        if relative_path in by_relative_path:
            raise FastCycleImportError(f"summary {path} contains duplicate paths")
        by_relative_path[relative_path] = item
    if set(by_relative_path) != {instance["id"] for instance in instances}:
        raise FastCycleImportError(f"summary {path} and CSV contain mismatched instances")
    for instance in instances:
        item = by_relative_path[instance["id"]]
        if item.get("row_index") != instance["row_index"] or str(
            item.get("id", "")
        ) != instance["source_id"]:
            raise FastCycleImportError(
                f"summary {path} metadata differs for {instance['id']!r}"
            )
        if item.get("expected_status") != instance["expected_status"]:
            raise FastCycleImportError(
                f"summary {path} expected status differs for {instance['id']!r}"
            )
        for label in ("candidate", "baseline"):
            arm = _require_mapping(item.get(label), f"summary {path} {instance['id']}/{label}")
            covered = instance["results"][label]["status"] == "solved"
            if arm.get("covered") is not covered or arm.get("correct") is not covered:
                raise FastCycleImportError(
                    f"summary {path} coverage differs for {instance['id']!r}/{label}"
                )
            times = [row["time_s"] for row in instance["rows"] if row["label"] == label]
            declared_median = _require_number(
                arm.get("median_time_s"),
                f"summary {path} {instance['id']}/{label}.median_time_s",
                positive=True,
            )
            if not math.isclose(
                declared_median, statistics.median(times), rel_tol=1e-7, abs_tol=1e-8
            ):
                raise FastCycleImportError(
                    f"summary {path} median differs for {instance['id']!r}/{label}"
                )

    candidate_digest = _require_text(
        summary["candidate_sha256"], f"summary {path}.candidate_sha256", maximum=64
    )
    baseline_digest = _require_text(
        summary["baseline_sha256"], f"summary {path}.baseline_sha256", maximum=64
    )
    if (
        SHA256_PATTERN.fullmatch(candidate_digest) is None
        or SHA256_PATTERN.fullmatch(baseline_digest) is None
    ):
        raise FastCycleImportError(f"summary {path} has an invalid executable SHA-256")
    return {
        "timeout_s": timeout_s,
        "host": _require_mapping(summary["host"], f"summary {path}.host"),
    }, instances, candidate_digest, baseline_digest


def _host_metadata(host: Mapping[str, Any], context: str) -> dict[str, str]:
    hostname = _require_text(host.get("hostname"), f"{context}.hostname", maximum=128)
    system = _require_text(host.get("system"), f"{context}.system", maximum=64)
    machine = _require_text(host.get("machine"), f"{context}.machine", maximum=64)
    identifier = _slug(f"{hostname}-{system}-{machine}", context)
    return {"id": identifier, "label": f"{hostname} ({system} {machine})"}


def _family_metadata(stage: str, instance_ids: Sequence[str]) -> dict[str, str]:
    known = KNOWN_STAGE_FAMILIES.get(stage)
    if known is not None:
        return {"id": known[0], "label": known[1]}
    components: set[str] = set()
    for identifier in instance_ids:
        parts = PurePosixPath(identifier).parts
        try:
            qf_uf_index = parts.index("QF_UF")
        except ValueError:
            continue
        if qf_uf_index + 1 < len(parts):
            components.add(parts[qf_uf_index + 1])
    if len(components) == 1:
        label = next(iter(components))
        return {"id": _slug(label, "family"), "label": label}
    return {"id": _slug(stage, "stage family"), "label": stage}


def _solver_result(solver_id: str, result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "solver_id": solver_id,
        "status": result["status"],
        "time_s": result["time_s"] if result["status"] == "solved" else None,
    }


def _validate_ledger(
    ledger_path: Path,
    ledger_payload: bytes,
    *,
    options: argparse.Namespace,
) -> tuple[list[dict[str, Any]], datetime, list[tuple[tuple[Any, ...], str, str]]]:
    ledger = _load_json_bytes(ledger_payload, f"ledger {ledger_path}")
    _require_exact_keys(ledger, LEDGER_KEYS, f"ledger {ledger_path}")
    if ledger["schema_version"] != LEDGER_SCHEMA_VERSION:
        raise FastCycleImportError(f"ledger {ledger_path} has an unsupported schema")
    if ledger["status"] != "passed":
        raise FastCycleImportError(f"ledger {ledger_path} is not passed")
    started = _parse_timestamp(ledger["started_at"], f"ledger {ledger_path}.started_at")
    finished = _parse_timestamp(ledger["finished_at"], f"ledger {ledger_path}.finished_at")
    if finished < started:
        raise FastCycleImportError(f"ledger {ledger_path} finishes before it starts")
    _require_text(ledger["campaign_id"], f"ledger {ledger_path}.campaign_id", maximum=128)
    _require_list(ledger["preflight"], f"ledger {ledger_path}.preflight", nonempty=False)
    if ledger["reference_binary"] is not None and type(ledger["reference_binary"]) is not str:
        raise FastCycleImportError(f"ledger {ledger_path}.reference_binary is invalid")
    repository = _require_exact_keys(
        ledger["repository"], REPOSITORY_KEYS, f"ledger {ledger_path}.repository"
    )
    _require_bool(repository["clean"], f"ledger {ledger_path}.repository.clean")
    revision = _require_text(
        repository["revision"], f"ledger {ledger_path}.repository.revision", maximum=64
    )
    if REVISION_PATTERN.fullmatch(revision) is None:
        raise FastCycleImportError(f"ledger {ledger_path} has an invalid revision")
    spec = _require_exact_keys(ledger["spec"], SPEC_KEYS, f"ledger {ledger_path}.spec")
    _require_text(spec["path"], f"ledger {ledger_path}.spec.path")
    spec_digest = _require_text(
        spec["sha256"], f"ledger {ledger_path}.spec.sha256", maximum=64
    )
    if SHA256_PATTERN.fullmatch(spec_digest) is None:
        raise FastCycleImportError(f"ledger {ledger_path} has an invalid spec SHA-256")
    selected_stages = _require_list(
        ledger["selected_stages"], f"ledger {ledger_path}.selected_stages"
    )
    if not all(type(stage) is str and stage for stage in selected_stages):
        raise FastCycleImportError(f"ledger {ledger_path}.selected_stages is invalid")
    selected_comparators = _require_mapping(
        ledger["selected_comparators"], f"ledger {ledger_path}.selected_comparators"
    )
    ledger_digest = _sha256(ledger_payload)
    source_path = _canonical_source_path(ledger_path)

    evidence: list[dict[str, Any]] = []
    binaries: list[tuple[tuple[Any, ...], str, str]] = []
    for run_index, value in enumerate(
        _require_list(ledger["runs"], f"ledger {ledger_path}.runs")
    ):
        context = f"ledger {ledger_path}.runs[{run_index}]"
        run = _require_exact_keys(value, RUN_KEYS, context)
        stage = _require_text(run["stage"], f"{context}.stage", maximum=64)
        comparator = _require_id(run["comparator"], f"{context}.comparator")
        if stage not in selected_stages:
            raise FastCycleImportError(f"{context}.stage was not selected")
        selected_for_stage = _require_list(
            selected_comparators.get(stage),
            f"ledger {ledger_path}.selected_comparators[{stage!r}]",
        )
        if comparator not in selected_for_stage:
            raise FastCycleImportError(f"{context}.comparator was not selected")
        if run["kind"] != "competitor":
            raise FastCycleImportError(f"{context} is not competitor evidence")
        if run["command_returncode"] != 0 or run["passed"] is not True or run["failures"] != []:
            raise FastCycleImportError(f"{context} did not pass its run gate")
        csv_path = _resolve_pointer(run["csv"], ledger_path.parent, f"{context}.csv")
        summary_path = _resolve_pointer(
            run["summary"], ledger_path.parent, f"{context}.summary"
        )
        _, csv_payload = _read_file(csv_path, f"{context}.csv")
        _, summary_payload = _read_file(summary_path, f"{context}.summary")
        summary = _load_json_bytes(summary_payload, f"summary {summary_path}")
        summary_meta, instances, candidate_digest, baseline_digest = _validate_summary(
            summary,
            path=summary_path,
            csv_path=csv_path,
            csv_payload=csv_payload,
            comparator=comparator,
        )
        host = _host_metadata(summary_meta["host"], f"summary {summary_path}.host")
        family = _family_metadata(stage, [instance["id"] for instance in instances])
        evidence_id = _slug(
            f"fast-cycle-{stage}-{comparator}-{ledger_digest[:16]}", "evidence"
        )
        solver_ids = sorted((options.viper_solver_id, comparator))
        evidence_instances = []
        for instance in instances:
            evidence_instances.append(
                {
                    "id": instance["id"],
                    "results": sorted(
                        (
                            _solver_result(
                                options.viper_solver_id,
                                instance["results"]["candidate"],
                            ),
                            _solver_result(
                                comparator, instance["results"]["baseline"]
                            ),
                        ),
                        key=lambda item: item["solver_id"],
                    ),
                }
            )
        sorted_instances = sorted(evidence_instances, key=lambda item: item["id"])
        status_panels = [("all", sorted_instances)]
        if options.include_status_panels:
            expected_by_id = {
                instance["id"]: instance["expected_status"] for instance in instances
            }
            status_panels.extend(
                (expected_status, selected)
                for expected_status in ("sat", "unsat")
                if (
                    selected := [
                        instance
                        for instance in sorted_instances
                        if expected_by_id[instance["id"]] == expected_status
                    ]
                )
            )
        for expected_status, status_instances in status_panels:
            evidence.append(
                {
                    "id": _slug(
                        f"{evidence_id}-{expected_status}", "evidence"
                    ),
                    "scope": "targeted",
                    "evidence_class": options.evidence_class,
                    "evidence_status": options.evidence_status,
                    "revision": revision,
                    "solver_ids": solver_ids,
                    "host": host,
                    "corpus": {
                        "id": options.corpus_id,
                        "label": options.corpus_label,
                    },
                    "timeout_s": summary_meta["timeout_s"],
                    "family": family,
                    "expected_status": expected_status,
                    "source": {"path": source_path, "sha256": ledger_digest},
                    "instances": status_instances,
                }
            )
        binary_boundary = (revision, host["id"], options.viper_solver_id)
        binaries.append((binary_boundary, candidate_digest, f"{context} candidate"))
        binaries.append(
            (
                (revision, host["id"], comparator),
                baseline_digest,
                f"{context} baseline",
            )
        )
    return evidence, finished, binaries


def _validate_options(options: argparse.Namespace) -> None:
    options.registry_id = _require_id(options.registry_id, "--registry-id")
    options.title = _require_text(options.title, "--title", maximum=240)
    options.viper_solver_id = _require_id(
        options.viper_solver_id, "--viper-solver-id"
    )
    options.viper_label = _require_text(options.viper_label, "--viper-label", maximum=240)
    options.corpus_id = _require_id(options.corpus_id, "--corpus-id")
    options.corpus_label = _require_text(
        options.corpus_label, "--corpus-label", maximum=240
    )
    options.evidence_class = _require_id(
        options.evidence_class, "--evidence-class"
    )
    if options.evidence_status not in EVIDENCE_STATUSES:
        raise FastCycleImportError(
            f"--evidence-status must be one of {sorted(EVIDENCE_STATUSES)!r}"
        )
    if type(options.include_status_panels) is not bool:
        raise FastCycleImportError("include_status_panels must be boolean")
    if (options.combined_family_id is None) != (options.combined_family_label is None):
        raise FastCycleImportError(
            "--combined-family-id and --combined-family-label must be supplied together"
        )
    if options.combined_family_id is not None:
        options.combined_family_id = _require_id(
            options.combined_family_id, "--combined-family-id"
        )
        options.combined_family_label = _require_text(
            options.combined_family_label,
            "--combined-family-label",
            maximum=240,
        )


def build_registry(
    ledger_paths: Sequence[Path], options: argparse.Namespace
) -> dict[str, Any]:
    """Validate ledgers and return a deterministic dashboard evidence registry."""

    _validate_options(options)
    if not ledger_paths:
        raise FastCycleImportError("at least one ledger is required")
    loaded_paths: set[Path] = set()
    evidence: list[dict[str, Any]] = []
    finished_times: list[datetime] = []
    binary_digests: dict[tuple[Any, ...], tuple[str, str]] = {}
    for supplied_path in ledger_paths:
        ledger_path, ledger_payload = _read_file(supplied_path, "ledger")
        if ledger_path in loaded_paths:
            raise FastCycleImportError(f"duplicate evidence ledger {ledger_path}")
        loaded_paths.add(ledger_path)
        records, finished, binaries = _validate_ledger(
            ledger_path, ledger_payload, options=options
        )
        evidence.extend(records)
        finished_times.append(finished)
        for boundary, digest, context in binaries:
            previous = binary_digests.get(boundary)
            if previous is not None and previous[0] != digest:
                raise FastCycleImportError(
                    f"binary identity mismatch between {previous[1]} and {context}"
                )
            binary_digests[boundary] = (digest, context)

    if options.combined_family_id is not None:
        groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
        for item in evidence:
            groups[
                (
                    item["scope"],
                    item["corpus"]["id"],
                    item["timeout_s"],
                    tuple(item["solver_ids"]),
                    item["expected_status"],
                    item["evidence_status"],
                    item["revision"],
                    item["host"]["id"],
                    item["evidence_class"],
                )
            ].append(item)
        combined_records: list[dict[str, Any]] = []
        for records in groups.values():
            if len({record["family"]["id"] for record in records}) < 2:
                continue
            for record in records:
                combined = dict(record)
                combined["id"] = _slug(
                    f"{record['id']}-{options.combined_family_id}",
                    "combined evidence",
                )
                combined["family"] = {
                    "id": options.combined_family_id,
                    "label": options.combined_family_label,
                }
                combined_records.append(combined)
        evidence.extend(combined_records)

    evidence_ids = [item["id"] for item in evidence]
    duplicates = sorted(
        identifier for identifier, count in Counter(evidence_ids).items() if count > 1
    )
    if duplicates:
        raise FastCycleImportError(f"duplicate evidence IDs {duplicates!r}")

    panel_instances: dict[tuple[Any, ...], set[str]] = {}
    for item in evidence:
        panel_key = (
            item["scope"],
            item["corpus"]["id"],
            item["timeout_s"],
            item["family"]["id"],
            item["expected_status"],
            tuple(item["solver_ids"]),
            item["evidence_status"],
            item["revision"],
            item["host"]["id"],
            item["evidence_class"],
        )
        identifiers = {instance["id"] for instance in item["instances"]}
        overlap = panel_instances.setdefault(panel_key, set()) & identifiers
        if overlap:
            raise FastCycleImportError(
                "duplicate evidence observations for " f"{sorted(overlap)!r}"
            )
        panel_instances[panel_key].update(identifiers)

    if options.updated_at is None:
        updated_at = _format_timestamp(max(finished_times))
    else:
        updated_at = _format_timestamp(
            _parse_timestamp(options.updated_at, "--updated-at")
        )
    comparator_ids = sorted(
        {solver_id for item in evidence for solver_id in item["solver_ids"]}
        - {options.viper_solver_id}
    )
    solvers = [{"id": options.viper_solver_id, "label": options.viper_label}]
    for comparator in comparator_ids:
        metadata = COMPARATORS.get(comparator)
        if metadata is None:
            raise FastCycleImportError(f"unsupported comparator ID {comparator!r}")
        solvers.append({"id": comparator, "label": metadata["label"]})
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "registry_id": options.registry_id,
        "title": options.title,
        "updated_at": updated_at,
        "viper_solver_id": options.viper_solver_id,
        "solvers": solvers,
        "evidence": sorted(evidence, key=lambda item: item["id"]),
    }


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledgers", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--registry-id", default="euf-viper-fast-cycle-targeted")
    parser.add_argument("--title", default="EUF Viper targeted fast-cycle evidence")
    parser.add_argument("--updated-at")
    parser.add_argument("--viper-solver-id", default="euf-viper")
    parser.add_argument("--viper-label", default="EUF Viper")
    parser.add_argument("--corpus-id", default="smtlib-2025-qf-uf-targeted")
    parser.add_argument("--corpus-label", default="SMT-LIB 2025 QF_UF targeted")
    parser.add_argument("--evidence-class", default="local-one-repeat-discovery")
    parser.add_argument("--evidence-status", default="provisional")
    parser.add_argument("--include-status-panels", action="store_true")
    parser.add_argument("--combined-family-id")
    parser.add_argument("--combined-family-label")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    options = parser.parse_args(argv)
    try:
        registry = build_registry(options.ledgers, options)
        atomic_write(options.output, _json_bytes(registry))
    except (FastCycleImportError, OSError) as error:
        print(f"fast-cycle dashboard import error: {error}", file=sys.stderr)
        return 2
    print(options.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
