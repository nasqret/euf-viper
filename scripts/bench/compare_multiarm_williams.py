#!/usr/bin/env python3
"""Run a strict multi-arm command benchmark in complete Williams blocks.

Arms are declared in order with ``--arm``. Each argv token is then supplied
with a separate ``--arm-arg`` option, and each optional environment override
with ``--arm-env``. Commands are executed directly, never through a shell, and
each template must contain exactly one literal ``{input}`` placeholder.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import compare_commands_abba as ABBA  # noqa: E402
import williams_design as WILLIAMS  # noqa: E402


SCHEMA_VERSION = 1
MIN_COMMAND_ARMS = 2
MAX_COMMAND_ARMS = 10
MIN_ARMS = MIN_COMMAND_ARMS
MAX_ARMS = MAX_COMMAND_ARMS
SUPPORTED_SCHEDULE_SCHEMA_VERSION = 1
SUPPORTED_SCHEDULE_DESIGN = "williams_first_order_carryover"
TIMING_SCOPE = "parser_inclusive_subprocess_wall_clock"
OBSERVED_RESULTS = frozenset(
    {*ABBA.VALID_RESULTS, "error", "invalid-output", "timeout"}
)

BenchmarkInputError = ABBA.BenchmarkInputError
VALID_RESULTS = ABBA.VALID_RESULTS
DECISIVE_RESULTS = ABBA.DECISIVE_RESULTS
INPUT_PLACEHOLDER = ABBA.INPUT_PLACEHOLDER
run_argv = ABBA.run_argv
run_command = ABBA.run_command
sha256_file = ABBA.sha256_file
atomic_write_json = ABBA.atomic_write_json

FIELDNAMES = [
    "sequence",
    "row_index",
    "id",
    "relative_path",
    "source_sha256",
    "source_size_bytes",
    "expected_status",
    "schedule_schema_version",
    "schedule_design",
    "schedule_sha256",
    "repeat",
    "schedule_row",
    "complete_block",
    "row_in_block",
    "order_in_repeat",
    "arm_position",
    "label",
    "arm",
    "schedule_order_json",
    "timing_scope",
    "parser_inclusive",
    "result",
    "time_s",
    "exit_code",
    "process_returncode",
    "timed_out",
    "error_kind",
    "error_detail",
    "stdout",
    "stderr",
    "argv_json",
]


def canonical_json_sha256(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise BenchmarkInputError(
            "schedule payload is not canonical ASCII JSON"
        ) from error
    return hashlib.sha256(encoded).hexdigest()


def _positive_integer(value: Any, context: str) -> int:
    if type(value) is not int or value < 1:
        raise BenchmarkInputError(f"{context} must be a positive integer")
    return value


def _validate_arm_names(names: Sequence[str]) -> list[str]:
    if isinstance(names, (str, bytes, Mapping)):
        raise BenchmarkInputError("arms must be an ordered collection")
    try:
        normalized = list(names)
    except TypeError as error:
        raise BenchmarkInputError("arms must be an ordered collection") from error
    if not MIN_COMMAND_ARMS <= len(normalized) <= MAX_COMMAND_ARMS:
        raise BenchmarkInputError(
            f"command arm count must be between {MIN_COMMAND_ARMS} and "
            f"{MAX_COMMAND_ARMS}; got {len(normalized)}"
        )
    for index, name in enumerate(normalized):
        if type(name) is not str or not name or not name.strip():
            raise BenchmarkInputError(
                f"arm name at index {index} must be a non-empty string"
            )
        if name != name.strip():
            raise BenchmarkInputError(
                f"arm name at index {index} cannot have surrounding whitespace"
            )
        if "\x00" in name:
            raise BenchmarkInputError(f"arm name at index {index} contains NUL")
    try:
        WILLIAMS.validate_arms(normalized)
    except WILLIAMS.DesignError as error:
        raise BenchmarkInputError(str(error)) from error
    return normalized


def _environment_overrides(values: Sequence[str], arm: str) -> dict[str, str]:
    if isinstance(values, (str, bytes, Mapping)):
        raise BenchmarkInputError(f"{arm} environment entries must be ordered")
    try:
        entries = list(values)
    except TypeError as error:
        raise BenchmarkInputError(
            f"{arm} environment entries must be ordered"
        ) from error
    overrides: dict[str, str] = {}
    for value in entries:
        if type(value) is not str or "=" not in value:
            raise BenchmarkInputError(
                f"{arm} environment entry must have the form KEY=VALUE: {value!r}"
            )
        key, setting = value.split("=", 1)
        if not key or "\x00" in key or "=" in key:
            raise BenchmarkInputError(f"invalid environment key for {arm}: {key!r}")
        if "\x00" in setting:
            raise BenchmarkInputError(
                f"environment value for {arm}/{key!r} contains NUL"
            )
        if key in overrides:
            raise BenchmarkInputError(
                f"duplicate environment key for {arm}: {key!r}"
            )
        overrides[key] = setting
    return overrides


def prepare_arms(
    specifications: Sequence[Mapping[str, Any]],
    *,
    base_environment: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Validate ordered CLI arm specifications and build execution envs."""

    if isinstance(specifications, (str, bytes, Mapping)):
        raise BenchmarkInputError("arm specifications must be an ordered collection")
    try:
        raw_specs = list(specifications)
    except TypeError as error:
        raise BenchmarkInputError(
            "arm specifications must be an ordered collection"
        ) from error
    names: list[str] = []
    for index, specification in enumerate(raw_specs):
        if type(specification) is not dict:
            raise BenchmarkInputError(f"arm specification {index} must be an object")
        unknown = set(specification) - {"name", "argv", "env"}
        if unknown:
            raise BenchmarkInputError(
                f"arm specification {index} has unknown keys: {sorted(unknown)}"
            )
        if "name" not in specification or "argv" not in specification:
            raise BenchmarkInputError(
                f"arm specification {index} requires name and argv"
            )
        names.append(specification["name"])
    names = _validate_arm_names(names)

    base = dict(os.environ if base_environment is None else base_environment)
    prepared: list[dict[str, Any]] = []
    for index, (name, specification) in enumerate(zip(names, raw_specs)):
        argv = specification["argv"]
        if isinstance(argv, (str, bytes, Mapping)):
            raise BenchmarkInputError(f"{name} argv must be an ordered token list")
        try:
            template = ABBA.validate_command_template(list(argv), name)
        except TypeError as error:
            raise BenchmarkInputError(
                f"{name} argv must be an ordered token list"
            ) from error
        raw_environment = specification.get("env", [])
        overrides = _environment_overrides(raw_environment, name)
        environment = ABBA.parse_environment(
            [f"{key}={value}" for key, value in overrides.items()],
            base=base,
        )
        prepared.append(
            {
                "index": index,
                "name": name,
                "argv": template,
                "env_entries": [
                    f"{key}={value}" for key, value in overrides.items()
                ],
                "env_overrides": overrides,
                "environment": environment,
            }
        )
    return prepared


def read_hashed_manifest(
    path: Path,
    limit: int | None = None,
    *,
    working_directory: Path | None = None,
) -> list[dict[str, Any]]:
    """Read a JSONL manifest and require a verified hash for every source."""

    if limit is not None:
        _positive_integer(limit, "limit")
    rows = ABBA.read_manifest(
        path,
        None,
        working_directory=working_directory,
    )
    for row in rows:
        line_number = row["_manifest_line"]
        if "sha256" not in row:
            raise BenchmarkInputError(
                f"manifest line {line_number} must declare source sha256"
            )
        if str(row["sha256"]).lower() != row["_file"]["sha256"]:
            raise BenchmarkInputError(
                f"manifest line {line_number} SHA-256 mismatch"
            )
    return rows if limit is None else rows[:limit]


def read_manifest(
    path: Path,
    limit: int | None = None,
    *,
    working_directory: Path | None = None,
) -> list[dict[str, Any]]:
    """Compatibility name for the runner's mandatory-hash manifest loader."""

    return read_hashed_manifest(
        path,
        limit,
        working_directory=working_directory,
    )


def _validate_schedule_payload(
    payload: Mapping[str, Any],
    arms: Sequence[str],
    repeats: int,
) -> None:
    if type(payload) is not dict:
        raise BenchmarkInputError("Williams schedule payload must be an object")
    required = {
        "arm_count",
        "arms",
        "balance",
        "complete_block_rows",
        "complete_blocks",
        "complete_design",
        "declared_balance_preserved",
        "design",
        "prefix_rows",
        "repeats",
        "rows",
        "schema_version",
        "status",
    }
    missing = required - payload.keys()
    if missing:
        raise BenchmarkInputError(
            f"Williams schedule is missing keys: {sorted(missing)}"
        )
    if type(payload["schema_version"]) is not int or (
        payload["schema_version"] != SUPPORTED_SCHEDULE_SCHEMA_VERSION
    ):
        raise BenchmarkInputError(
            "unsupported Williams schedule schema_version: "
            f"{payload['schema_version']!r}"
        )
    if payload["design"] != SUPPORTED_SCHEDULE_DESIGN:
        raise BenchmarkInputError(
            f"unsupported Williams schedule design: {payload['design']!r}"
        )
    expected_arms = list(arms)
    if payload["arms"] != expected_arms:
        raise BenchmarkInputError("Williams schedule arms do not match command arms")
    if type(payload["arm_count"]) is not int or payload["arm_count"] != len(arms):
        raise BenchmarkInputError("Williams schedule arm_count is inconsistent")
    if type(payload["repeats"]) is not int or payload["repeats"] != repeats:
        raise BenchmarkInputError("Williams schedule repeat count is inconsistent")

    expected_block_rows = WILLIAMS.complete_block_rows(len(arms))
    if (
        type(payload["complete_block_rows"]) is not int
        or payload["complete_block_rows"] != expected_block_rows
    ):
        raise BenchmarkInputError("Williams schedule complete_block_rows is inconsistent")
    if repeats % expected_block_rows:
        raise BenchmarkInputError(
            f"repeats must be a positive multiple of {expected_block_rows} "
            "to preserve complete Williams blocks"
        )
    if (
        type(payload["complete_blocks"]) is not int
        or payload["complete_blocks"] != repeats // expected_block_rows
    ):
        raise BenchmarkInputError("Williams schedule complete_blocks is inconsistent")
    if type(payload["prefix_rows"]) is not int or payload["prefix_rows"] != 0:
        raise BenchmarkInputError("Williams schedule contains an incomplete prefix")
    if payload["complete_design"] is not True:
        raise BenchmarkInputError("Williams schedule is not a complete design")
    if payload["declared_balance_preserved"] is not True:
        raise BenchmarkInputError("Williams schedule does not preserve declared balance")
    if payload["status"] != "balanced":
        raise BenchmarkInputError("Williams schedule status must be balanced")

    schedule_rows = payload["rows"]
    if type(schedule_rows) is not list or len(schedule_rows) != repeats:
        raise BenchmarkInputError("Williams schedule rows are inconsistent")
    orders: list[list[str]] = []
    for row_index, record in enumerate(schedule_rows):
        if type(record) is not dict:
            raise BenchmarkInputError(
                f"Williams schedule row {row_index} must be an object"
            )
        if not {"order", "repeat"} <= set(record):
            raise BenchmarkInputError(
                f"Williams schedule row {row_index} requires order and repeat"
            )
        if type(record["repeat"]) is not int or record["repeat"] != row_index:
            raise BenchmarkInputError(
                f"Williams schedule row {row_index} has an invalid repeat binding"
            )
        if type(record["order"]) is not list:
            raise BenchmarkInputError(
                f"Williams schedule row {row_index} order must be a list"
            )
        orders.append(list(record["order"]))
    try:
        report = WILLIAMS.validate_schedule(arms, orders, require_balance=True)
    except WILLIAMS.DesignError as error:
        raise BenchmarkInputError(f"invalid Williams schedule: {error}") from error
    if payload["balance"] != report:
        raise BenchmarkInputError("Williams schedule balance report is inconsistent")


def build_schedule(
    arms: Sequence[str],
    repeats: int | None = None,
    *,
    blocks: int | None = None,
) -> dict[str, Any]:
    """Build and validate the supported, complete Williams schedule version."""

    arm_names = _validate_arm_names(arms)
    if repeats is not None and blocks is not None:
        raise BenchmarkInputError("repeats and blocks are mutually exclusive")
    block_rows = WILLIAMS.complete_block_rows(len(arm_names))
    if blocks is not None:
        repeats = _positive_integer(blocks, "blocks") * block_rows
    elif repeats is None:
        repeats = block_rows
    else:
        repeats = _positive_integer(repeats, "repeats")
    try:
        payload = WILLIAMS.build_design(arm_names, repeats)
    except WILLIAMS.DesignError as error:
        raise BenchmarkInputError(str(error)) from error
    _validate_schedule_payload(payload, arm_names, repeats)
    return payload


def _regular_file_metadata(path: Path, context: str) -> dict[str, Any]:
    try:
        return ABBA._regular_file_metadata(path)
    except (OSError, BenchmarkInputError) as error:
        raise BenchmarkInputError(f"{context} is not a readable regular file: {path}") from error


def _verify_file_metadata(record: Mapping[str, Any], context: str) -> None:
    try:
        path = Path(str(record["resolved_path"]))
        resolved = path.resolve(strict=True)
        size_bytes = resolved.stat().st_size
        digest = sha256_file(resolved)
    except (KeyError, OSError) as error:
        raise BenchmarkInputError(f"{context} disappeared during the benchmark") from error
    if not resolved.is_file():
        raise BenchmarkInputError(f"{context} is no longer a regular file")
    if str(resolved) != str(record["resolved_path"]):
        raise BenchmarkInputError(f"{context} resolved path changed during the benchmark")
    if size_bytes != record.get("size_bytes") or digest != record.get("sha256"):
        raise BenchmarkInputError(f"{context} changed during the benchmark")


def verify_source_integrity(rows: Sequence[Mapping[str, Any]]) -> None:
    for row_index, row in enumerate(rows):
        file_record = row.get("_file")
        if type(file_record) is not dict:
            raise BenchmarkInputError(
                f"manifest row {row_index} lacks validated source metadata"
            )
        _verify_file_metadata(file_record, f"benchmark source row {row_index}")


def verify_command_integrity(
    command_artifacts: Mapping[str, Mapping[str, Any]],
) -> None:
    for arm, artifact in command_artifacts.items():
        executable = artifact.get("executable")
        if type(executable) is not dict:
            raise BenchmarkInputError(f"command metadata for {arm} lacks executable")
        _verify_file_metadata(executable, f"{arm} executable")
        static_files = artifact.get("static_file_arguments")
        if type(static_files) is not list:
            raise BenchmarkInputError(
                f"command metadata for {arm} has invalid static file arguments"
            )
        for index, record in enumerate(static_files):
            if type(record) is not dict:
                raise BenchmarkInputError(
                    f"command metadata for {arm} static file {index} is invalid"
                )
            _verify_file_metadata(record, f"{arm} static file argument {index}")


def _resolved_output(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except OSError as error:
        raise BenchmarkInputError(f"cannot resolve output path: {path}") from error


def validate_output_paths(
    output_csv: Path,
    summary_json: Path,
    *,
    protected_files: Sequence[Mapping[str, Any]],
) -> tuple[Path, Path]:
    destinations = [output_csv.expanduser(), summary_json.expanduser()]
    resolved = [_resolved_output(path) for path in destinations]
    if resolved[0] == resolved[1]:
        raise BenchmarkInputError("--out and --summary must be different paths")
    protected = {str(record["resolved_path"]) for record in protected_files}
    for path, identity in zip(destinations, resolved):
        if str(identity) in protected:
            raise BenchmarkInputError("output paths cannot overwrite benchmark inputs or tools")
        if path.is_symlink():
            raise BenchmarkInputError(f"output path cannot be a symbolic link: {path}")
        if path.exists() and not path.is_file():
            raise BenchmarkInputError(f"output path is not a file: {path}")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise BenchmarkInputError(
                f"cannot create output directory: {path.parent}"
            ) from error
        if not path.parent.is_dir():
            raise BenchmarkInputError(f"output parent is not a directory: {path.parent}")
    return destinations[0], destinations[1]


def _sample_record(
    *,
    sequence: int,
    row_index: int,
    row: Mapping[str, Any],
    schedule: Mapping[str, Any],
    schedule_sha256: str,
    schedule_row: int,
    arm_position: int,
    arm: str,
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    block_rows = int(schedule["complete_block_rows"])
    source = row["_file"]
    order = schedule["rows"][schedule_row]["order"]
    return {
        "sequence": sequence,
        "row_index": row_index,
        "id": row.get("id"),
        "relative_path": row["relative_path"],
        "source_sha256": source["sha256"],
        "source_size_bytes": source["size_bytes"],
        "expected_status": row["status"],
        "schedule_schema_version": schedule["schema_version"],
        "schedule_design": schedule["design"],
        "schedule_sha256": schedule_sha256,
        "repeat": schedule_row,
        "schedule_row": schedule_row,
        "complete_block": schedule_row // block_rows,
        "row_in_block": schedule_row % block_rows,
        "order_in_repeat": arm_position,
        "arm_position": arm_position,
        "label": arm,
        "arm": arm,
        "schedule_order": list(order),
        "timing_scope": TIMING_SCOPE,
        "parser_inclusive": True,
        **observation,
    }


def _csv_record(sample: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sequence": sample["sequence"],
        "row_index": sample["row_index"],
        "id": sample.get("id"),
        "relative_path": sample["relative_path"],
        "source_sha256": sample["source_sha256"],
        "source_size_bytes": sample["source_size_bytes"],
        "expected_status": sample["expected_status"],
        "schedule_schema_version": sample["schedule_schema_version"],
        "schedule_design": sample["schedule_design"],
        "schedule_sha256": sample["schedule_sha256"],
        "repeat": sample["repeat"],
        "schedule_row": sample["schedule_row"],
        "complete_block": sample["complete_block"],
        "row_in_block": sample["row_in_block"],
        "order_in_repeat": sample["order_in_repeat"],
        "arm_position": sample["arm_position"],
        "label": sample["label"],
        "arm": sample["arm"],
        "schedule_order_json": json.dumps(
            sample["schedule_order"], ensure_ascii=True, separators=(",", ":")
        ),
        "timing_scope": sample["timing_scope"],
        "parser_inclusive": int(bool(sample["parser_inclusive"])),
        "result": sample["result"],
        "time_s": f"{float(sample['time_s']):.9f}",
        "exit_code": sample["exit_code"],
        "process_returncode": sample["process_returncode"],
        "timed_out": int(bool(sample["timed_out"])),
        "error_kind": sample.get("error_kind") or "",
        "error_detail": sample.get("error_detail") or "",
        "stdout": str(sample.get("stdout", ""))[: ABBA.STDOUT_LIMIT],
        "stderr": str(sample.get("stderr", ""))[: ABBA.STDERR_LIMIT],
        "argv_json": json.dumps(
            sample["argv"], ensure_ascii=True, separators=(",", ":")
        ),
    }


def _atomic_csv(
    path: Path,
    rows: Sequence[Mapping[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
            writer.writeheader()
            for row in rows:
                writer.writerow(_csv_record(row))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def execute(
    *,
    rows: Sequence[Mapping[str, Any]],
    schedule: Mapping[str, Any],
    templates: Mapping[str, Sequence[str]],
    environments: Mapping[str, Mapping[str, str]],
    timeout_s: float,
    output_csv: Path,
    integrity_check: Callable[[], None] | None = None,
) -> list[dict[str, Any]]:
    """Execute all parser-inclusive raw runs and atomically publish their CSV."""

    ABBA.validate_timeout(timeout_s)
    if type(schedule) is not dict:
        raise BenchmarkInputError("Williams schedule payload must be an object")
    arms = list(schedule.get("arms", []))
    repeats = schedule.get("repeats")
    if type(repeats) is not int:
        raise BenchmarkInputError("schedule repeats must be an integer")
    _validate_schedule_payload(schedule, arms, repeats)
    if set(templates) != set(arms):
        raise BenchmarkInputError("command templates do not match schedule arms")
    if set(environments) != set(arms):
        raise BenchmarkInputError("command environments do not match schedule arms")
    if not rows:
        raise BenchmarkInputError("benchmark requires at least one manifest row")

    verify_source_integrity(rows)
    if integrity_check is not None:
        integrity_check()
    schedule_digest = canonical_json_sha256(schedule)
    samples: list[dict[str, Any]] = []
    sequence = 0
    for row_index, row in enumerate(rows):
        source_path = str(row["_file"]["resolved_path"])
        for schedule_row, schedule_record in enumerate(schedule["rows"]):
            for arm_position, arm in enumerate(schedule_record["order"]):
                observation = run_command(
                    templates[arm],
                    source_path,
                    environments[arm],
                    timeout_s,
                )
                samples.append(
                    _sample_record(
                        sequence=sequence,
                        row_index=row_index,
                        row=row,
                        schedule=schedule,
                        schedule_sha256=schedule_digest,
                        schedule_row=schedule_row,
                        arm_position=arm_position,
                        arm=arm,
                        observation=observation,
                    )
                )
                sequence += 1

    verify_source_integrity(rows)
    if integrity_check is not None:
        integrity_check()
    _atomic_csv(output_csv, samples)
    return samples


def _sample_arm(sample: Mapping[str, Any]) -> str:
    arm = sample.get("arm", sample.get("label"))
    if type(arm) is not str:
        raise BenchmarkInputError("sample arm must be a string")
    if "arm" in sample and "label" in sample and sample["arm"] != sample["label"]:
        raise BenchmarkInputError("sample arm and label bindings disagree")
    return arm


def _validate_sample_grid(
    rows: Sequence[Mapping[str, Any]],
    samples: Sequence[Mapping[str, Any]],
    schedule: Mapping[str, Any],
) -> dict[tuple[int, str], list[Mapping[str, Any]]]:
    arms = list(schedule["arms"])
    repeats = int(schedule["repeats"])
    expected_keys = {
        (row_index, repeat, arm)
        for row_index in range(len(rows))
        for repeat in range(repeats)
        for arm in arms
    }
    observed: dict[tuple[int, int, str], Mapping[str, Any]] = {}
    sequences: set[int] = set()
    schedule_digest = canonical_json_sha256(schedule)
    for sample_index, sample in enumerate(samples):
        if type(sample) is not dict:
            raise BenchmarkInputError(f"sample {sample_index} must be an object")
        row_index = sample.get("row_index")
        repeat = sample.get("repeat")
        arm = _sample_arm(sample)
        if type(row_index) is not int or not 0 <= row_index < len(rows):
            raise BenchmarkInputError(f"sample {sample_index} has invalid row_index")
        if type(repeat) is not int or not 0 <= repeat < repeats:
            raise BenchmarkInputError(f"sample {sample_index} has invalid repeat")
        expected_row = rows[row_index]
        if sample.get("relative_path") != expected_row["relative_path"]:
            raise BenchmarkInputError(
                f"sample {sample_index} relative_path is not bound to its manifest row"
            )
        if sample.get("expected_status") != expected_row["status"]:
            raise BenchmarkInputError(
                f"sample {sample_index} expected_status is not bound to its manifest row"
            )
        expected_source = expected_row.get("_file")
        if type(expected_source) is dict:
            if sample.get("source_sha256") != expected_source["sha256"]:
                raise BenchmarkInputError(
                    f"sample {sample_index} source hash is not bound to its manifest row"
                )
            if sample.get("source_size_bytes") != expected_source["size_bytes"]:
                raise BenchmarkInputError(
                    f"sample {sample_index} source size is not bound to its manifest row"
                )
        order = schedule["rows"][repeat]["order"]
        if arm not in order:
            raise BenchmarkInputError(f"sample {sample_index} has an unknown arm")
        expected_position = order.index(arm)
        position = sample.get("arm_position", sample.get("order_in_repeat"))
        if type(position) is not int or position != expected_position:
            raise BenchmarkInputError(
                f"sample {sample_index} arm position is not bound to the schedule"
            )
        if "order_in_repeat" in sample and sample["order_in_repeat"] != position:
            raise BenchmarkInputError(
                f"sample {sample_index} order fields disagree"
            )
        if "schedule_row" in sample and sample["schedule_row"] != repeat:
            raise BenchmarkInputError(
                f"sample {sample_index} schedule row fields disagree"
            )
        if "schedule_order" in sample and sample["schedule_order"] != order:
            raise BenchmarkInputError(
                f"sample {sample_index} schedule order does not match the design"
            )
        if "schedule_sha256" in sample and sample["schedule_sha256"] != schedule_digest:
            raise BenchmarkInputError(
                f"sample {sample_index} schedule hash does not match the design"
            )
        if "schedule_schema_version" in sample and sample[
            "schedule_schema_version"
        ] != schedule["schema_version"]:
            raise BenchmarkInputError(
                f"sample {sample_index} schedule schema does not match the design"
            )
        if "schedule_design" in sample and sample["schedule_design"] != schedule[
            "design"
        ]:
            raise BenchmarkInputError(
                f"sample {sample_index} schedule design does not match the design"
            )
        if "parser_inclusive" in sample and sample["parser_inclusive"] is not True:
            raise BenchmarkInputError(
                f"sample {sample_index} is not marked parser-inclusive"
            )
        if "timing_scope" in sample and sample["timing_scope"] != TIMING_SCOPE:
            raise BenchmarkInputError(
                f"sample {sample_index} has an unsupported timing scope"
            )

        result = sample.get("result")
        if result not in OBSERVED_RESULTS:
            raise BenchmarkInputError(f"sample {sample_index} has invalid result")
        elapsed = sample.get("time_s")
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
            raise BenchmarkInputError(f"sample {sample_index} has invalid elapsed time")
        if not math.isfinite(float(elapsed)) or float(elapsed) < 0:
            raise BenchmarkInputError(f"sample {sample_index} has invalid elapsed time")
        timed_out = sample.get("timed_out", False)
        if type(timed_out) is not bool:
            raise BenchmarkInputError(f"sample {sample_index} has invalid timed_out")
        if timed_out != (result == "timeout"):
            raise BenchmarkInputError(
                f"sample {sample_index} has inconsistent timeout accounting"
            )
        error_kind = sample.get("error_kind")
        if error_kind is not None and type(error_kind) is not str:
            raise BenchmarkInputError(f"sample {sample_index} has invalid error_kind")
        if timed_out and error_kind != "timeout":
            raise BenchmarkInputError(
                f"sample {sample_index} timeout lacks timeout error_kind"
            )
        if result in {"error", "invalid-output"} and not error_kind:
            raise BenchmarkInputError(
                f"sample {sample_index} has an unaccounted execution error"
            )
        exit_code = sample.get("exit_code")
        if exit_code is not None and (
            type(exit_code) is not int
        ):
            raise BenchmarkInputError(f"sample {sample_index} has invalid exit_code")
        if (
            not timed_out
            and exit_code not in (None, 0)
            and not error_kind
        ):
            raise BenchmarkInputError(
                f"sample {sample_index} has an unaccounted nonzero exit"
            )
        if (
            not timed_out
            and result in ABBA.VALID_RESULTS
            and not error_kind
            and exit_code != 0
        ):
            raise BenchmarkInputError(
                f"sample {sample_index} successful result lacks a zero exit"
            )
        if "sequence" in sample:
            sequence = sample["sequence"]
            if type(sequence) is not int or sequence < 0 or sequence in sequences:
                raise BenchmarkInputError(
                    f"sample {sample_index} has invalid or duplicate sequence"
                )
            sequences.add(sequence)

        key = (row_index, repeat, arm)
        if key in observed:
            raise BenchmarkInputError(f"duplicate raw sample for {key!r}")
        observed[key] = sample

    if sequences and (
        len(sequences) != len(samples) or sequences != set(range(len(samples)))
    ):
        raise BenchmarkInputError("raw sample sequences must be exactly 0..N-1")
    observed_keys = set(observed)
    if observed_keys != expected_keys:
        missing = len(expected_keys - observed_keys)
        extra = len(observed_keys - expected_keys)
        raise BenchmarkInputError(
            f"raw sample grid is incomplete or extra: missing={missing}, extra={extra}"
        )
    grouped: dict[tuple[int, str], list[Mapping[str, Any]]] = defaultdict(list)
    for (row_index, repeat, arm), sample in observed.items():
        grouped[(row_index, arm)].append(sample)
    for observations in grouped.values():
        observations.sort(key=lambda sample: int(sample["repeat"]))
    return grouped


def _issue_record(sample: Mapping[str, Any]) -> dict[str, Any]:
    arm = _sample_arm(sample)
    return {
        "sequence": sample.get("sequence"),
        "row_index": sample["row_index"],
        "relative_path": sample["relative_path"],
        "arm": arm,
        "label": arm,
        "repeat": sample["repeat"],
        "order_in_repeat": sample.get(
            "order_in_repeat", sample.get("arm_position")
        ),
        "result": sample["result"],
        "exit_code": sample.get("exit_code"),
        "error_kind": sample.get("error_kind"),
        "stderr": str(sample.get("stderr", ""))[: ABBA.STDERR_LIMIT],
    }


def summarize(
    rows: Sequence[Mapping[str, Any]],
    samples: Sequence[Mapping[str, Any]],
    schedule: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a deterministic multi-arm summary from a complete raw grid."""

    if not rows:
        raise BenchmarkInputError("summary requires at least one manifest row")
    if type(schedule) is not dict:
        raise BenchmarkInputError("Williams schedule payload must be an object")
    arms = list(schedule.get("arms", []))
    repeats = schedule.get("repeats")
    if type(repeats) is not int:
        raise BenchmarkInputError("schedule repeats must be an integer")
    _validate_schedule_payload(schedule, arms, repeats)
    grouped = _validate_sample_grid(rows, samples, schedule)

    arm_totals: dict[str, dict[str, Any]] = {
        arm: {
            "paths": len(rows),
            "runs": len(rows) * repeats,
            "covered_paths": 0,
            "correct_runs": 0,
            "wrong_runs": 0,
            "unexpected_runs": 0,
            "unknown_runs": 0,
            "timeout_runs": 0,
            "error_runs": 0,
            "total_time_s": 0.0,
            "result_counts": Counter(),
        }
        for arm in arms
    }
    paths: list[dict[str, Any]] = []
    wrong_answers: list[dict[str, Any]] = []
    unexpected_results: list[dict[str, Any]] = []
    execution_errors: list[dict[str, Any]] = []
    timeouts: list[dict[str, Any]] = []

    for row_index, row in enumerate(rows):
        expected = str(row["status"])
        if expected not in ABBA.VALID_RESULTS:
            raise BenchmarkInputError(
                f"manifest row {row_index} has invalid expected status"
            )
        path_summary: dict[str, Any] = {
            "row_index": row_index,
            "id": row.get("id"),
            "relative_path": row["relative_path"],
            "expected_status": expected,
            "arms": {},
        }
        for arm in arms:
            observations = grouped[(row_index, arm)]
            times = [float(sample["time_s"]) for sample in observations]
            correct_runs = sum(
                ABBA._is_success(sample) and sample["result"] == expected
                for sample in observations
            )
            wrong_runs = sum(
                sample["result"] in ABBA.DECISIVE_RESULTS
                and expected in ABBA.DECISIVE_RESULTS
                and sample["result"] != expected
                for sample in observations
            )
            unexpected_runs = sum(
                sample["result"] in ABBA.VALID_RESULTS
                and sample["result"] != expected
                for sample in observations
            )
            timeout_runs = sum(bool(sample["timed_out"]) for sample in observations)
            error_runs = sum(ABBA._is_execution_error(sample) for sample in observations)
            counts = Counter(str(sample["result"]) for sample in observations)
            covered = correct_runs == repeats

            totals = arm_totals[arm]
            totals["covered_paths"] += int(covered)
            totals["correct_runs"] += correct_runs
            totals["wrong_runs"] += wrong_runs
            totals["unexpected_runs"] += unexpected_runs
            totals["unknown_runs"] += counts.get("unknown", 0)
            totals["timeout_runs"] += timeout_runs
            totals["error_runs"] += error_runs
            totals["total_time_s"] += math.fsum(times)
            totals["result_counts"].update(counts)

            for sample in observations:
                mismatch = (
                    sample["result"] in ABBA.VALID_RESULTS
                    and sample["result"] != expected
                )
                wrong = (
                    sample["result"] in ABBA.DECISIVE_RESULTS
                    and expected in ABBA.DECISIVE_RESULTS
                    and sample["result"] != expected
                )
                if mismatch:
                    unexpected_results.append(
                        {**_issue_record(sample), "expected": expected}
                    )
                if wrong:
                    wrong_answers.append(
                        {**_issue_record(sample), "expected": expected}
                    )
                if bool(sample["timed_out"]):
                    timeouts.append(_issue_record(sample))
                elif ABBA._is_execution_error(sample):
                    execution_errors.append(_issue_record(sample))

            path_summary["arms"][arm] = {
                "covered": covered,
                "correct": covered,
                "correct_repeats": correct_runs,
                "wrong_repeats": wrong_runs,
                "unexpected_repeats": unexpected_runs,
                "unknown_repeats": counts.get("unknown", 0),
                "timeout_repeats": timeout_runs,
                "error_repeats": error_runs,
                "results": dict(sorted(counts.items())),
                "median_time_s": statistics.median(times),
            }
        paths.append(path_summary)

    common = [
        path
        for path in paths
        if all(path["arms"][arm]["covered"] for arm in arms)
    ]
    reference_arm = arms[0]
    reference_times = [
        float(path["arms"][reference_arm]["median_time_s"]) for path in common
    ]
    reference_total = math.fsum(reference_times)

    arm_summaries: dict[str, dict[str, Any]] = {}
    for arm in arms:
        totals = arm_totals[arm]
        arm_times = [float(path["arms"][arm]["median_time_s"]) for path in common]
        arm_total = math.fsum(arm_times)
        ratios = [
            reference / current
            for reference, current in zip(reference_times, arm_times)
            if reference > 0 and current > 0
        ]
        aggregate_speedup = (
            reference_total / arm_total if common and arm_total > 0 else None
        )
        geometric_speedup = (
            math.exp(math.fsum(math.log(ratio) for ratio in ratios) / len(ratios))
            if common and len(ratios) == len(common)
            else None
        )
        arm_summaries[arm] = {
            **{
                key: value
                for key, value in totals.items()
                if key != "result_counts"
            },
            "coverage": totals["covered_paths"] / len(rows),
            "coverage_delta_vs_reference": (
                totals["covered_paths"]
                - arm_totals[reference_arm]["covered_paths"]
            ),
            "failed_runs": totals["timeout_runs"] + totals["error_runs"],
            "uncovered_runs": totals["runs"] - totals["correct_runs"],
            "result_counts": dict(sorted(totals["result_counts"].items())),
            "common_total_time_s": arm_total,
            "common_aggregate_speedup_vs_reference": aggregate_speedup,
            "common_geometric_speedup_vs_reference": geometric_speedup,
            "wins_vs_reference": sum(
                current < reference
                for reference, current in zip(reference_times, arm_times)
            ),
            "losses_vs_reference": sum(
                reference < current
                for reference, current in zip(reference_times, arm_times)
            ),
            "ties_vs_reference": sum(
                reference == current
                for reference, current in zip(reference_times, arm_times)
            ),
        }

    return {
        "instances": len(rows),
        "arm_count": len(arms),
        "arm_order": arms,
        "reference_arm": reference_arm,
        "repeats": repeats,
        "complete_blocks": schedule["complete_blocks"],
        "measured_runs": len(samples),
        "timing_scope": TIMING_SCOPE,
        "parser_inclusive": True,
        "timing_basis": "per-instance median of complete schedule repeats",
        "speedup_direction": "reference_time / arm_time",
        "arms": arm_summaries,
        "common_correct": len(common),
        "common_correct_paths": [path["relative_path"] for path in common],
        "wrong_answers": wrong_answers,
        "unexpected_results": unexpected_results,
        "execution_errors": execution_errors,
        "timeouts": timeouts,
        "accounting": {
            "wrong_answers": len(wrong_answers),
            "unexpected_results": len(unexpected_results),
            "execution_errors": len(execution_errors),
            "timeouts": len(timeouts),
        },
        "paths": paths,
    }


class _StartArmAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        value: str,
        option_string: str | None = None,
    ) -> None:
        specifications = list(getattr(namespace, self.dest, None) or [])
        specifications.append({"name": value, "argv": [], "env": []})
        setattr(namespace, self.dest, specifications)


class _AppendArmFieldAction(argparse.Action):
    def __init__(self, *args: Any, field: str, **kwargs: Any) -> None:
        self.field = field
        super().__init__(*args, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        value: str,
        option_string: str | None = None,
    ) -> None:
        specifications = list(getattr(namespace, self.dest, None) or [])
        if not specifications:
            parser.error(f"{option_string} must follow an --arm declaration")
        current = dict(specifications[-1])
        current[self.field] = [*current[self.field], value]
        specifications[-1] = current
        setattr(namespace, self.dest, specifications)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--arm",
        dest="arm_specs",
        action=_StartArmAction,
        required=True,
        metavar="NAME",
        help="start one command arm; repeat in stable reference-first order",
    )
    parser.add_argument(
        "--arm-arg",
        "--command-arg",
        "--command-token",
        dest="arm_specs",
        action=_AppendArmFieldAction,
        field="argv",
        metavar="TOKEN",
        help=(
            "append one argv token to the current arm; use --arm-arg=VALUE "
            "for tokens beginning with '-'"
        ),
    )
    parser.add_argument(
        "--arm-env",
        dest="arm_specs",
        action=_AppendArmFieldAction,
        field="env",
        metavar="KEY=VALUE",
        help="append one environment override to the current arm",
    )
    schedule_group = parser.add_mutually_exclusive_group()
    schedule_group.add_argument(
        "--repeats",
        type=int,
        help="complete schedule row count; must be a full-block multiple",
    )
    schedule_group.add_argument(
        "--blocks",
        type=int,
        help="number of complete Williams blocks (default: one)",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out", type=Path, required=True, help="atomic raw-run CSV")
    parser.add_argument(
        "--summary", type=Path, required=True, help="atomic JSON summary"
    )
    return parser


def _protected_records(
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    commands: Mapping[str, Mapping[str, Any]],
    tool_sources: Mapping[str, Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = [manifest]
    records.extend(row["_file"] for row in rows)
    for artifact in commands.values():
        records.append(artifact["executable"])
        records.extend(artifact["static_file_arguments"])
    records.extend(tool_sources.values())
    return records


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        timeout_s = ABBA.validate_timeout(args.timeout)
        if args.limit is not None:
            _positive_integer(args.limit, "--limit")
        prepared = prepare_arms(args.arm_specs)
        arm_names = [arm["name"] for arm in prepared]
        schedule = build_schedule(
            arm_names,
            args.repeats,
            blocks=args.blocks,
        )

        manifest_path = args.manifest.expanduser()
        manifest_artifact = _regular_file_metadata(manifest_path, "manifest")
        rows = read_hashed_manifest(manifest_path, args.limit)
        _verify_file_metadata(manifest_artifact, "manifest")
        verify_source_integrity(rows)

        templates = {arm["name"]: arm["argv"] for arm in prepared}
        environments = {arm["name"]: arm["environment"] for arm in prepared}
        command_artifacts = {
            arm["name"]: ABBA.command_metadata(
                arm["argv"], arm["environment"]
            )
            for arm in prepared
        }
        tool_sources = {
            "runner": _regular_file_metadata(Path(__file__), "runner source"),
            "command_helper": _regular_file_metadata(
                Path(ABBA.__file__), "command helper source"
            ),
            "schedule_generator": _regular_file_metadata(
                Path(WILLIAMS.__file__), "schedule generator source"
            ),
        }
        output_csv, summary_json = validate_output_paths(
            args.out,
            args.summary,
            protected_files=_protected_records(
                manifest_artifact,
                rows,
                command_artifacts,
                tool_sources,
            ),
        )

        def integrity_check() -> None:
            _verify_file_metadata(manifest_artifact, "manifest")
            verify_source_integrity(rows)
            verify_command_integrity(command_artifacts)
            for name, record in tool_sources.items():
                _verify_file_metadata(record, f"{name} source")

        integrity_check()
    except (BenchmarkInputError, WILLIAMS.DesignError, OSError) as error:
        parser.error(str(error))

    started_at = ABBA.utc_now()
    started = time.perf_counter()
    try:
        samples = execute(
            rows=rows,
            schedule=schedule,
            templates=templates,
            environments=environments,
            timeout_s=timeout_s,
            output_csv=output_csv,
            integrity_check=integrity_check,
        )
        summary = summarize(rows, samples, schedule)
        integrity_check()
        results_artifact = _regular_file_metadata(output_csv, "results CSV")
    except (BenchmarkInputError, OSError) as error:
        parser.error(str(error))
    finished_at = ABBA.utc_now()

    schedule_digest = canonical_json_sha256(schedule)
    input_files = [
        {
            "row_index": index,
            "id": row.get("id"),
            "declared_path": row["path"],
            "relative_path": row["relative_path"],
            "expected_status": row["status"],
            **row["_file"],
        }
        for index, row in enumerate(rows)
    ]
    host = ABBA.host_metadata()
    payload = {
        "schema_version": SCHEMA_VERSION,
        "benchmark": "multiarm_williams_command",
        "status": "complete",
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_s": time.perf_counter() - started,
        "manifest": str(manifest_path),
        "manifest_order": [row["relative_path"] for row in rows],
        "manifest_sha256": manifest_artifact["sha256"],
        "expected_results": {
            "allowed": sorted(ABBA.VALID_RESULTS),
            "counts": dict(
                sorted(Counter(str(row["status"]) for row in rows).items())
            ),
        },
        "timeout_s": timeout_s,
        "commands": templates,
        "environment_overrides": {
            arm["name"]: dict(sorted(arm["env_overrides"].items()))
            for arm in prepared
        },
        "runtime_host": host["hostname"],
        "host": host,
        "schedule": schedule,
        "schedule_sha256": schedule_digest,
        "schedule_binding": {
            "schema_version": schedule["schema_version"],
            "design": schedule["design"],
            "arms": arm_names,
            "complete_block_rows": schedule["complete_block_rows"],
            "complete_blocks": schedule["complete_blocks"],
            "sha256": schedule_digest,
            "generator_sha256": tool_sources["schedule_generator"]["sha256"],
        },
        "executable_sha256": {
            arm: command_artifacts[arm]["executable"]["sha256"]
            for arm in arm_names
        },
        "source_sha256": {
            row["relative_path"]: row["_file"]["sha256"] for row in rows
        },
        "artifacts": {
            "manifest": manifest_artifact,
            "input_files": input_files,
            "commands": command_artifacts,
            "tool_sources": tool_sources,
            "results_csv": {
                **results_artifact,
                "fieldnames": FIELDNAMES,
                "stdout_limit": ABBA.STDOUT_LIMIT,
                "stderr_limit": ABBA.STDERR_LIMIT,
                "atomic_write": True,
            },
            "summary_json": {
                "path": str(summary_json),
                "atomic_write": True,
            },
        },
        **summary,
    }
    atomic_write_json(summary_json, payload)

    coverage = ", ".join(
        f"{arm}={summary['arms'][arm]['covered_paths']}/{len(rows)}"
        for arm in arm_names
    )
    print(
        f"coverage {coverage}; common={summary['common_correct']}/{len(rows)}; "
        f"wrong={summary['accounting']['wrong_answers']}; "
        f"errors={summary['accounting']['execution_errors']}; "
        f"timeouts={summary['accounting']['timeouts']}"
    )
    if summary["wrong_answers"]:
        return 2
    if summary["execution_errors"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
