#!/usr/bin/env python3
"""Run a strict paired ABBA benchmark for two argv command templates.

Each command is supplied one token at a time with ``--baseline-arg`` or
``--candidate-arg``. Exactly one literal ``{input}`` placeholder is required
in each template. Command tokens are executed directly; no shell is involved.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


VALID_RESULTS = frozenset({"sat", "unsat", "unknown"})
DECISIVE_RESULTS = frozenset({"sat", "unsat"})
INPUT_PLACEHOLDER = "{input}"
STDOUT_LIMIT = 1_000
STDERR_LIMIT = 4_000
FIELDNAMES = [
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
]


class BenchmarkInputError(ValueError):
    """Raised when benchmark inputs do not satisfy the reproducibility contract."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Write JSON through a same-directory temporary followed by os.replace."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _require_nonempty_string(value: Any, context: str) -> str:
    if type(value) is not str or not value:
        raise BenchmarkInputError(f"{context} must be a non-empty string")
    if "\x00" in value:
        raise BenchmarkInputError(f"{context} cannot contain NUL")
    return value


def _source_metadata(source: Path, declared: Mapping[str, Any], context: str) -> dict:
    try:
        resolved = source.resolve(strict=True)
    except OSError as error:
        raise BenchmarkInputError(f"{context} does not exist: {source}") from error
    if not resolved.is_file():
        raise BenchmarkInputError(f"{context} is not a regular file: {source}")

    size_bytes = resolved.stat().st_size
    digest = sha256_file(resolved)
    if "bytes" in declared:
        declared_size = declared["bytes"]
        if type(declared_size) is not int or declared_size < 0:
            raise BenchmarkInputError(f"{context} bytes must be a non-negative integer")
        if declared_size != size_bytes:
            raise BenchmarkInputError(
                f"{context} size mismatch: manifest has {declared_size}, file has {size_bytes}"
            )
    if "sha256" in declared:
        declared_digest = declared["sha256"]
        if (
            type(declared_digest) is not str
            or len(declared_digest) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in declared_digest)
        ):
            raise BenchmarkInputError(f"{context} sha256 must be 64 hexadecimal characters")
        if declared_digest.lower() != digest:
            raise BenchmarkInputError(f"{context} SHA-256 mismatch")
    return {
        "resolved_path": str(resolved),
        "size_bytes": size_bytes,
        "sha256": digest,
    }


def read_manifest(
    path: Path,
    limit: int | None = None,
    *,
    working_directory: Path | None = None,
) -> list[dict[str, Any]]:
    """Read and fully validate a JSONL manifest without changing its order."""

    if limit is not None and (type(limit) is not int or limit < 1):
        raise BenchmarkInputError("limit must be a positive integer")
    try:
        manifest_path = path.resolve(strict=True)
    except OSError as error:
        raise BenchmarkInputError(f"manifest does not exist: {path}") from error
    if not manifest_path.is_file():
        raise BenchmarkInputError(f"manifest is not a regular file: {path}")
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BenchmarkInputError(f"manifest is not valid UTF-8: {path}") from error
    if not lines:
        raise BenchmarkInputError("manifest is empty")

    base = Path.cwd() if working_directory is None else working_directory
    seen_relative_paths: set[str] = set()
    seen_resolved_paths: set[str] = set()
    seen_ids: set[Any] = set()
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise BenchmarkInputError(f"manifest line {line_number} is blank")
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as error:
            raise BenchmarkInputError(
                f"manifest line {line_number} is not valid JSON: {error.msg}"
            ) from error
        if type(raw) is not dict:
            raise BenchmarkInputError(f"manifest line {line_number} must be an object")
        missing = {"path", "relative_path", "status"} - raw.keys()
        if missing:
            raise BenchmarkInputError(
                f"manifest line {line_number} is missing keys: {sorted(missing)}"
            )

        declared_path = _require_nonempty_string(
            raw["path"], f"manifest line {line_number} path"
        )
        relative_path = _require_nonempty_string(
            raw["relative_path"], f"manifest line {line_number} relative_path"
        )
        status = _require_nonempty_string(
            raw["status"], f"manifest line {line_number} status"
        )
        if status not in VALID_RESULTS:
            raise BenchmarkInputError(
                f"manifest line {line_number} status must be sat, unsat, or unknown"
            )
        if relative_path in seen_relative_paths:
            raise BenchmarkInputError(
                f"manifest contains duplicate path {relative_path!r}"
            )
        seen_relative_paths.add(relative_path)

        source = Path(declared_path).expanduser()
        if not source.is_absolute():
            source = base / source
        file_metadata = _source_metadata(
            source, raw, f"manifest line {line_number} path"
        )
        resolved_path = file_metadata["resolved_path"]
        if resolved_path in seen_resolved_paths:
            raise BenchmarkInputError(
                f"manifest contains duplicate resolved path {resolved_path!r}"
            )
        seen_resolved_paths.add(resolved_path)

        if "id" in raw:
            identifier = raw["id"]
            if type(identifier) not in (str, int) or identifier == "":
                raise BenchmarkInputError(
                    f"manifest line {line_number} id must be a non-empty string or integer"
                )
            if identifier in seen_ids:
                raise BenchmarkInputError(
                    f"manifest contains duplicate id {identifier!r}"
                )
            seen_ids.add(identifier)

        row = dict(raw)
        row["_manifest_line"] = line_number
        row["_file"] = file_metadata
        rows.append(row)

    selected = rows if limit is None else rows[:limit]
    if not selected:
        raise BenchmarkInputError("manifest selection is empty")
    return selected


def validate_command_template(tokens: Sequence[str], label: str) -> list[str]:
    if not tokens:
        raise BenchmarkInputError(f"{label} command template is empty")
    normalized = []
    placeholder_count = 0
    for index, token in enumerate(tokens):
        if type(token) is not str or token == "":
            raise BenchmarkInputError(
                f"{label} command token {index} must be a non-empty string"
            )
        if "\x00" in token:
            raise BenchmarkInputError(f"{label} command token {index} contains NUL")
        placeholder_count += token.count(INPUT_PLACEHOLDER)
        normalized.append(token)
    if placeholder_count != 1:
        raise BenchmarkInputError(
            f"{label} command template must contain exactly one literal "
            f"{INPUT_PLACEHOLDER} placeholder"
        )
    if INPUT_PLACEHOLDER in normalized[0]:
        raise BenchmarkInputError(
            f"{label} executable token cannot contain {INPUT_PLACEHOLDER}"
        )
    return normalized


def expand_command(template: Sequence[str], input_path: str) -> list[str]:
    return [token.replace(INPUT_PLACEHOLDER, input_path) for token in template]


def parse_environment(
    values: Sequence[str], base: Mapping[str, str] | None = None
) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    for value in values:
        if "=" not in value:
            raise BenchmarkInputError(
                f"environment entry must have the form KEY=VALUE: {value!r}"
            )
        key, setting = value.split("=", 1)
        if not key or "\x00" in key or "=" in key:
            raise BenchmarkInputError(f"invalid environment key: {key!r}")
        if "\x00" in setting:
            raise BenchmarkInputError(f"environment value for {key!r} contains NUL")
        environment[key] = setting
    return environment


def _regular_file_metadata(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise BenchmarkInputError(f"not a regular file: {path}")
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        "size_bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def resolve_executable(token: str, environment: Mapping[str, str]) -> Path:
    resolved_name = shutil.which(token, path=environment.get("PATH"))
    if resolved_name is None:
        raise BenchmarkInputError(f"command executable is missing or not executable: {token}")
    path = Path(resolved_name).resolve()
    if not path.is_file():
        raise BenchmarkInputError(f"command executable is not a regular file: {token}")
    return path


def command_metadata(
    template: Sequence[str], environment: Mapping[str, str]
) -> dict[str, Any]:
    executable = resolve_executable(template[0], environment)
    static_files: list[dict[str, Any]] = []
    seen_files: set[str] = {str(executable)}
    for token in template[1:]:
        if INPUT_PLACEHOLDER in token:
            continue
        possible_file = Path(token).expanduser()
        if not possible_file.is_absolute():
            possible_file = Path.cwd() / possible_file
        try:
            resolved = possible_file.resolve(strict=True)
        except OSError:
            continue
        if not resolved.is_file() or str(resolved) in seen_files:
            continue
        seen_files.add(str(resolved))
        static_files.append(_regular_file_metadata(possible_file))
    return {
        "argv_template": list(template),
        "executable": {
            "requested": template[0],
            **_regular_file_metadata(executable),
        },
        "static_file_arguments": static_files,
    }


def host_metadata(
    environment: Mapping[str, str] | None = None,
    *,
    hostname: str | None = None,
) -> dict[str, Any]:
    environment = os.environ if environment is None else environment
    affinity: list[int] | None = None
    if hasattr(os, "sched_getaffinity"):
        try:
            affinity = sorted(os.sched_getaffinity(0))
        except OSError:
            affinity = None
    return {
        "hostname": platform.node() if hostname is None else hostname,
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "cpu_affinity": affinity,
        "git_revision": environment.get("EUF_VIPER_GIT_REVISION"),
        "slurm_job_id": environment.get("SLURM_JOB_ID"),
        "slurm_array_job_id": environment.get("SLURM_ARRAY_JOB_ID"),
        "slurm_array_task_id": environment.get("SLURM_ARRAY_TASK_ID"),
        "slurm_node_list": environment.get("SLURM_JOB_NODELIST"),
    }


def validate_stdout(stdout: str) -> tuple[str | None, str | None]:
    stripped = stdout.strip()
    if stripped in VALID_RESULTS and len(stripped.splitlines()) == 1:
        return stripped, None
    return None, "stdout must contain exactly one result: sat, unsat, or unknown"


def validate_timeout(timeout_s: float) -> float:
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
        raise BenchmarkInputError("timeout must be a finite positive number")
    value = float(timeout_s)
    if not math.isfinite(value) or value <= 0:
        raise BenchmarkInputError("timeout must be a finite positive number")
    return value


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            # start_new_session makes the child PID the process-group ID. Using
            # that ID directly still reaches descendants if the leader exited.
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        try:
            process.kill()
        except ProcessLookupError:
            pass


def _decode(output: bytes | None) -> str:
    return (output or b"").decode("utf-8", errors="replace")


def run_argv(
    argv: Sequence[str],
    environment: Mapping[str, str],
    timeout_s: float,
) -> dict[str, Any]:
    """Execute one argv vector and kill its complete process group on timeout."""

    timeout_s = validate_timeout(timeout_s)
    start = time.perf_counter()
    try:
        process = subprocess.Popen(
            list(argv),
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
        )
    except OSError as error:
        return {
            "argv": list(argv),
            "result": "error",
            "time_s": time.perf_counter() - start,
            "exit_code": 127 if isinstance(error, FileNotFoundError) else 126,
            "process_returncode": None,
            "timed_out": False,
            "error_kind": "launch_error",
            "error_detail": str(error),
            "stdout": "",
            "stderr": str(error),
        }

    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        stdout_bytes, stderr_bytes = process.communicate()
        return {
            "argv": list(argv),
            "result": "timeout",
            "time_s": time.perf_counter() - start,
            "exit_code": 124,
            "process_returncode": process.returncode,
            "timed_out": True,
            "error_kind": "timeout",
            "error_detail": f"exceeded {timeout_s:g} seconds",
            "stdout": _decode(stdout_bytes),
            "stderr": _decode(stderr_bytes),
        }

    stdout = _decode(stdout_bytes)
    stderr = _decode(stderr_bytes)
    result, validation_error = validate_stdout(stdout)
    errors = []
    if process.returncode != 0:
        errors.append("nonzero_exit")
    if validation_error is not None:
        errors.append("invalid_stdout")
    return {
        "argv": list(argv),
        "result": result if result is not None else "invalid-output",
        "time_s": time.perf_counter() - start,
        "exit_code": process.returncode,
        "process_returncode": process.returncode,
        "timed_out": False,
        "error_kind": "+".join(errors) if errors else None,
        "error_detail": validation_error,
        "stdout": stdout,
        "stderr": stderr,
    }


def run_command(
    template: Sequence[str],
    input_path: str,
    environment: Mapping[str, str],
    timeout_s: float,
) -> dict[str, Any]:
    return run_argv(expand_command(template, input_path), environment, timeout_s)


def arm_order(row_index: int, round_index: int) -> tuple[str, str]:
    """Alternate A/B by row and round, producing ABBA across adjacent rounds."""

    if (row_index + round_index) % 2 == 0:
        return ("baseline", "candidate")
    return ("candidate", "baseline")


def _is_execution_error(sample: Mapping[str, Any]) -> bool:
    return bool(sample.get("error_kind")) and not bool(sample.get("timed_out"))


def _is_success(sample: Mapping[str, Any]) -> bool:
    return (
        sample.get("error_kind") in (None, "")
        and sample.get("exit_code") == 0
        and sample.get("result") in VALID_RESULTS
    )


def _issue_record(sample: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "row_index": sample["row_index"],
        "relative_path": sample["relative_path"],
        "label": sample["label"],
        "repeat": sample["repeat"],
        "result": sample["result"],
        "exit_code": sample["exit_code"],
        "error_kind": sample.get("error_kind"),
        "stderr": str(sample.get("stderr", ""))[:STDERR_LIMIT],
    }


def summarize(
    rows: Sequence[Mapping[str, Any]],
    samples: Sequence[Mapping[str, Any]],
    repeats: int | None = None,
) -> dict[str, Any]:
    """Summarize measured samples using per-path medians on common coverage."""

    if repeats is None:
        repeat_values = [int(sample["repeat"]) for sample in samples]
        repeats = max(repeat_values, default=-1) + 1
    if repeats < 1:
        raise BenchmarkInputError("summary requires at least one repeat")

    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for sample in samples:
        key = (str(sample["relative_path"]), str(sample["label"]))
        grouped[key].append(sample)

    path_summaries: list[dict[str, Any]] = []
    wrong_answers: list[dict[str, Any]] = []
    execution_errors: list[dict[str, Any]] = []
    timeouts: list[dict[str, Any]] = []
    arm_totals = {
        label: {
            "paths": len(rows),
            "covered_paths": 0,
            "correct_runs": 0,
            "wrong_runs": 0,
            "unknown_runs": 0,
            "timeout_runs": 0,
            "error_runs": 0,
            "result_counts": Counter(),
        }
        for label in ("baseline", "candidate")
    }

    for row_index, row in enumerate(rows):
        relative_path = str(row["relative_path"])
        expected = str(row["status"])
        path_summary: dict[str, Any] = {
            "row_index": row_index,
            "id": row.get("id"),
            "relative_path": relative_path,
            "expected_status": expected,
        }
        for label in ("baseline", "candidate"):
            observations = sorted(
                grouped.get((relative_path, label), []),
                key=lambda sample: int(sample["repeat"]),
            )
            observed_repeats = [int(sample["repeat"]) for sample in observations]
            if observed_repeats != list(range(repeats)):
                raise BenchmarkInputError(
                    f"samples for {relative_path!r}/{label} do not contain "
                    f"exactly repeats 0..{repeats - 1}"
                )
            times = [float(sample["time_s"]) for sample in observations]
            if any(not math.isfinite(value) or value < 0 for value in times):
                raise BenchmarkInputError(
                    f"samples for {relative_path!r}/{label} contain invalid elapsed time"
                )

            correct_runs = sum(
                _is_success(sample) and sample["result"] == expected
                for sample in observations
            )
            wrong_runs = sum(
                sample["result"] in DECISIVE_RESULTS
                and expected in DECISIVE_RESULTS
                and sample["result"] != expected
                for sample in observations
            )
            timeout_runs = sum(bool(sample.get("timed_out")) for sample in observations)
            error_runs = sum(_is_execution_error(sample) for sample in observations)
            covered = correct_runs == repeats
            counts = Counter(str(sample["result"]) for sample in observations)
            arm = arm_totals[label]
            arm["covered_paths"] += int(covered)
            arm["correct_runs"] += correct_runs
            arm["wrong_runs"] += wrong_runs
            arm["unknown_runs"] += counts.get("unknown", 0)
            arm["timeout_runs"] += timeout_runs
            arm["error_runs"] += error_runs
            arm["result_counts"].update(counts)

            for sample in observations:
                if (
                    sample["result"] in DECISIVE_RESULTS
                    and expected in DECISIVE_RESULTS
                    and sample["result"] != expected
                ):
                    wrong_answers.append(
                        {
                            **_issue_record(sample),
                            "expected": expected,
                        }
                    )
                if bool(sample.get("timed_out")):
                    timeouts.append(_issue_record(sample))
                elif _is_execution_error(sample):
                    execution_errors.append(_issue_record(sample))

            path_summary[label] = {
                "covered": covered,
                "correct": covered,
                "correct_repeats": correct_runs,
                "wrong_repeats": wrong_runs,
                "unknown_repeats": counts.get("unknown", 0),
                "timeout_repeats": timeout_runs,
                "error_repeats": error_runs,
                "results": dict(sorted(counts.items())),
                "median_time_s": statistics.median(times),
            }
        path_summaries.append(path_summary)

    common = [
        path
        for path in path_summaries
        if path["baseline"]["covered"] and path["candidate"]["covered"]
    ]
    baseline_times = [float(path["baseline"]["median_time_s"]) for path in common]
    candidate_times = [float(path["candidate"]["median_time_s"]) for path in common]
    baseline_total = math.fsum(baseline_times)
    candidate_total = math.fsum(candidate_times)
    ratios = [
        baseline / candidate
        for baseline, candidate in zip(baseline_times, candidate_times)
        if baseline > 0 and candidate > 0
    ]
    common_aggregate = baseline_total / candidate_total if candidate_total > 0 else None
    common_geometric = (
        math.exp(math.fsum(math.log(ratio) for ratio in ratios) / len(ratios))
        if ratios and len(ratios) == len(common)
        else None
    )

    arms: dict[str, dict[str, Any]] = {}
    for label, values in arm_totals.items():
        arms[label] = {
            **{key: value for key, value in values.items() if key != "result_counts"},
            "coverage": values["covered_paths"] / len(rows) if rows else None,
            "failed_runs": values["timeout_runs"] + values["error_runs"],
            "uncovered_runs": len(rows) * repeats - values["correct_runs"],
            "result_counts": dict(sorted(values["result_counts"].items())),
        }

    baseline_only = [
        path["relative_path"]
        for path in path_summaries
        if path["baseline"]["covered"] and not path["candidate"]["covered"]
    ]
    candidate_only = [
        path["relative_path"]
        for path in path_summaries
        if path["candidate"]["covered"] and not path["baseline"]["covered"]
    ]
    return {
        "instances": len(rows),
        "repeats": repeats,
        "measured_runs": len(samples),
        "arms": arms,
        "baseline_correct": arms["baseline"]["covered_paths"],
        "candidate_correct": arms["candidate"]["covered_paths"],
        "coverage_delta": (
            arms["candidate"]["covered_paths"] - arms["baseline"]["covered_paths"]
        ),
        "baseline_only_correct": len(baseline_only),
        "candidate_only_correct": len(candidate_only),
        "baseline_only_examples": baseline_only[:25],
        "candidate_only_examples": candidate_only[:25],
        "common_correct": len(common),
        "common_correct_paths": [path["relative_path"] for path in common],
        "timing_basis": "per-instance median of measured repeats",
        "speedup_direction": "baseline_time / candidate_time",
        "baseline_common_total_time_s": baseline_total,
        "candidate_common_total_time_s": candidate_total,
        "common_aggregate_speedup": common_aggregate,
        "common_geometric_speedup": common_geometric,
        "candidate_speedup_by_total": common_aggregate,
        "candidate_geometric_speedup": common_geometric,
        "candidate_wins": sum(
            candidate < baseline
            for baseline, candidate in zip(baseline_times, candidate_times)
        ),
        "baseline_wins": sum(
            baseline < candidate
            for baseline, candidate in zip(baseline_times, candidate_times)
        ),
        "ties": sum(
            baseline == candidate
            for baseline, candidate in zip(baseline_times, candidate_times)
        ),
        "wrong_answers": wrong_answers,
        "execution_errors": execution_errors,
        "timeouts": timeouts,
        "accounting": {
            "wrong_answers": len(wrong_answers),
            "execution_errors": len(execution_errors),
            "timeouts": len(timeouts),
        },
        "paths": path_summaries,
    }


def _sample_record(
    *,
    sequence: int,
    row_index: int,
    row: Mapping[str, Any],
    label: str,
    repeat: int,
    order_in_repeat: int,
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "row_index": row_index,
        "id": row.get("id"),
        "relative_path": row["relative_path"],
        "expected_status": row["status"],
        "label": label,
        "repeat": repeat,
        "order_in_repeat": order_in_repeat,
        **observation,
    }


def _csv_record(sample: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sequence": sample["sequence"],
        "row_index": sample["row_index"],
        "id": sample.get("id"),
        "relative_path": sample["relative_path"],
        "expected_status": sample["expected_status"],
        "label": sample["label"],
        "repeat": sample["repeat"],
        "order_in_repeat": sample["order_in_repeat"],
        "result": sample["result"],
        "time_s": f"{float(sample['time_s']):.9f}",
        "exit_code": sample["exit_code"],
        "process_returncode": sample["process_returncode"],
        "timed_out": int(bool(sample["timed_out"])),
        "error_kind": sample.get("error_kind") or "",
        "stdout": str(sample.get("stdout", ""))[:STDOUT_LIMIT],
        "stderr": str(sample.get("stderr", ""))[:STDERR_LIMIT],
        "argv_json": json.dumps(sample["argv"], separators=(",", ":")),
    }


def _warmup_summary(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    wrong = []
    errors = []
    timeouts = []
    for sample in samples:
        expected = sample["expected_status"]
        if (
            sample["result"] in DECISIVE_RESULTS
            and expected in DECISIVE_RESULTS
            and sample["result"] != expected
        ):
            wrong.append({**_issue_record(sample), "expected": expected})
        if bool(sample.get("timed_out")):
            timeouts.append(_issue_record(sample))
        elif _is_execution_error(sample):
            errors.append(_issue_record(sample))
    return {
        "runs": len(samples),
        "wrong_answers": wrong,
        "execution_errors": errors,
        "timeouts": timeouts,
    }


def execute(
    *,
    rows: Sequence[Mapping[str, Any]],
    templates: Mapping[str, Sequence[str]],
    environments: Mapping[str, Mapping[str, str]],
    timeout_s: float,
    repeats: int,
    warmups: int,
    output_csv: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run warmups and measurements, writing measured observations in order."""

    validate_timeout(timeout_s)
    if repeats < 1 or warmups < 0:
        raise BenchmarkInputError("repeats must be positive and warmups non-negative")
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    warmup_samples: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    sequence = 0
    with output_csv.open("w", newline="", encoding="utf-8", buffering=1) as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row_index, row in enumerate(rows):
            for warmup in range(warmups):
                for order_index, label in enumerate(arm_order(row_index, warmup)):
                    observation = run_command(
                        templates[label],
                        str(row["path"]),
                        environments[label],
                        timeout_s,
                    )
                    warmup_samples.append(
                        {
                            "row_index": row_index,
                            "relative_path": row["relative_path"],
                            "expected_status": row["status"],
                            "label": label,
                            "repeat": warmup,
                            "order_in_repeat": order_index,
                            **observation,
                        }
                    )
            for repeat in range(repeats):
                for order_index, label in enumerate(arm_order(row_index, repeat)):
                    observation = run_command(
                        templates[label],
                        str(row["path"]),
                        environments[label],
                        timeout_s,
                    )
                    sample = _sample_record(
                        sequence=sequence,
                        row_index=row_index,
                        row=row,
                        label=label,
                        repeat=repeat,
                        order_in_repeat=order_index,
                        observation=observation,
                    )
                    samples.append(sample)
                    writer.writerow(_csv_record(sample))
                    handle.flush()
                    sequence += 1
    return warmup_samples, samples


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--baseline-arg",
        "--baseline-command",
        "--baseline-command-token",
        dest="baseline_argv",
        action="append",
        required=True,
        metavar="TOKEN",
        help=(
            "one baseline argv token; repeat in argv order and use "
            "--baseline-arg=VALUE for tokens beginning with '-'"
        ),
    )
    parser.add_argument(
        "--candidate-arg",
        "--candidate-command",
        "--candidate-command-token",
        dest="candidate_argv",
        action="append",
        required=True,
        metavar="TOKEN",
        help=(
            "one candidate argv token; repeat in argv order and use "
            "--candidate-arg=VALUE for tokens beginning with '-'"
        ),
    )
    parser.add_argument("--baseline-env", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--candidate-env", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out", type=Path, required=True, help="per-repeat CSV")
    parser.add_argument("--summary", type=Path, required=True, help="atomic JSON summary")
    return parser


def _parser_error(parser: argparse.ArgumentParser, error: Exception) -> None:
    parser.error(str(error))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_timeout(args.timeout)
    except BenchmarkInputError as error:
        _parser_error(parser, error)
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    if args.warmups < 0:
        parser.error("--warmups must be non-negative")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")

    try:
        templates = {
            "baseline": validate_command_template(args.baseline_argv, "baseline"),
            "candidate": validate_command_template(args.candidate_argv, "candidate"),
        }
        environments = {
            "baseline": parse_environment(args.baseline_env),
            "candidate": parse_environment(args.candidate_env),
        }
        rows = read_manifest(args.manifest, args.limit)

        manifest_resolved = args.manifest.resolve()
        output_resolved = args.out.resolve()
        summary_resolved = args.summary.resolve()
        if output_resolved == summary_resolved:
            raise BenchmarkInputError("--out and --summary must be different paths")
        if manifest_resolved in {output_resolved, summary_resolved}:
            raise BenchmarkInputError("output paths cannot overwrite the manifest")
        input_paths = {row["_file"]["resolved_path"] for row in rows}
        if str(output_resolved) in input_paths or str(summary_resolved) in input_paths:
            raise BenchmarkInputError("output paths cannot overwrite benchmark inputs")
        for destination in (args.out, args.summary):
            if destination.exists() and not destination.is_file():
                raise BenchmarkInputError(f"output path is not a file: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
        command_artifacts = {
            label: command_metadata(templates[label], environments[label])
            for label in ("baseline", "candidate")
        }
    except BenchmarkInputError as error:
        _parser_error(parser, error)

    started_at = utc_now()
    start = time.perf_counter()
    warmup_samples, samples = execute(
        rows=rows,
        templates=templates,
        environments=environments,
        timeout_s=args.timeout,
        repeats=args.repeats,
        warmups=args.warmups,
        output_csv=args.out,
    )
    summary = summarize(rows, samples, args.repeats)
    warmup = _warmup_summary(warmup_samples)
    finished_at = utc_now()

    input_files = [
        {
            "row_index": index,
            "id": row.get("id"),
            "path": row["path"],
            "relative_path": row["relative_path"],
            **row["_file"],
        }
        for index, row in enumerate(rows)
    ]
    host = host_metadata()
    payload = {
        "schema_version": 1,
        "status": "complete",
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_s": time.perf_counter() - start,
        "manifest": str(args.manifest),
        "manifest_order": [row["relative_path"] for row in rows],
        "timeout_s": args.timeout,
        "warmups": args.warmups,
        "baseline": templates["baseline"],
        "candidate": templates["candidate"],
        "baseline_env": list(args.baseline_env),
        "candidate_env": list(args.candidate_env),
        "runtime_host": host["hostname"],
        "host": host,
        "artifacts": {
            "manifest": _regular_file_metadata(args.manifest),
            "input_files": input_files,
            "commands": command_artifacts,
            "results_csv": {
                **_regular_file_metadata(args.out),
                "fieldnames": FIELDNAMES,
                "stdout_limit": STDOUT_LIMIT,
                "stderr_limit": STDERR_LIMIT,
            },
        },
        "manifest_sha256": sha256_file(args.manifest),
        "baseline_sha256": command_artifacts["baseline"]["executable"]["sha256"],
        "candidate_sha256": command_artifacts["candidate"]["executable"]["sha256"],
        "warmup": warmup,
        **summary,
    }
    atomic_write_json(args.summary, payload)

    aggregate = summary["common_aggregate_speedup"]
    geometric = summary["common_geometric_speedup"]
    speed_text = (
        f"common aggregate {aggregate:.4f}x, geometric {geometric:.4f}x"
        if aggregate is not None and geometric is not None
        else "no common-correct speedup"
    )
    print(
        f"coverage {summary['baseline_correct']}/{len(rows)} -> "
        f"{summary['candidate_correct']}/{len(rows)}; {speed_text}"
    )

    if summary["wrong_answers"] or warmup["wrong_answers"]:
        return 2
    if summary["execution_errors"] or warmup["execution_errors"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
