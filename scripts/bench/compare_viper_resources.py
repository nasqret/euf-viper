#!/usr/bin/env python3
"""Compare peak memory and elapsed time for two euf-viper configurations."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import platform
import re
import signal
import statistics
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DECISIVE_RESULTS = {"sat", "unsat"}
LABELS = ("baseline", "candidate")
MEASUREMENT_PREFIX = "euf-viper-resource-v1"
TIME_FORMAT = f"{MEASUREMENT_PREFIX}\t%e\t%M\t%x"
FIELDNAMES = [
    "relative_path",
    "expected_status",
    "label",
    "repeat",
    "order",
    "result",
    "correct",
    "elapsed_s",
    "peak_rss_kib",
    "exit_code",
    "stderr",
]


class ComparatorError(RuntimeError):
    """Raised when a comparison cannot produce trustworthy measurements."""


class ManifestError(ComparatorError):
    """Raised when the input manifest violates the expected JSONL schema."""


class MeasurementError(ComparatorError):
    """Raised when GNU time does not produce one complete measurement."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def parse_environment(
    values: Iterable[str], inherited: dict[str, str] | None = None
) -> dict[str, str]:
    """Return an inherited environment with explicit KEY=VALUE settings applied."""

    environment = dict(os.environ if inherited is None else inherited)
    for value in values:
        if "=" not in value:
            raise ValueError(f"environment entry must be KEY=VALUE: {value!r}")
        key, setting = value.split("=", 1)
        if not key:
            raise ValueError("environment key cannot be empty")
        if "\x00" in key or "\x00" in setting:
            raise ValueError("environment entries cannot contain NUL bytes")
        environment[key] = setting
    return environment


def environment_overrides(values: Iterable[str]) -> dict[str, str]:
    return parse_environment(values, inherited={})


def read_manifest(path: Path, limit: int | None = None) -> list[dict]:
    """Read and validate the existing euf-viper JSONL manifest format."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ManifestError(f"cannot read manifest {path}: {error}") from error

    rows: list[dict] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ManifestError(
                f"{path}:{line_number}: invalid JSON: {error.msg}"
            ) from error
        if not isinstance(row, dict):
            raise ManifestError(f"{path}:{line_number}: row must be a JSON object")

        for field in ("path", "relative_path", "status"):
            value = row.get(field)
            if not isinstance(value, str) or not value:
                raise ManifestError(
                    f"{path}:{line_number}: {field} must be a non-empty string"
                )
        if row["status"] not in DECISIVE_RESULTS:
            raise ManifestError(
                f"{path}:{line_number}: expected status must be sat or unsat, "
                f"got {row['status']!r}"
            )
        relative_path = row["relative_path"]
        if relative_path in seen:
            raise ManifestError(
                f"{path}:{line_number}: duplicate relative_path {relative_path!r}"
            )
        seen.add(relative_path)
        rows.append(row)

    if not rows:
        raise ManifestError("manifest is empty")
    return rows[:limit] if limit is not None else rows


def parse_measurement(path: Path) -> dict[str, float | int]:
    """Parse exactly one sentinel-formatted GNU-time record."""

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise MeasurementError(f"cannot read GNU time measurement: {error}") from error

    lines = text.splitlines()
    if len(lines) != 1:
        raise MeasurementError(
            f"GNU time measurement must contain exactly one line, got {len(lines)}"
        )
    fields = lines[0].split("\t")
    if len(fields) != 4 or fields[0] != MEASUREMENT_PREFIX:
        raise MeasurementError("GNU time measurement has an invalid format marker")

    elapsed_text, rss_text, exit_text = fields[1:]
    try:
        elapsed_s = float(elapsed_text)
    except ValueError as error:
        raise MeasurementError(
            f"GNU time reported invalid elapsed seconds {elapsed_text!r}"
        ) from error
    if not math.isfinite(elapsed_s) or elapsed_s < 0:
        raise MeasurementError(
            f"GNU time reported invalid elapsed seconds {elapsed_text!r}"
        )
    if re.fullmatch(r"[0-9]+", rss_text) is None:
        raise MeasurementError(f"GNU time reported invalid peak RSS {rss_text!r}")
    if re.fullmatch(r"[0-9]+", exit_text) is None:
        raise MeasurementError(f"GNU time reported invalid exit status {exit_text!r}")

    peak_rss_kib = int(rss_text)
    exit_code = int(exit_text)
    if exit_code > 255:
        raise MeasurementError(f"GNU time reported invalid exit status {exit_code}")
    return {
        "elapsed_s": elapsed_s,
        "peak_rss_kib": peak_rss_kib,
        "exit_code": exit_code,
    }


def _stop_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.communicate(timeout=0.25)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate()


def run_arm(
    *,
    label: str,
    binary: Path,
    source: str,
    environment: dict[str, str],
    timeout_s: float,
    time_executable: Path,
) -> dict:
    """Run one arm under GNU time and return one validated observation."""

    with tempfile.TemporaryDirectory(prefix="euf-viper-resource-") as temp_dir:
        measurement_path = Path(temp_dir) / "measurement.txt"
        command = [
            str(time_executable.resolve()),
            "--quiet",
            "--format",
            TIME_FORMAT,
            "--output",
            str(measurement_path),
            "--",
            str(binary.resolve()),
            "solve",
            source,
        ]
        try:
            process = subprocess.Popen(
                command,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            raise MeasurementError(
                f"cannot start {label} measurement with {time_executable}: {error}"
            ) from error

        try:
            stdout, stderr = process.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired as error:
            _stop_process_group(process)
            raise MeasurementError(
                f"{label} timed out after {timeout_s:g}s for {source!r}; "
                "no complete GNU time measurement is available"
            ) from error

        try:
            measurement = parse_measurement(measurement_path)
        except MeasurementError as error:
            detail = stderr.strip()
            suffix = f"; stderr={detail[:500]!r}" if detail else ""
            raise MeasurementError(
                f"invalid {label} measurement for {source!r}: {error}{suffix}"
            ) from error

    measured_exit = int(measurement["exit_code"])
    if process.returncode != measured_exit:
        raise MeasurementError(
            f"invalid {label} measurement for {source!r}: GNU time recorded "
            f"exit {measured_exit}, wrapper returned {process.returncode}"
        )

    lines = stdout.strip().splitlines()
    result = lines[0].strip() if lines else f"exit-{measured_exit}"
    return {
        "result": result,
        "elapsed_s": float(measurement["elapsed_s"]),
        "peak_rss_kib": int(measurement["peak_rss_kib"]),
        "exit_code": measured_exit,
        "stderr": stderr.strip(),
    }


def scheduled_labels(row_index: int, repeat: int) -> tuple[str, str]:
    if (row_index + repeat) % 2 == 0:
        return LABELS
    return ("candidate", "baseline")


def collect_samples(
    rows: list[dict],
    binaries: dict[str, Path],
    environments: dict[str, dict[str, str]],
    *,
    timeout_s: float,
    repeats: int,
    time_executable: Path,
) -> list[dict]:
    samples: list[dict] = []
    for row_index, row in enumerate(rows):
        for repeat in range(repeats):
            for order, label in enumerate(scheduled_labels(row_index, repeat)):
                observation = run_arm(
                    label=label,
                    binary=binaries[label],
                    source=row["path"],
                    environment=environments[label],
                    timeout_s=timeout_s,
                    time_executable=time_executable,
                )
                correct = (
                    observation["exit_code"] == 0
                    and observation["result"] == row["status"]
                )
                samples.append(
                    {
                        "relative_path": row["relative_path"],
                        "expected_status": row["status"],
                        "label": label,
                        "repeat": repeat,
                        "order": order,
                        "correct": correct,
                        **observation,
                    }
                )
    return samples


def _arm_summary(observations: list[dict], instance_count: int) -> dict:
    elapsed = [sample["elapsed_s"] for sample in observations]
    rss = [sample["peak_rss_kib"] for sample in observations]
    paths = defaultdict(list)
    for sample in observations:
        paths[sample["relative_path"]].append(sample)
    return {
        "observations": len(observations),
        "correct_observations": sum(sample["correct"] for sample in observations),
        "correct_instances": sum(
            all(sample["correct"] for sample in path_samples)
            for path_samples in paths.values()
        ),
        "instance_count": instance_count,
        "total_elapsed_s": sum(elapsed),
        "mean_elapsed_s": statistics.mean(elapsed),
        "median_elapsed_s": statistics.median(elapsed),
        "max_elapsed_s": max(elapsed),
        "max_peak_rss_kib": max(rss),
        "mean_peak_rss_kib": statistics.mean(rss),
        "median_peak_rss_kib": statistics.median(rss),
    }


def summarize(rows: list[dict], samples: list[dict], repeats: int) -> dict:
    expected_count = len(rows) * len(LABELS) * repeats
    if len(samples) != expected_count:
        raise ComparatorError(
            f"internal error: expected {expected_count} observations, got {len(samples)}"
        )

    by_label = {
        label: [sample for sample in samples if sample["label"] == label]
        for label in LABELS
    }
    status_mismatches = [
        {
            "relative_path": sample["relative_path"],
            "label": sample["label"],
            "repeat": sample["repeat"],
            "expected_status": sample["expected_status"],
            "result": sample["result"],
            "exit_code": sample["exit_code"],
        }
        for sample in samples
        if not sample["correct"]
    ]

    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for sample in samples:
        grouped[(sample["relative_path"], sample["label"])].append(sample)
    path_summaries = {}
    for row in rows:
        labels = {}
        for label in LABELS:
            observations = grouped[(row["relative_path"], label)]
            labels[label] = {
                "all_correct": all(sample["correct"] for sample in observations),
                "results": dict(
                    sorted(Counter(sample["result"] for sample in observations).items())
                ),
                "median_elapsed_s": statistics.median(
                    sample["elapsed_s"] for sample in observations
                ),
                "max_peak_rss_kib": max(
                    sample["peak_rss_kib"] for sample in observations
                ),
            }
        path_summaries[row["relative_path"]] = {
            "expected_status": row["status"],
            **labels,
        }

    baseline = _arm_summary(by_label["baseline"], len(rows))
    candidate = _arm_summary(by_label["candidate"], len(rows))

    def ratio(numerator: float, denominator: float) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "status": "valid" if not status_mismatches else "invalid",
        "valid": not status_mismatches,
        "instances": len(rows),
        "repeats": repeats,
        "observations": len(samples),
        "baseline": baseline,
        "candidate": candidate,
        "candidate_to_baseline_total_elapsed_ratio": ratio(
            candidate["total_elapsed_s"], baseline["total_elapsed_s"]
        ),
        "candidate_to_baseline_peak_rss_ratio": ratio(
            candidate["max_peak_rss_kib"], baseline["max_peak_rss_kib"]
        ),
        "status_mismatches": status_mismatches,
        "paths": path_summaries,
    }


def artifact_metadata(
    manifest: Path,
    baseline: Path,
    candidate: Path,
    time_executable: Path,
    timeout_s: float,
) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_host": platform.node(),
        "manifest": str(manifest),
        "manifest_sha256": sha256_file(manifest),
        "baseline_binary": str(baseline),
        "baseline_sha256": sha256_file(baseline),
        "candidate_binary": str(candidate),
        "candidate_sha256": sha256_file(candidate),
        "time_executable": str(time_executable),
        "time_executable_sha256": sha256_file(time_executable),
        "time_format": TIME_FORMAT,
        "timeout_s": timeout_s,
        "order_strategy": "baseline-first when (manifest_index + repeat) is even",
        "git_revision": os.environ.get("EUF_VIPER_GIT_REVISION"),
        "slurm_job_id": os.environ.get("SLURM_JOB_ID"),
        "slurm_array_job_id": os.environ.get("SLURM_ARRAY_JOB_ID"),
        "slurm_array_task_id": os.environ.get("SLURM_ARRAY_TASK_ID"),
        "slurm_node_list": os.environ.get("SLURM_JOB_NODELIST"),
    }


def csv_payload(samples: list[dict]) -> str:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=FIELDNAMES, lineterminator="\n")
    writer.writeheader()
    for sample in samples:
        row = dict(sample)
        row["stderr"] = row["stderr"][:1000]
        writer.writerow(row)
    return handle.getvalue()


def atomic_write_artifacts(artifacts: list[tuple[Path, str]]) -> None:
    staged: list[tuple[Path, Path]] = []
    try:
        for path, text in artifacts:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
            temporary.write_text(text, encoding="utf-8")
            staged.append((temporary, path))
        for temporary, path in staged:
            temporary.replace(path)
    finally:
        for temporary, _ in staged:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _same_path(first: Path, second: Path) -> bool:
    return first.resolve(strict=False) == second.resolve(strict=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare euf-viper peak RSS and elapsed time using GNU /usr/bin/time."
        )
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline-env", action="append", default=[])
    parser.add_argument("--candidate-env", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--time-executable",
        "--time",
        dest="time_executable",
        type=Path,
        default=Path("/usr/bin/time"),
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a positive finite number")
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")

    executables = {
        "baseline": args.baseline,
        "candidate": args.candidate,
        "GNU time": args.time_executable,
    }
    for label, executable in executables.items():
        if not executable.is_file():
            parser.error(f"missing {label} executable: {executable}")
        if not os.access(executable, os.X_OK):
            parser.error(f"{label} executable is not executable: {executable}")

    protected_paths = [args.manifest, args.baseline, args.candidate, args.time_executable]
    if _same_path(args.out, args.summary):
        parser.error("--out and --summary must be different paths")
    for output in (args.out, args.summary):
        if any(_same_path(output, protected) for protected in protected_paths):
            parser.error(f"output path would overwrite an input: {output}")

    try:
        rows = read_manifest(args.manifest, args.limit)
        environments = {
            "baseline": parse_environment(args.baseline_env),
            "candidate": parse_environment(args.candidate_env),
        }
        samples = collect_samples(
            rows,
            {"baseline": args.baseline, "candidate": args.candidate},
            environments,
            timeout_s=args.timeout,
            repeats=args.repeats,
            time_executable=args.time_executable,
        )
        payload = summarize(rows, samples, args.repeats)
        payload.update(
            artifact_metadata(
                args.manifest,
                args.baseline,
                args.candidate,
                args.time_executable,
                args.timeout,
            )
        )
        payload["baseline_env"] = list(args.baseline_env)
        payload["candidate_env"] = list(args.candidate_env)
        payload["baseline_env_overrides"] = environment_overrides(args.baseline_env)
        payload["candidate_env_overrides"] = environment_overrides(args.candidate_env)
        csv_text = csv_payload(samples)
        summary_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        atomic_write_artifacts(
            [(args.out, csv_text), (args.summary, summary_text)]
        )
    except (ComparatorError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 4

    print(
        f"instances={payload['instances']} observations={payload['observations']} "
        f"status={payload['status']} "
        f"elapsed_s={payload['baseline']['total_elapsed_s']:.6g}->"
        f"{payload['candidate']['total_elapsed_s']:.6g} "
        f"peak_rss_kib={payload['baseline']['max_peak_rss_kib']}->"
        f"{payload['candidate']['max_peak_rss_kib']}"
    )
    return 0 if payload["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
