#!/usr/bin/env python3
"""Run the preregistered T9 Stage 1 correctness and ABBA timing falsifier."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import resource
import signal
import statistics
import subprocess
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


SCHEMA = "euf-viper.t9-stage1.v1"
RAW_SCHEMA = "euf-viper.t9-stage1-observation.v1"
REPEATS = 4
TIMEOUT_SECONDS = 2.0
MAX_OUTPUT_BYTES = 64 * 1024
MAX_ADDRESS_SPACE_BYTES = 6 * 1024**3
MAX_OPEN_FILES = 64
CONTROL_SHA256 = "85c18f76bc4908477e906eb0706cb06724ef23ef0536112651fe75e86ff18390"
MANIFEST_SHA256 = "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
TARGET_PATH = (
    "QF_UF/2018-Goel-hwbench/"
    "QF_UF_sokoban.2.prop1_ab_br_max.smt2"
)
CHEAP_PRECHECK_REASONS = {
    "finite_added_nonzero",
    "application_count_cap",
    "backend_not_kissat",
}
BASE_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}


class Stage1Error(RuntimeError):
    pass


@dataclass(frozen=True)
class Source:
    relative_path: str
    path: Path
    sha256: str
    bytes: int
    status: str
    control_class: str
    projection: Mapping[str, Any]


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_input_identities(
    identities: list[tuple[str, Path, str, bool]],
) -> None:
    for label, path, expected_sha256, executable in identities:
        if (
            path.is_symlink()
            or not path.is_file()
            or (executable and not os.access(path, os.X_OK))
            or sha256_file(path) != expected_sha256
        ):
            raise Stage1Error(f"input identity changed during Stage1: {label}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Stage1Error(f"cannot load JSON {path}: {error}") from error
    if type(value) is not dict:
        raise Stage1Error(f"JSON root is not an object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="ascii") as handle:
            for line_number, line in enumerate(handle, start=1):
                value = json.loads(line)
                if type(value) is not dict:
                    raise Stage1Error(f"{path}:{line_number}: row is not an object")
                rows.append(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Stage1Error(f"cannot load JSONL {path}: {error}") from error
    return rows


def immutable_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise Stage1Error(f"refuse to replace output {path}: {error}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o400)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _child_limits() -> None:
    if os.uname().sysname == "Linux":
        resource.setrlimit(
            resource.RLIMIT_AS, (MAX_ADDRESS_SPACE_BYTES, MAX_ADDRESS_SPACE_BYTES)
        )
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN_FILES, MAX_OPEN_FILES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
    if hasattr(resource, "RLIMIT_NPROC"):
        soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
        limit = min(value for value in (64, soft, hard) if value >= 0)
        resource.setrlimit(resource.RLIMIT_NPROC, (limit, limit))


def _parse_result(stdout: bytes, return_code: int) -> str:
    if return_code != 0:
        return f"exit-{return_code}"
    tokens = [
        line.strip()
        for line in stdout.decode("utf-8", errors="replace").splitlines()
        if line.strip() in {"sat", "unsat", "unknown"}
    ]
    if len(tokens) == 1:
        return tokens[0]
    return "invalid-status-output"


def _read_output(handle: Any, stream: str) -> bytes:
    handle.flush()
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size > MAX_OUTPUT_BYTES:
        raise Stage1Error(f"{stream} exceeded {MAX_OUTPUT_BYTES} bytes")
    handle.seek(0)
    return handle.read()


def _signal_process_group(pid: int) -> bool:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise Stage1Error(f"cannot terminate process group {pid}: {error}") from error
    return True


def _wait_process_group_gone(pid: int) -> None:
    deadline = time.monotonic() + 1.0
    while True:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            # SIGKILL was accepted immediately before this check. Darwin can
            # report EPERM while its service manager reaps the dead orphan.
            return
        if time.monotonic() >= deadline:
            raise Stage1Error(f"process group {pid} survived SIGKILL")
        time.sleep(0.01)


def run_process(
    argv: list[str], environment: Mapping[str, str]
) -> tuple[dict[str, Any], str]:
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise Stage1Error("Stage1 refuses to replace an active process timer")
    start = time.perf_counter_ns()
    with (
        tempfile.TemporaryFile() as stdout_handle,
        tempfile.TemporaryFile() as stderr_handle,
    ):
        process = subprocess.Popen(
            argv,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=stderr_handle,
            start_new_session=True,
            close_fds=True,
            preexec_fn=_child_limits,
        )
        timed_out = False
        timeout_signalled = False

        def timeout_handler(_signum: int, _frame: Any) -> None:
            nonlocal timed_out, timeout_signalled
            timed_out = True
            timeout_signalled = _signal_process_group(process.pid)

        previous_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
        try:
            try:
                process.wait()
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0.0)
                signal.signal(signal.SIGALRM, previous_handler)
        except BaseException:
            _signal_process_group(process.pid)
            process.wait()
            raise
        if timed_out:
            group_signalled = timeout_signalled
        else:
            # Solvers are single-process. Kill any unexpected descendants before
            # the next observation even when the leader exited successfully.
            group_signalled = _signal_process_group(process.pid)
        if group_signalled:
            _wait_process_group_gone(process.pid)
        stdout_bytes = _read_output(stdout_handle, "stdout")
        stderr_bytes = _read_output(stderr_handle, "stderr")
    elapsed_ns = time.perf_counter_ns() - start
    record = {
        "result": (
            "timeout" if timed_out else _parse_result(stdout_bytes, process.returncode)
        ),
        "elapsed_ns": elapsed_ns,
        "exit_code": 124 if timed_out else process.returncode,
        "timed_out": timed_out,
        "stdout_sha256": sha256_bytes(stdout_bytes),
        "stderr_sha256": sha256_bytes(stderr_bytes),
        "stdout_b64": base64.b64encode(stdout_bytes).decode("ascii"),
        "stderr_b64": base64.b64encode(stderr_bytes).decode("ascii"),
    }
    return record, stderr_bytes.decode("utf-8", errors="replace")


def arm_environment(arm: str, *, profile: bool = False) -> dict[str, str]:
    environment = dict(BASE_ENVIRONMENT)
    if arm in {"off", "candidate"}:
        environment["EUF_VIPER_BACKEND"] = "auto"
        environment["EUF_VIPER_T9_ACKERMANN"] = (
            "clique-auto" if arm == "candidate" else "off"
        )
        if profile:
            environment["EUF_VIPER_PROFILE"] = "1"
    return environment


def arm_argv(arm: str, binary: Path, yices: Path, source: Path) -> list[str]:
    if arm == "yices":
        return [str(yices), str(source)]
    return [str(binary), "solve", str(source)]


def parse_t9_profile(stderr: str) -> dict[str, str]:
    lines = [
        line.removeprefix("profile_t9_ackermann ")
        for line in stderr.splitlines()
        if line.startswith("profile_t9_ackermann ")
    ]
    if len(lines) != 1:
        raise Stage1Error(f"expected one T9 profile line, observed {len(lines)}")
    fields: dict[str, str] = {}
    for token in lines[0].split():
        if "=" not in token:
            raise Stage1Error("T9 profile token is not key=value")
        key, value = token.split("=", 1)
        if not key or not value or key in fields:
            raise Stage1Error("T9 profile contains an invalid or duplicate field")
        fields[key] = value
    return fields


def projection_strings(projection: Mapping[str, Any]) -> dict[str, str]:
    rendered: dict[str, str] = {}
    for key, value in projection.items():
        if type(value) is bool:
            rendered[key] = "1" if value else "0"
        elif type(value) is int:
            rendered[key] = str(value)
        elif type(value) is str:
            rendered[key] = value
        else:
            raise Stage1Error(f"projection field {key!r} has unsupported type")
    return rendered


def validate_profile(source: Source, profile: Mapping[str, str]) -> str:
    expected = projection_strings(source.projection)
    if profile.get("precheck") == "1":
        required = {
            "selected": "0",
            "reason": expected["reason"],
            "precheck": "1",
        }
        if dict(profile) != required or expected["reason"] not in CHEAP_PRECHECK_REASONS:
            raise Stage1Error(
                f"{source.relative_path}: solve precheck differs from Stage0 projection"
            )
        return "precheck"
    if dict(profile) != expected:
        raise Stage1Error(
            f"{source.relative_path}: solve materialization differs from Stage0 projection"
        )
    if source.projection["selected"]:
        return "selected_materialization"
    if source.projection["baseline_before_sha256"] != source.projection["baseline_after_sha256"]:
        raise Stage1Error(f"{source.relative_path}: rejected T9 route changed baseline CNF")
    return "unchanged_rejection"


def quantile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _check(passed: bool, actual: Any, relation: str, threshold: Any) -> dict[str, Any]:
    return {
        "passed": bool(passed),
        "actual": actual,
        "relation": relation,
        "threshold": threshold,
    }


def evaluate(
    sources: list[Source], observations: list[dict[str, Any]], selected: set[str]
) -> dict[str, Any]:
    source_by_path = {source.relative_path: source for source in sources}
    timing = [row for row in observations if row["phase"] == "timing"]
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in timing:
        grouped[(row["relative_path"], row["comparison"], row["arm"])].append(row)

    path_metrics: dict[str, Any] = {}
    missing: list[str] = []
    for source in sources:
        path_payload: dict[str, Any] = {}
        for comparison, arms in (
            ("off_candidate", ("off", "candidate")),
            ("yices_candidate", ("yices", "candidate")),
        ):
            arm_payload: dict[str, Any] = {}
            for arm in arms:
                rows = grouped[(source.relative_path, comparison, arm)]
                if len(rows) != REPEATS:
                    missing.append(f"{source.relative_path}:{comparison}:{arm}")
                    continue
                elapsed = [row["elapsed_ns"] for row in rows]
                arm_payload[arm] = {
                    "correct": all(row["result"] == source.status for row in rows),
                    "results": sorted(row["result"] for row in rows),
                    "median_ns": int(statistics.median(elapsed)),
                }
            path_payload[comparison] = arm_payload
        path_metrics[source.relative_path] = path_payload

    wrong_answers = [
        {
            "relative_path": row["relative_path"],
            "phase": row["phase"],
            "comparison": row["comparison"],
            "arm": row["arm"],
            "result": row["result"],
            "expected": source_by_path[row["relative_path"]].status,
        }
        for row in observations
        if row["result"] in {"sat", "unsat"}
        and row["result"] != source_by_path[row["relative_path"]].status
    ]
    nondecisive_errors = [
        {
            "relative_path": row["relative_path"],
            "phase": row["phase"],
            "comparison": row["comparison"],
            "arm": row["arm"],
            "result": row["result"],
            "exit_code": row["exit_code"],
        }
        for row in observations
        if row["result"] not in {"sat", "unsat", "timeout"}
    ]

    candidate_only: list[str] = []
    baseline_only: list[str] = []
    anti_ratios: list[float] = []
    nonselected_ratios: list[float] = []
    selected_yices_speedups: list[float] = []
    selected_improvements: dict[str, bool] = {}
    selected_baseline_all_timeout: dict[str, bool] = {}
    candidate_timeout_yices_solve: list[str] = []
    for source in sources:
        metrics = path_metrics[source.relative_path]
        off_pair = metrics.get("off_candidate", {})
        yices_pair = metrics.get("yices_candidate", {})
        if set(off_pair) != {"off", "candidate"} or set(yices_pair) != {
            "yices",
            "candidate",
        }:
            continue
        off_correct = off_pair["off"]["correct"]
        candidate_correct = off_pair["candidate"]["correct"]
        baseline_all_timeout = False
        if source.relative_path in selected:
            selected_off_rows = [
                row
                for row in observations
                if row["relative_path"] == source.relative_path
                and row["arm"] == "off"
            ]
            baseline_all_timeout = len(selected_off_rows) == REPEATS + 1 and all(
                row["result"] == "timeout" for row in selected_off_rows
            )
            selected_baseline_all_timeout[source.relative_path] = baseline_all_timeout
        if candidate_correct and (
            baseline_all_timeout
            if source.relative_path in selected
            else not off_correct
        ):
            candidate_only.append(source.relative_path)
        if off_correct and not candidate_correct:
            baseline_only.append(source.relative_path)
        if source.relative_path not in selected and off_correct and candidate_correct:
            ratio = off_pair["candidate"]["median_ns"] / off_pair["off"]["median_ns"]
            nonselected_ratios.append(ratio)
            if source.control_class == "anti-target":
                anti_ratios.append(ratio)
        if source.relative_path in selected:
            selected_improvements[source.relative_path] = (
                candidate_correct
                and off_pair["candidate"]["median_ns"] < off_pair["off"]["median_ns"]
            )
            if yices_pair["candidate"]["correct"] and yices_pair["yices"]["correct"]:
                selected_yices_speedups.append(
                    yices_pair["yices"]["median_ns"]
                    / yices_pair["candidate"]["median_ns"]
                )
            if (
                "timeout" in yices_pair["candidate"]["results"]
                and yices_pair["yices"]["correct"]
            ):
                candidate_timeout_yices_solve.append(source.relative_path)

    median_speedup = (
        statistics.median(selected_yices_speedups) if selected_yices_speedups else None
    )
    geometric_speedup = (
        math.exp(statistics.mean(math.log(value) for value in selected_yices_speedups))
        if selected_yices_speedups
        else None
    )
    anti_p95 = quantile(anti_ratios, 0.95)
    nonselected_p95 = quantile(nonselected_ratios, 0.95)
    candidate_rows = [row for row in timing if row["arm"] == "candidate"]
    candidate_correct = all(
        row["result"] == source_by_path[row["relative_path"]].status
        for row in candidate_rows
    )
    all_required_correct = all(
        row["result"] == source_by_path[row["relative_path"]].status
        for row in observations
        if not (row["arm"] == "off" and row["relative_path"] in selected)
    )
    checks = {
        "complete_schedule": _check(not missing, len(missing), "==", 0),
        "wrong_answers": _check(not wrong_answers, len(wrong_answers), "==", 0),
        "execution_errors": _check(
            not nondecisive_errors, len(nondecisive_errors), "==", 0
        ),
        "required_arms_correct": _check(
            all_required_correct, all_required_correct, "==", True
        ),
        "candidate_correct": _check(candidate_correct, candidate_correct, "==", True),
        "baseline_only": _check(not baseline_only, len(baseline_only), "==", 0),
        "selected_baseline_all_timeout": _check(
            set(selected_baseline_all_timeout) == selected
            and all(selected_baseline_all_timeout.values()),
            selected_baseline_all_timeout,
            "all_true",
            sorted(selected),
        ),
        "selected_converted": _check(
            set(candidate_only) == selected,
            sorted(candidate_only),
            "==",
            sorted(selected),
        ),
        "selected_improvement": _check(
            set(selected_improvements) == selected and all(selected_improvements.values()),
            selected_improvements,
            "all_true",
            sorted(selected),
        ),
        "anti_target_p95_overhead": _check(
            anti_p95 is not None and anti_p95 <= 1.01, anti_p95, "<=", 1.01
        ),
        "selected_yices_median_speedup": _check(
            median_speedup is not None and median_speedup >= 1.05,
            median_speedup,
            ">=",
            1.05,
        ),
        "selected_yices_geometric_speedup": _check(
            geometric_speedup is not None and geometric_speedup >= 1.05,
            geometric_speedup,
            ">=",
            1.05,
        ),
        "candidate_timeout_yices_solve": _check(
            not candidate_timeout_yices_solve,
            len(candidate_timeout_yices_solve),
            "==",
            0,
        ),
    }
    return {
        "checks": checks,
        "decision": "pass" if all(check["passed"] for check in checks.values()) else "fail",
        "wrong_answers": wrong_answers,
        "execution_errors": nondecisive_errors,
        "missing_groups": missing,
        "candidate_only_paths": sorted(candidate_only),
        "baseline_only_paths": sorted(baseline_only),
        "selected_baseline_all_timeout": selected_baseline_all_timeout,
        "candidate_timeout_yices_solve": sorted(candidate_timeout_yices_solve),
        "anti_target_overhead_ratios": anti_ratios,
        "anti_target_p95_overhead": anti_p95,
        "nonselected_p95_overhead": nonselected_p95,
        "selected_yices_speedups": selected_yices_speedups,
        "selected_yices_median_speedup": median_speedup,
        "selected_yices_geometric_speedup": geometric_speedup,
        "paths": path_metrics,
    }


def load_sources(
    manifest_path: Path,
    control_path: Path,
    corpus_root: Path,
    records_path: Path,
    summary_path: Path,
    receipt_path: Path,
    binary_sha256: str,
) -> tuple[list[Source], dict[str, Any], dict[str, Any]]:
    if sha256_file(manifest_path) != MANIFEST_SHA256:
        raise Stage1Error("full manifest SHA-256 mismatch")
    if sha256_file(control_path) != CONTROL_SHA256:
        raise Stage1Error("control manifest SHA-256 mismatch")
    summary = load_json(summary_path)
    receipt = load_json(receipt_path)
    if summary.get("status") != "completed_no_sat" or summary.get("sat_calls") != 0:
        raise Stage1Error("Stage0 summary is not a completed no-SAT census")
    if (
        receipt.get("status") != "pass"
        or receipt.get("schema") != "euf-viper.t9-projection-audit.v2"
    ):
        raise Stage1Error("Stage0 audit receipt does not pass")
    if receipt.get("artifacts", {}).get("records_sha256") != sha256_file(records_path):
        raise Stage1Error("Stage0 records hash does not match its receipt")
    if receipt.get("artifacts", {}).get("summary_sha256") != sha256_file(summary_path):
        raise Stage1Error("Stage0 summary hash does not match its receipt")
    if summary.get("binary_sha256") != binary_sha256:
        raise Stage1Error("timed binary differs from the Stage0 binary")
    selected = summary.get("selected_paths")
    if selected != [TARGET_PATH] or receipt.get("selected_paths") != selected:
        raise Stage1Error("Stage0 selected population is not the frozen sole target")

    manifest_rows = load_jsonl(manifest_path)
    if len(manifest_rows) != 7503:
        raise Stage1Error("full manifest does not contain 7,503 rows")
    manifest_by_path = {row.get("relative_path"): row for row in manifest_rows}
    if len(manifest_by_path) != len(manifest_rows):
        raise Stage1Error("full manifest contains duplicate paths")
    control_rows = load_jsonl(control_path)
    if len(control_rows) != 24:
        raise Stage1Error("control manifest does not contain 24 rows")
    control_by_path = {row.get("relative_path"): row for row in control_rows}
    if len(control_by_path) != 24:
        raise Stage1Error("control manifest contains duplicate paths")

    wanted = set(control_by_path) | set(selected)
    projections: dict[str, Mapping[str, Any]] = {}
    record_count = 0
    try:
        with records_path.open("r", encoding="ascii") as handle:
            for line in handle:
                record_count += 1
                row = json.loads(line)
                relative_path = row.get("source", {}).get("relative_path")
                if relative_path in wanted:
                    if relative_path in projections:
                        raise Stage1Error("Stage0 records contain a duplicate wanted path")
                    projection = row.get("projection")
                    if type(projection) is not dict:
                        raise Stage1Error("Stage0 wanted record lacks a projection")
                    projections[relative_path] = projection
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Stage1Error(f"cannot load Stage0 records: {error}") from error
    if record_count != 7503 or set(projections) != wanted:
        raise Stage1Error("Stage0 record population is incomplete")

    sources: list[Source] = []
    resolved_root = corpus_root.resolve()
    for relative_path in sorted(wanted):
        relative = PurePosixPath(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise Stage1Error(f"unsafe relative path for {relative_path}")
        manifest_row = manifest_by_path.get(relative_path)
        if type(manifest_row) is not dict:
            raise Stage1Error(f"missing full-manifest row for {relative_path}")
        control_row = control_by_path.get(relative_path)
        unresolved_source_path = corpus_root / relative_path
        source_path = unresolved_source_path.resolve()
        expected_sha = manifest_row.get("sha256")
        expected_bytes = manifest_row.get("bytes")
        if (
            manifest_row.get("status") not in {"sat", "unsat"}
            or type(expected_sha) is not str
            or type(expected_bytes) is not int
            or unresolved_source_path.is_symlink()
            or source_path == resolved_root
            or resolved_root not in source_path.parents
            or not source_path.is_file()
            or source_path.stat().st_size != expected_bytes
            or sha256_file(source_path) != expected_sha
        ):
            raise Stage1Error(f"source identity mismatch for {relative_path}")
        if control_row is not None and (
            control_row.get("sha256") != expected_sha
            or control_row.get("bytes") != expected_bytes
            or control_row.get("status") != manifest_row.get("status")
            or control_row.get("control_class") not in {"target", "anti-target"}
        ):
            raise Stage1Error(f"control identity mismatch for {relative_path}")
        sources.append(
            Source(
                relative_path=relative_path,
                path=source_path,
                sha256=expected_sha,
                bytes=expected_bytes,
                status=manifest_row["status"],
                control_class=(
                    control_row["control_class"] if control_row is not None else "selected"
                ),
                projection=projections[relative_path],
            )
        )
    return sources, summary, receipt


def run_stage1(args: argparse.Namespace) -> dict[str, Any]:
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    if len(affinity) != 1:
        raise Stage1Error(f"Stage1 requires exactly one CPU in affinity, observed {affinity}")
    if args.raw_out == args.summary_out or any(
        path.exists() or path.is_symlink() for path in (args.raw_out, args.summary_out)
    ):
        raise Stage1Error("Stage1 output paths must be distinct and absent")
    runner_path = Path(__file__).resolve()
    runner_sha256 = sha256_file(runner_path)
    for path, expected in (
        (args.binary, args.binary_sha256),
        (args.yices, args.yices_sha256),
    ):
        if not path.is_file() or not os.access(path, os.X_OK) or sha256_file(path) != expected:
            raise Stage1Error(f"executable identity mismatch: {path}")
    sources, stage0_summary, stage0_receipt = load_sources(
        args.manifest,
        args.control_manifest,
        args.corpus_root,
        args.stage0_records,
        args.stage0_summary,
        args.stage0_receipt,
        args.binary_sha256,
    )
    stage0_receipt_sha256 = sha256_file(args.stage0_receipt)
    input_identities = [
        ("manifest", args.manifest, MANIFEST_SHA256, False),
        ("control_manifest", args.control_manifest, CONTROL_SHA256, False),
        (
            "stage0_records",
            args.stage0_records,
            stage0_receipt["artifacts"]["records_sha256"],
            False,
        ),
        (
            "stage0_summary",
            args.stage0_summary,
            stage0_receipt["artifacts"]["summary_sha256"],
            False,
        ),
        ("stage0_receipt", args.stage0_receipt, stage0_receipt_sha256, False),
        ("binary", args.binary, args.binary_sha256, True),
        ("yices", args.yices, args.yices_sha256, True),
        ("runner", runner_path, runner_sha256, True),
    ]
    input_identities.extend(
        (
            f"source:{source.relative_path}",
            source.path,
            source.sha256,
            False,
        )
        for source in sources
    )
    selected = set(stage0_summary["selected_paths"])
    observations: list[dict[str, Any]] = []
    ordinal = 0

    for source in sources:
        for arm in ("off", "candidate", "yices"):
            observation, stderr = run_process(
                arm_argv(arm, args.binary, args.yices, source.path),
                arm_environment(arm, profile=arm == "candidate"),
            )
            profile_kind = None
            profile = None
            if arm == "candidate":
                profile = parse_t9_profile(stderr)
                profile_kind = validate_profile(source, profile)
            observations.append(
                {
                    "schema": RAW_SCHEMA,
                    "ordinal": ordinal,
                    "phase": "preflight",
                    "comparison": None,
                    "repeat": None,
                    "position": None,
                    "relative_path": source.relative_path,
                    "expected_status": source.status,
                    "control_class": source.control_class,
                    "selected": source.relative_path in selected,
                    "arm": arm,
                    "profile_kind": profile_kind,
                    "profile": profile,
                    **observation,
                }
            )
            ordinal += 1

    comparisons = (
        ("off_candidate", "off", "candidate"),
        ("yices_candidate", "yices", "candidate"),
    )
    for source_index, source in enumerate(sources):
        for comparison_index, (comparison, first, second) in enumerate(comparisons):
            for repeat in range(REPEATS):
                arms = (
                    (first, second)
                    if (source_index + comparison_index + repeat) % 2 == 0
                    else (second, first)
                )
                for position, arm in enumerate(arms):
                    observation, _ = run_process(
                        arm_argv(arm, args.binary, args.yices, source.path),
                        arm_environment(arm),
                    )
                    observations.append(
                        {
                            "schema": RAW_SCHEMA,
                            "ordinal": ordinal,
                            "phase": "timing",
                            "comparison": comparison,
                            "repeat": repeat,
                            "position": position,
                            "relative_path": source.relative_path,
                            "expected_status": source.status,
                            "control_class": source.control_class,
                            "selected": source.relative_path in selected,
                            "arm": arm,
                            "profile_kind": None,
                            "profile": None,
                            **observation,
                        }
                    )
                    ordinal += 1

    validate_input_identities(input_identities)
    evaluation = evaluate(sources, observations, selected)
    raw_payload = b"".join(canonical_json_bytes(row) for row in observations)
    summary = {
        "schema": SCHEMA,
        "status": "completed",
        "decision": evaluation["decision"],
        "population_count": len(sources),
        "selected_paths": sorted(selected),
        "repeats": REPEATS,
        "timeout_seconds": TIMEOUT_SECONDS,
        "cpu_affinity": affinity,
        "observation_count": len(observations),
        "raw_sha256": sha256_bytes(raw_payload),
        "stage0": {
            "revision": stage0_summary["provenance"]["git_revision"],
            "tree": stage0_summary["provenance"]["git_tree"],
            "binary_sha256": stage0_summary["binary_sha256"],
            "records_sha256": stage0_receipt["artifacts"]["records_sha256"],
            "summary_sha256": stage0_receipt["artifacts"]["summary_sha256"],
            "receipt_sha256": stage0_receipt_sha256,
        },
        "artifacts": {
            "manifest_sha256": sha256_file(args.manifest),
            "control_manifest_sha256": sha256_file(args.control_manifest),
            "binary_sha256": args.binary_sha256,
            "yices_sha256": args.yices_sha256,
            "yices_version": args.yices_version,
            "runner_sha256": runner_sha256,
        },
        "environment": BASE_ENVIRONMENT,
        "evaluation": evaluation,
    }
    immutable_write(args.raw_out, raw_payload)
    immutable_write(args.summary_out, canonical_json_bytes(summary))
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--control-manifest", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--stage0-records", type=Path, required=True)
    parser.add_argument("--stage0-summary", type=Path, required=True)
    parser.add_argument("--stage0-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--yices", type=Path, required=True)
    parser.add_argument("--yices-sha256", required=True)
    parser.add_argument("--yices-version", required=True)
    parser.add_argument("--raw-out", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    try:
        summary = run_stage1(parse_args())
    except Stage1Error as error:
        print(f"T9 Stage1 rejected: {error}", file=os.sys.stderr)
        return 2
    return 0 if summary["decision"] == "pass" else 3


if __name__ == "__main__":
    raise SystemExit(main())
