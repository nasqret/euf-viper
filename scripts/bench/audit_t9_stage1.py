#!/usr/bin/env python3
"""Independently audit T9 Stage 1 raw ABBA evidence and its decision."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import statistics
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "euf-viper.t9-stage1.v1"
RAW_SCHEMA = "euf-viper.t9-stage1-observation.v1"
AUDIT_SCHEMA = "euf-viper.t9-stage1-audit.v1"
REPEATS = 4
TIMEOUT_SECONDS = 2.0
MAX_OUTPUT_BYTES = 64 * 1024
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
OBSERVATION_KEYS = {
    "schema",
    "ordinal",
    "phase",
    "comparison",
    "repeat",
    "position",
    "relative_path",
    "expected_status",
    "control_class",
    "selected",
    "arm",
    "profile_kind",
    "profile",
    "result",
    "elapsed_ns",
    "exit_code",
    "timed_out",
    "stdout_sha256",
    "stderr_sha256",
    "stdout_b64",
    "stderr_b64",
}


class AuditError(RuntimeError):
    pass


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


def decode_stream(row: dict[str, Any], stream: str) -> bytes:
    encoded = row.get(f"{stream}_b64")
    if type(encoded) is not str:
        raise AuditError(f"observation {stream} is not canonical base64")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AuditError(f"observation {stream} is not canonical base64") from error
    if (
        len(payload) > MAX_OUTPUT_BYTES
        or base64.b64encode(payload).decode("ascii") != encoded
    ):
        raise AuditError(f"observation {stream} exceeds or violates its encoding contract")
    if row.get(f"{stream}_sha256") != sha256_bytes(payload):
        raise AuditError(f"observation {stream} hash mismatch")
    return payload


def derive_result(stdout: bytes, exit_code: int, timed_out: bool) -> str:
    if timed_out:
        if exit_code != 124:
            raise AuditError("timeout observation does not use synthetic exit code 124")
        return "timeout"
    if exit_code != 0:
        return f"exit-{exit_code}"
    tokens = [
        line.strip()
        for line in stdout.decode("utf-8", errors="replace").splitlines()
        if line.strip() in {"sat", "unsat", "unknown"}
    ]
    if len(tokens) == 1:
        return tokens[0]
    return "invalid-status-output"


def parse_t9_profile(stderr: bytes) -> dict[str, str]:
    lines = [
        line.removeprefix("profile_t9_ackermann ")
        for line in stderr.decode("utf-8", errors="replace").splitlines()
        if line.startswith("profile_t9_ackermann ")
    ]
    if len(lines) != 1:
        raise AuditError(f"expected one T9 profile line, observed {len(lines)}")
    fields: dict[str, str] = {}
    for token in lines[0].split():
        if "=" not in token:
            raise AuditError("T9 profile token is not key=value")
        key, value = token.split("=", 1)
        if not key or not value or key in fields:
            raise AuditError("T9 profile contains an invalid or duplicate field")
        fields[key] = value
    return fields


def load_object(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot load {path}: {error}") from error
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise AuditError(f"{path} is not a canonical JSON object")
    return value


def load_jsonl(path: Path, *, canonical: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("rb") as handle:
            for line_number, payload in enumerate(handle, start=1):
                value = json.loads(payload.decode("ascii"))
                if type(value) is not dict:
                    raise AuditError(f"{path}:{line_number}: row is not an object")
                if canonical and canonical_json_bytes(value) != payload:
                    raise AuditError(f"{path}:{line_number}: row is not canonical")
                rows.append(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot load {path}: {error}") from error
    return rows


def immutable_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise AuditError(f"refuse to replace audit receipt {path}: {error}") from error
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


def check(passed: bool, actual: Any, relation: str, threshold: Any) -> dict[str, Any]:
    return {
        "passed": bool(passed),
        "actual": actual,
        "relation": relation,
        "threshold": threshold,
    }


def projection_strings(projection: dict[str, Any]) -> dict[str, str]:
    rendered: dict[str, str] = {}
    for key, value in projection.items():
        if type(value) is bool:
            rendered[key] = "1" if value else "0"
        elif type(value) is int:
            rendered[key] = str(value)
        elif type(value) is str:
            rendered[key] = value
        else:
            raise AuditError(f"projection field {key!r} has unsupported type")
    return rendered


def bind_stage0_projections(
    records_path: Path, contract: dict[str, dict[str, Any]]
) -> None:
    projections: dict[str, dict[str, Any]] = {}
    count = 0
    try:
        with records_path.open("r", encoding="ascii") as handle:
            for line in handle:
                count += 1
                row = json.loads(line)
                relative_path = row.get("source", {}).get("relative_path")
                if relative_path in contract:
                    projection = row.get("projection")
                    if type(projection) is not dict or relative_path in projections:
                        raise AuditError("Stage0 projection record is invalid or duplicated")
                    projections[relative_path] = projection
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot load Stage0 records: {error}") from error
    if count != 7503 or set(projections) != set(contract):
        raise AuditError("Stage0 projection population mismatch")
    for relative_path, projection in projections.items():
        contract[relative_path]["projection"] = projection


def source_contract(
    manifest_path: Path, control_path: Path, corpus_root: Path, selected: set[str]
) -> dict[str, dict[str, Any]]:
    if sha256_file(manifest_path) != MANIFEST_SHA256:
        raise AuditError("manifest SHA-256 mismatch")
    if sha256_file(control_path) != CONTROL_SHA256:
        raise AuditError("control manifest SHA-256 mismatch")
    manifest = load_jsonl(manifest_path, canonical=False)
    controls = load_jsonl(control_path, canonical=False)
    if len(manifest) != 7503 or len(controls) != 24:
        raise AuditError("manifest population mismatch")
    manifest_by_path = {row.get("relative_path"): row for row in manifest}
    control_by_path = {row.get("relative_path"): row for row in controls}
    if len(manifest_by_path) != 7503 or len(control_by_path) != 24:
        raise AuditError("manifest paths are not unique")
    wanted = set(control_by_path) | selected
    contract: dict[str, dict[str, Any]] = {}
    root = corpus_root.resolve()
    for relative_path in sorted(wanted):
        relative = PurePosixPath(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise AuditError(f"unsafe relative path {relative_path}")
        row = manifest_by_path.get(relative_path)
        control = control_by_path.get(relative_path)
        if type(row) is not dict:
            raise AuditError(f"missing manifest source {relative_path}")
        unresolved_path = corpus_root / relative_path
        path = unresolved_path.resolve()
        if (
            unresolved_path.is_symlink()
            or path == root
            or root not in path.parents
            or not path.is_file()
        ):
            raise AuditError(f"unsafe or missing source {relative_path}")
        expected_sha = row.get("sha256")
        expected_bytes = row.get("bytes")
        if (
            type(expected_sha) is not str
            or type(expected_bytes) is not int
            or row.get("status") not in {"sat", "unsat"}
            or path.stat().st_size != expected_bytes
            or sha256_file(path) != expected_sha
        ):
            raise AuditError(f"source identity mismatch {relative_path}")
        if control is not None and (
            control.get("sha256") != expected_sha
            or control.get("bytes") != expected_bytes
            or control.get("status") != row.get("status")
            or control.get("control_class") not in {"target", "anti-target"}
        ):
            raise AuditError(f"control identity mismatch {relative_path}")
        contract[relative_path] = {
            "status": row["status"],
            "control_class": control["control_class"] if control else "selected",
            "selected": relative_path in selected,
        }
    return contract


def validate_observations(
    observations: list[dict[str, Any]], contract: dict[str, dict[str, Any]]
) -> None:
    expected_count = len(contract) * (3 + 2 * 2 * REPEATS)
    if len(observations) != expected_count:
        raise AuditError("observation population mismatch")
    preflight: dict[tuple[str, str], int] = defaultdict(int)
    timing: dict[tuple[str, str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for ordinal, row in enumerate(observations):
        if row.keys() != OBSERVATION_KEYS or row.get("schema") != RAW_SCHEMA:
            raise AuditError(f"observation {ordinal} schema mismatch")
        if row.get("ordinal") != ordinal:
            raise AuditError("observation ordinals are not contiguous")
        relative_path = row.get("relative_path")
        source = contract.get(relative_path)
        if source is None:
            raise AuditError("observation references an unknown source")
        if (
            row.get("expected_status") != source["status"]
            or row.get("control_class") != source["control_class"]
            or row.get("selected") is not source["selected"]
            or type(row.get("elapsed_ns")) is not int
            or row["elapsed_ns"] <= 0
            or type(row.get("exit_code")) is not int
            or type(row.get("timed_out")) is not bool
        ):
            raise AuditError("observation source or scalar fields mismatch")
        for field in ("stdout_sha256", "stderr_sha256"):
            value = row.get(field)
            if type(value) is not str or len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise AuditError("observation stream hash is not canonical")
        stdout = decode_stream(row, "stdout")
        stderr = decode_stream(row, "stderr")
        derived_result = derive_result(stdout, row["exit_code"], row["timed_out"])
        if row.get("result") != derived_result:
            raise AuditError("observation result differs from complete stream evidence")
        if row["timed_out"] and row["elapsed_ns"] < int(TIMEOUT_SECONDS * 1e9):
            raise AuditError("timeout observation elapsed less than its wall limit")
        phase = row.get("phase")
        arm = row.get("arm")
        if phase == "preflight":
            if (
                row.get("comparison") is not None
                or row.get("repeat") is not None
                or row.get("position") is not None
                or arm not in {"off", "candidate", "yices"}
            ):
                raise AuditError("invalid preflight observation")
            if arm == "candidate":
                if row.get("profile_kind") not in {
                    "precheck",
                    "selected_materialization",
                    "unchanged_rejection",
                }:
                    raise AuditError("candidate preflight lacks profile validation")
                profile = row.get("profile")
                if type(profile) is not dict or not all(
                    type(key) is str and type(value) is str
                    for key, value in profile.items()
                ):
                    raise AuditError("candidate preflight profile is not canonical")
                if parse_t9_profile(stderr) != profile:
                    raise AuditError("published candidate profile differs from stderr")
                projection = source.get("projection")
                if type(projection) is not dict:
                    raise AuditError("candidate preflight lacks its Stage0 projection")
                expected = projection_strings(projection)
                if row["profile_kind"] == "precheck":
                    required = {
                        "selected": "0",
                        "reason": expected["reason"],
                        "precheck": "1",
                    }
                    if profile != required or expected["reason"] not in CHEAP_PRECHECK_REASONS:
                        raise AuditError("candidate precheck profile differs from Stage0")
                else:
                    if profile != expected:
                        raise AuditError("candidate materialization differs from Stage0")
                    if (
                        row["profile_kind"] == "selected_materialization"
                        and not projection["selected"]
                    ) or (
                        row["profile_kind"] == "unchanged_rejection"
                        and (
                            projection["selected"]
                            or projection["baseline_before_sha256"]
                            != projection["baseline_after_sha256"]
                        )
                    ):
                        raise AuditError("candidate profile kind contradicts Stage0")
            elif row.get("profile_kind") is not None or row.get("profile") is not None:
                raise AuditError("noncandidate preflight has a profile marker")
            preflight[(relative_path, arm)] += 1
        elif phase == "timing":
            comparison = row.get("comparison")
            repeat = row.get("repeat")
            position = row.get("position")
            if (
                comparison not in {"off_candidate", "yices_candidate"}
                or type(repeat) is not int
                or not 0 <= repeat < REPEATS
                or position not in {0, 1}
                or row.get("profile_kind") is not None
                or row.get("profile") is not None
            ):
                raise AuditError("invalid timing observation")
            if any(
                line.startswith(b"profile_t9_ackermann ")
                for line in stderr.splitlines()
            ):
                raise AuditError("timing observation unexpectedly enabled profiling")
            expected_arms = (
                {"off", "candidate"}
                if comparison == "off_candidate"
                else {"yices", "candidate"}
            )
            if arm not in expected_arms:
                raise AuditError("timing arm does not belong to comparison")
            timing[(relative_path, comparison, arm, repeat)].append(row)
        else:
            raise AuditError("unknown observation phase")
    if any(count != 1 for count in preflight.values()) or len(preflight) != len(contract) * 3:
        raise AuditError("preflight schedule is incomplete")
    if any(len(rows) != 1 for rows in timing.values()) or len(timing) != (
        len(contract) * 4 * REPEATS
    ):
        raise AuditError("timing schedule is incomplete")

    paths = sorted(contract)
    preflight_rows = [row for row in observations if row["phase"] == "preflight"]
    preflight_cursor = 0
    for relative_path in paths:
        for arm in ("off", "candidate", "yices"):
            row = preflight_rows[preflight_cursor]
            preflight_cursor += 1
            if row["relative_path"] != relative_path or row["arm"] != arm:
                raise AuditError("preflight order is not the frozen balanced warmup schedule")
    timing_rows = [row for row in observations if row["phase"] == "timing"]
    cursor = 0
    for source_index, relative_path in enumerate(paths):
        for comparison_index, (comparison, first, second) in enumerate(
            (
                ("off_candidate", "off", "candidate"),
                ("yices_candidate", "yices", "candidate"),
            )
        ):
            for repeat in range(REPEATS):
                arms = (
                    (first, second)
                    if (source_index + comparison_index + repeat) % 2 == 0
                    else (second, first)
                )
                for position, arm in enumerate(arms):
                    row = timing_rows[cursor]
                    cursor += 1
                    if (
                        row["relative_path"] != relative_path
                        or row["comparison"] != comparison
                        or row["repeat"] != repeat
                        or row["position"] != position
                        or row["arm"] != arm
                    ):
                        raise AuditError("timing order is not the frozen balanced ABBA schedule")


def recompute(
    observations: list[dict[str, Any]], contract: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    timing = [row for row in observations if row["phase"] == "timing"]
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in timing:
        grouped[(row["relative_path"], row["comparison"], row["arm"])].append(row)
    paths: dict[str, Any] = {}
    for relative_path, source in contract.items():
        payload: dict[str, Any] = {}
        for comparison, arms in (
            ("off_candidate", ("off", "candidate")),
            ("yices_candidate", ("yices", "candidate")),
        ):
            arm_payload: dict[str, Any] = {}
            for arm in arms:
                rows = grouped[(relative_path, comparison, arm)]
                arm_payload[arm] = {
                    "correct": all(row["result"] == source["status"] for row in rows),
                    "results": sorted(row["result"] for row in rows),
                    "median_ns": int(statistics.median(row["elapsed_ns"] for row in rows)),
                }
            payload[comparison] = arm_payload
        paths[relative_path] = payload

    wrong = []
    errors = []
    for row in observations:
        expected = contract[row["relative_path"]]["status"]
        if row["result"] in {"sat", "unsat"} and row["result"] != expected:
            wrong.append(
                {
                    "relative_path": row["relative_path"],
                    "phase": row["phase"],
                    "comparison": row["comparison"],
                    "arm": row["arm"],
                    "result": row["result"],
                    "expected": expected,
                }
            )
        if row["result"] not in {"sat", "unsat", "timeout"}:
            errors.append(
                {
                    "relative_path": row["relative_path"],
                    "phase": row["phase"],
                    "comparison": row["comparison"],
                    "arm": row["arm"],
                    "result": row["result"],
                    "exit_code": row["exit_code"],
                }
            )

    selected = {path for path, source in contract.items() if source["selected"]}
    candidate_only: list[str] = []
    baseline_only: list[str] = []
    anti_ratios: list[float] = []
    nonselected_ratios: list[float] = []
    yices_speedups: list[float] = []
    improvements: dict[str, bool] = {}
    selected_baseline_all_timeout: dict[str, bool] = {}
    candidate_timeout_yices: list[str] = []
    for relative_path, source in contract.items():
        off_pair = paths[relative_path]["off_candidate"]
        yices_pair = paths[relative_path]["yices_candidate"]
        off_correct = off_pair["off"]["correct"]
        candidate_correct = off_pair["candidate"]["correct"]
        baseline_all_timeout = False
        if relative_path in selected:
            selected_off_rows = [
                row
                for row in observations
                if row["relative_path"] == relative_path and row["arm"] == "off"
            ]
            baseline_all_timeout = len(selected_off_rows) == REPEATS + 1 and all(
                row["result"] == "timeout" for row in selected_off_rows
            )
            selected_baseline_all_timeout[relative_path] = baseline_all_timeout
        if candidate_correct and (
            baseline_all_timeout if relative_path in selected else not off_correct
        ):
            candidate_only.append(relative_path)
        if off_correct and not candidate_correct:
            baseline_only.append(relative_path)
        if relative_path not in selected and off_correct and candidate_correct:
            ratio = off_pair["candidate"]["median_ns"] / off_pair["off"]["median_ns"]
            nonselected_ratios.append(ratio)
            if source["control_class"] == "anti-target":
                anti_ratios.append(ratio)
        if relative_path in selected:
            improvements[relative_path] = (
                candidate_correct
                and off_pair["candidate"]["median_ns"] < off_pair["off"]["median_ns"]
            )
            if yices_pair["candidate"]["correct"] and yices_pair["yices"]["correct"]:
                yices_speedups.append(
                    yices_pair["yices"]["median_ns"]
                    / yices_pair["candidate"]["median_ns"]
                )
            if "timeout" in yices_pair["candidate"]["results"] and yices_pair["yices"]["correct"]:
                candidate_timeout_yices.append(relative_path)

    candidate_rows = [row for row in timing if row["arm"] == "candidate"]
    candidate_correct = all(
        row["result"] == contract[row["relative_path"]]["status"]
        for row in candidate_rows
    )
    all_required_correct = all(
        row["result"] == contract[row["relative_path"]]["status"]
        for row in observations
        if not (row["arm"] == "off" and contract[row["relative_path"]]["selected"])
    )
    anti_p95 = quantile(anti_ratios, 0.95)
    nonselected_p95 = quantile(nonselected_ratios, 0.95)
    median_speedup = statistics.median(yices_speedups) if yices_speedups else None
    geometric_speedup = (
        math.exp(statistics.mean(math.log(value) for value in yices_speedups))
        if yices_speedups
        else None
    )
    checks = {
        "complete_schedule": check(True, 0, "==", 0),
        "wrong_answers": check(not wrong, len(wrong), "==", 0),
        "execution_errors": check(not errors, len(errors), "==", 0),
        "required_arms_correct": check(all_required_correct, all_required_correct, "==", True),
        "candidate_correct": check(candidate_correct, candidate_correct, "==", True),
        "baseline_only": check(not baseline_only, len(baseline_only), "==", 0),
        "selected_baseline_all_timeout": check(
            set(selected_baseline_all_timeout) == selected
            and all(selected_baseline_all_timeout.values()),
            selected_baseline_all_timeout,
            "all_true",
            sorted(selected),
        ),
        "selected_converted": check(
            set(candidate_only) == selected,
            sorted(candidate_only),
            "==",
            sorted(selected),
        ),
        "selected_improvement": check(
            set(improvements) == selected and all(improvements.values()),
            improvements,
            "all_true",
            sorted(selected),
        ),
        "anti_target_p95_overhead": check(
            anti_p95 is not None and anti_p95 <= 1.01, anti_p95, "<=", 1.01
        ),
        "selected_yices_median_speedup": check(
            median_speedup is not None and median_speedup >= 1.05,
            median_speedup,
            ">=",
            1.05,
        ),
        "selected_yices_geometric_speedup": check(
            geometric_speedup is not None and geometric_speedup >= 1.05,
            geometric_speedup,
            ">=",
            1.05,
        ),
        "candidate_timeout_yices_solve": check(
            not candidate_timeout_yices, len(candidate_timeout_yices), "==", 0
        ),
    }
    return {
        "checks": checks,
        "decision": "pass" if all(value["passed"] for value in checks.values()) else "fail",
        "wrong_answers": wrong,
        "execution_errors": errors,
        "missing_groups": [],
        "candidate_only_paths": sorted(candidate_only),
        "baseline_only_paths": sorted(baseline_only),
        "selected_baseline_all_timeout": selected_baseline_all_timeout,
        "candidate_timeout_yices_solve": sorted(candidate_timeout_yices),
        "anti_target_overhead_ratios": anti_ratios,
        "anti_target_p95_overhead": anti_p95,
        "nonselected_p95_overhead": nonselected_p95,
        "selected_yices_speedups": yices_speedups,
        "selected_yices_median_speedup": median_speedup,
        "selected_yices_geometric_speedup": geometric_speedup,
        "paths": paths,
    }


def audit(args: argparse.Namespace) -> dict[str, Any]:
    for path in (args.raw, args.summary):
        if path.stat().st_mode & 0o777 != 0o400:
            raise AuditError(f"published artifact mode is not 0400: {path}")
    summary = load_object(args.summary)
    observations = load_jsonl(args.raw, canonical=True)
    if summary.get("schema") != SCHEMA or summary.get("status") != "completed":
        raise AuditError("Stage1 summary schema or status mismatch")
    if summary.get("raw_sha256") != sha256_file(args.raw):
        raise AuditError("raw evidence hash mismatch")
    if summary.get("repeats") != REPEATS or summary.get("timeout_seconds") != TIMEOUT_SECONDS:
        raise AuditError("Stage1 timing contract drift")
    affinity = summary.get("cpu_affinity")
    if (
        type(affinity) is not list
        or len(affinity) != 1
        or type(affinity[0]) is not int
        or affinity[0] < 0
    ):
        raise AuditError("Stage1 CPU affinity is not exactly one logical CPU")
    if summary.get("observation_count") != len(observations):
        raise AuditError("Stage1 observation count mismatch")
    if summary.get("environment") != {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}:
        raise AuditError("Stage1 closed environment contract drift")
    if summary.get("selected_paths") != [TARGET_PATH]:
        raise AuditError("Stage1 selected population drift")
    if summary.get("artifacts") != {
        "manifest_sha256": sha256_file(args.manifest),
        "control_manifest_sha256": sha256_file(args.control_manifest),
        "binary_sha256": sha256_file(args.binary),
        "yices_sha256": sha256_file(args.yices),
        "yices_version": args.yices_version,
        "runner_sha256": sha256_file(args.runner),
    }:
        raise AuditError("Stage1 artifact identities mismatch")
    stage0_summary = load_object(args.stage0_summary)
    stage0_receipt = load_object(args.stage0_receipt)
    if (
        stage0_summary.get("status") != "completed_no_sat"
        or stage0_summary.get("sat_calls") != 0
        or stage0_receipt.get("status") != "pass"
        or stage0_receipt.get("artifacts", {}).get("records_sha256")
        != sha256_file(args.stage0_records)
        or stage0_receipt.get("artifacts", {}).get("summary_sha256")
        != sha256_file(args.stage0_summary)
    ):
        raise AuditError("Stage0 evidence contract mismatch")
    expected_stage0 = {
        "revision": stage0_summary["provenance"]["git_revision"],
        "tree": stage0_summary["provenance"]["git_tree"],
        "binary_sha256": stage0_summary["binary_sha256"],
        "records_sha256": stage0_receipt["artifacts"]["records_sha256"],
        "summary_sha256": stage0_receipt["artifacts"]["summary_sha256"],
        "receipt_sha256": sha256_file(args.stage0_receipt),
    }
    if summary.get("stage0") != expected_stage0:
        raise AuditError("Stage1 summary is not bound to exact Stage0 evidence")
    contract = source_contract(
        args.manifest, args.control_manifest, args.corpus_root, {TARGET_PATH}
    )
    bind_stage0_projections(args.stage0_records, contract)
    if summary.get("population_count") != len(contract):
        raise AuditError("Stage1 summary population count mismatch")
    validate_observations(observations, contract)
    evaluation = recompute(observations, contract)
    if summary.get("evaluation") != evaluation or summary.get("decision") != evaluation["decision"]:
        raise AuditError("Stage1 decision does not match independent recomputation")
    receipt = {
        "schema": AUDIT_SCHEMA,
        "status": "verified",
        "scientific_decision": evaluation["decision"],
        "raw_sha256": sha256_file(args.raw),
        "summary_sha256": sha256_file(args.summary),
        "runner_sha256": sha256_file(args.runner),
        "auditor_sha256": sha256_file(Path(__file__).resolve()),
        "binary_sha256": sha256_file(args.binary),
        "yices_sha256": sha256_file(args.yices),
        "selected_paths": [TARGET_PATH],
        "observation_count": len(observations),
        "checks": evaluation["checks"],
    }
    immutable_write(args.receipt_out, canonical_json_bytes(receipt))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return receipt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--control-manifest", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--stage0-records", type=Path, required=True)
    parser.add_argument("--stage0-summary", type=Path, required=True)
    parser.add_argument("--stage0-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--yices", type=Path, required=True)
    parser.add_argument("--yices-version", required=True)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    try:
        receipt = audit(parse_args())
    except (AuditError, OSError, KeyError) as error:
        print(f"T9 Stage1 audit rejected: {error}", file=os.sys.stderr)
        return 2
    return 0 if receipt["scientific_decision"] == "pass" else 3


if __name__ == "__main__":
    raise SystemExit(main())
