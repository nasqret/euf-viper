#!/usr/bin/env python3
"""Audit complete rollback-control journals and apply the preregistered gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import statistics
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping


AUDIT_SCHEMA = "rollback-control-audit-v1"
JOURNAL_SCHEMA = "rollback-control-journal-v1"
LABELS = ("baseline", "candidate")
COMPARISONS = ("current", "model-cuts", "dynamic")
DECISIVE_RESULTS = {"sat", "unsat"}
CONTROL_CLASSES = {"target", "anti-target"}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

BASELINE_CONFIGS: dict[str, dict[str, str]] = {
    "current": {
        "EUF_VIPER_BACKEND": "cadical-refine",
        "EUF_VIPER_FULL_ACKERMANN": "off",
        "EUF_VIPER_PROFILE": "1",
        "EUF_VIPER_REFINEMENT_MODE": "current",
    },
    "model-cuts": {
        "EUF_VIPER_BACKEND": "cadical-refine",
        "EUF_VIPER_FULL_ACKERMANN": "off",
        "EUF_VIPER_PROFILE": "1",
        "EUF_VIPER_REFINEMENT_MODE": "model-cuts",
    },
    "dynamic": {
        "EUF_VIPER_BACKEND": "auto",
        "EUF_VIPER_FULL_ACKERMANN": "auto",
        "EUF_VIPER_PROFILE": "1",
        "EUF_VIPER_REFINEMENT_MODE": "current",
    },
}
CANDIDATE_CONFIG = {
    "EUF_VIPER_BACKEND": "cadical-rollback",
    "EUF_VIPER_PROFILE": "1",
}

PLAN_KEYS = {
    "argv_template",
    "binary_path",
    "binary_sha256",
    "binary_size",
    "clean_environment_sha256",
    "comparison",
    "cpu_affinity",
    "environment_sha256",
    "host",
    "journal_schema",
    "labels",
    "manifest_path",
    "manifest_rows",
    "manifest_sha256",
    "order",
    "previous_record_sha256",
    "record_hash",
    "record_type",
    "removed_ambient_euf_viper",
    "repeats",
    "schema_version",
    "selected_rows",
    "shard",
    "solver_environment",
    "timeout_s",
}
OBSERVATION_KEYS = {
    "argv",
    "binary_sha256",
    "comparison",
    "control_class",
    "environment_sha256",
    "exit_code",
    "expected_status",
    "key",
    "label",
    "manifest_index",
    "order_slot",
    "outcome",
    "previous_record_sha256",
    "profile",
    "record_hash",
    "record_type",
    "relative_path",
    "repeat",
    "result",
    "result_token",
    "schema_version",
    "sequence",
    "source_bytes",
    "source_path",
    "source_sha256",
    "spawn_error",
    "stats",
    "stderr_bytes",
    "stderr_excerpt",
    "stderr_sha256",
    "stdout_bytes",
    "stdout_excerpt",
    "stdout_sha256",
    "timed_out",
    "wall_time_ns",
}


class AuditError(RuntimeError):
    """Raised when benchmark evidence is malformed, incomplete, or unbound."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuditError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise AuditError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def record_hash(record: Mapping[str, Any]) -> str:
    unhashed = dict(record)
    unhashed.pop("record_hash", None)
    return sha256_bytes(canonical_bytes(unhashed))


def parse_json(line: str, context: str) -> dict[str, Any]:
    try:
        value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, AuditError) as error:
        raise AuditError(f"{context}: invalid JSON: {error}") from error
    if type(value) is not dict:
        raise AuditError(f"{context}: record must be an object")
    return value


def require_exact_keys(value: Mapping[str, Any], keys: set[str], context: str) -> None:
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        raise AuditError(f"{context}: key mismatch; missing={missing}, extra={extra}")


def require_hash(value: Any, context: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise AuditError(f"{context}: invalid SHA-256")
    return value


def load_manifest(path: Path) -> tuple[list[dict[str, Any]], str]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise AuditError(f"cannot read manifest {path}: {error}") from error
    if not raw or not raw.endswith(b"\n"):
        raise AuditError(f"manifest {path} is empty or lacks a final newline")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise AuditError(f"{path}:{line_number}: blank record")
        row = parse_json(line, f"{path}:{line_number}")
        for field in ("relative_path", "path", "sha256", "status", "control_class"):
            if type(row.get(field)) is not str or not row[field]:
                raise AuditError(f"{path}:{line_number}: invalid {field}")
        relative_path = row["relative_path"]
        if relative_path in seen:
            raise AuditError(f"{path}:{line_number}: duplicate {relative_path!r}")
        require_hash(row["sha256"], f"{path}:{line_number}.sha256")
        if row["status"] not in DECISIVE_RESULTS:
            raise AuditError(f"{path}:{line_number}: status is not sat/unsat")
        if row["control_class"] not in CONTROL_CLASSES:
            raise AuditError(f"{path}:{line_number}: invalid control_class")
        if type(row.get("bytes")) is not int or row["bytes"] < 0:
            raise AuditError(f"{path}:{line_number}: invalid bytes")
        seen.add(relative_path)
        rows.append(row)
    if not any(row["control_class"] == "target" for row in rows):
        raise AuditError("manifest has no target rows")
    if not any(row["control_class"] == "anti-target" for row in rows):
        raise AuditError("manifest has no anti-target rows")
    return rows, sha256_bytes(raw)


def classify_observation(
    *, expected_status: str, token: str | None, exit_code: int | None, timed_out: bool
) -> tuple[str, str]:
    if timed_out:
        return "timeout", "coverage_miss"
    if exit_code == 3:
        return "unsupported", "coverage_miss"
    if exit_code != 0:
        return token or "execution-error", "execution_error"
    if token in DECISIVE_RESULTS:
        return token, "correct" if token == expected_status else "wrong"
    return token or "malformed-output", "execution_error"


def validate_profile(value: Any, context: str) -> dict[str, dict[str, int]]:
    if type(value) is not dict:
        raise AuditError(f"{context}: profile must be an object")
    validated: dict[str, dict[str, int]] = {}
    for name, phase in value.items():
        if type(name) is not str or not name or type(phase) is not dict:
            raise AuditError(f"{context}: malformed profile phase")
        require_exact_keys(phase, {"elapsed_ns", "count"}, f"{context}.{name}")
        if any(type(phase[field]) is not int or phase[field] < 0 for field in phase):
            raise AuditError(f"{context}.{name}: metrics must be non-negative integers")
        validated[name] = phase
    return validated


def validate_stats(value: Any, context: str) -> dict[str, int]:
    if type(value) is not dict:
        raise AuditError(f"{context}: stats must be an object")
    for name, metric in value.items():
        if type(name) is not str or not name:
            raise AuditError(f"{context}: invalid stats key")
        if type(metric) is not int or metric < 0:
            raise AuditError(f"{context}.{name}: metric must be non-negative")
    return value


def expected_solver_environment(comparison: str) -> dict[str, dict[str, str]]:
    return {
        "baseline": BASELINE_CONFIGS[comparison],
        "candidate": CANDIDATE_CONFIG,
    }


def validate_plan(
    plan: dict[str, Any],
    *,
    context: str,
    manifest: Path,
    manifest_sha256: str,
    manifest_rows: int,
    requested_comparisons: set[str],
    requested_repeats: int | None,
    verified_binaries: set[tuple[str, int, str]] | None = None,
) -> None:
    require_exact_keys(plan, PLAN_KEYS, context)
    if plan["record_type"] != "plan" or plan["schema_version"] != 1:
        raise AuditError(f"{context}: incompatible plan schema")
    if plan["journal_schema"] != JOURNAL_SCHEMA:
        raise AuditError(f"{context}: incompatible journal schema")
    comparison = plan["comparison"]
    if comparison not in requested_comparisons:
        raise AuditError(f"{context}: unexpected comparison {comparison!r}")
    if plan["manifest_sha256"] != manifest_sha256:
        raise AuditError(f"{context}: manifest hash mismatch")
    if plan["manifest_path"] != str(manifest.resolve()):
        raise AuditError(f"{context}: manifest path mismatch")
    if plan["manifest_rows"] != manifest_rows:
        raise AuditError(f"{context}: manifest row count mismatch")
    if type(plan["selected_rows"]) is not int or plan["selected_rows"] < 0:
        raise AuditError(f"{context}: invalid selected row count")
    require_hash(plan["binary_sha256"], f"{context}.binary_sha256")
    require_hash(
        plan["clean_environment_sha256"],
        f"{context}.clean_environment_sha256",
    )
    if type(plan["binary_path"]) is not str or not plan["binary_path"]:
        raise AuditError(f"{context}: invalid binary path")
    if type(plan["binary_size"]) is not int or plan["binary_size"] < 1:
        raise AuditError(f"{context}: invalid binary size")
    binary_key = (
        plan["binary_path"],
        plan["binary_size"],
        plan["binary_sha256"],
    )
    if verified_binaries is None or binary_key not in verified_binaries:
        binary = Path(plan["binary_path"])
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise AuditError(f"{context}: bound binary is unavailable or not executable")
        if binary.stat().st_size != plan["binary_size"]:
            raise AuditError(f"{context}: bound binary size drift")
        if sha256_file(binary) != plan["binary_sha256"]:
            raise AuditError(f"{context}: bound binary hash drift")
        if verified_binaries is not None:
            verified_binaries.add(binary_key)
    if plan["labels"] != list(LABELS) or plan["order"] != "ABBA":
        raise AuditError(f"{context}: label/order contract drift")
    if (
        type(plan["repeats"]) is not int
        or plan["repeats"] < 2
        or plan["repeats"] % 2 != 0
    ):
        raise AuditError(f"{context}: repeats must contain complete ABBA blocks")
    if requested_repeats is not None and plan["repeats"] != requested_repeats:
        raise AuditError(f"{context}: repeat count does not match the audit request")
    if (
        type(plan["timeout_s"]) not in (int, float)
        or not math.isfinite(plan["timeout_s"])
        or plan["timeout_s"] <= 0
    ):
        raise AuditError(f"{context}: invalid timeout")
    if type(plan["host"]) is not str or not plan["host"]:
        raise AuditError(f"{context}: invalid host")
    if plan["solver_environment"] != expected_solver_environment(comparison):
        raise AuditError(f"{context}: solver environment drift")
    if set(plan["environment_sha256"]) != set(LABELS):
        raise AuditError(f"{context}: environment hash labels drift")
    for label in LABELS:
        require_hash(
            plan["environment_sha256"][label],
            f"{context}.environment_sha256.{label}",
        )
    removed = plan["removed_ambient_euf_viper"]
    if (
        type(removed) is not list
        or removed != sorted(set(removed))
        or any(type(key) is not str or not key.startswith("EUF_VIPER_") for key in removed)
    ):
        raise AuditError(f"{context}: invalid removed ambient variable ledger")
    expected_argv = [plan["binary_path"], "solve", "--stats", "{source}"]
    if plan["argv_template"] != expected_argv:
        raise AuditError(f"{context}: argv template drift")
    affinity = plan["cpu_affinity"]
    if type(affinity) is not dict:
        raise AuditError(f"{context}: cpu_affinity must be an object")
    require_exact_keys(
        affinity,
        {"cpu_ids", "expected_cpu_ids", "mechanism", "single_cpu_required"},
        f"{context}.cpu_affinity",
    )
    cpu_ids = affinity["cpu_ids"]
    expected_cpu_ids = affinity["expected_cpu_ids"]
    if (
        type(cpu_ids) is not list
        or any(type(cpu_id) is not int or cpu_id < 0 for cpu_id in cpu_ids)
        or cpu_ids != sorted(set(cpu_ids))
        or type(affinity["single_cpu_required"]) is not bool
    ):
        raise AuditError(f"{context}: invalid CPU affinity ids")
    if affinity["mechanism"] == "unavailable":
        if cpu_ids or expected_cpu_ids is not None or affinity["single_cpu_required"]:
            raise AuditError(f"{context}: unavailable CPU affinity is inconsistent")
    elif affinity["mechanism"] == "sched_getaffinity":
        if not cpu_ids:
            raise AuditError(f"{context}: verified CPU affinity cannot be empty")
        if expected_cpu_ids is not None and expected_cpu_ids != cpu_ids:
            raise AuditError(f"{context}: expected CPU affinity was not satisfied")
        if affinity["single_cpu_required"] and len(cpu_ids) != 1:
            raise AuditError(f"{context}: declared single-CPU affinity is not singleton")
    else:
        raise AuditError(f"{context}: unknown CPU affinity mechanism")
    shard = plan["shard"]
    if type(shard) is not dict:
        raise AuditError(f"{context}: shard must be an object")
    require_exact_keys(shard, {"count", "index", "mechanism"}, f"{context}.shard")
    if (
        type(shard["count"]) is not int
        or type(shard["index"]) is not int
        or shard["count"] < 1
        or not 0 <= shard["index"] < shard["count"]
        or shard["mechanism"] != "manifest-index-modulo"
    ):
        raise AuditError(f"{context}: invalid modulo shard")


def validate_observation(
    observation: dict[str, Any],
    *,
    context: str,
    plan: Mapping[str, Any],
    row: Mapping[str, Any],
    manifest_index: int,
    repeat: int,
    label: str,
    order_slot: int,
    sequence: int,
    verified_sources: set[tuple[str, int, str]] | None = None,
) -> None:
    require_exact_keys(observation, OBSERVATION_KEYS, context)
    if observation["record_type"] != "observation" or observation["schema_version"] != 1:
        raise AuditError(f"{context}: incompatible observation schema")
    expected_static = {
        "binary_sha256": plan["binary_sha256"],
        "comparison": plan["comparison"],
        "control_class": row["control_class"],
        "environment_sha256": plan["environment_sha256"][label],
        "expected_status": row["status"],
        "key": {
            "comparison": plan["comparison"],
            "label": label,
            "relative_path": row["relative_path"],
            "repeat": repeat,
        },
        "label": label,
        "manifest_index": manifest_index,
        "order_slot": order_slot,
        "relative_path": row["relative_path"],
        "repeat": repeat,
        "sequence": sequence,
        "source_bytes": row["bytes"],
        "source_path": row["path"],
        "source_sha256": row["sha256"],
    }
    for field, expected in expected_static.items():
        if observation[field] != expected:
            raise AuditError(f"{context}: bound field {field!r} drifted")
    argv = observation["argv"]
    if (
        type(argv) is not list
        or len(argv) != 4
        or argv[:3] != [plan["binary_path"], "solve", "--stats"]
        or type(argv[3]) is not str
    ):
        raise AuditError(f"{context}: argv drift")
    executed_source = Path(argv[3])
    source_key = (str(executed_source), row["bytes"], row["sha256"])
    if verified_sources is None or source_key not in verified_sources:
        if not executed_source.is_file():
            raise AuditError(f"{context}: executed source is unavailable")
        if (
            executed_source.stat().st_size != row["bytes"]
            or sha256_file(executed_source) != row["sha256"]
        ):
            raise AuditError(f"{context}: executed source does not match the manifest")
        if verified_sources is not None:
            verified_sources.add(source_key)
    if type(observation["wall_time_ns"]) is not int or observation["wall_time_ns"] < 1:
        raise AuditError(f"{context}: invalid wall time")
    if type(observation["timed_out"]) is not bool:
        raise AuditError(f"{context}: timed_out must be boolean")
    if observation["exit_code"] is not None and type(observation["exit_code"]) is not int:
        raise AuditError(f"{context}: exit_code must be an integer or null")
    if observation["result_token"] not in {None, "sat", "unsat", "unsupported"}:
        raise AuditError(f"{context}: invalid result token")
    if observation["spawn_error"] is not None and type(observation["spawn_error"]) is not str:
        raise AuditError(f"{context}: invalid spawn error")
    for field in ("stdout_sha256", "stderr_sha256"):
        require_hash(observation[field], f"{context}.{field}")
    for field in ("stdout_bytes", "stderr_bytes"):
        if type(observation[field]) is not int or observation[field] < 0:
            raise AuditError(f"{context}: invalid {field}")
    for field in ("stdout_excerpt", "stderr_excerpt"):
        if type(observation[field]) is not str:
            raise AuditError(f"{context}: invalid {field}")
    validate_profile(observation["profile"], f"{context}.profile")
    validate_stats(observation["stats"], f"{context}.stats")
    expected_result, expected_outcome = classify_observation(
        expected_status=row["status"],
        token=observation["result_token"],
        exit_code=observation["exit_code"],
        timed_out=observation["timed_out"],
    )
    if observation["result"] != expected_result or observation["outcome"] != expected_outcome:
        raise AuditError(f"{context}: result classification drift")


def read_journal(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise AuditError(f"cannot read journal {path}: {error}") from error
    if not raw or not raw.endswith(b"\n"):
        raise AuditError(f"journal {path} is empty or partial")
    records: list[dict[str, Any]] = []
    previous: str | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise AuditError(f"{path}:{line_number}: blank record")
        record = parse_json(line, f"{path}:{line_number}")
        if canonical_bytes(record) != (line + "\n").encode("ascii"):
            raise AuditError(f"{path}:{line_number}: record is not canonical JSON")
        if record.get("previous_record_sha256") != previous:
            raise AuditError(f"{path}:{line_number}: broken record hash chain")
        digest = require_hash(record.get("record_hash"), f"{path}:{line_number}.record_hash")
        if record_hash(record) != digest:
            raise AuditError(f"{path}:{line_number}: record hash drift")
        records.append(record)
        previous = digest
    if records[0].get("record_type") != "plan":
        raise AuditError(f"journal {path} does not start with a plan")
    if any(record.get("record_type") != "observation" for record in records[1:]):
        raise AuditError(f"journal {path} contains an unexpected record type")
    assert previous is not None
    return records[0], records[1:], previous


def abba_labels(repeat: int) -> tuple[str, str]:
    return LABELS if repeat % 2 == 0 else tuple(reversed(LABELS))


def phase_metric(observation: Mapping[str, Any], phase: str, field: str) -> int:
    return observation["profile"].get(phase, {}).get(field, 0)


def baseline_complete_validations(observation: Mapping[str, Any]) -> int:
    return phase_metric(observation, "kissat_validation", "count") + phase_metric(
        observation, "cadical_refine_validation", "count"
    )


def candidate_complete_validations(observation: Mapping[str, Any]) -> int:
    return phase_metric(
        observation, "cadical_rollback_complete_validations", "count"
    )


def median(values: Iterable[int | float]) -> float | None:
    materialized = list(values)
    return float(statistics.median(materialized)) if materialized else None


def geometric_mean(values: Iterable[float]) -> float | None:
    materialized = list(values)
    if not materialized or any(value <= 0 or not math.isfinite(value) for value in materialized):
        return None
    return math.exp(statistics.fmean(math.log(value) for value in materialized))


def percentile_nearest_rank(values: Iterable[float], percentile: float) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def label_metrics(observations: list[dict[str, Any]], repeats: int) -> dict[str, Any]:
    phase_names = sorted(
        {name for observation in observations for name in observation["profile"]}
    )
    stat_names = sorted(
        {name for observation in observations for name in observation["stats"]}
    )
    return {
        "complete_validations_median": median(
            baseline_complete_validations(observation)
            if observation["label"] == "baseline"
            else candidate_complete_validations(observation)
            for observation in observations
        ),
        "covered": len(observations) == repeats
        and all(observation["outcome"] == "correct" for observation in observations),
        "outcomes": dict(sorted(Counter(o["outcome"] for o in observations).items())),
        "profile_medians": {
            name: {
                "count": median(
                    phase_metric(observation, name, "count")
                    for observation in observations
                ),
                "elapsed_ns": median(
                    phase_metric(observation, name, "elapsed_ns")
                    for observation in observations
                ),
            }
            for name in phase_names
        },
        "results": dict(sorted(Counter(o["result"] for o in observations).items())),
        "stats_medians": {
            name: median(observation["stats"].get(name, 0) for observation in observations)
            for name in stat_names
        },
        "wall_time_s_median": (
            median(observation["wall_time_ns"] for observation in observations) / 1e9
            if observations
            else None
        ),
    }


def aggregate_label_metrics(observations: list[dict[str, Any]]) -> dict[str, Any]:
    phase_names = sorted(
        {name for observation in observations for name in observation["profile"]}
    )
    return {
        "complete_validations_median": median(
            baseline_complete_validations(observation)
            if observation["label"] == "baseline"
            else candidate_complete_validations(observation)
            for observation in observations
        ),
        "profile_medians": {
            name: {
                "count": median(
                    phase_metric(observation, name, "count")
                    for observation in observations
                ),
                "elapsed_ns": median(
                    phase_metric(observation, name, "elapsed_ns")
                    for observation in observations
                ),
            }
            for name in phase_names
        },
        "wall_time_s_median": (
            median(observation["wall_time_ns"] for observation in observations) / 1e9
            if observations
            else None
        ),
    }


def summarize_comparison(
    *,
    comparison: str,
    rows: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    repeats: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        grouped[(observation["relative_path"], observation["label"])].append(
            observation
        )

    paths: dict[str, Any] = {}
    coverage = {label: 0 for label in LABELS}
    baseline_only: list[str] = []
    candidate_only: list[str] = []
    target_speedups: list[float] = []
    anti_overheads: list[float] = []
    multi_round_targets: list[str] = []
    validation_failures: list[str] = []
    conflict_failures: list[str] = []
    for row in rows:
        relative_path = row["relative_path"]
        labels = {
            label: label_metrics(grouped[(relative_path, label)], repeats)
            for label in LABELS
        }
        for label in LABELS:
            coverage[label] += int(labels[label]["covered"])
        if labels["baseline"]["covered"] and not labels["candidate"]["covered"]:
            baseline_only.append(relative_path)
        if labels["candidate"]["covered"] and not labels["baseline"]["covered"]:
            candidate_only.append(relative_path)
        speedup: float | None = None
        if labels["baseline"]["covered"] and labels["candidate"]["covered"]:
            baseline_wall = labels["baseline"]["wall_time_s_median"]
            candidate_wall = labels["candidate"]["wall_time_s_median"]
            if baseline_wall is not None and candidate_wall is not None and candidate_wall > 0:
                speedup = baseline_wall / candidate_wall
                if row["control_class"] == "target":
                    target_speedups.append(speedup)
                else:
                    anti_overheads.append(candidate_wall / baseline_wall)
        baseline_validations = labels["baseline"]["complete_validations_median"]
        candidate_validations = labels["candidate"]["complete_validations_median"]
        multi_round = (
            row["control_class"] == "target"
            and labels["baseline"]["covered"]
            and labels["candidate"]["covered"]
            and baseline_validations is not None
            and baseline_validations > 1
        )
        replay_conflicts = [
            phase_metric(observation, "cadical_rollback_conflicts", "count")
            for observation in grouped[(relative_path, "candidate")]
        ]
        model_checks = [
            phase_metric(
                observation,
                "cadical_rollback_propagator_model_checks",
                "count",
            )
            for observation in grouped[(relative_path, "candidate")]
        ]
        if multi_round:
            multi_round_targets.append(relative_path)
            if candidate_validations is None or candidate_validations >= baseline_validations:
                validation_failures.append(relative_path)
            if not replay_conflicts or min(replay_conflicts) < 1:
                conflict_failures.append(relative_path)
        paths[relative_path] = {
            "candidate_model_checks_median": median(model_checks),
            "candidate_replay_conflicts_median": median(replay_conflicts),
            "control_class": row["control_class"],
            "labels": labels,
            "multi_round_target": multi_round,
            "speedup": speedup,
        }

    label_aggregate = {
        label: aggregate_label_metrics(
            [observation for observation in observations if observation["label"] == label]
        )
        for label in LABELS
    }
    wrong = [observation for observation in observations if observation["outcome"] == "wrong"]
    errors = [
        observation
        for observation in observations
        if observation["outcome"] == "execution_error"
    ]
    summary = {
        "aggregate": label_aggregate,
        "anti_target_common_paths": len(anti_overheads),
        "anti_target_p95_overhead": percentile_nearest_rank(anti_overheads, 0.95),
        "baseline_only_paths": sorted(baseline_only),
        "candidate_only_paths": sorted(candidate_only),
        "comparison": comparison,
        "coverage": coverage,
        "execution_errors": len(errors),
        "multi_round_conflict_failures": sorted(conflict_failures),
        "multi_round_target_count": len(multi_round_targets),
        "multi_round_targets": sorted(multi_round_targets),
        "multi_round_validation_failures": sorted(validation_failures),
        "paths": paths,
        "target_common_paths": len(target_speedups),
        "target_geometric_speedup": geometric_mean(target_speedups),
        "wrong_answers": len(wrong),
    }
    gate_inputs = {
        "anti_target_p95_overhead": summary["anti_target_p95_overhead"],
        "baseline_only": baseline_only,
        "candidate_coverage": coverage["candidate"],
        "conflict_failures": conflict_failures,
        "errors": len(errors),
        "baseline_coverage": coverage["baseline"],
        "multi_round_count": len(multi_round_targets),
        "target_geometric_speedup": summary["target_geometric_speedup"],
        "validation_failures": validation_failures,
        "wrong": len(wrong),
    }
    return summary, gate_inputs


def gate_check(name: str, passed: bool, detail: Mapping[str, Any]) -> dict[str, Any]:
    return {"check": name, "detail": dict(detail), "passed": bool(passed)}


def apply_gate(
    gate_inputs: Mapping[str, Mapping[str, Any]],
    *,
    min_multi_round_targets: int,
    target_speedup_threshold: float,
    anti_target_overhead_threshold: float,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    total_wrong = sum(value["wrong"] for value in gate_inputs.values())
    total_errors = sum(value["errors"] for value in gate_inputs.values())
    checks.append(
        gate_check(
            "zero_wrong_answers_and_execution_errors",
            total_wrong == 0 and total_errors == 0,
            {"execution_errors": total_errors, "wrong_answers": total_wrong},
        )
    )
    for comparison in sorted(gate_inputs):
        value = gate_inputs[comparison]
        prefix = f"{comparison}:"
        checks.extend(
            (
                gate_check(
                    prefix + "no_baseline_only_solve",
                    not value["baseline_only"],
                    {"paths": sorted(value["baseline_only"])},
                ),
                gate_check(
                    prefix + "candidate_coverage_at_least_baseline",
                    value["candidate_coverage"] >= value["baseline_coverage"],
                    {
                        "baseline": value["baseline_coverage"],
                        "candidate": value["candidate_coverage"],
                    },
                ),
                gate_check(
                    prefix + "minimum_multi_round_targets",
                    value["multi_round_count"] >= min_multi_round_targets,
                    {
                        "actual": value["multi_round_count"],
                        "minimum": min_multi_round_targets,
                    },
                ),
                gate_check(
                    prefix + "fewer_validations_on_every_multi_round_target",
                    value["multi_round_count"] >= min_multi_round_targets
                    and not value["validation_failures"],
                    {"failed_paths": sorted(value["validation_failures"])},
                ),
                gate_check(
                    prefix + "replay_conflicts_on_every_multi_round_target",
                    value["multi_round_count"] >= min_multi_round_targets
                    and not value["conflict_failures"],
                    {"failed_paths": sorted(value["conflict_failures"])},
                ),
                gate_check(
                    prefix + "target_geometric_speedup",
                    value["target_geometric_speedup"] is not None
                    and value["target_geometric_speedup"] >= target_speedup_threshold,
                    {
                        "actual": value["target_geometric_speedup"],
                        "minimum": target_speedup_threshold,
                    },
                ),
                gate_check(
                    prefix + "anti_target_p95_overhead",
                    value["anti_target_p95_overhead"] is not None
                    and value["anti_target_p95_overhead"]
                    <= anti_target_overhead_threshold,
                    {
                        "actual": value["anti_target_p95_overhead"],
                        "maximum": anti_target_overhead_threshold,
                    },
                ),
            )
        )
    return checks


def audit(
    *,
    manifest: Path,
    journals: list[Path],
    comparisons: tuple[str, ...],
    repeats: int | None,
    min_multi_round_targets: int,
    target_speedup_threshold: float,
    anti_target_overhead_threshold: float,
    require_single_cpu_binding: bool = False,
) -> dict[str, Any]:
    rows, manifest_sha256 = load_manifest(manifest)
    requested_comparisons = set(comparisons)
    if not journals:
        raise AuditError("at least one journal is required")
    loaded: list[tuple[Path, dict[str, Any], list[dict[str, Any]], str]] = []
    inferred_repeats: set[int] = set()
    verified_binaries: set[tuple[str, int, str]] = set()
    for path in journals:
        plan, observations, chain_head = read_journal(path)
        validate_plan(
            plan,
            context=f"journal {path} plan",
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            manifest_rows=len(rows),
            requested_comparisons=requested_comparisons,
            requested_repeats=repeats,
            verified_binaries=verified_binaries,
        )
        inferred_repeats.add(plan["repeats"])
        if require_single_cpu_binding and not (
            plan["cpu_affinity"]["mechanism"] == "sched_getaffinity"
            and plan["cpu_affinity"]["single_cpu_required"]
            and len(plan["cpu_affinity"]["cpu_ids"]) == 1
        ):
            raise AuditError(
                f"journal {path} was not run with a verified single-CPU binding"
            )
        loaded.append((path, plan, observations, chain_head))
    if len(inferred_repeats) != 1:
        raise AuditError("journals disagree on repeat count")
    effective_repeats = repeats if repeats is not None else next(iter(inferred_repeats))

    plans: dict[tuple[str, int], dict[str, Any]] = {}
    shard_counts: set[int] = set()
    binary_hashes: set[str] = set()
    all_observations: list[dict[str, Any]] = []
    journal_bindings: list[dict[str, Any]] = []
    global_keys: set[tuple[str, str, str, int]] = set()
    verified_sources: set[tuple[str, int, str]] = set()
    for path, plan, observations, chain_head in loaded:
        comparison = plan["comparison"]
        shard_index = plan["shard"]["index"]
        shard_count = plan["shard"]["count"]
        plan_key = (comparison, shard_index)
        if plan_key in plans:
            raise AuditError(f"duplicate plan for comparison/shard {plan_key}")
        plans[plan_key] = plan
        shard_counts.add(shard_count)
        binary_hashes.add(plan["binary_sha256"])
        selected = [
            (index, row)
            for index, row in enumerate(rows)
            if index % shard_count == shard_index
        ]
        if plan["selected_rows"] != len(selected):
            raise AuditError(f"journal {path}: selected row count drift")
        expected_count = len(selected) * len(LABELS) * effective_repeats
        if len(observations) != expected_count:
            raise AuditError(
                f"journal {path}: expected {expected_count} observations, "
                f"found {len(observations)}"
            )
        sequence = 0
        for manifest_index, row in selected:
            for repeat_index in range(effective_repeats):
                for order_slot, label in enumerate(abba_labels(repeat_index)):
                    observation = observations[sequence]
                    validate_observation(
                        observation,
                        context=f"journal {path} observation {sequence}",
                        plan=plan,
                        row=row,
                        manifest_index=manifest_index,
                        repeat=repeat_index,
                        label=label,
                        order_slot=order_slot,
                        sequence=sequence,
                        verified_sources=verified_sources,
                    )
                    key = (
                        comparison,
                        row["relative_path"],
                        label,
                        repeat_index,
                    )
                    if key in global_keys:
                        raise AuditError(f"duplicate observation key {key}")
                    global_keys.add(key)
                    all_observations.append(observation)
                    sequence += 1
        journal_bindings.append(
            {
                "chain_head": chain_head,
                "comparison": comparison,
                "cpu_affinity": plan["cpu_affinity"],
                "journal_sha256": sha256_file(path),
                "path": str(path.resolve()),
                "plan_record_hash": plan["record_hash"],
                "shard": plan["shard"],
            }
        )
    if len(shard_counts) != 1:
        raise AuditError("journals disagree on shard count")
    shard_count = next(iter(shard_counts))
    expected_plan_keys = {
        (comparison, shard_index)
        for comparison in requested_comparisons
        for shard_index in range(shard_count)
    }
    if set(plans) != expected_plan_keys:
        missing = sorted(expected_plan_keys - set(plans))
        extra = sorted(set(plans) - expected_plan_keys)
        raise AuditError(f"plan cross-product mismatch; missing={missing}, extra={extra}")
    if len(binary_hashes) != 1:
        raise AuditError("comparison journals do not use one same binary")
    expected_keys = {
        (comparison, row["relative_path"], label, repeat_index)
        for comparison in requested_comparisons
        for row in rows
        for label in LABELS
        for repeat_index in range(effective_repeats)
    }
    if global_keys != expected_keys:
        missing = sorted(expected_keys - global_keys)[:20]
        extra = sorted(global_keys - expected_keys)[:20]
        raise AuditError(
            f"observation cross-product mismatch; missing={missing}, extra={extra}"
        )

    comparison_summaries: dict[str, Any] = {}
    gate_inputs: dict[str, Any] = {}
    for comparison in comparisons:
        summary, inputs = summarize_comparison(
            comparison=comparison,
            rows=rows,
            observations=[
                observation
                for observation in all_observations
                if observation["comparison"] == comparison
            ],
            repeats=effective_repeats,
        )
        comparison_summaries[comparison] = summary
        gate_inputs[comparison] = inputs
    checks = apply_gate(
        gate_inputs,
        min_multi_round_targets=min_multi_round_targets,
        target_speedup_threshold=target_speedup_threshold,
        anti_target_overhead_threshold=anti_target_overhead_threshold,
    )
    passed = all(check["passed"] for check in checks)
    payload: dict[str, Any] = {
        "audit_sha256": "",
        "binary_sha256": next(iter(binary_hashes)),
        "checks": checks,
        "comparisons": comparison_summaries,
        "counts": {
            "comparisons": len(comparisons),
            "journals": len(journals),
            "manifest_rows": len(rows),
            "observations": len(all_observations),
            "repeats": effective_repeats,
            "shards": shard_count,
        },
        "errors": [],
        "journal_bindings": sorted(
            journal_bindings,
            key=lambda value: (value["comparison"], value["shard"]["index"]),
        ),
        "manifest_path": str(manifest.resolve()),
        "manifest_sha256": manifest_sha256,
        "resource_contract": {
            "single_cpu_binding_required": require_single_cpu_binding,
        },
        "schema_version": AUDIT_SCHEMA,
        "status": "pass" if passed else "reject",
        "thresholds": {
            "anti_target_p95_overhead_max": anti_target_overhead_threshold,
            "minimum_multi_round_targets_per_comparison": min_multi_round_targets,
            "target_geometric_speedup_min": target_speedup_threshold,
        },
    }
    payload["audit_sha256"] = sha256_bytes(canonical_bytes(payload))
    return payload


def invalid_payload(
    *, manifest: Path, journals: list[Path], error: str
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "audit_sha256": "",
        "errors": [error],
        "journals": [str(path.resolve()) for path in journals],
        "manifest_path": str(manifest.resolve()),
        "schema_version": AUDIT_SCHEMA,
        "status": "invalid",
    }
    payload["audit_sha256"] = sha256_bytes(canonical_bytes(payload))
    return payload


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise AuditError(f"refusing to overwrite audit {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--journal", type=Path, action="append", required=True)
    parser.add_argument("--comparison", choices=COMPARISONS, action="append")
    parser.add_argument("--repeats", type=int)
    parser.add_argument(
        "--min-multi-round-targets",
        "--minimum-multi-round-targets",
        dest="min_multi_round_targets",
        type=int,
        default=1,
    )
    parser.add_argument("--target-speedup", type=float, default=1.10)
    parser.add_argument("--anti-target-overhead", type=float, default=1.10)
    parser.add_argument(
        "--require-single-cpu",
        action="store_true",
        help="accept only plans that required and verified singleton CPU affinity",
    )
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if args.repeats is not None and (
        args.repeats < 2 or args.repeats % 2 != 0
    ):
        parser.error("--repeats must be a positive even count")
    if args.min_multi_round_targets < 1:
        parser.error("--min-multi-round-targets must be positive")
    for value, option in (
        (args.target_speedup, "--target-speedup"),
        (args.anti_target_overhead, "--anti-target-overhead"),
    ):
        if not math.isfinite(value) or value <= 0:
            parser.error(f"{option} must be a positive finite number")
    comparisons = tuple(args.comparison or COMPARISONS)
    if len(set(comparisons)) != len(comparisons):
        parser.error("--comparison values must be unique")
    if args.out.exists():
        parser.error("--out already exists")
    try:
        payload = audit(
            manifest=args.manifest,
            journals=args.journal,
            comparisons=comparisons,
            repeats=args.repeats,
            min_multi_round_targets=args.min_multi_round_targets,
            target_speedup_threshold=args.target_speedup,
            anti_target_overhead_threshold=args.anti_target_overhead,
            require_single_cpu_binding=args.require_single_cpu,
        )
        atomic_write(args.out, canonical_bytes(payload))
    except Exception as error:
        payload = invalid_payload(
            manifest=args.manifest,
            journals=args.journal,
            error=str(error),
        )
        try:
            atomic_write(args.out, canonical_bytes(payload))
        except (AuditError, OSError) as write_error:
            print(f"rollback-control audit error: {error}; cannot emit audit: {write_error}", file=sys.stderr)
            return 2
        print(f"rollback-control audit invalid: {error}", file=sys.stderr)
        return 2
    print(f"rollback-control audit: {payload['status']}")
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
