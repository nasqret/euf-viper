#!/usr/bin/env python3
"""Publish a descriptor-bound, no-replace index for locked campaign analyses."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
CERT_DIR = ROOT / "scripts" / "cert"
WMI_DIR = ROOT / "scripts" / "wmi"
if str(CERT_DIR) not in sys.path:
    sys.path.insert(0, str(CERT_DIR))
if str(WMI_DIR) not in sys.path:
    sys.path.insert(0, str(WMI_DIR))

from strict_artifacts import (  # noqa: E402
    StrictArtifactError,
    assert_descriptor_path_nofollow,
    atomic_write_nofollow,
    canonical_json_bytes,
    open_read_nofollow,
    read_open_descriptor,
    strict_json_loads,
)
from hermetic_provenance import (  # noqa: E402
    ProvenanceError,
    verify_preparation_environment_compatibility,
)


SCHEMA = "euf-viper.locked-p0-audit.v4"
ANALYSIS_SCHEMA_VERSION = 1
HEX_DIGITS = frozenset("0123456789abcdef")

ANALYSIS_KEYS = {
    "schema_version",
    "status",
    "promoted",
    "inputs",
    "input_hashes",
    "configuration",
    "assumptions",
    "comparisons",
    "hypotheses",
    "promotion",
}
ANALYSIS_INPUT_KEYS = {
    "parent_lock",
    "shards",
    "campaign_id",
    "instances",
    "families",
    "budgets_s",
    "raw_records",
    "candidate_id",
    "baseline_ids",
}
ANALYSIS_HASH_KEYS = {
    "lock_file_sha256",
    "shard_bundle_sha256",
    "shard_lock_file_sha256",
    "shard_raw_sha256",
    "lock_sha256",
    "manifest_sha256",
    "taxonomy_sha256",
    "solver_binary_sha256",
}
ANALYSIS_SHARD_KEYS = {
    "index",
    "lock",
    "lock_file_sha256",
    "lock_sha256",
    "raw",
    "raw_sha256",
    "raw_records",
    "cpu_ids",
}
ANALYSIS_PROMOTION_KEYS = {
    "failed_comparisons",
    "lock_promotion_eligible",
    "passed",
    "status",
}
COMPARISON_KEYS = {
    "baseline_id",
    "candidate_id",
    "budgets",
    "promotion",
}
COMPARISON_PROMOTION_KEYS = {
    "failed_budgets",
    "passed",
    "status",
}
BUDGET_REPORT_KEYS = {
    "aggregate",
    "bootstrap",
    "budget_s",
    "families",
    "family_macro",
    "promotion",
    "statuses",
}
BUDGET_PROMOTION_KEYS = {"checks", "passed", "status"}
BUDGET_PROMOTION_CHECK_KEYS = {
    "zero_invalid_results",
    "zero_execution_errors",
    "zero_coverage_loss",
    "family_non_regression",
    "status_non_regression",
    "family_macro_non_regression",
    "timeout_charged_wall_bootstrap_lower_bound",
    "common_wall_total_bootstrap_lower_bound",
    "common_wall_geometric_bootstrap_lower_bound",
}
NON_REGRESSION_METRICS = (
    "timeout_charged_wall",
    "par2_wall",
    "common_wall_total",
    "common_wall_geometric",
)
REQUIRED_PROMOTION_METRICS = (
    "timeout_charged_wall",
    "common_wall_total",
    "common_wall_geometric",
)
PARENT_LOCK_KEYS = {
    "schema_version",
    "campaign_id",
    "lock_sha256",
    "created_from_commit_time",
    "promotion_eligible",
    "spec",
    "repository",
    "host",
    "corpus",
    "solver_config",
    "solver_release_lock",
    "solvers",
    "budgets_s",
    "execution",
    "output",
}
PARENT_REPOSITORY_KEYS = {
    "root",
    "commit",
    "commit_time",
    "clean",
    "promotion_eligible",
}
PARENT_CORPUS_KEYS = {
    "id",
    "manifest_path",
    "manifest_sha256",
    "taxonomy_path",
    "taxonomy_sha256",
    "root",
    "instances",
}
PARENT_INSTANCE_KEYS = {
    "id",
    "relative_path",
    "path",
    "sha256",
    "bytes",
    "status",
    "family",
    "lineage",
    "normalized_sha256",
    "split",
}
PARENT_SOLVER_KEYS = {
    "id",
    "comparator_id",
    "configuration",
    "version",
    "binary",
    "sha256",
    "argv_template",
    "version_output",
    "version_output_sha256",
    "environment",
}
CANDIDATE_ID = "euf-viper"
PREPARATION_KEYS = {
    "schema",
    "status",
    "attempt",
    "artifacts",
    "build_features",
    "corpus",
    "environment",
    "execution_environment",
    "feature_report",
    "hostname",
    "job",
    "paths",
    "revision",
    "runtime_tools",
    "shards",
    "solver_executables",
    "sealed_build",
    "execution_closure",
    "source",
    "submission_manifest_sha256",
    "viper",
}
PREPARATION_ARTIFACT_NAMES = {
    "solver-config.json",
    "taxonomy/full.jsonl",
    "taxonomy/full-split.json",
    "taxonomy/official.jsonl",
    "taxonomy/official-split.json",
    "locks/full-parent.json",
    "locks/official-parent.json",
}
SCHEDULER_RECEIPT_KEYS = {
    "schema",
    "status",
    "run_root",
    "revision",
    "submission_manifest_sha256",
    "preparation_receipt",
    "jobs",
    "shards",
    "parent_locks",
    "analyses",
}
VALIDATED_ANALYSIS_KEYS = {"sha256", "process_exit"}


class AuditFinalizeError(ValueError):
    """Raised when an analysis cannot be bound to one immutable index."""


@dataclass
class BoundArtifact:
    path: Path
    descriptor: int
    raw: bytes
    metadata: os.stat_result
    context: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


@dataclass
class BoundAnalysis(BoundArtifact):
    value: dict[str, Any]


def _exact_object(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise AuditFinalizeError(f"{context} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing keys {missing!r}")
        if extra:
            details.append(f"unexpected keys {extra!r}")
        raise AuditFinalizeError(f"{context} has " + " and ".join(details))
    return value


def _string(value: Any, context: str) -> str:
    if type(value) is not str or not value:
        raise AuditFinalizeError(f"{context} must be a non-empty string")
    return value


def _hash(value: Any, context: str) -> str:
    result = _string(value, context)
    if len(result) != 64 or any(character not in HEX_DIGITS for character in result):
        raise AuditFinalizeError(f"{context} must be a canonical SHA-256 digest")
    return result


def _integer(value: Any, context: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise AuditFinalizeError(f"{context} must be an integer at least {minimum}")
    return value


def _boolean(value: Any, context: str) -> bool:
    if type(value) is not bool:
        raise AuditFinalizeError(f"{context} must be boolean")
    return value


def _number(value: Any, context: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise AuditFinalizeError(f"{context} must be a finite number")
    return float(value)


def _count(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise AuditFinalizeError(f"{context} must be a non-negative integer")
    return value


def _same_json(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            _same_json(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _same_json(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return bool(left == right)


def _semantic_check(
    passed: bool,
    *,
    actual: Any,
    operator: str,
    threshold: Any,
    details: Any | None = None,
) -> dict[str, Any]:
    result = {
        "actual": actual,
        "operator": operator,
        "passed": passed,
        "threshold": threshold,
    }
    if details is not None:
        result["details"] = details
    return result


def _non_regression_failures(
    summaries: Any, group_type: str, context: str
) -> list[dict[str, Any]]:
    if type(summaries) is not dict:
        raise AuditFinalizeError(f"{context} must be an object")
    failures: list[dict[str, Any]] = []
    for name in sorted(summaries):
        if type(name) is not str or not name:
            raise AuditFinalizeError(f"{context} has an invalid group name")
        summary = summaries[name]
        if type(summary) is not dict:
            raise AuditFinalizeError(f"{context}[{name!r}] must be an object")
        coverage = summary.get("coverage")
        speedups = summary.get("speedups")
        if type(coverage) is not dict or type(speedups) is not dict:
            raise AuditFinalizeError(
                f"{context}[{name!r}] lacks coverage or speedup source data"
            )
        baseline_only = _count(
            coverage.get("baseline_only"),
            f"{context}[{name!r}].coverage.baseline_only",
        )
        if baseline_only:
            failures.append(
                {
                    "actual": baseline_only,
                    "group": name,
                    "group_type": group_type,
                    "metric": "baseline_only_solves",
                    "required": 0,
                }
            )
        for metric in NON_REGRESSION_METRICS:
            if metric not in speedups:
                raise AuditFinalizeError(
                    f"{context}[{name!r}].speedups lacks {metric!r}"
                )
            value = speedups[metric]
            if value is not None:
                _number(value, f"{context}[{name!r}].speedups[{metric!r}]")
                if value < 1.0:
                    failures.append(
                        {
                            "actual": value,
                            "group": name,
                            "group_type": group_type,
                            "metric": metric,
                            "required": 1.0,
                        }
                    )
    return failures


def _macro_non_regression_failures(value: Any, context: str) -> list[dict[str, Any]]:
    if type(value) is not dict or type(value.get("speedups")) is not dict:
        raise AuditFinalizeError(f"{context} lacks speedup source data")
    speedups = value["speedups"]
    if set(speedups) != set(NON_REGRESSION_METRICS):
        raise AuditFinalizeError(f"{context}.speedups has an incompatible metric set")
    failures: list[dict[str, Any]] = []
    for metric in sorted(speedups):
        if type(metric) is not str or not metric:
            raise AuditFinalizeError(f"{context}.speedups has an invalid metric")
        item = speedups[metric]
        if item is not None:
            _number(item, f"{context}.speedups[{metric!r}]")
            if item < 1.0:
                failures.append(
                    {"actual": item, "metric": metric, "required": 1.0}
                )
    return failures


def _recompute_budget_checks(
    budget: dict[str, Any], minimum_speedup: float, context: str
) -> dict[str, dict[str, Any]]:
    aggregate = budget["aggregate"]
    if type(aggregate) is not dict or type(aggregate.get("arms")) is not dict:
        raise AuditFinalizeError(f"{context}.aggregate lacks arm source data")
    statuses: dict[str, dict[str, Any]] = {}
    for label in ("baseline", "candidate"):
        arm = aggregate["arms"].get(label)
        if type(arm) is not dict or type(arm.get("statuses")) is not dict:
            raise AuditFinalizeError(
                f"{context}.aggregate.arms[{label!r}] lacks status source data"
            )
        statuses[label] = arm["statuses"]
    invalid_count = sum(
        _count(statuses[label].get("invalid"), f"{context}.{label}.invalid")
        for label in statuses
    )
    error_count = sum(
        _count(statuses[label].get("error"), f"{context}.{label}.error")
        for label in statuses
    )
    coverage = aggregate.get("coverage")
    if type(coverage) is not dict:
        raise AuditFinalizeError(f"{context}.aggregate.coverage must be an object")
    baseline_only = _count(
        coverage.get("baseline_only"),
        f"{context}.aggregate.coverage.baseline_only",
    )
    family_failures = _non_regression_failures(
        budget["families"], "family", f"{context}.families"
    )
    status_failures = _non_regression_failures(
        budget["statuses"], "expected_status", f"{context}.statuses"
    )
    macro_failures = _macro_non_regression_failures(
        budget["family_macro"], f"{context}.family_macro"
    )
    checks = {
        "zero_invalid_results": _semantic_check(
            invalid_count == 0, actual=invalid_count, operator="==", threshold=0
        ),
        "zero_execution_errors": _semantic_check(
            error_count == 0, actual=error_count, operator="==", threshold=0
        ),
        "zero_coverage_loss": _semantic_check(
            baseline_only == 0, actual=baseline_only, operator="==", threshold=0
        ),
        "family_non_regression": _semantic_check(
            not family_failures,
            actual=len(family_failures),
            operator="==",
            threshold=0,
            details=family_failures,
        ),
        "status_non_regression": _semantic_check(
            not status_failures,
            actual=len(status_failures),
            operator="==",
            threshold=0,
            details=status_failures,
        ),
        "family_macro_non_regression": _semantic_check(
            not macro_failures,
            actual=len(macro_failures),
            operator="==",
            threshold=0,
            details=macro_failures,
        ),
    }
    bootstrap = budget["bootstrap"]
    metrics = bootstrap.get("metrics") if type(bootstrap) is dict else None
    if type(metrics) is not dict:
        raise AuditFinalizeError(f"{context}.bootstrap.metrics must be an object")
    for metric in REQUIRED_PROMOTION_METRICS:
        interval = metrics.get(metric)
        if type(interval) is not dict or "ci_lower" not in interval:
            raise AuditFinalizeError(
                f"{context}.bootstrap.metrics[{metric!r}] lacks ci_lower"
            )
        lower = interval["ci_lower"]
        if lower is not None:
            _number(lower, f"{context}.bootstrap.metrics[{metric!r}].ci_lower")
        checks[f"{metric}_bootstrap_lower_bound"] = _semantic_check(
            lower is not None and lower > minimum_speedup,
            actual=lower,
            operator=">",
            threshold=minimum_speedup,
        )
    return checks


def _budget_names(value: Any, context: str) -> list[str]:
    if type(value) is not list or not value:
        raise AuditFinalizeError(f"{context} must be a non-empty array")
    budgets: list[float] = []
    for index, item in enumerate(value):
        if (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            or float(item) <= 0.0
        ):
            raise AuditFinalizeError(
                f"{context}[{index}] must be finite and positive"
            )
        budgets.append(float(item))
    if any(left >= right for left, right in zip(budgets, budgets[1:])):
        raise AuditFinalizeError(f"{context} must be strictly increasing")
    return [format(budget, ".17g") for budget in budgets]


def _string_list(value: Any, context: str, *, nonempty: bool = False) -> list[str]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise AuditFinalizeError(f"{context} must be a list of non-empty strings")
    if nonempty and not value:
        raise AuditFinalizeError(f"{context} must not be empty")
    return value


def _canonical_analysis_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise AuditFinalizeError(f"cannot canonicalize analysis binding: {error}") from error
    return (rendered + "\n").encode("utf-8")


def _open_artifact(path: Path, context: str, run_root: Path) -> BoundArtifact:
    descriptor = -1
    try:
        absolute, descriptor = open_read_nofollow(path, context)
        try:
            absolute.relative_to(run_root)
        except ValueError as error:
            raise AuditFinalizeError(f"{context} escapes the run root") from error
        raw, metadata = read_open_descriptor(descriptor, context)
        result = BoundArtifact(absolute, descriptor, raw, metadata, context)
        descriptor = -1
        return result
    except StrictArtifactError as error:
        raise AuditFinalizeError(str(error)) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_analysis(path: Path, kind: str, run_root: Path) -> BoundAnalysis:
    artifact = _open_artifact(path, f"{kind} global analysis", run_root)
    try:
        try:
            value = strict_json_loads(
                artifact.raw.decode("utf-8"), f"{kind} global analysis"
            )
        except (UnicodeError, StrictArtifactError) as error:
            raise AuditFinalizeError(str(error)) from error
        if type(value) is not dict:
            raise AuditFinalizeError(f"{kind} global analysis is not one JSON object")
        if stat.S_IMODE(artifact.metadata.st_mode) != 0o400:
            raise AuditFinalizeError(f"{kind} global analysis mode is not 0400")
        return BoundAnalysis(
            artifact.path,
            artifact.descriptor,
            artifact.raw,
            artifact.metadata,
            artifact.context,
            value,
        )
    except BaseException:
        os.close(artifact.descriptor)
        raise


def _validate_analysis_schema(
    value: dict[str, Any], kind: str, shard_count: int
) -> None:
    context = f"{kind} global analysis"
    _exact_object(value, ANALYSIS_KEYS, context)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != ANALYSIS_SCHEMA_VERSION
    ):
        raise AuditFinalizeError(f"{context} has an incompatible schema version")
    promoted = _boolean(value["promoted"], f"{context}.promoted")
    expected_status = "promoted" if promoted else "rejected"
    if value["status"] != expected_status:
        raise AuditFinalizeError(f"{context} status and promoted fields disagree")

    inputs = _exact_object(value["inputs"], ANALYSIS_INPUT_KEYS, f"{context}.inputs")
    _string(inputs["parent_lock"], f"{context}.inputs.parent_lock")
    _string(inputs["campaign_id"], f"{context}.inputs.campaign_id")
    _integer(inputs["instances"], f"{context}.inputs.instances", 1)
    _integer(inputs["families"], f"{context}.inputs.families", 1)
    _integer(inputs["raw_records"], f"{context}.inputs.raw_records", 1)
    candidate_id = _string(inputs["candidate_id"], f"{context}.inputs.candidate_id")
    baseline_ids = _string_list(
        inputs["baseline_ids"], f"{context}.inputs.baseline_ids", nonempty=True
    )
    if len(set(baseline_ids)) != len(baseline_ids) or candidate_id in baseline_ids:
        raise AuditFinalizeError(f"{context}.inputs solver ids are not distinct")
    budgets = inputs["budgets_s"]
    budget_names = _budget_names(budgets, f"{context}.inputs.budgets_s")

    shards = inputs["shards"]
    if type(shards) is not list or len(shards) != shard_count:
        raise AuditFinalizeError(
            f"{context}.inputs.shards must contain exactly {shard_count} entries"
        )
    shard_raw_records = 0
    for expected_index, item in enumerate(shards):
        shard = _exact_object(
            item, ANALYSIS_SHARD_KEYS, f"{context}.inputs.shards[{expected_index}]"
        )
        if (
            _integer(
                shard["index"],
                f"{context}.inputs.shards[{expected_index}].index",
            )
            != expected_index
        ):
            raise AuditFinalizeError(
                f"{context}.inputs.shards are not contiguous and sorted"
            )
        for field in ("lock", "raw"):
            _string(shard[field], f"{context}.inputs.shards[{expected_index}].{field}")
        for field in ("lock_file_sha256", "lock_sha256", "raw_sha256"):
            _hash(shard[field], f"{context}.inputs.shards[{expected_index}].{field}")
        shard_raw_records += _integer(
            shard["raw_records"],
            f"{context}.inputs.shards[{expected_index}].raw_records",
            1,
        )
        cpu_ids = shard["cpu_ids"]
        if (
            type(cpu_ids) is not list
            or not cpu_ids
            or any(type(cpu_id) is not int or cpu_id < 0 for cpu_id in cpu_ids)
            or len(set(cpu_ids)) != len(cpu_ids)
        ):
            raise AuditFinalizeError(
                f"{context}.inputs.shards[{expected_index}].cpu_ids is invalid"
            )
    if shard_raw_records != inputs["raw_records"]:
        raise AuditFinalizeError(f"{context}.inputs raw record counts disagree")

    hashes = _exact_object(
        value["input_hashes"], ANALYSIS_HASH_KEYS, f"{context}.input_hashes"
    )
    for field in (
        "lock_file_sha256",
        "shard_bundle_sha256",
        "lock_sha256",
        "manifest_sha256",
        "taxonomy_sha256",
    ):
        _hash(hashes[field], f"{context}.input_hashes.{field}")
    expected_indices = {str(index) for index in range(shard_count)}
    for field in ("shard_lock_file_sha256", "shard_raw_sha256"):
        mapping = _exact_object(
            hashes[field], expected_indices, f"{context}.input_hashes.{field}"
        )
        for index, digest in mapping.items():
            _hash(digest, f"{context}.input_hashes.{field}[{index!r}]")
    solver_hashes = _exact_object(
        hashes["solver_binary_sha256"],
        {candidate_id, *baseline_ids},
        f"{context}.input_hashes.solver_binary_sha256",
    )
    for solver_id, digest in solver_hashes.items():
        _hash(digest, f"{context}.input_hashes.solver_binary_sha256[{solver_id!r}]")

    for field in ("configuration", "assumptions", "hypotheses"):
        if type(value[field]) is not dict:
            raise AuditFinalizeError(f"{context}.{field} must be an object")
    minimum_speedup = _number(
        value["configuration"].get("minimum_speedup"),
        f"{context}.configuration.minimum_speedup",
    )
    if minimum_speedup <= 0.0:
        raise AuditFinalizeError(
            f"{context}.configuration.minimum_speedup must be positive"
        )
    comparisons = _exact_object(
        value["comparisons"], set(baseline_ids), f"{context}.comparisons"
    )
    failed_by_comparison: list[str] = []
    expected_budget_names = set(budget_names)
    for baseline_id, comparison_value in comparisons.items():
        comparison = _exact_object(
            comparison_value,
            COMPARISON_KEYS,
            f"{context}.comparisons[{baseline_id!r}]",
        )
        if (
            comparison["baseline_id"] != baseline_id
            or comparison["candidate_id"] != candidate_id
        ):
            raise AuditFinalizeError(f"{context} comparison solver ids disagree")
        comparison_budgets = _exact_object(
            comparison["budgets"],
            expected_budget_names,
            f"{context}.comparisons[{baseline_id!r}].budgets",
        )
        failed_budgets: list[str] = []
        for budget_name, budget_value in comparison_budgets.items():
            budget = _exact_object(
                budget_value,
                BUDGET_REPORT_KEYS,
                f"{context}.comparisons[{baseline_id!r}].budgets[{budget_name!r}]",
            )
            if (
                isinstance(budget["budget_s"], bool)
                or not isinstance(budget["budget_s"], (int, float))
                or format(float(budget["budget_s"]), ".17g") != budget_name
            ):
                raise AuditFinalizeError(f"{context} comparison budget value disagrees")
            for field in ("aggregate", "bootstrap", "families", "family_macro", "statuses"):
                if type(budget[field]) is not dict:
                    raise AuditFinalizeError(
                        f"{context} comparison budget {field} must be an object"
                    )
            budget_promotion = _exact_object(
                budget["promotion"],
                BUDGET_PROMOTION_KEYS,
                f"{context}.comparisons[{baseline_id!r}].budgets[{budget_name!r}].promotion",
            )
            budget_passed = _boolean(
                budget_promotion["passed"],
                f"{context}.comparisons[{baseline_id!r}].budgets[{budget_name!r}].promotion.passed",
            )
            checks = _exact_object(
                budget_promotion["checks"],
                BUDGET_PROMOTION_CHECK_KEYS,
                f"{context}.comparisons[{baseline_id!r}]"
                f".budgets[{budget_name!r}].promotion.checks",
            )
            expected_checks = _recompute_budget_checks(
                budget,
                minimum_speedup,
                f"{context}.comparisons[{baseline_id!r}]"
                f".budgets[{budget_name!r}]",
            )
            for check_name in sorted(BUDGET_PROMOTION_CHECK_KEYS):
                if not _same_json(checks[check_name], expected_checks[check_name]):
                    raise AuditFinalizeError(
                        f"{context} promotion check {check_name!r} "
                        "contradicts source data"
                    )
            derived_budget_passed = all(
                check["passed"] for check in expected_checks.values()
            )
            if budget_passed != derived_budget_passed:
                raise AuditFinalizeError(
                    f"{context} budget promotion outcome contradicts individual checks"
                )
            if budget_promotion["status"] != (
                "promoted" if budget_passed else "rejected"
            ):
                raise AuditFinalizeError(f"{context} budget promotion fields disagree")
            if not budget_passed:
                failed_budgets.append(budget_name)
        comparison_promotion = _exact_object(
            comparison["promotion"],
            COMPARISON_PROMOTION_KEYS,
            f"{context}.comparisons[{baseline_id!r}].promotion",
        )
        comparison_passed = _boolean(
            comparison_promotion["passed"],
            f"{context}.comparisons[{baseline_id!r}].promotion.passed",
        )
        if comparison_promotion["status"] != (
            "promoted" if comparison_passed else "rejected"
        ):
            raise AuditFinalizeError(f"{context} comparison promotion fields disagree")
        declared_failed_budgets = _string_list(
            comparison_promotion["failed_budgets"],
            f"{context}.comparisons[{baseline_id!r}].promotion.failed_budgets",
        )
        if (
            len(set(declared_failed_budgets)) != len(declared_failed_budgets)
            or set(declared_failed_budgets) != set(failed_budgets)
        ):
            raise AuditFinalizeError(f"{context} failed-budget summary disagrees")
        if comparison_passed != (not failed_budgets):
            raise AuditFinalizeError(f"{context} comparison outcome disagrees")
        if not comparison_passed:
            failed_by_comparison.append(baseline_id)

    promotion = _exact_object(
        value["promotion"], ANALYSIS_PROMOTION_KEYS, f"{context}.promotion"
    )
    if _boolean(promotion["passed"], f"{context}.promotion.passed") != promoted:
        raise AuditFinalizeError(f"{context} promotion outcome disagrees")
    _boolean(
        promotion["lock_promotion_eligible"],
        f"{context}.promotion.lock_promotion_eligible",
    )
    if promotion["status"] != expected_status:
        raise AuditFinalizeError(f"{context} promotion status disagrees")
    failed_comparisons = _string_list(
        promotion["failed_comparisons"],
        f"{context}.promotion.failed_comparisons",
    )
    if any(item not in baseline_ids for item in failed_comparisons):
        raise AuditFinalizeError(f"{context} names an unknown failed comparison")
    if (
        len(set(failed_comparisons)) != len(failed_comparisons)
        or set(failed_comparisons) != set(failed_by_comparison)
    ):
        raise AuditFinalizeError(f"{context} failed-comparison summary disagrees")
    expected_promoted = promotion["lock_promotion_eligible"] and not failed_comparisons
    if promoted != expected_promoted:
        raise AuditFinalizeError(f"{context} promotion eligibility disagrees")


def _lock_sha256(artifact: BoundArtifact) -> str:
    try:
        value = strict_json_loads(artifact.raw.decode("utf-8"), artifact.context)
    except (UnicodeError, StrictArtifactError) as error:
        raise AuditFinalizeError(str(error)) from error
    if type(value) is not dict:
        raise AuditFinalizeError(f"{artifact.context} is not one JSON object")
    declared = _hash(value.get("lock_sha256"), f"{artifact.context}.lock_sha256")
    unsigned = dict(value)
    unsigned["lock_sha256"] = ""
    actual = hashlib.sha256(_canonical_analysis_bytes(unsigned)).hexdigest()
    if declared != actual:
        raise AuditFinalizeError(f"{artifact.context} self-hash mismatch")
    return declared


def _parse_parent_lock(artifact: BoundArtifact) -> dict[str, Any]:
    try:
        value = strict_json_loads(artifact.raw.decode("utf-8"), artifact.context)
    except (UnicodeError, StrictArtifactError) as error:
        raise AuditFinalizeError(str(error)) from error
    parent = _exact_object(value, PARENT_LOCK_KEYS, artifact.context)
    if type(parent["schema_version"]) is not int or parent["schema_version"] != 1:
        raise AuditFinalizeError(
            f"{artifact.context}.schema_version must be integer 1"
        )
    lock_sha256 = _lock_sha256(artifact)
    campaign_id = _string(parent["campaign_id"], f"{artifact.context}.campaign_id")

    repository = _exact_object(
        parent["repository"],
        PARENT_REPOSITORY_KEYS,
        f"{artifact.context}.repository",
    )
    for field in ("root", "commit", "commit_time"):
        _string(repository[field], f"{artifact.context}.repository.{field}")
    repository_commit = repository["commit"]
    repository_clean = _boolean(
        repository["clean"], f"{artifact.context}.repository.clean"
    )
    repository_eligible = _boolean(
        repository["promotion_eligible"],
        f"{artifact.context}.repository.promotion_eligible",
    )
    if repository_eligible != repository_clean:
        raise AuditFinalizeError(
            f"{artifact.context} repository promotion eligibility contradicts cleanliness"
        )

    corpus = _exact_object(
        parent["corpus"], PARENT_CORPUS_KEYS, f"{artifact.context}.corpus"
    )
    for field in ("id", "manifest_path", "taxonomy_path", "root"):
        _string(corpus[field], f"{artifact.context}.corpus.{field}")
    manifest_sha256 = _hash(
        corpus["manifest_sha256"], f"{artifact.context}.corpus.manifest_sha256"
    )
    taxonomy_sha256 = _hash(
        corpus["taxonomy_sha256"], f"{artifact.context}.corpus.taxonomy_sha256"
    )
    solver_config = _exact_object(
        parent["solver_config"],
        {"path", "sha256"},
        f"{artifact.context}.solver_config",
    )
    solver_config_path = _string(
        solver_config["path"], f"{artifact.context}.solver_config.path"
    )
    solver_config_sha256 = _hash(
        solver_config["sha256"], f"{artifact.context}.solver_config.sha256"
    )
    instances = corpus["instances"]
    if type(instances) is not list or not instances:
        raise AuditFinalizeError(
            f"{artifact.context}.corpus.instances must be a non-empty array"
        )
    instance_ids: set[str] = set()
    families: set[str] = set()
    for index, instance_value in enumerate(instances):
        instance = _exact_object(
            instance_value,
            PARENT_INSTANCE_KEYS,
            f"{artifact.context}.corpus.instances[{index}]",
        )
        instance_id = _string(
            instance["id"], f"{artifact.context}.corpus.instances[{index}].id"
        )
        if instance_id in instance_ids:
            raise AuditFinalizeError(
                f"{artifact.context} contains duplicate corpus instance ids"
            )
        instance_ids.add(instance_id)
        families.add(
            _string(
                instance["family"],
                f"{artifact.context}.corpus.instances[{index}].family",
            )
        )

    solver_values = parent["solvers"]
    if type(solver_values) is not list or len(solver_values) < 2:
        raise AuditFinalizeError(
            f"{artifact.context}.solvers must contain at least two entries"
        )
    solver_hashes: dict[str, str] = {}
    for index, solver_value in enumerate(solver_values):
        expected_keys = PARENT_SOLVER_KEYS | (
            {"evidence"}
            if type(solver_value) is dict and "evidence" in solver_value
            else set()
        )
        solver = _exact_object(
            solver_value, expected_keys, f"{artifact.context}.solvers[{index}]"
        )
        solver_id = _string(
            solver["id"], f"{artifact.context}.solvers[{index}].id"
        )
        if solver_id in solver_hashes:
            raise AuditFinalizeError(
                f"{artifact.context} contains duplicate solver ids"
            )
        solver_hashes[solver_id] = _hash(
            solver["sha256"], f"{artifact.context}.solvers[{index}].sha256"
        )
    if list(solver_hashes) != sorted(solver_hashes):
        raise AuditFinalizeError(f"{artifact.context}.solvers must be sorted by id")
    if CANDIDATE_ID not in solver_hashes:
        raise AuditFinalizeError(
            f"{artifact.context} does not contain the production candidate"
        )

    budget_names = _budget_names(
        parent["budgets_s"], f"{artifact.context}.budgets_s"
    )
    promotion_eligible = _boolean(
        parent["promotion_eligible"],
        f"{artifact.context}.promotion_eligible",
    )
    expected_eligibility = bool(repository_eligible and corpus["taxonomy_path"])
    if promotion_eligible != expected_eligibility:
        raise AuditFinalizeError(
            f"{artifact.context} promotion eligibility contradicts repository and taxonomy"
        )
    return {
        "campaign_id": campaign_id,
        "repository_commit": repository_commit,
        "candidate_id": CANDIDATE_ID,
        "baseline_ids": sorted(
            solver_id for solver_id in solver_hashes if solver_id != CANDIDATE_ID
        ),
        "promotion_eligible": promotion_eligible,
        "budgets_s": [float(name) for name in budget_names],
        "budget_names": budget_names,
        "manifest_sha256": manifest_sha256,
        "manifest_path": corpus["manifest_path"],
        "taxonomy_sha256": taxonomy_sha256,
        "taxonomy_path": corpus["taxonomy_path"],
        "solver_config_path": solver_config_path,
        "solver_config_sha256": solver_config_sha256,
        "solver_binary_sha256": solver_hashes,
        "instances": len(instances),
        "families": len(families),
        "lock_sha256": lock_sha256,
    }


def _validate_analysis_parent_identity(
    value: dict[str, Any], parent: dict[str, Any], context: str
) -> None:
    inputs = value["inputs"]
    hashes = value["input_hashes"]
    if inputs["campaign_id"] != parent["campaign_id"]:
        raise AuditFinalizeError(f"{context} campaign identity disagrees with parent lock")
    if _budget_names(inputs["budgets_s"], f"{context}.inputs.budgets_s") != parent[
        "budget_names"
    ]:
        raise AuditFinalizeError(f"{context} budget identity disagrees with parent lock")
    if inputs["instances"] != parent["instances"]:
        raise AuditFinalizeError(f"{context} instance count disagrees with parent lock")
    if inputs["families"] != parent["families"]:
        raise AuditFinalizeError(f"{context} family count disagrees with parent lock")
    if inputs["candidate_id"] != CANDIDATE_ID:
        raise AuditFinalizeError(f"{context} candidate identity is not production-bound")
    if inputs["baseline_ids"] != parent["baseline_ids"]:
        raise AuditFinalizeError(f"{context} baseline identities disagree with parent lock")
    if hashes["solver_binary_sha256"] != parent["solver_binary_sha256"]:
        raise AuditFinalizeError(f"{context} solver hashes disagree with parent lock")
    if hashes["manifest_sha256"] != parent["manifest_sha256"]:
        raise AuditFinalizeError(f"{context} manifest identity disagrees with parent lock")
    if hashes["taxonomy_sha256"] != parent["taxonomy_sha256"]:
        raise AuditFinalizeError(f"{context} taxonomy identity disagrees with parent lock")
    if (
        value["promotion"]["lock_promotion_eligible"]
        != parent["promotion_eligible"]
    ):
        raise AuditFinalizeError(
            f"{context} promotion eligibility disagrees with parent lock"
        )


def _artifact_index(artifact: BoundArtifact) -> dict[str, Any]:
    return {
        "bytes": len(artifact.raw),
        "device": artifact.metadata.st_dev,
        "inode": artifact.metadata.st_ino,
        "path": str(artifact.path),
        "sha256": artifact.sha256,
    }


def _bind_current_inputs(
    kind: str,
    analysis: BoundAnalysis,
    run_root: Path,
    shard_count: int,
) -> tuple[dict[str, Any], list[BoundArtifact]]:
    inputs = analysis.value["inputs"]
    hashes = analysis.value["input_hashes"]
    opened: list[BoundArtifact] = []
    try:
        parent = _open_artifact(
            run_root / "locks" / f"{kind}-parent.json",
            f"{kind} current parent lock",
            run_root,
        )
        opened.append(parent)
        if inputs["parent_lock"] != str(parent.path):
            raise AuditFinalizeError(f"{kind} analysis parent-lock path is stale")
        if hashes["lock_file_sha256"] != parent.sha256:
            raise AuditFinalizeError(f"{kind} analysis parent-lock file hash is stale")
        parent_identity = _parse_parent_lock(parent)
        parent_lock_sha256 = parent_identity["lock_sha256"]
        if hashes["lock_sha256"] != parent_lock_sha256:
            raise AuditFinalizeError(f"{kind} analysis parent-lock self-hash is stale")
        _validate_analysis_parent_identity(
            analysis.value, parent_identity, f"{kind} global analysis"
        )

        source_shards: list[dict[str, Any]] = []
        bundle_shards: list[dict[str, Any]] = []
        for index, shard_value in enumerate(inputs["shards"]):
            suffix = f"{index:04d}"
            lock = _open_artifact(
                run_root / "locks" / kind / f"bound-{suffix}.json",
                f"{kind} current shard {index} lock",
                run_root,
            )
            opened.append(lock)
            raw = _open_artifact(
                run_root / f"{kind}-2s" / f"shard-{suffix}" / "raw.jsonl",
                f"{kind} current shard {index} raw results",
                run_root,
            )
            opened.append(raw)
            if shard_value["lock"] != str(lock.path) or shard_value["raw"] != str(raw.path):
                raise AuditFinalizeError(f"{kind} analysis shard {index} paths are stale")
            lock_sha256 = _lock_sha256(lock)
            expected_lock_file_sha256 = hashes["shard_lock_file_sha256"][str(index)]
            expected_raw_sha256 = hashes["shard_raw_sha256"][str(index)]
            if (
                shard_value["lock_file_sha256"] != lock.sha256
                or expected_lock_file_sha256 != lock.sha256
                or shard_value["lock_sha256"] != lock_sha256
            ):
                raise AuditFinalizeError(f"{kind} analysis shard {index} lock hashes are stale")
            if shard_value["raw_sha256"] != raw.sha256 or expected_raw_sha256 != raw.sha256:
                raise AuditFinalizeError(f"{kind} analysis shard {index} raw hash is stale")
            raw_records = len(raw.raw.splitlines())
            if raw_records != shard_value["raw_records"]:
                raise AuditFinalizeError(f"{kind} analysis shard {index} raw count is stale")

            lock_index = _artifact_index(lock)
            lock_index["lock_sha256"] = lock_sha256
            source_shards.append(
                {
                    "index": index,
                    "cpu_ids": shard_value["cpu_ids"],
                    "raw_records": raw_records,
                    "lock": lock_index,
                    "raw": _artifact_index(raw),
                }
            )
            bundle_shards.append(
                {
                    "index": index,
                    "lock_file_sha256": lock.sha256,
                    "lock_sha256": lock_sha256,
                    "raw_sha256": raw.sha256,
                    "raw_records": raw_records,
                    "cpu_ids": shard_value["cpu_ids"],
                }
            )

        bundle_sha256 = hashlib.sha256(
            _canonical_analysis_bytes(
                {
                    "parent_lock_sha256": parent_lock_sha256,
                    "shards": bundle_shards,
                }
            )
        ).hexdigest()
        if hashes["shard_bundle_sha256"] != bundle_sha256:
            raise AuditFinalizeError(f"{kind} analysis shard bundle hash is stale")
        parent_index = _artifact_index(parent)
        parent_index["lock_sha256"] = parent_lock_sha256
        parent_index["identity"] = {
            field: parent_identity[field]
            for field in (
                "campaign_id",
                "repository_commit",
                "candidate_id",
                "baseline_ids",
                "promotion_eligible",
                "budgets_s",
                "manifest_sha256",
                "manifest_path",
                "taxonomy_sha256",
                "taxonomy_path",
                "solver_config_path",
                "solver_config_sha256",
                "solver_binary_sha256",
                "instances",
                "families",
            )
        }
        return (
            {
                "parent_lock": parent_index,
                "shard_bundle_sha256": bundle_sha256,
                "shards": source_shards,
            },
            opened,
        )
    except BaseException:
        for artifact in opened:
            os.close(artifact.descriptor)
        raise


def _metadata_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_external_artifact(path: Path, context: str) -> BoundArtifact:
    descriptor = -1
    try:
        absolute, descriptor = open_read_nofollow(path, context)
        raw, metadata = read_open_descriptor(descriptor, context)
        result = BoundArtifact(absolute, descriptor, raw, metadata, context)
        descriptor = -1
        return result
    except StrictArtifactError as error:
        raise AuditFinalizeError(str(error)) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canonical_receipt_object(
    artifact: BoundArtifact, expected_keys: set[str]
) -> dict[str, Any]:
    try:
        value = strict_json_loads(artifact.raw.decode("utf-8"), artifact.context)
    except (UnicodeError, StrictArtifactError) as error:
        raise AuditFinalizeError(str(error)) from error
    result = _exact_object(value, expected_keys, artifact.context)
    if _canonical_analysis_bytes(result) != artifact.raw:
        raise AuditFinalizeError(f"{artifact.context} is not canonical JSON")
    return result


def _validated_analysis_bindings(value: Any) -> dict[str, dict[str, Any]]:
    bindings = _exact_object(value, {"full", "official"}, "validated analyses")
    result: dict[str, dict[str, Any]] = {}
    for kind, raw_binding in bindings.items():
        binding = _exact_object(
            raw_binding, VALIDATED_ANALYSIS_KEYS, f"validated analyses.{kind}"
        )
        digest = _hash(binding["sha256"], f"validated analyses.{kind}.sha256")
        process_exit = binding["process_exit"]
        if type(process_exit) is not int or process_exit not in {0, 1}:
            raise AuditFinalizeError(
                f"validated analyses.{kind}.process_exit must be 0 or 1"
            )
        result[kind] = {"sha256": digest, "process_exit": process_exit}
    return result


def _open_current_audit(
    run_root: Path,
    shards: int,
    validated_analyses: dict[str, dict[str, Any]],
) -> tuple[
    dict[str, BoundAnalysis],
    dict[str, dict[str, Any]],
    list[BoundArtifact],
]:
    opened: list[BoundArtifact] = []
    try:
        analyses: dict[str, BoundAnalysis] = {}
        for kind in ("full", "official"):
            analysis = _open_analysis(
                run_root / "audit" / kind / "global.json", kind, run_root
            )
            opened.append(analysis)
            _validate_analysis_schema(analysis.value, kind, shards)
            expected = validated_analyses[kind]
            if analysis.sha256 != expected["sha256"]:
                raise AuditFinalizeError(
                    f"{kind} analysis bytes differ from validated analysis receipt"
                )
            expected_promoted = expected["process_exit"] == 0
            if analysis.value["promoted"] != expected_promoted:
                raise AuditFinalizeError(
                    f"{kind} analysis outcome contradicts validated process exit"
                )
            analyses[kind] = analysis

        current_inputs: dict[str, dict[str, Any]] = {}
        for kind, analysis in analyses.items():
            binding, source_artifacts = _bind_current_inputs(
                kind, analysis, run_root, shards
            )
            opened.extend(source_artifacts)
            current_inputs[kind] = binding
        return analyses, current_inputs, opened
    except BaseException:
        for artifact in opened:
            os.close(artifact.descriptor)
        raise


def _verify_preparation_receipt(
    receipt_path: Path,
    expected_sha256: str,
    provenance: dict[str, Any],
    run_root: Path,
    prepare_job: int,
    shards: int,
    current_inputs: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[BoundArtifact]]:
    opened: list[BoundArtifact] = []
    try:
        expected_path = run_root / "prepare.json"
        if receipt_path.resolve(strict=True) != expected_path:
            raise AuditFinalizeError(
                "preparation receipt path is not the locked run receipt"
            )
        receipt = _open_artifact(expected_path, "preparation receipt", run_root)
        opened.append(receipt)
        expected_receipt_sha256 = _hash(
            expected_sha256, "preparation receipt expected SHA-256"
        )
        if receipt.sha256 != expected_receipt_sha256:
            raise AuditFinalizeError(
                "preparation receipt SHA-256 differs from external binding"
            )
        value = _canonical_receipt_object(receipt, PREPARATION_KEYS)
        if (
            value["schema"] != "euf-viper.locked-p0-preparation.v3"
            or value["status"] != "prepared"
        ):
            raise AuditFinalizeError("preparation receipt schema or status is invalid")

        provenance_revision = _string(
            provenance.get("revision"), "provenance.revision"
        )
        provenance_manifest = _hash(
            provenance.get("manifest_sha256"), "provenance.manifest_sha256"
        )
        if _string(value["revision"], "preparation receipt revision") != provenance_revision:
            raise AuditFinalizeError("preparation receipt revision disagrees")
        if (
            _hash(
                value["submission_manifest_sha256"],
                "preparation receipt submission manifest SHA-256",
            )
            != provenance_manifest
        ):
            raise AuditFinalizeError(
                "preparation receipt submission manifest disagrees"
            )
        for field in (
            "attempt",
            "execution_environment",
            "runtime_tools",
        ):
            if field not in provenance or not _same_json(value[field], provenance[field]):
                raise AuditFinalizeError(
                    f"preparation receipt {field} disagrees with provenance"
                )
        job = _exact_object(value["job"], {"id", "submit_directory"}, "prepare job")
        if _integer(job["id"], "preparation receipt prepare job", 1) != prepare_job:
            raise AuditFinalizeError("preparation receipt prepare job disagrees")
        if _integer(value["shards"], "preparation receipt shards", 1) != shards:
            raise AuditFinalizeError("preparation receipt shard count disagrees")
        try:
            verify_preparation_environment_compatibility(
                value["environment"],
                provenance,
                prepare_job=prepare_job,
                shards=shards,
                receipt_sha256=expected_receipt_sha256,
            )
        except ProvenanceError as error:
            raise AuditFinalizeError(str(error)) from error
        paths = _exact_object(
            value["paths"],
            {"checkout", "run_root", "submission_manifest"},
            "preparation receipt paths",
        )
        if _string(paths["run_root"], "preparation receipt run root") != str(run_root):
            raise AuditFinalizeError("preparation receipt run root disagrees")
        if value["build_features"] != [
            "certificates",
            "default",
            "finite-symmetry",
            "production-evidence",
        ]:
            raise AuditFinalizeError("preparation receipt build features disagree")
        source = _exact_object(
            value["source"],
            {
                "blob_count",
                "blobs_sha256",
                "tree",
                "snapshot_manifest_sha256",
                "build_execution_closure_sha256",
            },
            "preparation receipt source",
        )
        for receipt_field, provenance_field in (
            ("blob_count", "source_blob_count"),
            ("blobs_sha256", "source_blobs_sha256"),
            ("tree", "source_tree"),
        ):
            if not _same_json(
                source[receipt_field], provenance.get(provenance_field)
            ):
                raise AuditFinalizeError(
                    "preparation receipt source disagrees with provenance"
                )

        artifacts = _exact_object(
            value["artifacts"],
            PREPARATION_ARTIFACT_NAMES,
            "preparation receipt artifacts",
        )
        for name, raw_record in artifacts.items():
            record = _exact_object(
                raw_record, {"path", "sha256"}, f"preparation artifact {name}"
            )
            record_path = _string(
                record["path"], f"preparation artifact {name} path"
            )
            record_sha256 = _hash(
                record["sha256"], f"preparation artifact {name} SHA-256"
            )
            artifact = _open_artifact(
                run_root / name, f"preparation artifact {name}", run_root
            )
            opened.append(artifact)
            if record_path != str(artifact.path) or record_sha256 != artifact.sha256:
                raise AuditFinalizeError(
                    f"preparation artifact {name} path or SHA-256 disagrees"
                )

        for kind in ("full", "official"):
            identity = current_inputs[kind]["parent_lock"]["identity"]
            parent_record = artifacts[f"locks/{kind}-parent.json"]
            parent_index = current_inputs[kind]["parent_lock"]
            if (
                parent_record["path"] != parent_index["path"]
                or parent_record["sha256"] != parent_index["sha256"]
            ):
                raise AuditFinalizeError(
                    f"preparation receipt {kind} parent lock hash disagrees"
                )
            if identity["repository_commit"] != provenance_revision:
                raise AuditFinalizeError(
                    f"{kind} parent repository commit disagrees with provenance revision"
                )
            taxonomy_record = artifacts[f"taxonomy/{kind}.jsonl"]
            if (
                taxonomy_record["path"] != identity["taxonomy_path"]
                or taxonomy_record["sha256"] != identity["taxonomy_sha256"]
            ):
                raise AuditFinalizeError(
                    f"preparation receipt {kind} taxonomy identity disagrees"
                )
            solver_config_record = artifacts["solver-config.json"]
            if (
                solver_config_record["path"] != identity["solver_config_path"]
                or solver_config_record["sha256"] != identity["solver_config_sha256"]
            ):
                raise AuditFinalizeError(
                    f"preparation receipt {kind} solver configuration disagrees"
                )

        corpus = _exact_object(
            value["corpus"],
            {"full_manifest", "official_manifest", "root"},
            "preparation receipt corpus",
        )
        manifest_records: dict[str, dict[str, Any]] = {}
        for kind in ("full", "official"):
            record = _exact_object(
                corpus[f"{kind}_manifest"],
                {"path", "sha256"},
                f"preparation corpus {kind} manifest",
            )
            record_path = _string(
                record["path"], f"preparation corpus {kind} manifest path"
            )
            record_sha256 = _hash(
                record["sha256"],
                f"preparation corpus {kind} manifest SHA-256",
            )
            manifest = _open_external_artifact(
                Path(record_path), f"preparation corpus {kind} manifest"
            )
            opened.append(manifest)
            if record_path != str(manifest.path) or record_sha256 != manifest.sha256:
                raise AuditFinalizeError(
                    f"preparation corpus {kind} manifest path or hash disagrees"
                )
            identity = current_inputs[kind]["parent_lock"]["identity"]
            if (
                record["path"] != identity["manifest_path"]
                or record["sha256"] != identity["manifest_sha256"]
            ):
                raise AuditFinalizeError(
                    f"preparation corpus {kind} manifest identity disagrees"
                )
            manifest_records[kind] = record
        if (
            manifest_records["full"]["path"] == manifest_records["official"]["path"]
            or manifest_records["full"]["sha256"]
            == manifest_records["official"]["sha256"]
        ):
            raise AuditFinalizeError(
                "full and official preparation manifests must be distinct"
            )
        full_taxonomy = artifacts["taxonomy/full.jsonl"]
        official_taxonomy = artifacts["taxonomy/official.jsonl"]
        if (
            full_taxonomy["path"] == official_taxonomy["path"]
            or full_taxonomy["sha256"] == official_taxonomy["sha256"]
        ):
            raise AuditFinalizeError(
                "full and official preparation taxonomies must be distinct"
            )
        return value, opened
    except BaseException:
        for artifact in opened:
            os.close(artifact.descriptor)
        raise


def _scheduler_payload(
    provenance: dict[str, Any],
    run_root: Path,
    prepare_job: int,
    audit_job: int,
    shards: int,
    preparation_receipt_path: Path,
    preparation_receipt_sha256: str,
    validated_analyses: dict[str, dict[str, Any]],
    current_inputs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": "euf-viper.locked-p0-audit-scheduler.v1",
        "status": "bound",
        "run_root": str(run_root),
        "revision": provenance["revision"],
        "submission_manifest_sha256": provenance["manifest_sha256"],
        "preparation_receipt": {
            "path": str(preparation_receipt_path),
            "sha256": preparation_receipt_sha256,
        },
        "jobs": {"prepare": prepare_job, "audit": audit_job},
        "shards": shards,
        "parent_locks": {
            kind: {
                "path": current_inputs[kind]["parent_lock"]["path"],
                "file_sha256": current_inputs[kind]["parent_lock"]["sha256"],
                "lock_sha256": current_inputs[kind]["parent_lock"]["lock_sha256"],
            }
            for kind in ("full", "official")
        },
        "analyses": {
            kind: {
                "path": str(run_root / "audit" / kind / "global.json"),
                "sha256": validated_analyses[kind]["sha256"],
                "process_exit": validated_analyses[kind]["process_exit"],
            }
            for kind in ("full", "official")
        },
    }


def _verify_opened_artifacts(opened: list[BoundArtifact]) -> None:
    for artifact in opened:
        assert_descriptor_path_nofollow(
            artifact.path, artifact.descriptor, artifact.context
        )
        current, metadata = read_open_descriptor(
            artifact.descriptor, f"{artifact.context} final rehash"
        )
        if (
            current != artifact.raw
            or _metadata_identity(metadata) != _metadata_identity(artifact.metadata)
        ):
            raise StrictArtifactError(
                f"{artifact.context} changed before receipt publication"
            )


def create_scheduler_receipt(
    output: Path,
    provenance: dict[str, Any],
    run_root: Path,
    prepare_job: int,
    shards: int,
    audit_job: int,
    preparation_receipt_path: Path,
    preparation_receipt_sha256: str,
    validated_analyses: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    opened: list[BoundArtifact] = []
    try:
        run_root = run_root.resolve(strict=True)
        _integer(prepare_job, "prepare job", 1)
        _integer(audit_job, "audit job", 1)
        _integer(shards, "shards", 1)
        validated_analyses = _validated_analysis_bindings(validated_analyses)
        analyses, current_inputs, audit_artifacts = _open_current_audit(
            run_root, shards, validated_analyses
        )
        del analyses
        opened.extend(audit_artifacts)
        preparation, preparation_artifacts = _verify_preparation_receipt(
            preparation_receipt_path,
            preparation_receipt_sha256,
            provenance,
            run_root,
            prepare_job,
            shards,
            current_inputs,
        )
        del preparation
        opened.extend(preparation_artifacts)
        receipt_path = (run_root / "prepare.json").resolve(strict=True)
        payload = _scheduler_payload(
            provenance,
            run_root,
            prepare_job,
            audit_job,
            shards,
            receipt_path,
            preparation_receipt_sha256,
            validated_analyses,
            current_inputs,
        )
        expected_output = run_root / "audit" / "scheduler.json"
        if output.absolute() != expected_output:
            raise AuditFinalizeError(
                "scheduler receipt output is not the locked audit receipt path"
            )

        def verify_sources() -> None:
            _verify_opened_artifacts(opened)

        atomic_write_nofollow(
            output,
            canonical_json_bytes(payload),
            "locked audit scheduler receipt",
            immutable=True,
            mode=0o400,
            pre_publish=verify_sources,
            post_publish=verify_sources,
        )
        return payload
    except AuditFinalizeError:
        raise
    except (KeyError, OSError, StrictArtifactError) as error:
        raise AuditFinalizeError(str(error)) from error
    finally:
        for artifact in opened:
            os.close(artifact.descriptor)


def _verify_scheduler_receipt(
    receipt_path: Path,
    expected_sha256: str,
    expected_payload: dict[str, Any],
    run_root: Path,
) -> BoundArtifact:
    expected_path = run_root / "audit" / "scheduler.json"
    if receipt_path.resolve(strict=True) != expected_path:
        raise AuditFinalizeError("scheduler receipt path is not locked")
    receipt = _open_artifact(expected_path, "audit scheduler receipt", run_root)
    try:
        digest = _hash(expected_sha256, "scheduler receipt expected SHA-256")
        if receipt.sha256 != digest:
            raise AuditFinalizeError(
                "scheduler receipt SHA-256 differs from external binding"
            )
        value = _canonical_receipt_object(receipt, SCHEDULER_RECEIPT_KEYS)
        if not _same_json(value, expected_payload):
            raise AuditFinalizeError(
                "scheduler receipt disagrees with current jobs, locks, or analyses"
            )
        if stat.S_IMODE(receipt.metadata.st_mode) != 0o400:
            raise AuditFinalizeError("scheduler receipt mode is not 0400")
        return receipt
    except BaseException:
        os.close(receipt.descriptor)
        raise


def validate_analysis_output(
    run_root: Path,
    kind: str,
    shards: int,
    expected_analysis_exit: int,
) -> dict[str, Any]:
    """Validate one just-produced analysis against all of its live inputs."""

    if kind not in {"full", "official"}:
        raise AuditFinalizeError("analysis kind must be full or official")
    _integer(shards, "shards", 1)
    if type(expected_analysis_exit) is not int or expected_analysis_exit not in {0, 1}:
        raise AuditFinalizeError("expected analysis exit must be 0 or 1")
    opened: list[BoundArtifact] = []
    try:
        run_root = run_root.resolve(strict=True)
        analysis = _open_analysis(
            run_root / "audit" / kind / "global.json", kind, run_root
        )
        opened.append(analysis)
        _validate_analysis_schema(analysis.value, kind, shards)
        input_artifacts, source_artifacts = _bind_current_inputs(
            kind, analysis, run_root, shards
        )
        opened.extend(source_artifacts)
        expected_promoted = expected_analysis_exit == 0
        if analysis.value["promoted"] != expected_promoted:
            raise AuditFinalizeError(
                f"{kind} analysis outcome contradicts process exit "
                f"{expected_analysis_exit}"
            )
        return {
            "schema": "euf-viper.locked-analysis-validation.v1",
            "kind": kind,
            "analysis_sha256": analysis.sha256,
            "expected_analysis_exit": expected_analysis_exit,
            "promoted": expected_promoted,
            "input_artifacts": input_artifacts,
        }
    except AuditFinalizeError:
        raise
    except (KeyError, OSError, StrictArtifactError) as error:
        raise AuditFinalizeError(str(error)) from error
    finally:
        for artifact in opened:
            os.close(artifact.descriptor)


def finalize(
    output: Path,
    provenance: dict[str, Any],
    run_root: Path,
    prepare_job: int,
    shards: int,
    audit_job: int,
    preparation_receipt_path: Path,
    preparation_receipt_sha256: str,
    scheduler_receipt_path: Path,
    scheduler_receipt_sha256: str,
    validated_analyses: dict[str, dict[str, Any]],
    *,
    pre_publish_hook: Callable[[], None] | None = None,
) -> dict[str, Any]:
    opened: list[BoundArtifact] = []
    try:
        run_root = run_root.resolve(strict=True)
        _integer(prepare_job, "prepare job", 1)
        _integer(audit_job, "audit job", 1)
        _integer(shards, "shards", 1)
        validated_analyses = _validated_analysis_bindings(validated_analyses)
        analyses, current_inputs, audit_artifacts = _open_current_audit(
            run_root, shards, validated_analyses
        )
        opened.extend(audit_artifacts)
        preparation, preparation_artifacts = _verify_preparation_receipt(
            preparation_receipt_path,
            preparation_receipt_sha256,
            provenance,
            run_root,
            prepare_job,
            shards,
            current_inputs,
        )
        opened.extend(preparation_artifacts)
        canonical_preparation_path = (run_root / "prepare.json").resolve(strict=True)
        expected_scheduler = _scheduler_payload(
            provenance,
            run_root,
            prepare_job,
            audit_job,
            shards,
            canonical_preparation_path,
            preparation_receipt_sha256,
            validated_analyses,
            current_inputs,
        )
        scheduler = _verify_scheduler_receipt(
            scheduler_receipt_path,
            scheduler_receipt_sha256,
            expected_scheduler,
            run_root,
        )
        opened.append(scheduler)
        preparation_artifact = preparation_artifacts[0]

        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "status": "complete",
            "attempt": provenance["attempt"],
            "analyses": {},
            "environment": provenance["environment"],
            "job_id": audit_job,
            "prepare_job_id": prepare_job,
            "preparation_receipt": {
                **_artifact_index(preparation_artifact),
                "job_id": preparation["job"]["id"],
                "revision": preparation["revision"],
                "status": preparation["status"],
            },
            "scheduler_receipt": {
                **_artifact_index(scheduler),
                "job_id": audit_job,
                "status": "bound",
            },
            "revision": provenance["revision"],
            "run_root": str(run_root),
            "shards": shards,
            "source": {
                "blob_count": provenance["source_blob_count"],
                "blobs_sha256": provenance["source_blobs_sha256"],
                "tree": provenance["source_tree"],
            },
            "submission_manifest_sha256": provenance["manifest_sha256"],
        }
        for kind, binding in analyses.items():
            value = binding.value
            payload["analyses"][kind] = {
                "bytes": len(binding.raw),
                "device": binding.metadata.st_dev,
                "inode": binding.metadata.st_ino,
                "input_artifacts": current_inputs[kind],
                "instances": value["inputs"]["instances"],
                "path": str(binding.path),
                "promoted": value["promoted"],
                "raw_records": value["inputs"]["raw_records"],
                "sha256": binding.sha256,
                "shards": len(value["inputs"]["shards"]),
                "status": value["status"],
                "validated_process_exit": validated_analyses[kind]["process_exit"],
            }

        encoded = canonical_json_bytes(payload)

        def verify_sources() -> None:
            if pre_publish_hook is not None:
                pre_publish_hook()
            for artifact in opened:
                assert_descriptor_path_nofollow(
                    artifact.path, artifact.descriptor, artifact.context
                )
                current, metadata = read_open_descriptor(
                    artifact.descriptor, f"{artifact.context} final rehash"
                )
                if (
                    current != artifact.raw
                    or _metadata_identity(metadata)
                    != _metadata_identity(artifact.metadata)
                ):
                    raise StrictArtifactError(
                        f"{artifact.context} changed before index publication"
                    )

        atomic_write_nofollow(
            output,
            encoded,
            "locked audit index",
            immutable=True,
            mode=0o400,
            pre_publish=verify_sources,
            post_publish=verify_sources,
        )
        _, index_fd = open_read_nofollow(output, "locked audit index")
        try:
            actual, metadata = read_open_descriptor(index_fd, "locked audit index")
            assert_descriptor_path_nofollow(output, index_fd, "locked audit index")
            if actual != encoded or (metadata.st_mode & 0o777) != 0o400:
                raise AuditFinalizeError("published audit index bytes or mode differ")
        finally:
            os.close(index_fd)
        return payload
    except AuditFinalizeError:
        raise
    except (KeyError, OSError, StrictArtifactError) as error:
        raise AuditFinalizeError(str(error)) from error
    finally:
        for artifact in opened:
            os.close(artifact.descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--provenance")
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--prepare-job", type=int)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--audit-job", type=int)
    parser.add_argument("--preparation-receipt", type=Path)
    parser.add_argument("--preparation-receipt-sha256")
    parser.add_argument("--scheduler-receipt", type=Path)
    parser.add_argument("--scheduler-receipt-sha256")
    parser.add_argument("--full-analysis-sha256")
    parser.add_argument("--full-analysis-exit", type=int, choices=(0, 1))
    parser.add_argument("--official-analysis-sha256")
    parser.add_argument("--official-analysis-exit", type=int, choices=(0, 1))
    parser.add_argument("--write-scheduler-receipt", action="store_true")
    parser.add_argument("--validate-analysis", choices=("full", "official"))
    parser.add_argument("--expected-analysis-exit", type=int, choices=(0, 1))
    args = parser.parse_args()
    try:
        analysis_options = {
            "full": {
                "sha256": args.full_analysis_sha256,
                "process_exit": args.full_analysis_exit,
            },
            "official": {
                "sha256": args.official_analysis_sha256,
                "process_exit": args.official_analysis_exit,
            },
        }
        if args.validate_analysis is not None:
            if args.expected_analysis_exit is None:
                parser.error(
                    "--validate-analysis requires --expected-analysis-exit"
                )
            if any(
                value is not None
                for value in (
                    args.out,
                    args.provenance,
                    args.prepare_job,
                    args.audit_job,
                    args.preparation_receipt,
                    args.preparation_receipt_sha256,
                    args.scheduler_receipt,
                    args.scheduler_receipt_sha256,
                    args.full_analysis_sha256,
                    args.full_analysis_exit,
                    args.official_analysis_sha256,
                    args.official_analysis_exit,
                )
            ) or args.write_scheduler_receipt:
                parser.error(
                    "analysis validation does not accept final publication options"
                )
            payload = validate_analysis_output(
                args.run_root,
                args.validate_analysis,
                args.shards,
                args.expected_analysis_exit,
            )
        elif args.write_scheduler_receipt:
            if args.expected_analysis_exit is not None:
                parser.error(
                    "--expected-analysis-exit requires --validate-analysis"
                )
            required = {
                "--out": args.out,
                "--provenance": args.provenance,
                "--prepare-job": args.prepare_job,
                "--audit-job": args.audit_job,
                "--preparation-receipt": args.preparation_receipt,
                "--preparation-receipt-sha256": args.preparation_receipt_sha256,
                "--full-analysis-sha256": args.full_analysis_sha256,
                "--full-analysis-exit": args.full_analysis_exit,
                "--official-analysis-sha256": args.official_analysis_sha256,
                "--official-analysis-exit": args.official_analysis_exit,
            }
            missing = [name for name, value in required.items() if value is None]
            if missing:
                parser.error("scheduler receipt requires " + ", ".join(missing))
            if args.scheduler_receipt is not None or args.scheduler_receipt_sha256 is not None:
                parser.error("scheduler receipt creation cannot consume itself")
            assert args.out is not None
            assert args.provenance is not None
            assert args.prepare_job is not None
            assert args.audit_job is not None
            assert args.preparation_receipt is not None
            assert args.preparation_receipt_sha256 is not None
            payload = create_scheduler_receipt(
                args.out,
                json.loads(args.provenance),
                args.run_root,
                args.prepare_job,
                args.shards,
                args.audit_job,
                args.preparation_receipt,
                args.preparation_receipt_sha256,
                analysis_options,
            )
        else:
            if args.expected_analysis_exit is not None:
                parser.error(
                    "--expected-analysis-exit requires --validate-analysis"
                )
            required = {
                "--out": args.out,
                "--provenance": args.provenance,
                "--prepare-job": args.prepare_job,
                "--audit-job": args.audit_job,
                "--preparation-receipt": args.preparation_receipt,
                "--preparation-receipt-sha256": args.preparation_receipt_sha256,
                "--scheduler-receipt": args.scheduler_receipt,
                "--scheduler-receipt-sha256": args.scheduler_receipt_sha256,
                "--full-analysis-sha256": args.full_analysis_sha256,
                "--full-analysis-exit": args.full_analysis_exit,
                "--official-analysis-sha256": args.official_analysis_sha256,
                "--official-analysis-exit": args.official_analysis_exit,
            }
            missing = [name for name, value in required.items() if value is None]
            if missing:
                parser.error("final publication requires " + ", ".join(missing))
            assert args.out is not None
            assert args.provenance is not None
            assert args.prepare_job is not None
            assert args.audit_job is not None
            assert args.preparation_receipt is not None
            assert args.preparation_receipt_sha256 is not None
            assert args.scheduler_receipt is not None
            assert args.scheduler_receipt_sha256 is not None
            payload = finalize(
                args.out,
                json.loads(args.provenance),
                args.run_root,
                args.prepare_job,
                args.shards,
                args.audit_job,
                args.preparation_receipt,
                args.preparation_receipt_sha256,
                args.scheduler_receipt,
                args.scheduler_receipt_sha256,
                analysis_options,
            )
    except (AuditFinalizeError, json.JSONDecodeError, OSError, ValueError) as error:
        print(f"locked audit finalization rejected: {error}", file=sys.stderr)
        return 2
    print(canonical_json_bytes(payload).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
