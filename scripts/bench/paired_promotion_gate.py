#!/usr/bin/env python3
"""Deterministic promotion gate for paired compare_viper_ab.py CSV output."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
FIELDNAMES = [
    "relative_path",
    "expected_status",
    "label",
    "repeat",
    "result",
    "time_s",
    "exit_code",
    "stderr",
]
LABELS = ("baseline", "candidate")
DECISIVE_RESULTS = {"sat", "unsat"}

DEFAULT_SEED = 0
DEFAULT_BOOTSTRAP_ITERATIONS = 10_000
DEFAULT_PERMUTATION_ITERATIONS = 10_000
DEFAULT_CONFIDENCE_LEVEL = 0.95
DEFAULT_MIN_PAIRED_INSTANCES = 1
DEFAULT_MIN_SPEEDUP = 1.0
DEFAULT_MAX_P_VALUE = 0.05
DEFAULT_TIE_RELATIVE_TOLERANCE = 0.0

TIMEOUT_POLICY_STRICT = "strict_no_timeouts"
TIMEOUT_POLICY_COMMON = "allow_common_timeouts"
TIMEOUT_POLICY_CANDIDATE_IMPROVEMENTS = (
    "allow_candidate_timeout_improvements"
)


class GateInputError(ValueError):
    """Raised when an input is not a complete compare_viper_ab.py CSV."""

    def __init__(self, errors: list[str]):
        if not errors:
            raise ValueError("GateInputError requires at least one error")
        self.errors = errors
        super().__init__(errors[0])


def _parse_canonical_int(raw: str, field: str, context: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{context}: invalid {field} {raw!r}") from error
    if str(value) != raw:
        raise ValueError(f"{context}: invalid {field} {raw!r}")
    return value


def _parse_record(record: dict[str | None, Any], context: str) -> dict[str, Any]:
    if None in record:
        raise ValueError(f"{context}: unexpected extra fields {record[None]!r}")
    missing = [field for field in FIELDNAMES if record.get(field) is None]
    if missing:
        raise ValueError(f"{context}: missing fields {missing!r}")

    relative_path = record["relative_path"]
    expected_status = record["expected_status"]
    label = record["label"]
    result = record["result"]
    raw_repeat = record["repeat"]
    raw_time = record["time_s"]
    raw_exit_code = record["exit_code"]
    stderr = record["stderr"]
    assert relative_path is not None
    assert expected_status is not None
    assert label is not None
    assert result is not None
    assert raw_repeat is not None
    assert raw_time is not None
    assert raw_exit_code is not None
    assert stderr is not None

    if not relative_path:
        raise ValueError(f"{context}: relative_path cannot be empty")
    if expected_status not in DECISIVE_RESULTS:
        raise ValueError(
            f"{context}: expected_status must be 'sat' or 'unsat', "
            f"got {expected_status!r}"
        )
    if label not in LABELS:
        raise ValueError(f"{context}: unexpected label {label!r}")
    if not result:
        raise ValueError(f"{context}: result cannot be empty")

    repeat = _parse_canonical_int(raw_repeat, "repeat", context)
    if repeat < 0:
        raise ValueError(f"{context}: repeat must be non-negative")
    try:
        time_s = float(raw_time)
    except ValueError as error:
        raise ValueError(f"{context}: invalid time_s {raw_time!r}") from error
    if not math.isfinite(time_s) or time_s <= 0.0:
        raise ValueError(f"{context}: time_s must be finite and positive")
    exit_code = _parse_canonical_int(raw_exit_code, "exit_code", context)

    if (result == "timeout") != (exit_code == 124):
        raise ValueError(
            f"{context}: timeout rows must use result='timeout' and exit_code=124"
        )

    return {
        "relative_path": relative_path,
        "expected_status": expected_status,
        "label": label,
        "repeat": repeat,
        "result": result,
        "time_s": time_s,
        "exit_code": exit_code,
        "stderr": stderr,
    }


def load_campaign(path: Path) -> dict[str, Any]:
    """Load and strictly validate a complete rectangular paired campaign."""

    observations: dict[tuple[str, int, str], dict[str, Any]] = {}
    expected_by_path: dict[str, str] = {}
    errors: list[str] = []
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames != FIELDNAMES:
                raise GateInputError(
                    [
                        f"{path}: incompatible CSV header: expected {FIELDNAMES!r}; "
                        f"got {reader.fieldnames!r}"
                    ]
                )
            for record in reader:
                context = f"{path}: row ending at line {reader.line_num}"
                try:
                    parsed = _parse_record(record, context)
                except ValueError as error:
                    errors.append(str(error))
                    continue

                relative_path = parsed["relative_path"]
                expected = parsed["expected_status"]
                previous_expected = expected_by_path.setdefault(relative_path, expected)
                if previous_expected != expected:
                    errors.append(
                        f"{context}: inconsistent expected_status for "
                        f"{relative_path!r}: {previous_expected!r} vs {expected!r}"
                    )
                    continue

                key = (relative_path, parsed["repeat"], parsed["label"])
                if key in observations:
                    errors.append(f"{context}: duplicate observation {key!r}")
                    continue
                observations[key] = parsed
    except GateInputError:
        raise
    except (OSError, UnicodeError, csv.Error) as error:
        raise GateInputError([f"{path}: cannot read CSV: {error}"]) from error

    if errors:
        raise GateInputError(errors)
    if not observations:
        raise GateInputError([f"{path}: CSV contains no observations"])

    paths = sorted(expected_by_path)
    repeats = sorted({key[1] for key in observations})
    expected_repeats = list(range(repeats[-1] + 1))
    if repeats != expected_repeats:
        raise GateInputError(
            [
                f"{path}: repeat values must be contiguous from zero: "
                f"got {repeats!r}"
            ]
        )

    missing = [
        (relative_path, repeat, label)
        for relative_path in paths
        for repeat in repeats
        for label in LABELS
        if (relative_path, repeat, label) not in observations
    ]
    if missing:
        expected_rows = len(paths) * len(repeats) * len(LABELS)
        raise GateInputError(
            [
                f"{path}: incomplete paired campaign: rows={len(observations)}/"
                f"{expected_rows}; first_missing={missing[:10]!r}"
            ]
        )

    return {
        "observations": observations,
        "paths": paths,
        "repeats": repeats,
    }


def _is_timeout(observation: dict[str, Any]) -> bool:
    return observation["result"] == "timeout" or observation["exit_code"] == 124


def _is_correct(observation: dict[str, Any]) -> bool:
    return (
        observation["result"] == observation["expected_status"]
        and observation["exit_code"] == 0
    )


def _is_wrong_answer(observation: dict[str, Any]) -> bool:
    return (
        observation["result"] in DECISIVE_RESULTS
        and observation["result"] != observation["expected_status"]
    )


def _is_execution_error(observation: dict[str, Any]) -> bool:
    return observation["exit_code"] != 0 and not _is_timeout(observation)


def _select_timeout_policy(
    *,
    allow_common_timeouts: bool,
    allow_candidate_timeout_improvements: bool,
) -> str:
    if allow_common_timeouts and allow_candidate_timeout_improvements:
        raise ValueError(
            "allow_common_timeouts and allow_candidate_timeout_improvements "
            "are mutually exclusive"
        )
    if allow_candidate_timeout_improvements:
        return TIMEOUT_POLICY_CANDIDATE_IMPROVEMENTS
    if allow_common_timeouts:
        return TIMEOUT_POLICY_COMMON
    return TIMEOUT_POLICY_STRICT


def _classify_timeouts(
    observations: dict[tuple[str, int, str], dict[str, Any]],
    paths: list[str],
    repeats: list[int],
    *,
    policy: str,
) -> tuple[dict[str, Any], bool, int]:
    common_timeout_samples = 0
    common_timeout_instances = 0
    matched_common_timeout_samples = 0
    matched_common_timeout_instances = 0
    timeout_samples = 0
    timeout_instances: set[str] = set()
    unmatched_timeout_samples = 0
    unmatched_timeout_instances = 0
    unmatched_examples: list[dict[str, Any]] = []
    timeout_examples: list[dict[str, Any]] = []
    candidate_improvement_samples: list[dict[str, Any]] = []
    candidate_improvement_instances: set[str] = set()
    disallowed_improvement_policy_samples: list[dict[str, Any]] = []
    disallowed_improvement_policy_instances: set[str] = set()

    for relative_path in paths:
        timeout_repeats = {
            label: {
                repeat
                for repeat in repeats
                if _is_timeout(observations[(relative_path, repeat, label)])
            }
            for label in LABELS
        }
        baseline_repeats = timeout_repeats["baseline"]
        candidate_repeats = timeout_repeats["candidate"]
        common_repeats = baseline_repeats & candidate_repeats
        any_timeout_repeats = baseline_repeats | candidate_repeats
        timeout_samples += len(any_timeout_repeats)
        if any_timeout_repeats:
            timeout_instances.add(relative_path)
        common_timeout_samples += len(common_repeats)
        common_timeout_instances += bool(common_repeats)

        for repeat in sorted(any_timeout_repeats):
            baseline = observations[(relative_path, repeat, "baseline")]
            candidate = observations[(relative_path, repeat, "candidate")]
            baseline_timeout = _is_timeout(baseline)
            candidate_timeout = _is_timeout(candidate)
            example = {
                "baseline_result": baseline["result"],
                "candidate_result": candidate["result"],
                "relative_path": relative_path,
                "repeat": repeat,
            }
            timeout_examples.append(example)

            if baseline_timeout and _is_correct(candidate):
                candidate_improvement_samples.append(
                    {"relative_path": relative_path, "repeat": repeat}
                )
                candidate_improvement_instances.add(relative_path)

            if baseline_timeout and candidate_timeout:
                continue
            if baseline_timeout and _is_correct(candidate):
                continue

            if candidate_timeout and _is_correct(baseline):
                reason = "candidate_timeout_with_baseline_correct"
            elif candidate_timeout:
                reason = "candidate_timeout_without_matching_baseline_timeout"
            else:
                reason = "baseline_timeout_without_candidate_correct"
            disallowed_improvement_policy_samples.append(
                {**example, "reason": reason}
            )
            disallowed_improvement_policy_instances.add(relative_path)

        if baseline_repeats == candidate_repeats and baseline_repeats:
            matched_common_timeout_samples += len(baseline_repeats)
            matched_common_timeout_instances += 1
            continue
        if not baseline_repeats and not candidate_repeats:
            continue

        unmatched_timeout_instances += 1
        for label, unmatched_repeats in (
            ("baseline", baseline_repeats - candidate_repeats),
            ("candidate", candidate_repeats - baseline_repeats),
        ):
            for repeat in sorted(unmatched_repeats):
                unmatched_timeout_samples += 1
                unmatched_examples.append(
                    {
                        "label": label,
                        "relative_path": relative_path,
                        "repeat": repeat,
                    }
                )

    total_timeout_observations = sum(
        _is_timeout(observation) for observation in observations.values()
    )
    if policy == TIMEOUT_POLICY_STRICT:
        allowed_timeout_patterns: list[str] = []
        rejected_timeout_samples = timeout_samples
        rejected_timeout_instances = len(timeout_instances)
        rejected_timeout_examples = timeout_examples
    elif policy == TIMEOUT_POLICY_COMMON:
        allowed_timeout_patterns = [
            "identical_baseline_candidate_timeout_repeat_sets_per_instance"
        ]
        rejected_timeout_samples = unmatched_timeout_samples
        rejected_timeout_instances = unmatched_timeout_instances
        rejected_timeout_examples = unmatched_examples
    elif policy == TIMEOUT_POLICY_CANDIDATE_IMPROVEMENTS:
        allowed_timeout_patterns = [
            "paired_common_timeout",
            "baseline_timeout_to_candidate_correct",
        ]
        rejected_timeout_samples = len(disallowed_improvement_policy_samples)
        rejected_timeout_instances = len(disallowed_improvement_policy_instances)
        rejected_timeout_examples = disallowed_improvement_policy_samples
    else:
        raise ValueError(f"unknown timeout policy {policy!r}")

    common_only = policy == TIMEOUT_POLICY_COMMON
    tolerate_improvements = policy == TIMEOUT_POLICY_CANDIDATE_IMPROVEMENTS
    summary = {
        "allow_candidate_timeout_improvements": tolerate_improvements,
        "allow_common_timeouts": common_only or tolerate_improvements,
        "allowed_timeout_patterns": allowed_timeout_patterns,
        "candidate_timeout_improvement_instances": len(
            candidate_improvement_instances
        ),
        "candidate_timeout_improvement_samples": len(candidate_improvement_samples),
        "candidate_timeout_improvement_examples": candidate_improvement_samples[:25],
        "common_timeout_instances": common_timeout_instances,
        "common_timeout_samples": common_timeout_samples,
        "matched_common_timeout_instances": matched_common_timeout_instances,
        "matched_common_timeout_samples": matched_common_timeout_samples,
        "name": policy,
        "rejected_timeout_examples": rejected_timeout_examples[:25],
        "rejected_timeout_instances": rejected_timeout_instances,
        "rejected_timeout_samples": rejected_timeout_samples,
        "sample_unit": "paired_(relative_path,repeat)",
        "timeout_observations": total_timeout_observations,
        "timeout_samples": timeout_samples,
        "tolerated_common_timeout_instances": (
            common_timeout_instances
            if tolerate_improvements
            else matched_common_timeout_instances
            if common_only
            else 0
        ),
        "tolerated_common_timeout_samples": (
            common_timeout_samples
            if tolerate_improvements
            else matched_common_timeout_samples
            if common_only
            else 0
        ),
        "tolerated_candidate_timeout_improvement_instances": (
            len(candidate_improvement_instances) if tolerate_improvements else 0
        ),
        "tolerated_candidate_timeout_improvement_samples": (
            len(candidate_improvement_samples) if tolerate_improvements else 0
        ),
        "unmatched_timeout_instances": unmatched_timeout_instances,
        "unmatched_timeout_samples": unmatched_timeout_samples,
        "unmatched_timeout_examples": unmatched_examples[:25],
    }
    return (
        summary,
        rejected_timeout_samples == 0,
        rejected_timeout_samples,
    )


def _finite_ratio(numerator: float, denominator: float) -> float:
    ratio = numerator / denominator
    if not math.isfinite(ratio) or ratio <= 0.0:
        raise ArithmeticError("timing ratio is not finite and positive")
    return ratio


def _metric_bundle(entries: list[tuple[float, float, float]]) -> dict[str, float]:
    ratios = [entry[2] for entry in entries]
    try:
        baseline_total = math.fsum(entry[0] for entry in entries)
        candidate_total = math.fsum(entry[1] for entry in entries)
        total_speedup = _finite_ratio(baseline_total, candidate_total)
        geometric_speedup = math.exp(
            math.fsum(math.log(ratio) for ratio in ratios) / len(ratios)
        )
    except (OverflowError, ValueError) as error:
        raise ArithmeticError("timing aggregates are outside the finite range") from error
    metrics = {
        "median_speedup": statistics.median(ratios),
        "total_speedup": total_speedup,
        "geometric_speedup": geometric_speedup,
    }
    if not all(math.isfinite(value) and value > 0.0 for value in metrics.values()):
        raise ArithmeticError("timing aggregates are not finite and positive")
    return metrics


def _quantile(sorted_values: list[float], probability: float) -> float:
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def paired_bootstrap(
    entries: list[tuple[float, float, float]],
    *,
    iterations: int,
    confidence_level: float,
    seed: int,
) -> dict[str, Any]:
    """Bootstrap paired instance medians by resampling whole instances."""

    if not entries:
        return {
            "confidence_level": confidence_level,
            "interval_method": "percentile",
            "iterations": iterations,
            "metrics": {
                name: {"estimate": None, "ci_lower": None, "ci_upper": None}
                for name in (
                    "median_speedup",
                    "total_speedup",
                    "geometric_speedup",
                )
            },
            "resampling_unit": "paired_instance_medians",
            "seed": seed,
        }

    estimates = _metric_bundle(entries)
    samples = {name: [] for name in estimates}
    random_source = random.Random(seed)
    sample_size = len(entries)
    for _ in range(iterations):
        resample = [entries[random_source.randrange(sample_size)] for _ in entries]
        metrics = _metric_bundle(resample)
        for name, value in metrics.items():
            samples[name].append(value)

    tail = (1.0 - confidence_level) / 2.0
    intervals = {}
    for name, estimate in estimates.items():
        ordered = sorted(samples[name])
        intervals[name] = {
            "estimate": estimate,
            "ci_lower": _quantile(ordered, tail),
            "ci_upper": _quantile(ordered, 1.0 - tail),
        }
    return {
        "confidence_level": confidence_level,
        "interval_method": "percentile",
        "iterations": iterations,
        "metrics": intervals,
        "resampling_unit": "paired_instance_medians",
        "seed": seed,
    }


def paired_sign_flip_test(
    ratios: list[float], *, iterations: int, seed: int
) -> dict[str, Any]:
    """One-sided paired randomization test on summed log speedups."""

    if not ratios:
        return {
            "alternative": "candidate_faster",
            "evaluated_permutations": 0,
            "method": "not_computed",
            "observed_sum_log_speedup": None,
            "p_value": None,
            "seed": seed,
        }

    differences = [math.log(ratio) for ratio in ratios]
    observed = math.fsum(differences)
    tolerance = 1e-15 * max(1.0, abs(observed))
    exact_count = 1 << len(differences)
    extreme = 0
    if exact_count <= iterations:
        for mask in range(exact_count):
            statistic = math.fsum(
                difference if mask & (1 << index) else -difference
                for index, difference in enumerate(differences)
            )
            extreme += statistic >= observed - tolerance
        p_value = extreme / exact_count
        method = "exact_paired_sign_flip"
        evaluated = exact_count
    else:
        random_source = random.Random(seed ^ 0x9E3779B97F4A7C15)
        for _ in range(iterations):
            statistic = math.fsum(
                difference if random_source.getrandbits(1) else -difference
                for difference in differences
            )
            extreme += statistic >= observed - tolerance
        p_value = (extreme + 1) / (iterations + 1)
        method = "monte_carlo_paired_sign_flip"
        evaluated = iterations

    return {
        "alternative": "candidate_faster",
        "evaluated_permutations": evaluated,
        "method": method,
        "observed_sum_log_speedup": observed,
        "p_value": p_value,
        "seed": seed,
    }


def _check(
    *, passed: bool, actual: int | float | None, operator: str, threshold: int | float
) -> dict[str, Any]:
    return {
        "actual": actual,
        "operator": operator,
        "passed": passed,
        "threshold": threshold,
    }


def _validate_parameters(
    *,
    bootstrap_iterations: int,
    permutation_iterations: int,
    confidence_level: float,
    min_paired_instances: int,
    min_median_speedup: float,
    min_total_speedup: float,
    min_geometric_speedup: float,
    max_p_value: float,
    tie_relative_tolerance: float,
) -> None:
    if bootstrap_iterations < 1:
        raise ValueError("bootstrap_iterations must be positive")
    if permutation_iterations < 1:
        raise ValueError("permutation_iterations must be positive")
    if not 0.0 < confidence_level < 1.0:
        raise ValueError("confidence_level must be in (0, 1)")
    if min_paired_instances < 1:
        raise ValueError("min_paired_instances must be positive")
    speedups = (
        min_median_speedup,
        min_total_speedup,
        min_geometric_speedup,
    )
    if not all(math.isfinite(value) and value > 0.0 for value in speedups):
        raise ValueError("speedup thresholds must be finite and positive")
    if not math.isfinite(max_p_value) or not 0.0 <= max_p_value <= 1.0:
        raise ValueError("max_p_value must be in [0, 1]")
    if (
        not math.isfinite(tie_relative_tolerance)
        or not 0.0 <= tie_relative_tolerance < 1.0
    ):
        raise ValueError("tie_relative_tolerance must be in [0, 1)")


def evaluate_csv(
    path: Path,
    *,
    seed: int = DEFAULT_SEED,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    permutation_iterations: int = DEFAULT_PERMUTATION_ITERATIONS,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
    min_paired_instances: int = DEFAULT_MIN_PAIRED_INSTANCES,
    min_median_speedup: float = DEFAULT_MIN_SPEEDUP,
    min_total_speedup: float = DEFAULT_MIN_SPEEDUP,
    min_geometric_speedup: float = DEFAULT_MIN_SPEEDUP,
    max_p_value: float = DEFAULT_MAX_P_VALUE,
    tie_relative_tolerance: float = DEFAULT_TIE_RELATIVE_TOLERANCE,
    allow_common_timeouts: bool = False,
    allow_candidate_timeout_improvements: bool = False,
) -> dict[str, Any]:
    """Evaluate a valid paired campaign and return a stable JSON-ready result."""

    timeout_policy_name = _select_timeout_policy(
        allow_common_timeouts=allow_common_timeouts,
        allow_candidate_timeout_improvements=(
            allow_candidate_timeout_improvements
        ),
    )
    _validate_parameters(
        bootstrap_iterations=bootstrap_iterations,
        permutation_iterations=permutation_iterations,
        confidence_level=confidence_level,
        min_paired_instances=min_paired_instances,
        min_median_speedup=min_median_speedup,
        min_total_speedup=min_total_speedup,
        min_geometric_speedup=min_geometric_speedup,
        max_p_value=max_p_value,
        tie_relative_tolerance=tie_relative_tolerance,
    )
    campaign = load_campaign(path)
    observations = campaign["observations"]
    paths = campaign["paths"]
    repeats = campaign["repeats"]

    quality: dict[str, dict[str, int]] = {
        label: {
            "correct_instances": 0,
            "correct_samples": 0,
            "execution_error_samples": 0,
            "failed_samples": 0,
            "timeout_samples": 0,
            "wrong_answer_samples": 0,
        }
        for label in LABELS
    }
    issue_examples: dict[str, list[dict[str, Any]]] = {
        "execution_errors": [],
        "timeouts": [],
        "wrong_answers": [],
    }
    instance_correct: dict[tuple[str, str], bool] = {}

    for relative_path in paths:
        for label in LABELS:
            side = [observations[(relative_path, repeat, label)] for repeat in repeats]
            correctness = [_is_correct(observation) for observation in side]
            quality[label]["correct_samples"] += sum(correctness)
            quality[label]["failed_samples"] += len(side) - sum(correctness)
            instance_correct[(relative_path, label)] = all(correctness)
            quality[label]["correct_instances"] += all(correctness)
            for observation in side:
                example = {
                    "label": label,
                    "relative_path": relative_path,
                    "repeat": observation["repeat"],
                    "result": observation["result"],
                }
                if _is_timeout(observation):
                    quality[label]["timeout_samples"] += 1
                    issue_examples["timeouts"].append(example)
                if _is_execution_error(observation):
                    quality[label]["execution_error_samples"] += 1
                    issue_examples["execution_errors"].append(
                        {**example, "exit_code": observation["exit_code"]}
                    )
                if _is_wrong_answer(observation):
                    quality[label]["wrong_answer_samples"] += 1
                    issue_examples["wrong_answers"].append(
                        {**example, "expected_status": observation["expected_status"]}
                    )

    baseline_only = [
        relative_path
        for relative_path in paths
        if instance_correct[(relative_path, "baseline")]
        and not instance_correct[(relative_path, "candidate")]
    ]
    candidate_only = [
        relative_path
        for relative_path in paths
        if instance_correct[(relative_path, "candidate")]
        and not instance_correct[(relative_path, "baseline")]
    ]

    paired_entries: list[tuple[float, float, float]] = []
    common_correct_sample_pairs = 0
    baseline_only_samples: list[dict[str, Any]] = []
    candidate_only_samples: list[dict[str, Any]] = []
    for relative_path in paths:
        for repeat in repeats:
            baseline = observations[(relative_path, repeat, "baseline")]
            candidate = observations[(relative_path, repeat, "candidate")]
            baseline_correct = _is_correct(baseline)
            candidate_correct = _is_correct(candidate)
            common_correct_sample_pairs += baseline_correct and candidate_correct
            sample = {"relative_path": relative_path, "repeat": repeat}
            if baseline_correct and not candidate_correct:
                baseline_only_samples.append(sample)
            if candidate_correct and not baseline_correct:
                candidate_only_samples.append(sample)
        if not (
            instance_correct[(relative_path, "baseline")]
            and instance_correct[(relative_path, "candidate")]
        ):
            continue
        baseline_median = statistics.median(
            observations[(relative_path, repeat, "baseline")]["time_s"]
            for repeat in repeats
        )
        candidate_median = statistics.median(
            observations[(relative_path, repeat, "candidate")]["time_s"]
            for repeat in repeats
        )
        try:
            ratio = _finite_ratio(baseline_median, candidate_median)
        except ArithmeticError as error:
            raise GateInputError(
                [
                    f"{path}: invalid timing ratio for {relative_path!r}: "
                    f"{error}"
                ]
            ) from error
        paired_entries.append((baseline_median, candidate_median, ratio))

    try:
        metrics = _metric_bundle(paired_entries) if paired_entries else {
            "median_speedup": None,
            "total_speedup": None,
            "geometric_speedup": None,
        }
    except ArithmeticError as error:
        raise GateInputError([f"{path}: invalid timing aggregates: {error}"]) from error
    wins = sum(
        candidate < baseline
        and not math.isclose(
            baseline,
            candidate,
            rel_tol=tie_relative_tolerance,
            abs_tol=0.0,
        )
        for baseline, candidate, _ in paired_entries
    )
    losses = sum(
        baseline < candidate
        and not math.isclose(
            baseline,
            candidate,
            rel_tol=tie_relative_tolerance,
            abs_tol=0.0,
        )
        for baseline, candidate, _ in paired_entries
    )
    ties = len(paired_entries) - wins - losses

    try:
        bootstrap = paired_bootstrap(
            paired_entries,
            iterations=bootstrap_iterations,
            confidence_level=confidence_level,
            seed=seed,
        )
        permutation_test = paired_sign_flip_test(
            [entry[2] for entry in paired_entries],
            iterations=permutation_iterations,
            seed=seed,
        )
    except ArithmeticError as error:
        raise GateInputError([f"{path}: invalid timing aggregates: {error}"]) from error

    sample_delta = (
        quality["candidate"]["correct_samples"]
        - quality["baseline"]["correct_samples"]
    )
    instance_delta = (
        quality["candidate"]["correct_instances"]
        - quality["baseline"]["correct_instances"]
    )
    timeout_policy, timeouts_satisfy_policy, timeout_policy_actual = (
        _classify_timeouts(
            observations,
            paths,
            repeats,
            policy=timeout_policy_name,
        )
    )
    execution_error_count = sum(
        quality[label]["execution_error_samples"] for label in LABELS
    )
    wrong_answer_count = sum(
        quality[label]["wrong_answer_samples"] for label in LABELS
    )
    thresholds = {
        "max_p_value": max_p_value,
        "min_geometric_speedup": min_geometric_speedup,
        "min_median_speedup": min_median_speedup,
        "min_paired_instances": min_paired_instances,
        "min_total_speedup": min_total_speedup,
    }

    checks = {
        "candidate_has_no_wrong_answers": _check(
            passed=quality["candidate"]["wrong_answer_samples"] == 0,
            actual=quality["candidate"]["wrong_answer_samples"],
            operator="==",
            threshold=0,
        ),
        "geometric_bootstrap_lower_bound": _check(
            passed=(
                bootstrap["metrics"]["geometric_speedup"]["ci_lower"] is not None
                and bootstrap["metrics"]["geometric_speedup"]["ci_lower"]
                >= min_geometric_speedup
            ),
            actual=bootstrap["metrics"]["geometric_speedup"]["ci_lower"],
            operator=">=",
            threshold=min_geometric_speedup,
        ),
        "geometric_speedup": _check(
            passed=(
                metrics["geometric_speedup"] is not None
                and metrics["geometric_speedup"] >= min_geometric_speedup
            ),
            actual=metrics["geometric_speedup"],
            operator=">=",
            threshold=min_geometric_speedup,
        ),
        "instance_coverage_non_regression": _check(
            passed=instance_delta >= 0,
            actual=instance_delta,
            operator=">=",
            threshold=0,
        ),
        "median_bootstrap_lower_bound": _check(
            passed=(
                bootstrap["metrics"]["median_speedup"]["ci_lower"] is not None
                and bootstrap["metrics"]["median_speedup"]["ci_lower"]
                >= min_median_speedup
            ),
            actual=bootstrap["metrics"]["median_speedup"]["ci_lower"],
            operator=">=",
            threshold=min_median_speedup,
        ),
        "median_speedup": _check(
            passed=(
                metrics["median_speedup"] is not None
                and metrics["median_speedup"] >= min_median_speedup
            ),
            actual=metrics["median_speedup"],
            operator=">=",
            threshold=min_median_speedup,
        ),
        "minimum_paired_instances": _check(
            passed=len(paired_entries) >= min_paired_instances,
            actual=len(paired_entries),
            operator=">=",
            threshold=min_paired_instances,
        ),
        "no_execution_errors": _check(
            passed=execution_error_count == 0,
            actual=execution_error_count,
            operator="==",
            threshold=0,
        ),
        "no_wrong_answers": _check(
            passed=wrong_answer_count == 0,
            actual=wrong_answer_count,
            operator="==",
            threshold=0,
        ),
        "no_instance_coverage_regressions": _check(
            passed=not baseline_only,
            actual=len(baseline_only),
            operator="==",
            threshold=0,
        ),
        "no_sample_coverage_regressions": _check(
            passed=not baseline_only_samples,
            actual=len(baseline_only_samples),
            operator="==",
            threshold=0,
        ),
        "timeouts_satisfy_policy": _check(
            passed=timeouts_satisfy_policy,
            actual=timeout_policy_actual,
            operator="==",
            threshold=0,
        )
        | {
            "actual_metric": "rejected_timeout_samples",
            "policy": timeout_policy["name"],
        },
        "permutation_p_value": _check(
            passed=(
                permutation_test["p_value"] is not None
                and permutation_test["p_value"] <= max_p_value
            ),
            actual=permutation_test["p_value"],
            operator="<=",
            threshold=max_p_value,
        ),
        "sample_coverage_non_regression": _check(
            passed=sample_delta >= 0,
            actual=sample_delta,
            operator=">=",
            threshold=0,
        ),
        "total_bootstrap_lower_bound": _check(
            passed=(
                bootstrap["metrics"]["total_speedup"]["ci_lower"] is not None
                and bootstrap["metrics"]["total_speedup"]["ci_lower"]
                >= min_total_speedup
            ),
            actual=bootstrap["metrics"]["total_speedup"]["ci_lower"],
            operator=">=",
            threshold=min_total_speedup,
        ),
        "total_speedup": _check(
            passed=(
                metrics["total_speedup"] is not None
                and metrics["total_speedup"] >= min_total_speedup
            ),
            actual=metrics["total_speedup"],
            operator=">=",
            threshold=min_total_speedup,
        ),
    }
    promoted = all(check["passed"] for check in checks.values())

    return {
        "bootstrap": bootstrap,
        "checks": checks,
        "input": {
            "instances": len(paths),
            "repeats": len(repeats),
            "rows": len(observations),
            "source_csv": str(path),
        },
        "issues": {
            name: {"count": len(examples), "examples": examples[:25]}
            for name, examples in issue_examples.items()
        },
        "pairing": {
            "common_correct_sample_pairs": common_correct_sample_pairs,
            "expected_sample_pairs": len(paths) * len(repeats),
            "paired_instance_medians": len(paired_entries),
            "paired_timing_samples": len(paired_entries) * len(repeats),
        },
        "parameters": {
            "allow_candidate_timeout_improvements": (
                allow_candidate_timeout_improvements
            ),
            "allow_common_timeouts": allow_common_timeouts,
            "bootstrap_iterations": bootstrap_iterations,
            "confidence_level": confidence_level,
            "permutation_iterations": permutation_iterations,
            "seed": seed,
            "thresholds": thresholds,
            "tie_relative_tolerance": tie_relative_tolerance,
            "timeout_policy": timeout_policy["name"],
        },
        "permutation_test": permutation_test,
        "promoted": promoted,
        "quality": {
            "baseline": quality["baseline"],
            "baseline_only_correct_instances": {
                "count": len(baseline_only),
                "examples": baseline_only[:25],
            },
            "baseline_only_correct_samples": {
                "count": len(baseline_only_samples),
                "examples": baseline_only_samples[:25],
            },
            "candidate": quality["candidate"],
            "candidate_only_correct_instances": {
                "count": len(candidate_only),
                "examples": candidate_only[:25],
            },
            "candidate_only_correct_samples": {
                "count": len(candidate_only_samples),
                "examples": candidate_only_samples[:25],
            },
            "instance_coverage_delta": instance_delta,
            "sample_coverage_delta": sample_delta,
        },
        "ratio_direction": "baseline_over_candidate",
        "schema_version": SCHEMA_VERSION,
        "status": "promoted" if promoted else "rejected",
        "timing": {
            "geometric_speedup": metrics["geometric_speedup"],
            "losses": losses,
            "median_speedup": metrics["median_speedup"],
            "ties": ties,
            "total_speedup": metrics["total_speedup"],
            "unit": "paired_instance_medians",
            "wins": wins,
        },
        "timeout_policy": timeout_policy,
    }


def invalid_input_payload(path: Path, errors: list[str]) -> dict[str, Any]:
    return {
        "errors": errors,
        "input": {"source_csv": str(path)},
        "promoted": False,
        "schema_version": SCHEMA_VERSION,
        "status": "invalid_input",
    }


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def _finite_positive_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(value) or value <= 0.0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return value


def _confidence_level(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(value) or not 0.0 < value < 1.0:
        raise argparse.ArgumentTypeError("must be in (0, 1)")
    return value


def _probability(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError("must be in [0, 1]")
    return value


def _tie_tolerance(raw: str) -> float:
    value = _probability(raw)
    if value >= 1.0:
        raise argparse.ArgumentTypeError("must be in [0, 1)")
    return value


def _write_json(payload: dict[str, Any], output: Path | None) -> None:
    rendered = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Apply a deterministic statistical promotion gate to paired "
            "compare_viper_ab.py CSV output."
        ),
        epilog=(
            "Speedups are baseline/candidate, so values above one favor the "
            "candidate. Exit status is 0 for promotion, 1 for a valid rejection, "
            "and 2 for invalid input or arguments."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("csv", type=Path, help="paired A/B observations CSV")
    parser.add_argument(
        "--out",
        "--output",
        dest="out",
        type=Path,
        help="write JSON here instead of stdout",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="deterministic bootstrap and permutation seed",
    )
    parser.add_argument(
        "--bootstrap-iterations",
        type=_positive_int,
        default=DEFAULT_BOOTSTRAP_ITERATIONS,
        help="paired instance bootstrap resamples",
    )
    parser.add_argument(
        "--permutation-iterations",
        type=_positive_int,
        default=DEFAULT_PERMUTATION_ITERATIONS,
        help="maximum exact permutations or Monte Carlo sign flips",
    )
    parser.add_argument(
        "--confidence-level",
        type=_confidence_level,
        default=DEFAULT_CONFIDENCE_LEVEL,
        help="percentile bootstrap confidence level",
    )
    parser.add_argument(
        "--min-paired-instances",
        type=_positive_int,
        default=DEFAULT_MIN_PAIRED_INSTANCES,
        help="minimum number of common-correct paired instance medians",
    )
    parser.add_argument(
        "--min-median-speedup",
        type=_finite_positive_float,
        default=DEFAULT_MIN_SPEEDUP,
        help="minimum median estimate and bootstrap lower bound",
    )
    parser.add_argument(
        "--min-total-speedup",
        type=_finite_positive_float,
        default=DEFAULT_MIN_SPEEDUP,
        help="minimum total estimate and bootstrap lower bound",
    )
    parser.add_argument(
        "--min-geometric-speedup",
        type=_finite_positive_float,
        default=DEFAULT_MIN_SPEEDUP,
        help="minimum geometric estimate and bootstrap lower bound",
    )
    parser.add_argument(
        "--max-p-value",
        type=_probability,
        default=DEFAULT_MAX_P_VALUE,
        help="maximum one-sided paired sign-flip p-value",
    )
    parser.add_argument(
        "--tie-relative-tolerance",
        type=_tie_tolerance,
        default=DEFAULT_TIE_RELATIVE_TOLERANCE,
        help="relative tolerance used only for win/loss/tie classification",
    )
    timeout_policy = parser.add_mutually_exclusive_group()
    timeout_policy.add_argument(
        "--allow-common-timeouts",
        action="store_true",
        help=(
            "tolerate only instances with identical baseline/candidate timeout "
            "repeat sets"
        ),
    )
    timeout_policy.add_argument(
        "--allow-candidate-timeout-improvements",
        action="store_true",
        help=(
            "tolerate paired common timeouts and baseline timeouts converted "
            "to correct candidate solves"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        payload = evaluate_csv(
            args.csv,
            seed=args.seed,
            bootstrap_iterations=args.bootstrap_iterations,
            permutation_iterations=args.permutation_iterations,
            confidence_level=args.confidence_level,
            min_paired_instances=args.min_paired_instances,
            min_median_speedup=args.min_median_speedup,
            min_total_speedup=args.min_total_speedup,
            min_geometric_speedup=args.min_geometric_speedup,
            max_p_value=args.max_p_value,
            tie_relative_tolerance=args.tie_relative_tolerance,
            allow_common_timeouts=args.allow_common_timeouts,
            allow_candidate_timeout_improvements=(
                args.allow_candidate_timeout_improvements
            ),
        )
        exit_code = 0 if payload["promoted"] else 1
    except GateInputError as error:
        payload = invalid_input_payload(args.csv, error.errors)
        exit_code = 2

    try:
        _write_json(payload, args.out)
    except (OSError, ValueError) as error:
        parser.error(f"cannot write JSON output: {error}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
