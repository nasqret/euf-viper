#!/usr/bin/env python3
"""Apply the frozen promotion rule to a Viper standard/PGO Williams summary."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "euf-viper.pgo-holdout-decision.v1"
BASELINE_ARM = "viper-standard"
CANDIDATE_ARM = "viper-pgo"
BOOTSTRAP_ITERATIONS = 20_000
CONFIDENCE_LEVEL = 0.99
BOOTSTRAP_SEED = 0
MIN_COMMON_INSTANCES = 30
MIN_SPEEDUP = 1.0
MAX_P95_SLOWDOWN = 1.05


class DecisionError(ValueError):
    """Raised when the benchmark summary cannot support an adjudication."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def strict_json_loads(text: str) -> Any:
    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number {value}")

    return json.loads(
        text, object_pairs_hook=object_hook, parse_constant=reject_constant
    )


def finite_number(value: object, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DecisionError(f"{label} is not a number")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0.0):
        raise DecisionError(f"{label} is outside its finite domain")
    return result


def exact_nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DecisionError(f"{label} is not a nonnegative integer")
    return value


def percentile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise DecisionError("cannot take a percentile of an empty sample")
    position = probability * (len(sorted_values) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1.0 - fraction) + sorted_values[upper] * fraction


def paired_metrics(pairs: Sequence[tuple[float, float]]) -> dict[str, float]:
    if not pairs:
        raise DecisionError("no common-correct timing pairs")
    baseline_total = math.fsum(baseline for baseline, _ in pairs)
    candidate_total = math.fsum(candidate for _, candidate in pairs)
    log_ratios = [math.log(baseline / candidate) for baseline, candidate in pairs]
    slowdowns = sorted(candidate / baseline for baseline, candidate in pairs)
    return {
        "aggregate_speedup": baseline_total / candidate_total,
        "geometric_speedup": math.exp(math.fsum(log_ratios) / len(log_ratios)),
        "p95_slowdown": percentile(slowdowns, 0.95),
    }


def paired_bootstrap(
    pairs: Sequence[tuple[float, float]],
    *,
    iterations: int = BOOTSTRAP_ITERATIONS,
    confidence_level: float = CONFIDENCE_LEVEL,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, Any]:
    if not pairs:
        raise DecisionError("bootstrap requires common-correct timing pairs")
    if iterations < 1:
        raise DecisionError("bootstrap iteration count must be positive")
    if not 0.0 < confidence_level < 1.0:
        raise DecisionError("confidence level must be strictly between zero and one")

    generator = random.Random(seed)
    count = len(pairs)
    geometric: list[float] = []
    aggregate: list[float] = []
    for _ in range(iterations):
        sampled = [pairs[generator.randrange(count)] for _ in range(count)]
        metrics = paired_metrics(sampled)
        geometric.append(metrics["geometric_speedup"])
        aggregate.append(metrics["aggregate_speedup"])
    geometric.sort()
    aggregate.sort()
    tail = (1.0 - confidence_level) / 2.0
    return {
        "confidence_level": confidence_level,
        "iterations": iterations,
        "resampling_unit": "instance",
        "seed": seed,
        "metrics": {
            "aggregate_speedup": {
                "ci_lower": percentile(aggregate, tail),
                "ci_upper": percentile(aggregate, 1.0 - tail),
            },
            "geometric_speedup": {
                "ci_lower": percentile(geometric, tail),
                "ci_upper": percentile(geometric, 1.0 - tail),
            },
        },
    }


def check(passed: bool, *, actual: object, threshold: object) -> dict[str, Any]:
    return {"actual": actual, "passed": bool(passed), "threshold": threshold}


def arm_path(path: Mapping[str, Any], arm: str, repeats: int) -> Mapping[str, Any]:
    try:
        record = path["arms"][arm]
    except (KeyError, TypeError) as error:
        raise DecisionError(f"path lacks arm {arm!r}") from error
    if not isinstance(record, dict):
        raise DecisionError(f"path arm {arm!r} is not an object")
    for field in ("correct", "covered"):
        if type(record.get(field)) is not bool:
            raise DecisionError(f"path arm {arm!r} has invalid {field}")
    if record["correct"] != record["covered"]:
        raise DecisionError(f"path arm {arm!r} disagrees on correct and covered")
    correct_repeats = exact_nonnegative_int(
        record.get("correct_repeats"), f"path arm {arm} correct repeats"
    )
    if record["correct"] != (correct_repeats == repeats):
        raise DecisionError(f"path arm {arm!r} has inconsistent repeat coverage")
    return record


def evaluate(
    summary: Mapping[str, Any],
    *,
    summary_sha256: str,
    expected_instances: int,
) -> dict[str, Any]:
    if summary.get("schema_version") != 1 or summary.get("status") != "complete":
        raise DecisionError("Williams summary is not a complete schema-v1 artifact")
    arm_order = summary.get("arm_order")
    if (
        type(arm_order) is not list
        or any(type(arm) is not str or not arm for arm in arm_order)
        or len(arm_order) != len(set(arm_order))
        or BASELINE_ARM not in arm_order
        or CANDIDATE_ARM not in arm_order
    ):
        raise DecisionError("Williams arm order is invalid")
    instances = exact_nonnegative_int(summary.get("instances"), "instance count")
    if instances != expected_instances:
        raise DecisionError(
            f"instance count mismatch: expected {expected_instances}, got {instances}"
        )
    repeats = exact_nonnegative_int(summary.get("repeats"), "repeat count")
    if repeats < 1:
        raise DecisionError("repeat count must be positive")
    measured_runs = exact_nonnegative_int(summary.get("measured_runs"), "measured runs")
    if measured_runs != instances * repeats * len(arm_order):
        raise DecisionError("measured run count does not match the complete design")

    accounting = summary.get("accounting")
    if not isinstance(accounting, dict):
        raise DecisionError("summary accounting is not an object")
    invalid_run_count = sum(
        exact_nonnegative_int(accounting.get(field), f"accounting {field}")
        for field in ("execution_errors", "unexpected_results", "wrong_answers")
    )

    arms = summary.get("arms")
    if not isinstance(arms, dict):
        raise DecisionError("summary arms are not an object")
    for arm in (BASELINE_ARM, CANDIDATE_ARM):
        record = arms.get(arm)
        if not isinstance(record, dict):
            raise DecisionError(f"summary lacks arm totals for {arm}")
        if exact_nonnegative_int(record.get("runs"), f"{arm} runs") != instances * repeats:
            raise DecisionError(f"{arm} run count is incomplete")
        for field in ("error_runs", "unexpected_runs", "wrong_runs"):
            invalid_run_count += exact_nonnegative_int(
                record.get(field), f"{arm} {field}"
            )

    paths = summary.get("paths")
    if type(paths) is not list or len(paths) != instances:
        raise DecisionError("summary paths do not match the instance count")
    seen_paths: set[str] = set()
    common_pairs: list[tuple[float, float]] = []
    baseline_only: list[str] = []
    candidate_only: list[str] = []
    baseline_covered = 0
    candidate_covered = 0
    for index, path in enumerate(paths):
        if not isinstance(path, dict):
            raise DecisionError(f"path {index} is not an object")
        relative_path = path.get("relative_path")
        if type(relative_path) is not str or not relative_path or relative_path in seen_paths:
            raise DecisionError(f"path {index} has an invalid or duplicate relative path")
        seen_paths.add(relative_path)
        baseline = arm_path(path, BASELINE_ARM, repeats)
        candidate = arm_path(path, CANDIDATE_ARM, repeats)
        baseline_correct = baseline["correct"]
        candidate_correct = candidate["correct"]
        baseline_covered += int(baseline_correct)
        candidate_covered += int(candidate_correct)
        if baseline_correct and not candidate_correct:
            baseline_only.append(relative_path)
        elif candidate_correct and not baseline_correct:
            candidate_only.append(relative_path)
        elif baseline_correct and candidate_correct:
            baseline_time = finite_number(
                baseline.get("median_time_s"),
                f"{relative_path} baseline median",
                positive=True,
            )
            candidate_time = finite_number(
                candidate.get("median_time_s"),
                f"{relative_path} candidate median",
                positive=True,
            )
            common_pairs.append((baseline_time, candidate_time))

    metrics = paired_metrics(common_pairs)
    bootstrap = paired_bootstrap(common_pairs)
    baseline_timeout_runs = exact_nonnegative_int(
        arms[BASELINE_ARM].get("timeout_runs"), "baseline timeout runs"
    )
    candidate_timeout_runs = exact_nonnegative_int(
        arms[CANDIDATE_ARM].get("timeout_runs"), "candidate timeout runs"
    )
    checks = {
        "aggregate_bootstrap_lower_bound": check(
            bootstrap["metrics"]["aggregate_speedup"]["ci_lower"] > MIN_SPEEDUP,
            actual=bootstrap["metrics"]["aggregate_speedup"]["ci_lower"],
            threshold={"exclusive_minimum": MIN_SPEEDUP},
        ),
        "aggregate_point_speedup": check(
            metrics["aggregate_speedup"] > MIN_SPEEDUP,
            actual=metrics["aggregate_speedup"],
            threshold={"exclusive_minimum": MIN_SPEEDUP},
        ),
        "common_instance_floor": check(
            len(common_pairs) >= MIN_COMMON_INSTANCES,
            actual=len(common_pairs),
            threshold={"minimum": MIN_COMMON_INSTANCES},
        ),
        "coverage_nonregression": check(
            candidate_covered >= baseline_covered and not baseline_only,
            actual={
                "baseline": baseline_covered,
                "baseline_only": len(baseline_only),
                "candidate": candidate_covered,
            },
            threshold={"baseline_only": 0, "candidate_at_least_baseline": True},
        ),
        "geometric_bootstrap_lower_bound": check(
            bootstrap["metrics"]["geometric_speedup"]["ci_lower"] > MIN_SPEEDUP,
            actual=bootstrap["metrics"]["geometric_speedup"]["ci_lower"],
            threshold={"exclusive_minimum": MIN_SPEEDUP},
        ),
        "geometric_point_speedup": check(
            metrics["geometric_speedup"] > MIN_SPEEDUP,
            actual=metrics["geometric_speedup"],
            threshold={"exclusive_minimum": MIN_SPEEDUP},
        ),
        "p95_slowdown_cap": check(
            metrics["p95_slowdown"] <= MAX_P95_SLOWDOWN,
            actual=metrics["p95_slowdown"],
            threshold={"maximum": MAX_P95_SLOWDOWN},
        ),
        "run_validity": check(
            invalid_run_count == 0,
            actual=invalid_run_count,
            threshold={"maximum": 0},
        ),
        "timeout_nonregression": check(
            candidate_timeout_runs <= baseline_timeout_runs,
            actual={
                "baseline": baseline_timeout_runs,
                "candidate": candidate_timeout_runs,
            },
            threshold={"candidate_at_most_baseline": True},
        ),
    }
    promoted = all(item["passed"] for item in checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "decision": "promote" if promoted else "reject",
        "arms": {"baseline": BASELINE_ARM, "candidate": CANDIDATE_ARM},
        "input": {
            "expected_instances": expected_instances,
            "summary_sha256": summary_sha256,
        },
        "policy": {
            "bootstrap_iterations": BOOTSTRAP_ITERATIONS,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "confidence_level": CONFIDENCE_LEVEL,
            "max_p95_slowdown": MAX_P95_SLOWDOWN,
            "min_common_instances": MIN_COMMON_INSTANCES,
            "min_speedup_exclusive": MIN_SPEEDUP,
        },
        "coverage": {
            "baseline_covered": baseline_covered,
            "baseline_only_examples": baseline_only[:20],
            "candidate_covered": candidate_covered,
            "candidate_only_examples": candidate_only[:20],
            "common_correct": len(common_pairs),
        },
        "timing": metrics,
        "bootstrap": bootstrap,
        "checks": dict(sorted(checks.items())),
    }


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    parser.add_argument("--expected-instances", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.expected_instances < 1:
        raise DecisionError("expected instance count must be positive")
    summary_path = args.summary.resolve(strict=True)
    output_path = args.out.resolve()
    if summary_path == output_path:
        raise DecisionError("decision output must not overwrite its summary")
    raw = summary_path.read_bytes()
    try:
        summary = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise DecisionError(f"cannot read strict Williams summary: {error}") from error
    if not isinstance(summary, dict):
        raise DecisionError("Williams summary is not a JSON object")
    report = evaluate(
        summary,
        summary_sha256=hashlib.sha256(raw).hexdigest(),
        expected_instances=args.expected_instances,
    )
    atomic_write(output_path, canonical_json_bytes(report))
    print(
        f"decision={report['decision']} common={report['coverage']['common_correct']} "
        f"geometric={report['timing']['geometric_speedup']:.6f} "
        f"aggregate={report['timing']['aggregate_speedup']:.6f}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DecisionError, OSError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(2)
