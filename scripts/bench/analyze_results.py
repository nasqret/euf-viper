#!/usr/bin/env python3
"""Summarize coverage and pairwise speed from compare_solvers.py CSV output."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath


DECISIVE_RESULTS = {"sat", "unsat"}


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def family_name(relative_path: str) -> str:
    parts = PurePosixPath(relative_path).parts
    if len(parts) >= 2 and parts[0] == "QF_UF":
        return parts[1]
    return parts[0] if parts else "unknown"


def load_csv(path: Path) -> tuple[list[str], dict[str, dict[str, dict]], dict[str, str]]:
    solver_order: list[str] = []
    by_path: dict[str, dict[str, dict]] = defaultdict(dict)
    expected: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for line_number, row in enumerate(csv.DictReader(fh), start=2):
            relative_path = row["relative_path"]
            solver = row["solver"]
            if solver not in solver_order:
                solver_order.append(solver)
            if solver in by_path[relative_path]:
                raise SystemExit(
                    f"{path}:{line_number}: duplicate result for {relative_path} and {solver}"
                )
            status = row["expected_status"]
            if relative_path in expected and expected[relative_path] != status:
                raise SystemExit(
                    f"{path}:{line_number}: inconsistent expected status for {relative_path}"
                )
            expected[relative_path] = status
            by_path[relative_path][solver] = {
                "result": row["result"],
                "time_s": float(row["time_s"]),
                "exit_code": int(row["exit_code"]),
                "stderr": row["stderr"],
            }
    return solver_order, dict(by_path), expected


def solver_summary(
    solver: str,
    by_path: dict[str, dict[str, dict]],
    expected: dict[str, str],
    top: int,
) -> dict:
    records = [
        (relative_path, observations[solver])
        for relative_path, observations in by_path.items()
        if solver in observations
    ]
    correct = [
        (relative_path, observation)
        for relative_path, observation in records
        if observation["result"] == expected[relative_path]
    ]
    wrong = [
        (relative_path, observation)
        for relative_path, observation in records
        if observation["result"] in DECISIVE_RESULTS
        and observation["result"] != expected[relative_path]
    ]
    unresolved = [
        (relative_path, observation)
        for relative_path, observation in records
        if observation["result"] not in DECISIVE_RESULTS
    ]
    times = [observation["time_s"] for _, observation in records]
    correct_times = [observation["time_s"] for _, observation in correct]
    slowest = sorted(correct, key=lambda item: item[1]["time_s"], reverse=True)[:top]
    gaps = sorted(
        wrong + unresolved,
        key=lambda item: (item[1]["result"], -item[1]["time_s"], item[0]),
    )[:top]
    return {
        "count": len(records),
        "correct": len(correct),
        "wrong": len(wrong),
        "unresolved": len(unresolved),
        "coverage": len(correct) / len(expected) if expected else None,
        "results": dict(sorted(Counter(obs["result"] for _, obs in records).items())),
        "total_time_s": sum(times),
        "median_time_s": statistics.median(times) if times else None,
        "p95_time_s": percentile(times, 0.95),
        "correct_total_time_s": sum(correct_times),
        "correct_median_time_s": statistics.median(correct_times)
        if correct_times
        else None,
        "slowest_correct": [
            {
                "relative_path": relative_path,
                "time_s": observation["time_s"],
            }
            for relative_path, observation in slowest
        ],
        "coverage_gaps": [
            {
                "relative_path": relative_path,
                "expected": expected[relative_path],
                "result": observation["result"],
                "time_s": observation["time_s"],
                "exit_code": observation["exit_code"],
                "stderr": observation["stderr"],
            }
            for relative_path, observation in gaps
        ],
    }


def pairwise_summary(
    first: str,
    second: str,
    by_path: dict[str, dict[str, dict]],
    expected: dict[str, str],
) -> dict:
    common: list[tuple[float, float]] = []
    first_wins = 0
    second_wins = 0
    ties = 0
    first_only_correct = 0
    second_only_correct = 0
    either_correct = 0
    first_only_paths = []
    second_only_paths = []
    for relative_path, observations in by_path.items():
        if first not in observations or second not in observations:
            continue
        first_result = observations[first]
        second_result = observations[second]
        target = expected[relative_path]
        first_correct = first_result["result"] == target
        second_correct = second_result["result"] == target
        either_correct += first_correct or second_correct
        first_only_correct += first_correct and not second_correct
        second_only_correct += second_correct and not first_correct
        if first_correct and not second_correct:
            first_only_paths.append(relative_path)
        if second_correct and not first_correct:
            second_only_paths.append(relative_path)
        if not first_correct or not second_correct:
            continue
        first_time = first_result["time_s"]
        second_time = second_result["time_s"]
        common.append((first_time, second_time))
        if math.isclose(first_time, second_time, rel_tol=0.0, abs_tol=1e-9):
            ties += 1
        elif first_time < second_time:
            first_wins += 1
        else:
            second_wins += 1

    first_total = sum(first_time for first_time, _ in common)
    second_total = sum(second_time for _, second_time in common)
    positive = [
        (first_time, second_time)
        for first_time, second_time in common
        if first_time > 0.0 and second_time > 0.0
    ]
    geometric_speedup = (
        math.exp(
            statistics.mean(
                math.log(second_time / first_time)
                for first_time, second_time in positive
            )
        )
        if positive
        else None
    )
    return {
        "first": first,
        "second": second,
        "common_correct": len(common),
        "first_wins": first_wins,
        "second_wins": second_wins,
        "ties": ties,
        "first_only_correct": first_only_correct,
        "second_only_correct": second_only_correct,
        "first_only_examples": sorted(first_only_paths)[:25],
        "second_only_examples": sorted(second_only_paths)[:25],
        "either_correct": either_correct,
        "portfolio_coverage": either_correct / len(expected) if expected else None,
        "first_total_time_s": first_total,
        "second_total_time_s": second_total,
        "first_speedup_by_total": second_total / first_total if first_total else None,
        "first_geometric_speedup": geometric_speedup,
    }


def grouped_summaries(
    groups: dict[str, list[str]],
    solvers: list[str],
    by_path: dict[str, dict[str, dict]],
    expected: dict[str, str],
) -> dict[str, dict]:
    payload = {}
    for group, paths in sorted(groups.items()):
        solver_data = {}
        for solver in solvers:
            observations = [
                by_path[relative_path][solver]
                for relative_path in paths
                if solver in by_path.get(relative_path, {})
            ]
            correct_observations = [
                by_path[relative_path][solver]
                for relative_path in paths
                if solver in by_path.get(relative_path, {})
                and by_path[relative_path][solver]["result"] == expected[relative_path]
            ]
            times = [observation["time_s"] for observation in observations]
            correct_times = [
                observation["time_s"] for observation in correct_observations
            ]
            solver_data[solver] = {
                "count": len(observations),
                "correct": len(correct_observations),
                "coverage": len(correct_observations) / len(paths),
                "results": dict(
                    sorted(Counter(obs["result"] for obs in observations).items())
                ),
                "total_time_s": sum(times),
                "median_time_s": statistics.median(times) if times else None,
                "correct_total_time_s": sum(correct_times),
                "correct_median_time_s": (
                    statistics.median(correct_times) if correct_times else None
                ),
            }
        payload[group] = {"instances": len(paths), "solvers": solver_data}
    return payload


def family_groups(expected: dict[str, str]) -> dict[str, list[str]]:
    families: dict[str, list[str]] = defaultdict(list)
    for relative_path in expected:
        families[family_name(relative_path)].append(relative_path)
    return dict(families)


def stratum_groups(expected: dict[str, str]) -> dict[str, list[str]]:
    groups = {"QG-classification": [], "non-QG": []}
    for relative_path in expected:
        group = (
            "QG-classification"
            if family_name(relative_path) == "QG-classification"
            else "non-QG"
        )
        groups[group].append(relative_path)
    return groups


def grouped_pairwise_summaries(
    groups: dict[str, list[str]],
    solvers: list[str],
    by_path: dict[str, dict[str, dict]],
    expected: dict[str, str],
) -> dict[str, list[dict]]:
    payload = {}
    for group, paths in sorted(groups.items()):
        group_expected = {path: expected[path] for path in paths}
        group_observations = {path: by_path[path] for path in paths if path in by_path}
        payload[group] = [
            pairwise_summary(
                solvers[first], solvers[second], group_observations, group_expected
            )
            for first in range(len(solvers))
            for second in range(first + 1, len(solvers))
        ]
    return payload


def oracle_portfolio_summary(
    solvers: list[str],
    by_path: dict[str, dict[str, dict]],
    expected: dict[str, str],
) -> dict:
    solved_paths = []
    unsolved_paths = []
    all_correct = 0
    unique_paths: dict[str, list[str]] = {solver: [] for solver in solvers}
    fastest_counts = Counter()
    oracle_times = []
    for relative_path, target in expected.items():
        correct = [
            solver
            for solver in solvers
            if solver in by_path.get(relative_path, {})
            and by_path[relative_path][solver]["result"] == target
        ]
        if not correct:
            unsolved_paths.append(relative_path)
            continue
        solved_paths.append(relative_path)
        all_correct += len(correct) == len(solvers)
        if len(correct) == 1:
            unique_paths[correct[0]].append(relative_path)
        fastest = min(
            correct,
            key=lambda solver: by_path[relative_path][solver]["time_s"],
        )
        fastest_counts[fastest] += 1
        oracle_times.append(by_path[relative_path][fastest]["time_s"])
    return {
        "solved": len(solved_paths),
        "coverage": len(solved_paths) / len(expected) if expected else None,
        "all_solvers_correct": all_correct,
        "unsolved": len(unsolved_paths),
        "unsolved_paths": sorted(unsolved_paths),
        "unique_correct": {
            solver: {
                "count": len(paths),
                "examples": sorted(paths)[:25],
            }
            for solver, paths in unique_paths.items()
        },
        "fastest_correct": {
            solver: fastest_counts[solver] for solver in solvers
        },
        "oracle_total_time_s": sum(oracle_times),
        "oracle_median_time_s": (
            statistics.median(oracle_times) if oracle_times else None
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--top", type=int, default=25)
    args = parser.parse_args()
    if args.top < 1:
        raise SystemExit("--top must be at least 1")

    solvers, by_path, expected = load_csv(args.csv)
    solver_data = {
        solver: solver_summary(solver, by_path, expected, args.top)
        for solver in solvers
    }
    pairwise = [
        pairwise_summary(solvers[first], solvers[second], by_path, expected)
        for first in range(len(solvers))
        for second in range(first + 1, len(solvers))
    ]
    complete_instances = sum(
        all(solver in observations for solver in solvers)
        for observations in by_path.values()
    )
    families = family_groups(expected)
    strata = stratum_groups(expected)
    payload = {
        "source_csv": str(args.csv),
        "instances": len(expected),
        "complete_instances": complete_instances,
        "solvers": solver_data,
        "pairwise": pairwise,
        "oracle_portfolio": oracle_portfolio_summary(
            solvers, by_path, expected
        ),
        "families": grouped_summaries(families, solvers, by_path, expected),
        "family_pairwise": grouped_pairwise_summaries(
            families, solvers, by_path, expected
        ),
        "strata": grouped_summaries(strata, solvers, by_path, expected),
        "stratum_pairwise": grouped_pairwise_summaries(
            strata, solvers, by_path, expected
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
