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
    for relative_path, observations in by_path.items():
        if first not in observations or second not in observations:
            continue
        first_result = observations[first]
        second_result = observations[second]
        target = expected[relative_path]
        if first_result["result"] != target or second_result["result"] != target:
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
        "first_total_time_s": first_total,
        "second_total_time_s": second_total,
        "first_speedup_by_total": second_total / first_total if first_total else None,
        "first_geometric_speedup": geometric_speedup,
    }


def family_summaries(
    solvers: list[str],
    by_path: dict[str, dict[str, dict]],
    expected: dict[str, str],
) -> dict[str, dict]:
    families: dict[str, list[str]] = defaultdict(list)
    for relative_path in expected:
        families[family_name(relative_path)].append(relative_path)

    payload = {}
    for family, paths in sorted(families.items()):
        solver_data = {}
        for solver in solvers:
            results = [
                by_path[relative_path][solver]["result"]
                for relative_path in paths
                if solver in by_path.get(relative_path, {})
            ]
            correct = sum(
                by_path[relative_path][solver]["result"] == expected[relative_path]
                for relative_path in paths
                if solver in by_path.get(relative_path, {})
            )
            solver_data[solver] = {
                "count": len(results),
                "correct": correct,
                "coverage": correct / len(paths),
                "results": dict(sorted(Counter(results).items())),
            }
        payload[family] = {"instances": len(paths), "solvers": solver_data}
    return payload


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
    payload = {
        "source_csv": str(args.csv),
        "instances": len(expected),
        "complete_instances": complete_instances,
        "solvers": solver_data,
        "pairwise": pairwise,
        "families": family_summaries(solvers, by_path, expected),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
