#!/usr/bin/env python3
"""Compare one solver across two benchmark CSV runs."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path


DECISIVE_RESULTS = {"sat", "unsat"}


def load_solver(path: Path, solver: str) -> dict[str, dict]:
    records: dict[str, dict] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for line_number, row in enumerate(csv.DictReader(handle), start=2):
            if row["solver"] != solver:
                continue
            relative_path = row["relative_path"]
            if relative_path in records:
                raise SystemExit(
                    f"{path}:{line_number}: duplicate result for {relative_path} and {solver}"
                )
            records[relative_path] = {
                "expected": row["expected_status"],
                "result": row["result"],
                "time_s": float(row["time_s"]),
                "exit_code": int(row["exit_code"]),
            }
    if not records:
        raise SystemExit(f"{path}: no records for solver {solver!r}")
    return records


def result_entry(path: str, baseline: dict, candidate: dict) -> dict:
    baseline_time = baseline["time_s"]
    candidate_time = candidate["time_s"]
    return {
        "relative_path": path,
        "expected": candidate["expected"],
        "baseline_result": baseline["result"],
        "candidate_result": candidate["result"],
        "baseline_time_s": baseline_time,
        "candidate_time_s": candidate_time,
        "delta_time_s": candidate_time - baseline_time,
        "speedup": baseline_time / candidate_time if candidate_time > 0.0 else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--solver", default="euf-viper")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--top", type=int, default=25)
    args = parser.parse_args()
    if args.top < 1:
        raise SystemExit("--top must be at least 1")

    baseline = load_solver(args.baseline, args.solver)
    candidate = load_solver(args.candidate, args.solver)
    common_paths = sorted(set(baseline) & set(candidate))
    missing_from_baseline = sorted(set(candidate) - set(baseline))
    if not common_paths:
        raise SystemExit("the runs have no common instances")

    entries = []
    for path in common_paths:
        if baseline[path]["expected"] != candidate[path]["expected"]:
            raise SystemExit(f"inconsistent expected result for {path}")
        entries.append(result_entry(path, baseline[path], candidate[path]))

    def correct(record: dict) -> bool:
        return record["result"] == record["expected"]

    baseline_correct = sum(correct(baseline[path]) for path in common_paths)
    candidate_correct = sum(correct(candidate[path]) for path in common_paths)
    gained = [
        entry
        for entry in entries
        if not correct(baseline[entry["relative_path"]])
        and correct(candidate[entry["relative_path"]])
    ]
    lost = [
        entry
        for entry in entries
        if correct(baseline[entry["relative_path"]])
        and not correct(candidate[entry["relative_path"]])
    ]
    both_correct = [
        entry
        for entry in entries
        if correct(baseline[entry["relative_path"]])
        and correct(candidate[entry["relative_path"]])
    ]
    positive = [
        entry
        for entry in both_correct
        if entry["baseline_time_s"] > 0.0 and entry["candidate_time_s"] > 0.0
    ]
    baseline_common_total = sum(entry["baseline_time_s"] for entry in both_correct)
    candidate_common_total = sum(entry["candidate_time_s"] for entry in both_correct)
    geometric_speedup = (
        math.exp(statistics.mean(math.log(entry["speedup"]) for entry in positive))
        if positive
        else None
    )

    regressions = sorted(
        both_correct,
        key=lambda entry: (entry["delta_time_s"], entry["relative_path"]),
        reverse=True,
    )[: args.top]
    improvements = sorted(
        both_correct,
        key=lambda entry: (entry["delta_time_s"], entry["relative_path"]),
    )[: args.top]
    wrong_answers = [
        entry
        for entry in entries
        if candidate[entry["relative_path"]]["result"] in DECISIVE_RESULTS
        and not correct(candidate[entry["relative_path"]])
    ]

    payload = {
        "baseline_csv": str(args.baseline),
        "candidate_csv": str(args.candidate),
        "solver": args.solver,
        "common_instances": len(common_paths),
        "missing_from_baseline": missing_from_baseline,
        "baseline_correct": baseline_correct,
        "candidate_correct": candidate_correct,
        "coverage_delta": (candidate_correct - baseline_correct) / len(common_paths),
        "gained_coverage": gained,
        "lost_coverage": lost,
        "wrong_answers": wrong_answers,
        "common_correct": len(both_correct),
        "baseline_common_total_time_s": baseline_common_total,
        "candidate_common_total_time_s": candidate_common_total,
        "candidate_speedup_by_total": (
            baseline_common_total / candidate_common_total
            if candidate_common_total > 0.0
            else None
        ),
        "candidate_geometric_speedup": geometric_speedup,
        "candidate_wins": sum(entry["delta_time_s"] < 0.0 for entry in both_correct),
        "baseline_wins": sum(entry["delta_time_s"] > 0.0 for entry in both_correct),
        "ties": sum(entry["delta_time_s"] == 0.0 for entry in both_correct),
        "largest_regressions": regressions,
        "largest_improvements": improvements,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(
        f"coverage {baseline_correct}/{len(common_paths)} -> "
        f"{candidate_correct}/{len(common_paths)}; "
        f"common-correct speedup {payload['candidate_speedup_by_total']:.4f}x; "
        f"geomean {geometric_speedup:.4f}x"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
