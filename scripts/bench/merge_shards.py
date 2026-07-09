#!/usr/bin/env python3
"""Validate and merge complete solver CSV shards into one campaign result."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from compare_solvers import FIELDNAMES, atomic_write_json, read_manifest, summarize


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--solver", action="append", dest="solvers", required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--resume-run-id")
    parser.add_argument("--retry-result", action="append", default=[])
    parser.add_argument("--retry-solver", action="append", default=[])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    rows = read_manifest(args.manifest, None)
    rows_by_path = {row["relative_path"]: row for row in rows}
    if len(rows_by_path) != len(rows):
        raise SystemExit("manifest contains duplicate relative_path values")
    solver_set = set(args.solvers)
    if len(solver_set) != len(args.solvers):
        raise SystemExit("--solver contains duplicates")

    observations: dict[tuple[str, str], dict] = {}
    for path in args.inputs:
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames != FIELDNAMES:
                raise SystemExit(f"{path}: incompatible CSV header")
            for line_number, record in enumerate(reader, start=2):
                relative_path = record["relative_path"]
                solver = record["solver"]
                if relative_path not in rows_by_path:
                    raise SystemExit(f"{path}:{line_number}: path is not in manifest")
                if solver not in solver_set:
                    raise SystemExit(f"{path}:{line_number}: unexpected solver {solver!r}")
                key = (relative_path, solver)
                if key in observations:
                    raise SystemExit(f"duplicate solver-instance row {key}")
                observations[key] = {
                    "result": record["result"],
                    "time_s": float(record["time_s"]),
                    "exit_code": int(record["exit_code"]),
                    "stderr": record.get("stderr", ""),
                }

    expected = len(rows) * len(args.solvers)
    if len(observations) != expected:
        missing = [
            (row["relative_path"], solver)
            for row in rows
            for solver in args.solvers
            if (row["relative_path"], solver) not in observations
        ]
        raise SystemExit(
            f"incomplete campaign: rows={len(observations)}/{expected}; "
            f"first_missing={missing[:10]}"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            relative_path = row["relative_path"]
            for solver in args.solvers:
                observation = observations[(relative_path, solver)]
                writer.writerow(
                    {
                        "id": row.get("id"),
                        "relative_path": relative_path,
                        "expected_status": row.get("status"),
                        "solver": solver,
                        "result": observation["result"],
                        "time_s": f'{observation["time_s"]:.9f}',
                        "exit_code": observation["exit_code"],
                        "stderr": observation["stderr"][:500],
                    }
                )

    summary, wrong, disagreements, execution_errors = summarize(
        rows, args.solvers, observations
    )
    payload = {
        "manifest": str(args.manifest),
        "timeout_s": args.timeout,
        "resume_run_id": args.resume_run_id,
        "retry_results": sorted(set(args.retry_result)),
        "retry_solvers": sorted(set(args.retry_solver)),
        "instances": len(rows),
        "solvers": summary,
        "wrong_answers": wrong,
        "solver_disagreements": disagreements,
        "execution_errors": execution_errors,
        "mismatches": disagreements,
        "shards": [str(path) for path in args.inputs],
    }
    atomic_write_json(args.summary, payload)
    print(json.dumps({"instances": len(rows), "solvers": summary}, sort_keys=True))
    if wrong or disagreements:
        return 2
    if execution_errors:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
