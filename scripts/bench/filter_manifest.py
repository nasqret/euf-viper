#!/usr/bin/env python3
"""Select SMT-LIB manifest rows by path, status, or file content."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def result_paths(
    path: Path,
    solver: str,
    results: set[str],
    time_at_least: float | None,
    time_at_most: float | None,
) -> set[str]:
    selected = set()
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["solver"] != solver:
                continue
            if results and row["result"] not in results:
                continue
            if time_at_least is not None and float(row["time_s"]) < time_at_least:
                continue
            if time_at_most is not None and float(row["time_s"]) > time_at_most:
                continue
            selected.add(row["relative_path"])
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--path-regex")
    parser.add_argument("--status", choices=["sat", "unsat", "unknown"])
    parser.add_argument("--contains", action="append", default=[])
    parser.add_argument("--result-csv", type=Path)
    parser.add_argument("--solver", default="euf-viper")
    parser.add_argument("--result", action="append", default=[])
    parser.add_argument("--time-at-least", type=float)
    parser.add_argument("--time-at-most", type=float)
    args = parser.parse_args()

    if (
        args.result
        or args.time_at_least is not None
        or args.time_at_most is not None
    ) and not args.result_csv:
        parser.error("result and time filters require --result-csv")
    if args.time_at_least is not None and args.time_at_least < 0:
        parser.error("--time-at-least must be nonnegative")
    if args.time_at_most is not None and args.time_at_most < 0:
        parser.error("--time-at-most must be nonnegative")
    if (
        args.time_at_least is not None
        and args.time_at_most is not None
        and args.time_at_least > args.time_at_most
    ):
        parser.error("--time-at-least cannot exceed --time-at-most")

    path_pattern = re.compile(args.path_regex) if args.path_regex else None
    observed_paths = (
        result_paths(
            args.result_csv,
            args.solver,
            set(args.result),
            args.time_at_least,
            args.time_at_most,
        )
        if args.result_csv
        and (
            args.result
            or args.time_at_least is not None
            or args.time_at_most is not None
        )
        else None
    )
    selected = []
    for line in args.manifest.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if path_pattern and not path_pattern.search(row["relative_path"]):
            continue
        if args.status and row.get("status") != args.status:
            continue
        if observed_paths is not None and row["relative_path"] not in observed_paths:
            continue
        if args.contains:
            source = Path(row["path"]).read_text(errors="replace")
            if not any(needle in source for needle in args.contains):
                continue
        selected.append(row)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in selected))
    print(f"selected={len(selected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
