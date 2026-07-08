#!/usr/bin/env python3
"""Select SMT-LIB manifest rows by path, status, or file content."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def result_paths(path: Path, solver: str, results: set[str]) -> set[str]:
    selected = set()
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["solver"] == solver and row["result"] in results:
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
    args = parser.parse_args()

    if args.result and not args.result_csv:
        parser.error("--result requires --result-csv")

    path_pattern = re.compile(args.path_regex) if args.path_regex else None
    observed_paths = (
        result_paths(args.result_csv, args.solver, set(args.result))
        if args.result_csv and args.result
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
