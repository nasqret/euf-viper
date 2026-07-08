#!/usr/bin/env python3
"""Validate and merge complete paired euf-viper A/B CSV shards."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from compare_viper_ab import FIELDNAMES, summarize


LABELS = ("baseline", "candidate")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--repeats", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")

    rows = [
        json.loads(line)
        for line in args.manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows_by_path = {row["relative_path"]: row for row in rows}
    if len(rows_by_path) != len(rows):
        raise SystemExit("manifest contains duplicate relative_path values")

    observations = {}
    for path in args.inputs:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != FIELDNAMES:
                raise SystemExit(f"{path}: incompatible CSV header")
            for line_number, record in enumerate(reader, start=2):
                relative_path = record["relative_path"]
                label = record["label"]
                try:
                    repeat = int(record["repeat"])
                except ValueError as error:
                    raise SystemExit(
                        f"{path}:{line_number}: invalid repeat {record['repeat']!r}"
                    ) from error
                if relative_path not in rows_by_path:
                    raise SystemExit(f"{path}:{line_number}: path is not in manifest")
                if record["expected_status"] != rows_by_path[relative_path]["status"]:
                    raise SystemExit(f"{path}:{line_number}: expected status mismatch")
                if label not in LABELS:
                    raise SystemExit(f"{path}:{line_number}: unexpected label {label!r}")
                if not 0 <= repeat < args.repeats:
                    raise SystemExit(f"{path}:{line_number}: repeat is out of range")
                key = (relative_path, label, repeat)
                if key in observations:
                    raise SystemExit(f"duplicate A/B observation {key}")
                observations[key] = {
                    "relative_path": relative_path,
                    "expected_status": record["expected_status"],
                    "label": label,
                    "repeat": repeat,
                    "result": record["result"],
                    "time_s": float(record["time_s"]),
                    "exit_code": int(record["exit_code"]),
                    "stderr": record.get("stderr", ""),
                }

    expected_count = len(rows) * len(LABELS) * args.repeats
    if len(observations) != expected_count:
        missing = [
            (row["relative_path"], label, repeat)
            for row in rows
            for label in LABELS
            for repeat in range(args.repeats)
            if (row["relative_path"], label, repeat) not in observations
        ]
        raise SystemExit(
            f"incomplete A/B campaign: rows={len(observations)}/{expected_count}; "
            f"first_missing={missing[:10]}"
        )

    samples = [
        observations[(row["relative_path"], label, repeat)]
        for row in rows
        for repeat in range(args.repeats)
        for label in LABELS
    ]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(samples)

    payload, wrong_answers = summarize(rows, samples)
    payload.update(
        {
            "manifest": str(args.manifest),
            "shards": [str(path) for path in args.inputs],
        }
    )
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    def format_speedup(value: float | None) -> str:
        return f"{value:.4f}x" if value is not None else "n/a"

    print(
        f"instances={len(rows)} observations={len(samples)} "
        f"coverage={payload['baseline_correct']}->{payload['candidate_correct']} "
        "common_total_speedup="
        f"{format_speedup(payload['candidate_speedup_by_total'])} "
        "all_total_speedup="
        f"{format_speedup(payload['candidate_all_speedup_by_total'])} "
        f"geomean={format_speedup(payload['candidate_geometric_speedup'])}"
    )
    if wrong_answers:
        return 2
    return 3 if payload["execution_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
