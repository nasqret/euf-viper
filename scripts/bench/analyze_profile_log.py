#!/usr/bin/env python3
"""Summarize BEGIN/END profile blocks emitted by euf_viper_ab_profile.sbatch."""

from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path


BEGIN = re.compile(r"^BEGIN label=(\S+) repeat=(\d+) path=(.+)$")
END = re.compile(r"^END label=(\S+) repeat=(\d+) status=(\d+) path=(.+)$")
RESULTS = {"sat", "unsat", "unsupported"}


def parse_telemetry_fields(line: str) -> tuple[list[tuple[str, int]], dict | None]:
    tokens = line.split()
    numeric_fields = []
    metadata_fields = {}
    context = None

    if tokens and "=" not in tokens[0] and tokens[0].startswith("profile_"):
        context = tokens[0]

    for field in tokens:
        if "=" not in field:
            continue
        key, value = field.split("=", 1)
        if context is None and key.startswith("profile_"):
            context = key
        try:
            numeric_fields.append((key, int(value)))
        except ValueError:
            metadata_fields[key] = value

    metadata = None
    if context is not None and metadata_fields:
        metadata = {
            "context": context,
            "fields": dict(sorted(metadata_fields.items())),
        }
    return numeric_fields, metadata


def parse_log(path: Path) -> list[dict]:
    records = []
    current = None
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if match := BEGIN.match(raw_line):
            if current is not None:
                raise ValueError(f"{path}:{line_number}: nested BEGIN block")
            current = {
                "label": match.group(1),
                "repeat": int(match.group(2)),
                "path": match.group(3),
                "result": None,
                "metrics": {},
                "metadata": [],
            }
            continue
        if match := END.match(raw_line):
            if current is None:
                raise ValueError(f"{path}:{line_number}: END without BEGIN")
            identity = (match.group(1), int(match.group(2)), match.group(4))
            if identity != (current["label"], current["repeat"], current["path"]):
                raise ValueError(f"{path}:{line_number}: END does not match BEGIN")
            current["status"] = int(match.group(3))
            records.append(current)
            current = None
            continue
        if current is None:
            continue
        stripped = raw_line.strip()
        if stripped in RESULTS:
            current["result"] = stripped
            continue
        parsed_fields, metadata = parse_telemetry_fields(stripped)
        if metadata is not None:
            current["metadata"].append(metadata)
        if (
            len(parsed_fields) == 2
            and parsed_fields[0][0].startswith("profile_")
            and parsed_fields[0][0].endswith("_ns")
            and parsed_fields[1][0] == "count"
        ):
            phase_key, phase_value = parsed_fields[0]
            current["metrics"][phase_key] = phase_value
            current["metrics"][f"{phase_key[:-3]}_count"] = parsed_fields[1][1]
        else:
            current["metrics"].update(parsed_fields)
    if current is not None:
        raise ValueError(f"{path}: unterminated BEGIN block")
    return records


def summarize_metadata(samples: list[dict]) -> list[dict]:
    observations = Counter()
    for sample in samples:
        for observation in sample.get("metadata", []):
            fields = tuple(sorted(observation["fields"].items()))
            observations[(observation["context"], fields)] += 1

    return [
        {
            "context": context,
            "fields": dict(fields),
            "count": count,
        }
        for (context, fields), count in sorted(observations.items())
    ]


def summarize(records: list[dict]) -> dict:
    grouped: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for record in records:
        grouped[record["path"]][record["label"]].append(record)

    paths = {}
    aggregate_ratios = []
    for benchmark, labels in sorted(grouped.items()):
        label_summaries = {}
        for label, samples in sorted(labels.items()):
            metric_names = sorted(
                {name for sample in samples for name in sample["metrics"]}
            )
            medians = {
                name: statistics.median(
                    sample["metrics"][name]
                    for sample in samples
                    if name in sample["metrics"]
                )
                for name in metric_names
            }
            label_summaries[label] = {
                "samples": len(samples),
                "statuses": dict(sorted(Counter(s["status"] for s in samples).items())),
                "results": dict(sorted(Counter(s["result"] for s in samples).items())),
                "median_metrics": medians,
                "metadata_summary": summarize_metadata(samples),
            }
        comparison = None
        if {"baseline", "candidate"}.issubset(label_summaries):
            baseline = label_summaries["baseline"]["median_metrics"].get("elapsed_ns")
            candidate = label_summaries["candidate"]["median_metrics"].get("elapsed_ns")
            if baseline is not None and candidate:
                speedup = baseline / candidate
                aggregate_ratios.append(speedup)
                comparison = {
                    "baseline_elapsed_ns": baseline,
                    "candidate_elapsed_ns": candidate,
                    "candidate_speedup": speedup,
                }
        paths[benchmark] = {"labels": label_summaries, "comparison": comparison}

    return {
        "records": len(records),
        "benchmarks": len(paths),
        "geometric_candidate_speedup": (
            statistics.geometric_mean(aggregate_ratios) if aggregate_ratios else None
        ),
        "paths": paths,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    payload = summarize(parse_log(args.log))
    payload["source_log"] = str(args.log)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(
        f"benchmarks={payload['benchmarks']} records={payload['records']} "
        f"geomean_speedup={payload['geometric_candidate_speedup']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
