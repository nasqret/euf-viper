#!/usr/bin/env python3
"""Find deterministic follow-up opportunities in a paired A/B summary."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath


LABELS = ("baseline", "candidate")
TIMEOUT_RESULT = "timeout"


class SummarySchemaError(ValueError):
    """Raised when an input is not a compare_viper_ab.py summary."""


def family_name(relative_path: str) -> str:
    """Return the benchmark family using the repository's QF_UF convention."""
    parts = PurePosixPath(relative_path).parts
    if len(parts) >= 2 and parts[0] == "QF_UF":
        return parts[1]
    return parts[0] if parts else "unknown"


def _expect_object(value: object, location: str) -> dict:
    if not isinstance(value, dict):
        raise SummarySchemaError(f"{location} must be a JSON object")
    return value


def _expect_nonnegative_number(value: object, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SummarySchemaError(f"{location} must be a non-negative number")
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise SummarySchemaError(f"{location} must be a non-negative number")
    return number


def _validate_side(value: object, location: str) -> dict:
    side = _expect_object(value, location)
    if not isinstance(side.get("correct"), bool):
        raise SummarySchemaError(f"{location}.correct must be a boolean")
    median_time_s = _expect_nonnegative_number(
        side.get("median_time_s"), f"{location}.median_time_s"
    )
    raw_results = _expect_object(side.get("results"), f"{location}.results")
    results = {}
    for result in raw_results:
        if not isinstance(result, str) or not result:
            raise SummarySchemaError(
                f"{location}.results keys must be non-empty strings"
            )
    for result, count in sorted(raw_results.items()):
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise SummarySchemaError(
                f"{location}.results[{result!r}] must be a non-negative integer"
            )
        results[result] = count
    return {
        "correct": side["correct"],
        "median_time_s": median_time_s,
        "results": results,
    }


def validate_summary(payload: object) -> dict[str, dict[str, dict]]:
    """Validate and normalize the path records used by the analyzer."""
    summary = _expect_object(payload, "summary")
    raw_paths = _expect_object(summary.get("paths"), "summary.paths")
    paths = {}
    for relative_path in raw_paths:
        if not isinstance(relative_path, str) or not relative_path:
            raise SummarySchemaError(
                "summary.paths keys must be non-empty relative-path strings"
            )
    for relative_path, raw_comparison in sorted(raw_paths.items()):
        comparison = _expect_object(
            raw_comparison, f"summary.paths[{relative_path!r}]"
        )
        paths[relative_path] = {
            label: _validate_side(
                comparison.get(label),
                f"summary.paths[{relative_path!r}].{label}",
            )
            for label in LABELS
        }

    if "instances" in summary:
        instances = summary["instances"]
        if isinstance(instances, bool) or not isinstance(instances, int):
            raise SummarySchemaError("summary.instances must be an integer")
        if instances != len(paths):
            raise SummarySchemaError(
                "summary.instances does not match the number of path records"
            )
    return paths


def _comparison_entry(relative_path: str, comparison: dict[str, dict]) -> dict:
    baseline = comparison["baseline"]
    candidate = comparison["candidate"]
    baseline_time = baseline["median_time_s"]
    candidate_time = candidate["median_time_s"]
    return {
        "relative_path": relative_path,
        "family": family_name(relative_path),
        "baseline": {
            "correct": baseline["correct"],
            "median_time_s": baseline_time,
            "results": dict(baseline["results"]),
        },
        "candidate": {
            "correct": candidate["correct"],
            "median_time_s": candidate_time,
            "results": dict(candidate["results"]),
        },
        "delta_time_s": candidate_time - baseline_time,
        "candidate_speedup": (
            baseline_time / candidate_time if candidate_time > 0.0 else None
        ),
        "candidate_slowdown": (
            candidate_time / baseline_time if baseline_time > 0.0 else None
        ),
    }


def _aggregate(paths: dict[str, dict[str, dict]]) -> dict:
    baseline_correct = 0
    candidate_correct = 0
    baseline_only = 0
    candidate_only = 0
    common = []
    baseline_results: Counter[str] = Counter()
    candidate_results: Counter[str] = Counter()
    timeout_cases = 0

    for comparison in paths.values():
        baseline = comparison["baseline"]
        candidate = comparison["candidate"]
        baseline_correct += baseline["correct"]
        candidate_correct += candidate["correct"]
        baseline_only += baseline["correct"] and not candidate["correct"]
        candidate_only += candidate["correct"] and not baseline["correct"]
        baseline_results.update(baseline["results"])
        candidate_results.update(candidate["results"])
        timeout_cases += any(
            comparison[label]["results"].get(TIMEOUT_RESULT, 0) > 0
            for label in LABELS
        )
        if baseline["correct"] and candidate["correct"]:
            common.append(
                (baseline["median_time_s"], candidate["median_time_s"])
            )

    baseline_common_total = sum(baseline for baseline, _ in common)
    candidate_common_total = sum(candidate for _, candidate in common)
    baseline_all_total = sum(
        comparison["baseline"]["median_time_s"] for comparison in paths.values()
    )
    candidate_all_total = sum(
        comparison["candidate"]["median_time_s"] for comparison in paths.values()
    )
    positive_ratios = [
        baseline / candidate
        for baseline, candidate in common
        if baseline > 0.0 and candidate > 0.0
    ]
    instances = len(paths)
    return {
        "instances": instances,
        "baseline_correct": baseline_correct,
        "candidate_correct": candidate_correct,
        "coverage_delta": candidate_correct - baseline_correct,
        "baseline_coverage": baseline_correct / instances if instances else None,
        "candidate_coverage": candidate_correct / instances if instances else None,
        "baseline_only_correct": baseline_only,
        "candidate_only_correct": candidate_only,
        "common_correct": len(common),
        "baseline_common_total_time_s": baseline_common_total,
        "candidate_common_total_time_s": candidate_common_total,
        "common_time_delta_s": candidate_common_total - baseline_common_total,
        "candidate_speedup_by_total": (
            baseline_common_total / candidate_common_total
            if candidate_common_total > 0.0
            else None
        ),
        "candidate_geometric_speedup": (
            math.exp(
                sum(math.log(ratio) for ratio in positive_ratios)
                / len(positive_ratios)
            )
            if positive_ratios
            else None
        ),
        "baseline_all_total_time_s": baseline_all_total,
        "candidate_all_total_time_s": candidate_all_total,
        "candidate_all_speedup_by_total": (
            baseline_all_total / candidate_all_total
            if candidate_all_total > 0.0
            else None
        ),
        "candidate_wins": sum(candidate < baseline for baseline, candidate in common),
        "baseline_wins": sum(baseline < candidate for baseline, candidate in common),
        "ties": sum(baseline == candidate for baseline, candidate in common),
        "timeout_cases": timeout_cases,
        "results": {
            "baseline": dict(sorted(baseline_results.items())),
            "candidate": dict(sorted(candidate_results.items())),
        },
    }


def _metadata_timeout(payload: dict) -> tuple[float | None, str | None]:
    for key in ("timeout_s", "timeout"):
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        value = float(value)
        if math.isfinite(value) and value > 0.0:
            return value, f"summary.{key}"
    return None, None


def _resolve_timeout(
    payload: dict, paths: dict[str, dict[str, dict]], explicit: float | None
) -> tuple[float | None, str]:
    if explicit is not None:
        return explicit, "explicit"
    metadata_timeout, source = _metadata_timeout(payload)
    if metadata_timeout is not None:
        return metadata_timeout, source or "summary"
    observed = [
        comparison[label]["median_time_s"]
        for comparison in paths.values()
        for label in LABELS
        if comparison[label]["results"].get(TIMEOUT_RESULT, 0) > 0
        and comparison[label]["median_time_s"] > 0.0
    ]
    if observed:
        return statistics.median(observed), "inferred_from_timeout_results"
    return None, "unavailable"


def _timeout_cases(
    paths: dict[str, dict[str, dict]],
    timeout_s: float | None,
    timeout_fraction: float,
) -> list[dict]:
    threshold = timeout_s * timeout_fraction if timeout_s is not None else None
    cases = []
    for relative_path, comparison in paths.items():
        timeout_labels = []
        near_timeout_labels = []
        reasons = []
        for label in LABELS:
            side = comparison[label]
            if side["results"].get(TIMEOUT_RESULT, 0) > 0:
                timeout_labels.append(label)
                reasons.append(f"{label}_timeout")
            elif threshold is not None and side["median_time_s"] >= threshold:
                near_timeout_labels.append(label)
                reasons.append(f"{label}_near_timeout")
        if not reasons:
            continue
        entry = _comparison_entry(relative_path, comparison)
        entry.update(
            {
                "reasons": reasons,
                "timeout_labels": timeout_labels,
                "near_timeout_labels": near_timeout_labels,
                "max_timeout_fraction": (
                    max(
                        comparison[label]["median_time_s"] / timeout_s
                        for label in LABELS
                    )
                    if timeout_s is not None
                    else None
                ),
            }
        )
        cases.append(entry)

    def sort_key(entry: dict) -> tuple:
        proximity = entry["max_timeout_fraction"]
        if proximity is None:
            proximity = max(
                entry[label]["median_time_s"] for label in LABELS
            )
        return (
            -bool(entry["timeout_labels"]),
            -proximity,
            entry["relative_path"],
        )

    return sorted(cases, key=sort_key)


def _experiment_selection(
    paths: dict[str, dict[str, dict]],
    reason_groups: list[tuple[str, list[dict]]],
) -> dict:
    selected: dict[str, dict] = {}
    order = []
    by_reason = {}
    for reason, entries in reason_groups:
        reason_paths = [entry["relative_path"] for entry in entries]
        by_reason[reason] = reason_paths
        for relative_path in reason_paths:
            if relative_path not in selected:
                selected[relative_path] = _comparison_entry(
                    relative_path, paths[relative_path]
                )
                selected[relative_path]["reasons"] = []
                order.append(relative_path)
            selected[relative_path]["reasons"].append(reason)
    return {
        "count": len(order),
        "by_reason": by_reason,
        "cases": [selected[relative_path] for relative_path in order],
    }


def analyze_summary(
    payload: object,
    *,
    top: int = 25,
    timeout_s: float | None = None,
    timeout_fraction: float = 0.8,
    source_summary: str | None = None,
) -> dict:
    """Build a deterministic, machine-readable opportunity analysis."""
    if isinstance(top, bool) or not isinstance(top, int) or top < 1:
        raise ValueError("top must be at least 1")
    if timeout_s is not None:
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or timeout_s <= 0.0
        ):
            raise ValueError("timeout_s must be positive")
        timeout_s = float(timeout_s)
    if (
        isinstance(timeout_fraction, bool)
        or not isinstance(timeout_fraction, (int, float))
        or not math.isfinite(timeout_fraction)
        or not 0.0 < timeout_fraction <= 1.0
    ):
        raise ValueError("timeout_fraction must be in (0, 1]")
    timeout_fraction = float(timeout_fraction)

    paths = validate_summary(payload)
    summary = _expect_object(payload, "summary")
    resolved_timeout, timeout_source = _resolve_timeout(summary, paths, timeout_s)

    baseline_only = [
        _comparison_entry(relative_path, comparison)
        for relative_path, comparison in paths.items()
        if comparison["baseline"]["correct"]
        and not comparison["candidate"]["correct"]
    ]
    candidate_only = [
        _comparison_entry(relative_path, comparison)
        for relative_path, comparison in paths.items()
        if comparison["candidate"]["correct"]
        and not comparison["baseline"]["correct"]
    ]
    common_entries = [
        _comparison_entry(relative_path, comparison)
        for relative_path, comparison in paths.items()
        if comparison["baseline"]["correct"]
        and comparison["candidate"]["correct"]
    ]
    slowdowns = sorted(
        (entry for entry in common_entries if entry["delta_time_s"] > 0.0),
        key=lambda entry: (-entry["delta_time_s"], entry["relative_path"]),
    )
    speedups = sorted(
        (entry for entry in common_entries if entry["delta_time_s"] < 0.0),
        key=lambda entry: (entry["delta_time_s"], entry["relative_path"]),
    )
    timeout_cases = _timeout_cases(paths, resolved_timeout, timeout_fraction)

    grouped: dict[str, dict[str, dict[str, dict]]] = defaultdict(dict)
    for relative_path, comparison in paths.items():
        grouped[family_name(relative_path)][relative_path] = comparison
    family_aggregates = {
        family: _aggregate(family_paths)
        for family, family_paths in sorted(grouped.items())
    }

    largest_slowdowns = slowdowns[:top]
    largest_speedups = speedups[:top]
    top_timeout_cases = timeout_cases[:top]
    analysis = {
        "schema_version": 1,
        "parameters": {
            "top": top,
            "performance_ranking": "absolute_time_delta_s",
            "timeout_s": resolved_timeout,
            "timeout_source": timeout_source,
            "timeout_fraction": timeout_fraction,
            "timeout_threshold_s": (
                resolved_timeout * timeout_fraction
                if resolved_timeout is not None
                else None
            ),
        },
        "overview": _aggregate(paths),
        "coverage_only": {
            "baseline_only_correct": baseline_only,
            "candidate_only_correct": candidate_only,
        },
        "performance_counts": {
            "slowdowns": len(slowdowns),
            "speedups": len(speedups),
            "ties": sum(entry["delta_time_s"] == 0.0 for entry in common_entries),
        },
        "largest_slowdowns": largest_slowdowns,
        "largest_speedups": largest_speedups,
        "timeout_adjacent": {
            "count": len(timeout_cases),
            "cases": top_timeout_cases,
        },
        "family_aggregates": family_aggregates,
    }
    analysis["experiment_selection"] = _experiment_selection(
        paths,
        [
            ("baseline_only_correct", baseline_only),
            ("candidate_only_correct", candidate_only),
            ("timeout_adjacent", top_timeout_cases),
            ("largest_slowdown", largest_slowdowns),
            ("largest_speedup", largest_speedups),
        ],
    )
    if source_summary is not None:
        analysis["source_summary"] = source_summary
    return analysis


def _load_json(source: str) -> object:
    if source == "-":
        return json.loads(sys.stdin.read())
    return json.loads(Path(source).read_text(encoding="utf-8"))


def _write_json(payload: dict, destination: str) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if destination == "-":
        sys.stdout.write(rendered)
        return
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze a compare_viper_ab.py summary for follow-up experiments."
    )
    parser.add_argument("summary", help="A/B summary JSON path, or - for stdin")
    parser.add_argument("--out", default="-", help="output JSON path (default: stdout)")
    parser.add_argument("--top", type=int, default=25, help="ranked cases to retain")
    parser.add_argument(
        "--timeout-s",
        "--timeout",
        dest="timeout_s",
        type=float,
        help="campaign timeout in seconds (otherwise read or inferred)",
    )
    parser.add_argument(
        "--timeout-fraction",
        "--near-timeout-fraction",
        dest="timeout_fraction",
        type=float,
        default=0.8,
        help="minimum fraction of timeout considered adjacent (default: 0.8)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.top < 1:
        parser.error("--top must be at least 1")
    if args.timeout_s is not None and args.timeout_s <= 0.0:
        parser.error("--timeout must be positive")
    if not 0.0 < args.timeout_fraction <= 1.0:
        parser.error("--timeout-fraction must be in (0, 1]")

    try:
        payload = _load_json(args.summary)
        analysis = analyze_summary(
            payload,
            top=args.top,
            timeout_s=args.timeout_s,
            timeout_fraction=args.timeout_fraction,
            source_summary="<stdin>" if args.summary == "-" else args.summary,
        )
        _write_json(analysis, args.out)
    except json.JSONDecodeError as error:
        parser.error(
            f"{args.summary}: invalid JSON at line {error.lineno}, column {error.colno}"
        )
    except (OSError, SummarySchemaError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
