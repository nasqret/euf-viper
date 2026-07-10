#!/usr/bin/env python3
"""Collect finite-structure metrics from an euf-viper benchmark manifest."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import operator
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Callable, NamedTuple


FINITE_ANALYSIS_TAG = "finite_analysis"
METRIC_TOKEN_RE = re.compile(r"([a-z][a-z0-9_]*)=(0|[1-9][0-9]*)")
PREDICATE_RE = re.compile(
    r"\s*([a-z][a-z0-9_]*)\s*(<=|>=|==|!=|<|>)\s*"
    r"([a-z][a-z0-9_]*|[0-9]+)\s*"
)

# These are the metrics emitted by the current euf-viper finite analyzer.
# Unknown well-formed metrics are retained so newer binaries remain inspectable.
KNOWN_METRICS = (
    "domain_size",
    "covered_finite_terms",
    "recognized_finite_terms",
    "distinct_constants",
    "closed_table_functions",
    "unary_table_apps",
    "binary_table_apps",
    "higher_arity_table_apps",
    "equality_graph_vertices",
    "equality_graph_edges",
    "equality_graph_density_ppm",
    "disequality_graph_edges",
    "disequality_graph_density_ppm",
    "guarded_disequality_clauses",
    "guarded_disequality_edges",
    "guarded_disequality_vertices",
    "guarded_disequality_density_ppm",
    "guarded_disequality_clique_lb",
    "all_different_clique_lb",
    "one_hot_variables_est",
    "one_hot_clauses_est",
)

# Candidate and target selection depend on these fields. A record missing any
# of them is unusable and therefore fails closed instead of receiving zeros.
REQUIRED_METRICS = (
    "domain_size",
    "unary_table_apps",
    "binary_table_apps",
    "higher_arity_table_apps",
    "guarded_disequality_clique_lb",
    "one_hot_variables_est",
    "one_hot_clauses_est",
)

DEFAULT_TARGET_PREDICATES = (
    "domain_size>0",
    "guarded_disequality_clique_lb>=domain_size",
)

COMPARATORS: dict[str, Callable[[int, int], bool]] = {
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
    ">=": operator.ge,
    ">": operator.gt,
}


class AnalyzerError(ValueError):
    """Raised for invalid analyzer input or configuration."""


class ManifestError(AnalyzerError):
    """Raised when the benchmark manifest is malformed."""


class FiniteAnalysisOutputError(AnalyzerError):
    """Raised when euf-viper output has no trustworthy metric record."""


class MetricPredicate(NamedTuple):
    text: str
    left: str
    comparison: str
    right: str | int

    @property
    def metrics(self) -> set[str]:
        names = {self.left}
        if isinstance(self.right, str):
            names.add(self.right)
        return names

    def matches(self, values: dict[str, int]) -> bool:
        if not self.metrics.issubset(values):
            return False
        right = values[self.right] if isinstance(self.right, str) else self.right
        return COMPARATORS[self.comparison](values[self.left], right)


class CandidateSpec(NamedTuple):
    name: str
    predicate: str
    matches: Callable[[dict[str, int]], bool]


CANDIDATE_SPECS = (
    CandidateSpec(
        "guarded_clique_covers_domain",
        "domain_size > 0 and guarded_disequality_clique_lb >= domain_size",
        lambda metrics: metrics["domain_size"] > 0
        and metrics["guarded_disequality_clique_lb"] >= metrics["domain_size"],
    ),
    CandidateSpec(
        "finite_domain",
        "domain_size > 0",
        lambda metrics: metrics["domain_size"] > 0,
    ),
    CandidateSpec(
        "one_hot_pressure",
        "one_hot_variables_est > 0 or one_hot_clauses_est > 0",
        lambda metrics: metrics["one_hot_variables_est"] > 0
        or metrics["one_hot_clauses_est"] > 0,
    ),
    CandidateSpec(
        "unary_table_applications",
        "unary_table_apps > 0",
        lambda metrics: metrics["unary_table_apps"] > 0,
    ),
    CandidateSpec(
        "binary_table_applications",
        "binary_table_apps > 0",
        lambda metrics: metrics["binary_table_apps"] > 0,
    ),
    CandidateSpec(
        "higher_arity_table_applications",
        "higher_arity_table_apps > 0",
        lambda metrics: metrics["higher_arity_table_apps"] > 0,
    ),
    CandidateSpec(
        "any_table_applications",
        "unary_table_apps + binary_table_apps + higher_arity_table_apps > 0",
        lambda metrics: (
            metrics["unary_table_apps"]
            + metrics["binary_table_apps"]
            + metrics["higher_arity_table_apps"]
        )
        > 0,
    ),
)


def parse_finite_analysis(stdout: str) -> dict[str, int]:
    """Parse exactly one complete ``finite_analysis`` stdout record."""
    records: list[tuple[int, list[str]]] = []
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        fields = line.strip().split()
        if fields and fields[0] == FINITE_ANALYSIS_TAG:
            records.append((line_number, fields[1:]))

    if not records:
        raise FiniteAnalysisOutputError("missing finite_analysis record on stdout")
    if len(records) != 1:
        lines = ", ".join(str(line_number) for line_number, _ in records)
        raise FiniteAnalysisOutputError(
            f"expected one finite_analysis record, found {len(records)} on lines {lines}"
        )

    line_number, tokens = records[0]
    if not tokens:
        raise FiniteAnalysisOutputError(
            f"finite_analysis record on line {line_number} has no metrics"
        )

    metrics: dict[str, int] = {}
    for token in tokens:
        match = METRIC_TOKEN_RE.fullmatch(token)
        if match is None:
            raise FiniteAnalysisOutputError(
                f"malformed metric token {token!r} on line {line_number}"
            )
        key, raw_value = match.groups()
        if key in metrics:
            raise FiniteAnalysisOutputError(
                f"duplicate metric {key!r} on line {line_number}"
            )
        metrics[key] = int(raw_value)

    missing = sorted(set(REQUIRED_METRICS) - metrics.keys())
    if missing:
        raise FiniteAnalysisOutputError(
            "finite_analysis record is missing required metrics: "
            + ", ".join(missing)
        )
    return dict(sorted(metrics.items()))


def parse_metric_predicate(text: str) -> MetricPredicate:
    """Parse a metric-to-number or metric-to-metric comparison."""
    match = PREDICATE_RE.fullmatch(text)
    if match is None:
        raise AnalyzerError(
            f"invalid metric predicate {text!r}; expected METRIC OP VALUE"
        )
    left, comparison, raw_right = match.groups()
    right: str | int = int(raw_right) if raw_right.isdigit() else raw_right
    canonical = f"{left}{comparison}{raw_right}"
    return MetricPredicate(canonical, left, comparison, right)


def read_manifest(path: Path) -> list[dict]:
    """Read, validate, and deterministically order a JSONL manifest."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc

    entries = []
    seen_paths: dict[str, int] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ManifestError(
                f"{path}:{line_number}: invalid JSON: {exc.msg}"
            ) from exc
        if not isinstance(row, dict):
            raise ManifestError(f"{path}:{line_number}: row must be a JSON object")

        relative_path = row.get("relative_path")
        if not isinstance(relative_path, str) or not relative_path:
            raise ManifestError(
                f"{path}:{line_number}: relative_path must be a non-empty string"
            )
        relative = PurePosixPath(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ManifestError(
                f"{path}:{line_number}: relative_path must stay below the benchmark root"
            )
        if relative_path in seen_paths:
            raise ManifestError(
                f"{path}:{line_number}: duplicate relative_path {relative_path!r}; "
                f"first seen on line {seen_paths[relative_path]}"
            )
        seen_paths[relative_path] = line_number

        raw_path = row.get("path")
        if raw_path is not None and (
            not isinstance(raw_path, str) or not raw_path
        ):
            raise ManifestError(
                f"{path}:{line_number}: path must be a non-empty string when present"
            )
        entries.append(
            {
                "line_number": line_number,
                "relative_path": relative_path,
                "row": row,
            }
        )

    entries.sort(key=lambda entry: entry["relative_path"])
    return entries


def resolve_corpus_path(
    entry: dict, manifest: Path, benchmark_root: Path | None
) -> Path:
    """Resolve one corpus path, replacing stale absolute roots when requested."""
    if benchmark_root is not None:
        relative = PurePosixPath(entry["relative_path"])
        return benchmark_root.joinpath(*relative.parts)

    raw_path = entry["row"].get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise AnalyzerError("manifest row has no path and --benchmark-root was not set")
    candidate = Path(raw_path)
    if candidate.is_absolute() or candidate.exists():
        return candidate
    return manifest.parent / candidate


def resolve_executable(value: str) -> str:
    """Resolve an executable path or PATH command before starting the corpus."""
    candidate = Path(value)
    if candidate.is_file():
        resolved = candidate.resolve()
    else:
        located = shutil.which(value)
        if located is None:
            raise AnalyzerError(f"euf-viper executable not found: {value}")
        resolved = Path(located).resolve()
    if not os.access(resolved, os.X_OK):
        raise AnalyzerError(f"euf-viper path is not executable: {resolved}")
    return str(resolved)


def _identity(entry: dict, resolved_path: Path) -> dict:
    return {
        "id": entry["row"].get("id"),
        "manifest_line": entry["line_number"],
        "relative_path": entry["relative_path"],
        "resolved_path": str(resolved_path),
    }


def _output_excerpt(value: str | bytes | None, limit: int = 2_000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode(encoding="utf-8", errors="replace")
    value = value.strip()
    return value if len(value) <= limit else value[:limit] + "..."


def analyze_instance(
    entry: dict,
    manifest: Path,
    executable: str,
    timeout_s: float,
    benchmark_root: Path | None,
) -> dict:
    """Run one stats command and return either an instance or a failure."""
    try:
        resolved_path = resolve_corpus_path(entry, manifest, benchmark_root)
    except AnalyzerError as exc:
        fallback = Path(entry["relative_path"])
        failure = _identity(entry, fallback)
        failure.update({"kind": "path_error", "message": str(exc)})
        return {"failure": failure}

    identity = _identity(entry, resolved_path)
    if not resolved_path.is_file():
        failure = dict(identity)
        failure.update(
            {
                "kind": "missing_input",
                "message": f"resolved corpus path is not a file: {resolved_path}",
            }
        )
        return {"failure": failure}

    command = [executable, "stats", str(resolved_path)]
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        failure = dict(identity)
        failure.update(
            {
                "kind": "timeout",
                "message": f"stats command exceeded timeout of {timeout_s:g}s",
            }
        )
        return {"failure": failure}
    except OSError as exc:
        failure = dict(identity)
        failure.update(
            {
                "kind": "process_error",
                "message": f"failed to execute stats command: {exc}",
            }
        )
        return {"failure": failure}

    if completed.returncode != 0:
        failure = dict(identity)
        failure.update(
            {
                "kind": "nonzero_exit",
                "message": f"stats command exited with code {completed.returncode}",
                "exit_code": completed.returncode,
            }
        )
        stdout = _output_excerpt(completed.stdout)
        stderr = _output_excerpt(completed.stderr)
        if stdout:
            failure["stdout"] = stdout
        if stderr:
            failure["stderr"] = stderr
        return {"failure": failure}

    try:
        metrics = parse_finite_analysis(completed.stdout)
    except FiniteAnalysisOutputError as exc:
        failure = dict(identity)
        failure.update({"kind": "malformed_output", "message": str(exc)})
        stdout = _output_excerpt(completed.stdout)
        stderr = _output_excerpt(completed.stderr)
        if stdout:
            failure["stdout"] = stdout
        if stderr:
            failure["stderr"] = stderr
        return {"failure": failure}

    instance = dict(identity)
    instance["metrics"] = metrics
    return {"instance": instance, "row": entry["row"]}


def _candidate_sets(instances: list[dict]) -> dict[str, dict]:
    candidates = {}
    for spec in CANDIDATE_SPECS:
        paths = [
            instance["relative_path"]
            for instance in instances
            if spec.matches(instance["metrics"])
        ]
        candidates[spec.name] = {
            "predicate": spec.predicate,
            "count": len(paths),
            "relative_paths": paths,
        }
    return candidates


def _aggregates(
    instances: list[dict], failures: list[dict], candidate_sets: dict[str, dict]
) -> dict:
    metric_names = sorted(
        {metric for instance in instances for metric in instance["metrics"]}
    )
    histograms = {}
    totals = {}
    coverage = {}
    for metric in metric_names:
        observed = [
            instance["metrics"][metric]
            for instance in instances
            if metric in instance["metrics"]
        ]
        histogram = Counter(observed)
        histograms[metric] = {
            str(value): histogram[value] for value in sorted(histogram)
        }
        totals[metric] = sum(observed)
        coverage[metric] = len(observed)

    failure_counts = Counter(failure["kind"] for failure in failures)
    return {
        "successful_instances": len(instances),
        "failed_instances": len(failures),
        "failure_counts": dict(sorted(failure_counts.items())),
        "candidate_counts": {
            name: candidate_sets[name]["count"] for name in sorted(candidate_sets)
        },
        "metric_coverage": coverage,
        "metric_histograms": histograms,
        "metric_totals": totals,
    }


def _validate_predicates(
    predicates: list[MetricPredicate], instances: list[dict]
) -> None:
    available = set(KNOWN_METRICS)
    available.update(
        metric for instance in instances for metric in instance["metrics"]
    )
    unknown = sorted(
        metric
        for predicate in predicates
        for metric in predicate.metrics
        if metric not in available
    )
    if unknown:
        raise AnalyzerError(
            "target predicate references unknown metrics: "
            + ", ".join(sorted(set(unknown)))
        )


def _target_matches(
    metrics: dict[str, int], predicates: list[MetricPredicate], match: str
) -> bool:
    decisions = [predicate.matches(metrics) for predicate in predicates]
    return all(decisions) if match == "all" else any(decisions)


def analyze_manifest(
    manifest: Path,
    executable: str,
    timeout_s: float,
    benchmark_root: Path | None = None,
    jobs: int = 1,
    target_predicates: list[MetricPredicate] | None = None,
    target_match: str = "all",
) -> tuple[dict, list[dict]]:
    """Analyze all manifest rows and return the report and selected source rows."""
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise AnalyzerError("timeout must be a finite number greater than zero")
    if jobs < 1:
        raise AnalyzerError("jobs must be at least one")
    if target_match not in {"all", "any"}:
        raise AnalyzerError("target_match must be 'all' or 'any'")
    if target_predicates is not None and not target_predicates:
        raise AnalyzerError("at least one target predicate is required")

    entries = read_manifest(manifest)
    inspect = lambda entry: analyze_instance(
        entry, manifest, executable, timeout_s, benchmark_root
    )
    if jobs == 1:
        results = [inspect(entry) for entry in entries]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
            # executor.map preserves the already sorted manifest order.
            results = list(executor.map(inspect, entries))

    instances = [result["instance"] for result in results if "instance" in result]
    failures = [result["failure"] for result in results if "failure" in result]
    successful_rows = {
        result["instance"]["relative_path"]: result["row"]
        for result in results
        if "instance" in result
    }

    candidate_sets = _candidate_sets(instances)
    memberships: dict[str, list[str]] = {
        instance["relative_path"]: [] for instance in instances
    }
    for candidate_name, candidate in candidate_sets.items():
        for relative_path in candidate["relative_paths"]:
            memberships[relative_path].append(candidate_name)
    for instance in instances:
        instance["candidate_sets"] = sorted(memberships[instance["relative_path"]])

    if target_predicates is None:
        target_predicates = [
            parse_metric_predicate(text) for text in DEFAULT_TARGET_PREDICATES
        ]
    _validate_predicates(target_predicates, instances)
    target_paths = [
        instance["relative_path"]
        for instance in instances
        if _target_matches(instance["metrics"], target_predicates, target_match)
    ]
    target_rows = [successful_rows[relative_path] for relative_path in target_paths]

    report = {
        "schema_version": 1,
        "manifest": str(manifest),
        "viper": executable,
        "parameters": {
            "benchmark_root": (
                str(benchmark_root) if benchmark_root is not None else None
            ),
            "jobs": jobs,
            "timeout_s": timeout_s,
        },
        "counts": {
            "manifest_instances": len(entries),
            "successful_instances": len(instances),
            "failed_instances": len(failures),
            "target_instances": len(target_paths),
        },
        "aggregates": _aggregates(instances, failures, candidate_sets),
        "candidate_sets": candidate_sets,
        "target_selection": {
            "match": target_match,
            "predicates": [predicate.text for predicate in target_predicates],
            "count": len(target_paths),
            "relative_paths": target_paths,
        },
        "instances": instances,
        "failures": failures,
    }
    return report, target_rows


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path: Path, payload: dict) -> None:
    _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    content = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    _atomic_write(path, content)


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least one")
    return parsed


def _same_path(first: Path, second: Path) -> bool:
    return first.resolve() == second.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze euf-viper finite-structure metrics over a JSONL manifest."
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--viper",
        "--binary",
        dest="viper",
        default="target/release/euf-viper",
        help="euf-viper executable (default: %(default)s)",
    )
    parser.add_argument("--timeout", type=_positive_float, default=10.0)
    parser.add_argument("--jobs", type=_positive_int, default=1)
    parser.add_argument(
        "--benchmark-root",
        "--corpus-root",
        dest="benchmark_root",
        type=Path,
        help="resolve every relative_path below this root, ignoring manifest path",
    )
    parser.add_argument("--out", type=Path, help="write the JSON report here")
    parser.add_argument(
        "--target-manifest",
        "--targets-out",
        dest="target_manifest",
        type=Path,
        help="write source manifest rows selected by metric predicates",
    )
    parser.add_argument(
        "--target-predicate",
        "--select",
        dest="target_predicates",
        action="append",
        default=[],
        metavar="EXPR",
        help=(
            "metric comparison, e.g. domain_size>=4 or "
            "guarded_disequality_clique_lb>=domain_size; repeatable"
        ),
    )
    parser.add_argument(
        "--target-match",
        choices=("all", "any"),
        default="all",
        help="combine repeated target predicates (default: %(default)s)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.out is not None and _same_path(args.out, args.manifest):
        parser.error("--out must not overwrite the input manifest")
    if args.target_manifest is not None and _same_path(
        args.target_manifest, args.manifest
    ):
        parser.error("--target-manifest must not overwrite the input manifest")
    if (
        args.out is not None
        and args.target_manifest is not None
        and _same_path(args.out, args.target_manifest)
    ):
        parser.error("--out and --target-manifest must be different paths")

    try:
        executable = resolve_executable(args.viper)
        predicates = (
            [parse_metric_predicate(text) for text in args.target_predicates]
            if args.target_predicates
            else None
        )
        report, target_rows = analyze_manifest(
            args.manifest,
            executable,
            args.timeout,
            benchmark_root=args.benchmark_root,
            jobs=args.jobs,
            target_predicates=predicates,
            target_match=args.target_match,
        )
        if args.target_manifest is not None:
            write_jsonl(args.target_manifest, target_rows)
        if args.out is not None:
            write_json(args.out, report)
        else:
            sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    except (AnalyzerError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
