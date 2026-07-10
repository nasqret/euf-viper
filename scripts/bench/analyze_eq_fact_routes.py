#!/usr/bin/env python3
"""Rank deterministic, pre-SAT routes for prospective equality facts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Iterable, Sequence


FOLD_COUNT = 5
MAX_THRESHOLDS_PER_FEATURE = 2
RAW_COUNT_FEATURES = (
    "star_edges",
    "nodes",
    "work",
    "memo_entries",
    "partition_terms",
)
RATIO_FEATURES = {
    "star_edges_per_node": ("star_edges", "nodes"),
    "work_per_node": ("work", "nodes"),
    "memo_entries_per_node": ("memo_entries", "nodes"),
    "partition_terms_per_node": ("partition_terms", "nodes"),
    "work_per_memo_entry": ("work", "memo_entries"),
    "work_per_partition_term": ("work", "partition_terms"),
}
FINITE_METRIC_FEATURES = (
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
PREDICATE_FEATURES = (
    "applicable",
    "cap_reason",
    "infeasible",
    *RAW_COUNT_FEATURES,
    *RATIO_FEATURES,
    *FINITE_METRIC_FEATURES,
)
FORBIDDEN_PREDICATE_FIELDS = (
    "family",
    "expected_status",
    "basename",
    "relative_path",
    "correct",
    "median_time_s",
    "result",
    "results",
)


class AnalyzerError(ValueError):
    """Raised when analyzer inputs violate the expected schemas."""


@dataclass(frozen=True)
class Comparison:
    correct: bool
    median_time_s: float


@dataclass(frozen=True)
class Row:
    relative_path: str
    features: dict[str, object]
    baseline: Comparison
    candidate: Comparison


@dataclass(frozen=True, order=True)
class Clause:
    feature: str
    operator: str
    value: object

    def matches(self, features: dict[str, object]) -> bool:
        observed = features[self.feature]
        if self.operator == "==":
            return observed == self.value
        if self.operator == "<=":
            return int(observed) <= int(self.value)
        if self.operator == ">":
            return int(observed) > int(self.value)
        raise AssertionError(f"unsupported clause operator: {self.operator}")

    def as_json(self) -> dict:
        return {
            "source": "finite" if self.feature in FINITE_METRIC_FEATURES else "shadow",
            "feature": self.feature,
            "operator": self.operator,
            "value": self.value,
        }


def _reject_constant(value: str) -> None:
    raise AnalyzerError(f"non-finite JSON number {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AnalyzerError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _loads_json(text: str, context: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise AnalyzerError(f"{context}: invalid JSON: {exc.msg}") from exc
    except AnalyzerError as exc:
        raise AnalyzerError(f"{context}: {exc}") from exc


def _expect_object(value: object, context: str) -> dict:
    if not isinstance(value, dict):
        raise AnalyzerError(f"{context} must be a JSON object")
    return value


def _expect_bool(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise AnalyzerError(f"{context} must be a boolean")
    return value


def _expect_count(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AnalyzerError(f"{context} must be a non-negative integer")
    return value


def _expect_time(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalyzerError(f"{context} must be a non-negative finite number")
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise AnalyzerError(f"{context} must be a non-negative finite number")
    return number


def load_summary(path: Path) -> dict[str, tuple[Comparison, Comparison]]:
    try:
        payload = _loads_json(path.read_text(encoding="utf-8"), str(path))
    except OSError as exc:
        raise AnalyzerError(f"cannot read summary {path}: {exc}") from exc
    summary = _expect_object(payload, "summary")
    raw_paths = _expect_object(summary.get("paths"), "summary.paths")
    comparisons = {}
    for relative_path, raw_sides in sorted(raw_paths.items()):
        if not isinstance(relative_path, str) or not relative_path:
            raise AnalyzerError("summary path keys must be non-empty strings")
        sides = _expect_object(raw_sides, f"summary.paths[{relative_path!r}]")
        normalized = []
        for label in ("baseline", "candidate"):
            side = _expect_object(
                sides.get(label), f"summary.paths[{relative_path!r}].{label}"
            )
            normalized.append(
                Comparison(
                    correct=_expect_bool(
                        side.get("correct"),
                        f"summary.paths[{relative_path!r}].{label}.correct",
                    ),
                    median_time_s=_expect_time(
                        side.get("median_time_s"),
                        f"summary.paths[{relative_path!r}].{label}.median_time_s",
                    ),
                )
            )
        comparisons[relative_path] = (normalized[0], normalized[1])
    instances = summary.get("instances")
    if instances is not None and _expect_count(instances, "summary.instances") != len(
        comparisons
    ):
        raise AnalyzerError("summary.instances does not match summary.paths")
    return comparisons


def _integer_ratio(numerator: int, denominator: int) -> int:
    return numerator // max(denominator, 1)


def shadow_features(record: dict, context: str) -> dict[str, object]:
    if record.get("profile_available") is not True:
        raise AnalyzerError(f"{context}: profile_available must be true")
    features: dict[str, object] = {
        "applicable": _expect_bool(record.get("applicable"), f"{context}.applicable"),
        "infeasible": _expect_bool(record.get("infeasible"), f"{context}.infeasible"),
    }
    cap_reason = record.get("cap_reason")
    if not isinstance(cap_reason, str) or not cap_reason:
        raise AnalyzerError(f"{context}.cap_reason must be a non-empty string")
    features["cap_reason"] = cap_reason
    for field in RAW_COUNT_FEATURES:
        features[field] = _expect_count(record.get(field), f"{context}.{field}")
    for name, (numerator, denominator) in RATIO_FEATURES.items():
        features[name] = _integer_ratio(
            int(features[numerator]), int(features[denominator])
        )
    return features


def load_shadow(path: Path) -> dict[str, dict[str, object]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AnalyzerError(f"cannot read shadow telemetry {path}: {exc}") from exc
    records = {}
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        context = f"{path}:{line_number}"
        record = _expect_object(_loads_json(line, context), context)
        relative_path = record.get("relative_path")
        if not isinstance(relative_path, str) or not relative_path:
            raise AnalyzerError(f"{context}.relative_path must be a non-empty string")
        if relative_path in records:
            raise AnalyzerError(f"duplicate shadow relative_path {relative_path!r}")
        records[relative_path] = shadow_features(record, context)
    return records


def load_finite_analysis(path: Path) -> dict[str, dict[str, object]]:
    try:
        payload = _loads_json(path.read_text(encoding="utf-8"), str(path))
    except OSError as exc:
        raise AnalyzerError(f"cannot read finite analysis {path}: {exc}") from exc
    report = _expect_object(payload, "finite analysis")
    raw_instances = report.get("instances")
    if not isinstance(raw_instances, list):
        raise AnalyzerError("finite analysis.instances must be a JSON array")
    records = {}
    for index, raw_instance in enumerate(raw_instances):
        context = f"finite analysis.instances[{index}]"
        instance = _expect_object(raw_instance, context)
        relative_path = instance.get("relative_path")
        if not isinstance(relative_path, str) or not relative_path:
            raise AnalyzerError(f"{context}.relative_path must be a non-empty string")
        if relative_path in records:
            raise AnalyzerError(f"duplicate finite relative_path {relative_path!r}")
        raw_metrics = _expect_object(instance.get("metrics"), f"{context}.metrics")
        records[relative_path] = {
            feature: _expect_count(
                raw_metrics.get(feature), f"{context}.metrics.{feature}"
            )
            for feature in FINITE_METRIC_FEATURES
        }
    return records


def join_inputs(
    comparisons: dict[str, tuple[Comparison, Comparison]],
    shadow: dict[str, dict[str, object]],
    finite: dict[str, dict[str, object]] | None = None,
) -> list[Row]:
    summary_paths = set(comparisons)
    shadow_paths = set(shadow)
    missing_shadow = sorted(summary_paths - shadow_paths)
    missing_summary = sorted(shadow_paths - summary_paths)
    if missing_shadow or missing_summary:
        details = []
        if missing_shadow:
            details.append(f"missing from shadow={missing_shadow[:10]}")
        if missing_summary:
            details.append(f"missing from summary={missing_summary[:10]}")
        raise AnalyzerError("relative_path join mismatch: " + "; ".join(details))
    if finite is not None:
        finite_paths = set(finite)
        missing_finite = sorted(summary_paths - finite_paths)
        extra_finite = sorted(finite_paths - summary_paths)
        if missing_finite or extra_finite:
            details = []
            if missing_finite:
                details.append(f"missing from finite analysis={missing_finite[:10]}")
            if extra_finite:
                details.append(f"missing from summary={extra_finite[:10]}")
            raise AnalyzerError(
                "finite relative_path join mismatch: " + "; ".join(details)
            )
    return [
        Row(
            path,
            {**shadow[path], **(finite[path] if finite is not None else {})},
            *comparisons[path],
        )
        for path in sorted(summary_paths)
    ]


def fold_for_path(relative_path: str) -> int:
    digest = hashlib.sha256(relative_path.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % FOLD_COUNT


def _bounded_thresholds(values: Iterable[int]) -> list[int]:
    boundaries = sorted(set(values))[:-1]
    if len(boundaries) <= MAX_THRESHOLDS_PER_FEATURE:
        return boundaries
    indexes = {
        round(index * (len(boundaries) - 1) / (MAX_THRESHOLDS_PER_FEATURE - 1))
        for index in range(MAX_THRESHOLDS_PER_FEATURE)
    }
    return [boundaries[index] for index in sorted(indexes)]


def build_clauses(rows: Sequence[Row]) -> list[Clause]:
    clauses = [
        Clause(feature, "==", value)
        for feature in ("applicable", "infeasible")
        for value in (False, True)
    ]
    clauses.extend(
        Clause("cap_reason", "==", value)
        for value in sorted({str(row.features["cap_reason"]) for row in rows})
    )
    numeric_features = (*RAW_COUNT_FEATURES, *RATIO_FEATURES)
    if rows and all(
        feature in row.features for row in rows for feature in FINITE_METRIC_FEATURES
    ):
        numeric_features += FINITE_METRIC_FEATURES
    for feature in numeric_features:
        for threshold in _bounded_thresholds(
            int(row.features[feature]) for row in rows
        ):
            clauses.append(Clause(feature, "<=", threshold))
            clauses.append(Clause(feature, ">", threshold))
    return sorted(clauses)


def _selection_mask(rows: Sequence[Row], clauses: Sequence[Clause]) -> int:
    mask = 0
    for index, row in enumerate(rows):
        if all(clause.matches(row.features) for clause in clauses):
            mask |= 1 << index
    return mask


def enumerate_routes(rows: Sequence[Row], clauses: Sequence[Clause]) -> list[tuple]:
    atom_masks = {clause: _selection_mask(rows, (clause,)) for clause in clauses}
    routes_by_mask: dict[int, tuple[Clause, ...]] = {}
    for clause in clauses:
        mask = atom_masks[clause]
        if mask:
            routes_by_mask.setdefault(mask, (clause,))
    for left, right in combinations(clauses, 2):
        if left.feature == right.feature:
            continue
        mask = atom_masks[left] & atom_masks[right]
        if mask:
            routes_by_mask.setdefault(mask, (left, right))
    return sorted(
        ((route, mask) for mask, route in routes_by_mask.items()),
        key=lambda item: item[0],
    )


def _baseline_state(rows: Sequence[Row], universe_mask: int) -> dict:
    indexes = [index for index in range(len(rows)) if universe_mask & (1 << index)]
    coverage = sum(rows[index].baseline.correct for index in indexes)
    total = sum(rows[index].baseline.median_time_s for index in indexes)
    correct_total = sum(
        rows[index].baseline.median_time_s
        for index in indexes
        if rows[index].baseline.correct
    )
    return {
        "instances": len(indexes),
        "coverage": coverage,
        "total": total,
        "correct_total": correct_total,
        "positive_ratio_count": sum(
            rows[index].baseline.correct
            and rows[index].baseline.median_time_s > 0.0
            for index in indexes
        ),
    }


def evaluate_selection(
    rows: Sequence[Row],
    selected_mask: int,
    universe_mask: int | None = None,
    baseline_state: dict | None = None,
    include_path_lists: bool = True,
) -> dict:
    if universe_mask is None:
        universe_mask = (1 << len(rows)) - 1
    selected_mask &= universe_mask
    baseline = baseline_state or _baseline_state(rows, universe_mask)
    coverage = baseline["coverage"]
    routed_all_total = baseline["total"]
    common_correct = baseline["coverage"]
    common_baseline_total = baseline["correct_total"]
    common_routed_total = baseline["correct_total"]
    log_ratio_sum = 0.0
    positive_ratio_count = baseline["positive_ratio_count"]
    candidate_wins = 0
    baseline_wins = 0
    ties = baseline["coverage"]
    candidate_only = []
    baseline_only = []
    remaining = selected_mask

    while remaining:
        least_bit = remaining & -remaining
        index = least_bit.bit_length() - 1
        remaining ^= least_bit
        row = rows[index]
        baseline_time = row.baseline.median_time_s
        candidate_time = row.candidate.median_time_s
        routed_all_total += candidate_time - baseline_time
        coverage += row.candidate.correct - row.baseline.correct
        if (
            include_path_lists
            and row.candidate.correct
            and not row.baseline.correct
        ):
            candidate_only.append(row.relative_path)
        if row.baseline.correct and not row.candidate.correct:
            if include_path_lists:
                baseline_only.append(row.relative_path)
            common_correct -= 1
            common_baseline_total -= baseline_time
            common_routed_total -= baseline_time
            ties -= 1
            if baseline_time > 0.0:
                positive_ratio_count -= 1
            continue
        if not (row.baseline.correct and row.candidate.correct):
            continue
        common_routed_total += candidate_time - baseline_time
        ties -= 1
        if baseline_time > 0.0 and candidate_time > 0.0:
            log_ratio_sum += math.log(baseline_time / candidate_time)
        elif baseline_time > 0.0:
            positive_ratio_count -= 1
        if candidate_time < baseline_time:
            candidate_wins += 1
        elif baseline_time < candidate_time:
            baseline_wins += 1
        else:
            ties += 1

    return {
        "instances": baseline["instances"],
        "selected_count": selected_mask.bit_count(),
        "coverage": coverage,
        "coverage_fraction": (
            coverage / baseline["instances"] if baseline["instances"] else None
        ),
        "all_baseline_coverage": baseline["coverage"],
        "coverage_delta_vs_all_baseline": coverage - baseline["coverage"],
        "all_baseline_timeout_charged_total_time_s": baseline["total"],
        "route_timeout_charged_total_time_s": routed_all_total,
        "timeout_charged_all_total_speedup": (
            baseline["total"] / routed_all_total if routed_all_total > 0.0 else None
        ),
        "common_correct": common_correct,
        "common_correct_baseline_total_time_s": common_baseline_total,
        "common_correct_route_total_time_s": common_routed_total,
        "common_correct_total_speedup": (
            common_baseline_total / common_routed_total
            if common_routed_total > 0.0
            else None
        ),
        "geometric_speedup": (
            math.exp(log_ratio_sum / positive_ratio_count)
            if positive_ratio_count > 0
            else None
        ),
        "candidate_wins": candidate_wins,
        "baseline_wins": baseline_wins,
        "ties": ties,
        "selected_candidate_only_paths": sorted(candidate_only),
        "selected_baseline_only_paths": sorted(baseline_only),
    }


def _passes_gate(evaluation: dict) -> bool:
    ratios = (
        evaluation["timeout_charged_all_total_speedup"],
        evaluation["common_correct_total_speedup"],
        evaluation["geometric_speedup"],
    )
    return evaluation["coverage_delta_vs_all_baseline"] >= 0 and all(
        ratio is not None and ratio >= 1.0 for ratio in ratios
    )


def _compact_evaluation(evaluation: dict) -> dict:
    return {
        key: value
        for key, value in evaluation.items()
        if key
        not in {"selected_candidate_only_paths", "selected_baseline_only_paths"}
    }


def _rank_key(item: tuple[tuple[Clause, ...], int, dict]) -> tuple:
    route, _mask, evaluation = item
    return (
        -evaluation["timeout_charged_all_total_speedup"],
        -evaluation["common_correct_total_speedup"],
        -evaluation["geometric_speedup"],
        -evaluation["coverage_delta_vs_all_baseline"],
        -evaluation["selected_count"],
        route,
    )


def analyze_rows(rows: Sequence[Row], top: int = 10) -> dict:
    if top < 1:
        raise AnalyzerError("top must be at least one")
    clauses = build_clauses(rows)
    routes = enumerate_routes(rows, clauses)
    full_universe = (1 << len(rows)) - 1
    full_baseline = _baseline_state(rows, full_universe)
    eligible = []
    for route, mask in routes:
        evaluation = evaluate_selection(
            rows,
            mask,
            full_universe,
            baseline_state=full_baseline,
            include_path_lists=False,
        )
        if _passes_gate(evaluation):
            eligible.append((route, mask, evaluation))
    eligible.sort(key=_rank_key)

    fold_universes = [
        sum(
            1 << index
            for index, row in enumerate(rows)
            if fold_for_path(row.relative_path) == fold
        )
        for fold in range(FOLD_COUNT)
    ]
    fold_baselines = [
        _baseline_state(rows, universe) for universe in fold_universes
    ]
    reported_routes = []
    for rank, (route, mask, _evaluation) in enumerate(eligible[:top], start=1):
        evaluation = evaluate_selection(
            rows, mask, full_universe, baseline_state=full_baseline
        )
        folds = []
        for fold, (universe, fold_baseline) in enumerate(
            zip(fold_universes, fold_baselines)
        ):
            fold_evaluation = evaluate_selection(
                rows,
                mask,
                universe,
                baseline_state=fold_baseline,
                include_path_lists=False,
            )
            folds.append(
                {
                    "fold": fold,
                    "passes_gate": (
                        _passes_gate(fold_evaluation)
                        if fold_evaluation["instances"]
                        else None
                    ),
                    **_compact_evaluation(fold_evaluation),
                }
            )
        reported_routes.append(
            {
                "rank": rank,
                "predicate": {"all": [clause.as_json() for clause in route]},
                "evaluation": evaluation,
                "folds": folds,
                "nonempty_folds_passing": sum(
                    fold["passes_gate"] is True for fold in folds
                ),
                "nonempty_folds": sum(fold["instances"] > 0 for fold in folds),
                "all_nonempty_folds_pass": all(
                    fold["passes_gate"] is not False for fold in folds
                ),
            }
        )

    all_baseline = evaluate_selection(
        rows, 0, full_universe, baseline_state=full_baseline
    )
    return {
        "schema_version": 1,
        "instances": len(rows),
        "parameters": {
            "top": top,
            "folds": FOLD_COUNT,
            "max_thresholds_per_numeric_feature": MAX_THRESHOLDS_PER_FEATURE,
        },
        "predicate_contract": {
            "allowed_shadow_features": [
                "applicable",
                "cap_reason",
                "infeasible",
                *RAW_COUNT_FEATURES,
                *RATIO_FEATURES,
            ],
            "allowed_finite_metrics": list(FINITE_METRIC_FEATURES),
            "active_features": sorted(
                set.intersection(*(set(row.features) for row in rows)) if rows else set()
            ),
            "forbidden_fields": list(FORBIDDEN_PREDICATE_FIELDS),
            "ratio_definition": "numerator // max(denominator, 1)",
            "ratio_features": {
                name: {"numerator": numerator, "denominator": denominator}
                for name, (numerator, denominator) in RATIO_FEATURES.items()
            },
            "forms": "one clause or conjunction of two clauses on distinct features",
        },
        "fold_assignment": {
            "count": FOLD_COUNT,
            "method": "first 64 bits of SHA-256(relative_path UTF-8), modulo 5",
            "predicate_uses_path": False,
        },
        "all_baseline": _compact_evaluation(all_baseline),
        "search": {
            "clauses": len(clauses),
            "distinct_nonempty_routes": len(routes),
            "eligible_routes": len(eligible),
            "reported_routes": len(reported_routes),
        },
        "routes": reported_routes,
    }


def analyze(
    summary_path: Path,
    shadow_path: Path,
    top: int = 10,
    finite_analysis_path: Path | None = None,
) -> dict:
    comparisons = load_summary(summary_path)
    shadow = load_shadow(shadow_path)
    finite = (
        load_finite_analysis(finite_analysis_path)
        if finite_analysis_path is not None
        else None
    )
    rows = join_inputs(comparisons, shadow, finite)
    payload = analyze_rows(rows, top=top)
    payload["sources"] = {
        "compare_viper_ab_summary": str(summary_path),
        "eq_abstraction_shadow_jsonl": str(shadow_path),
        "finite_analysis": (
            str(finite_analysis_path) if finite_analysis_path is not None else None
        ),
    }
    return payload


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least one")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    parser.add_argument("shadow", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--top", type=_positive_int, default=10)
    parser.add_argument("--finite-analysis", type=Path)
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        payload = analyze(
            args.summary,
            args.shadow,
            top=args.top,
            finite_analysis_path=args.finite_analysis,
        )
        _write_json(args.out, payload)
    except (AnalyzerError, OSError) as exc:
        parser.error(str(exc))
    search = payload["search"]
    best = payload["routes"][0]["evaluation"] if payload["routes"] else None
    if best is None:
        print(
            f"instances={payload['instances']} routes={search['distinct_nonempty_routes']} "
            "eligible=0"
        )
    else:
        print(
            f"instances={payload['instances']} routes={search['distinct_nonempty_routes']} "
            f"eligible={search['eligible_routes']} reported={search['reported_routes']} "
            f"best_all_speedup={best['timeout_charged_all_total_speedup']:.6f}x "
            f"coverage_delta={best['coverage_delta_vs_all_baseline']:+d}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
