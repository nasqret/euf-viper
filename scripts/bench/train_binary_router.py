#!/usr/bin/env python3
"""Train a small, coverage-preserving structural router for two binaries."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


DECISIVE_RESULTS = {"sat", "unsat"}
PATTERN_FEATURES = {
    "asserts": b"(assert",
    "declarations": b"(declare-fun",
    "sorts": b"(declare-sort",
    "lets": b"(let",
    "ands": b"(and",
    "ors": b"(or",
    "nots": b"(not",
    "ites": b"(ite",
    "distincts": b"(distinct",
    "equalities": b"(=",
    "implications": b"=>",
}
FEATURES = ("bytes", "lines", "parens", "max_depth", *PATTERN_FEATURES)
FORBIDDEN_FEATURES = {
    "path",
    "relative_path",
    "family",
    "status",
    "expected_status",
    "result",
    "baseline_result",
    "candidate_result",
    "baseline_correct",
    "candidate_correct",
    "time_s",
    "baseline_time_s",
    "candidate_time_s",
}


@dataclass(frozen=True)
class Sample:
    relative_path: str
    source_sha256: str
    expected_status: str
    features: dict[str, int]
    baseline_time_s: float
    candidate_time_s: float
    baseline_correct: bool
    candidate_correct: bool
    baseline_wrong_answer: bool = False
    candidate_wrong_answer: bool = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Train and cross-validate a structural baseline/candidate router from "
            "repeated compare_viper_ab.py observations."
        )
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("results", type=Path)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument(
        "--router",
        type=Path,
        help="evaluate an existing router JSON instead of training a new tree",
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--depth", type=int, action="append", dest="depths")
    parser.add_argument("--min-leaf", type=int, action="append", dest="min_leaves")
    parser.add_argument("--max-thresholds", type=int, default=32)
    return parser.parse_args()


def structural_features_from_bytes(data: bytes, source: str = "<bytes>") -> dict[str, int]:
    depth = 0
    max_depth = 0
    for byte in data:
        if byte == ord("("):
            depth += 1
            max_depth = max(max_depth, depth)
        elif byte == ord(")"):
            depth -= 1
            if depth < 0:
                raise ValueError(f"unbalanced parentheses in {source}")
    if depth != 0:
        raise ValueError(f"unbalanced parentheses in {source}")

    features = {
        "bytes": len(data),
        "lines": data.count(b"\n") + 1,
        "parens": data.count(b"("),
        "max_depth": max_depth,
    }
    features.update(
        {name: data.count(pattern) for name, pattern in PATTERN_FEATURES.items()}
    )
    return features


def structural_features(path: Path) -> dict[str, int]:
    return structural_features_from_bytes(path.read_bytes(), str(path))


def resolve_source_path(
    row: Mapping[str, Any], manifest_path: Path, corpus_root: Path | None
) -> Path:
    relative_path = Path(str(row["relative_path"]))
    candidates: list[Path] = []
    if corpus_root is not None:
        candidates.append(corpus_root / relative_path)
        if relative_path.parts and corpus_root.name == relative_path.parts[0]:
            candidates.append(corpus_root.joinpath(*relative_path.parts[1:]))
    raw_path = row.get("path")
    if raw_path:
        candidates.append(Path(str(raw_path)))
    candidates.append(manifest_path.parent / relative_path)

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    attempted = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(
        f"cannot resolve source for {row['relative_path']}; tried: {attempted}"
    )


def _valid_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            relative_path = str(row["relative_path"])
            if relative_path in rows:
                raise ValueError(f"duplicate manifest path: {relative_path}")
            sha256 = str(row["sha256"])
            if not _valid_sha256(sha256):
                raise ValueError(
                    f"invalid SHA-256 at {path}:{line_number}: {sha256!r}"
                )
            rows[relative_path] = row
    if not rows:
        raise ValueError("manifest is empty")
    return rows


def load_observations(path: Path) -> dict[str, dict[str, list[dict[str, str]]]]:
    grouped: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "relative_path",
            "expected_status",
            "label",
            "result",
            "time_s",
        }
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"results CSV is missing columns: {sorted(missing)}")
        for row in reader:
            label = row["label"]
            if label not in {"baseline", "candidate"}:
                raise ValueError(f"unexpected binary label: {label!r}")
            time_s = float(row["time_s"])
            if not math.isfinite(time_s) or time_s <= 0:
                raise ValueError(f"invalid time_s for {row['relative_path']}: {time_s}")
            grouped[row["relative_path"]][label].append(row)
    return grouped


def _side_summary(
    observations: Sequence[Mapping[str, str]], expected_status: str
) -> tuple[float, bool, bool]:
    if not observations:
        raise ValueError("cannot aggregate an empty observation list")
    statuses = {row["expected_status"] for row in observations}
    if statuses != {expected_status}:
        raise ValueError(
            f"inconsistent expected statuses: expected {expected_status!r}, got {statuses}"
        )
    times = [float(row["time_s"]) for row in observations]
    correct = all(row["result"] == expected_status for row in observations)
    wrong_answer = any(
        row["result"] in DECISIVE_RESULTS and row["result"] != expected_status
        for row in observations
    )
    return statistics.median(times), correct, wrong_answer


def load_samples(
    manifest_path: Path, results_path: Path, corpus_root: Path | None = None
) -> list[Sample]:
    manifest = load_manifest(manifest_path)
    observations = load_observations(results_path)
    unknown = sorted(set(observations) - set(manifest))
    if unknown:
        raise ValueError(f"results contain paths absent from manifest: {unknown[:5]}")

    samples = []
    for relative_path, row in manifest.items():
        sides = observations.get(relative_path, {})
        missing = {"baseline", "candidate"} - set(sides)
        if missing:
            raise ValueError(
                f"missing {sorted(missing)} observations for {relative_path}"
            )
        expected_status = str(row["status"])
        baseline_time, baseline_correct, baseline_wrong = _side_summary(
            sides["baseline"], expected_status
        )
        candidate_time, candidate_correct, candidate_wrong = _side_summary(
            sides["candidate"], expected_status
        )
        source_path = resolve_source_path(row, manifest_path, corpus_root)
        samples.append(
            Sample(
                relative_path=relative_path,
                source_sha256=str(row["sha256"]).lower(),
                expected_status=expected_status,
                features=structural_features(source_path),
                baseline_time_s=baseline_time,
                candidate_time_s=candidate_time,
                baseline_correct=baseline_correct,
                candidate_correct=candidate_correct,
                baseline_wrong_answer=baseline_wrong,
                candidate_wrong_answer=candidate_wrong,
            )
        )
    return samples


def leaf(samples: Sequence[Sample]) -> dict[str, Any]:
    baseline_cost = sum(sample.baseline_time_s for sample in samples)
    candidate_cost = sum(sample.candidate_time_s for sample in samples)
    candidate_safe = all(sample.candidate_correct for sample in samples)
    action = (
        "candidate"
        if candidate_safe and candidate_cost < baseline_cost
        else "baseline"
    )
    return {
        "action": action,
        "count": len(samples),
        "training_baseline_time_s": baseline_cost,
        "training_candidate_time_s": candidate_cost,
        "training_cost_s": candidate_cost if action == "candidate" else baseline_cost,
        "training_baseline_correct": sum(sample.baseline_correct for sample in samples),
        "training_candidate_correct": sum(sample.candidate_correct for sample in samples),
    }


def threshold_candidates(
    samples: Sequence[Sample], feature: str, maximum: int
) -> Iterable[int]:
    values = sorted({sample.features[feature] for sample in samples})
    if len(values) < 2:
        return []
    boundaries = values[:-1]
    if len(boundaries) <= maximum:
        return boundaries
    indexes = {
        round(index * (len(boundaries) - 1) / (maximum - 1))
        for index in range(maximum)
    }
    return [boundaries[index] for index in sorted(indexes)]


def train_tree(
    samples: Sequence[Sample], depth: int, min_leaf: int, max_thresholds: int
) -> dict[str, Any]:
    base = leaf(samples)
    if depth == 0 or len(samples) < 2 * min_leaf:
        return base

    best: tuple[float, str, int, list[Sample], list[Sample]] | None = None
    for feature in FEATURES:
        for threshold in threshold_candidates(samples, feature, max_thresholds):
            left = [sample for sample in samples if sample.features[feature] <= threshold]
            if len(left) < min_leaf or len(samples) - len(left) < min_leaf:
                continue
            right = [sample for sample in samples if sample.features[feature] > threshold]
            split_cost = leaf(left)["training_cost_s"] + leaf(right)["training_cost_s"]
            gain = base["training_cost_s"] - split_cost
            if best is None or gain > best[0]:
                best = (gain, feature, threshold, left, right)

    if best is None or best[0] <= 0:
        return base
    gain, feature, threshold, left, right = best
    return {
        "feature": feature,
        "threshold": threshold,
        "training_gain_s": gain,
        "count": len(samples),
        "left": train_tree(left, depth - 1, min_leaf, max_thresholds),
        "right": train_tree(right, depth - 1, min_leaf, max_thresholds),
    }


def route(tree: Mapping[str, Any], sample: Sample) -> str:
    node = tree
    while "action" not in node:
        feature = str(node["feature"])
        branch = "left" if sample.features[feature] <= int(node["threshold"]) else "right"
        node = node[branch]
    return str(node["action"])


def _ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator > 0 else None


def evaluate_choices(
    samples: Sequence[Sample], choices: Mapping[str, str]
) -> dict[str, Any]:
    baseline_all = 0.0
    selected_all = 0.0
    baseline_common = 0.0
    selected_common = 0.0
    common_ratios = []
    baseline_correct = 0
    candidate_correct = 0
    selected_correct = 0
    candidate_routes = []
    coverage_losses = []
    coverage_gains = []
    candidate_incorrect_routes = []
    candidate_wrong_answer_routes = []

    for sample in samples:
        choice = choices[sample.relative_path]
        if choice not in {"baseline", "candidate"}:
            raise ValueError(f"invalid route for {sample.relative_path}: {choice!r}")
        baseline_correct += sample.baseline_correct
        candidate_correct += sample.candidate_correct
        baseline_all += sample.baseline_time_s
        if choice == "candidate":
            candidate_routes.append(sample.relative_path)
            selected_time = sample.candidate_time_s
            is_correct = sample.candidate_correct
            if not is_correct:
                candidate_incorrect_routes.append(sample.relative_path)
            if sample.candidate_wrong_answer:
                candidate_wrong_answer_routes.append(sample.relative_path)
        else:
            selected_time = sample.baseline_time_s
            is_correct = sample.baseline_correct
        selected_all += selected_time
        selected_correct += is_correct

        if sample.baseline_correct and is_correct:
            baseline_common += sample.baseline_time_s
            selected_common += selected_time
            common_ratios.append(sample.baseline_time_s / selected_time)
        if sample.baseline_correct and not is_correct:
            coverage_losses.append(sample.relative_path)
        if not sample.baseline_correct and is_correct:
            coverage_gains.append(sample.relative_path)

    all_speedup = _ratio(baseline_all, selected_all)
    common_speedup = _ratio(baseline_common, selected_common)
    geometric_speedup = (
        math.exp(statistics.mean(math.log(ratio) for ratio in common_ratios))
        if common_ratios
        else None
    )
    gate_failures = []
    if coverage_losses:
        gate_failures.append("baseline_coverage_loss")
    if selected_correct < baseline_correct:
        gate_failures.append("aggregate_coverage_regression")
    if candidate_wrong_answer_routes:
        gate_failures.append("candidate_wrong_answer_route")
    if not candidate_routes:
        gate_failures.append("no_candidate_routes")
    for name, value in (
        ("all_speedup", all_speedup),
        ("common_speedup", common_speedup),
        ("geometric_speedup", geometric_speedup),
    ):
        if value is None or value <= 1.0:
            gate_failures.append(f"{name}_not_above_one")

    return {
        "instances": len(samples),
        "baseline_correct": baseline_correct,
        "candidate_correct": candidate_correct,
        "selected_correct": selected_correct,
        "coverage_delta_vs_baseline": selected_correct - baseline_correct,
        "candidate_routes": len(candidate_routes),
        "baseline_routes": len(samples) - len(candidate_routes),
        "candidate_route_paths": sorted(candidate_routes),
        "candidate_incorrect_route_paths": sorted(candidate_incorrect_routes),
        "candidate_wrong_answer_route_paths": sorted(candidate_wrong_answer_routes),
        "baseline_coverage_loss_paths": sorted(coverage_losses),
        "coverage_gain_paths": sorted(coverage_gains),
        "baseline_all_time_s": baseline_all,
        "selected_all_time_s": selected_all,
        "baseline_common_time_s": baseline_common,
        "selected_common_time_s": selected_common,
        "all_speedup": all_speedup,
        "common_speedup": common_speedup,
        "geometric_speedup": geometric_speedup,
        "gate_failures": gate_failures,
        "valid": not gate_failures,
    }


def evaluate(tree: Mapping[str, Any], samples: Sequence[Sample]) -> dict[str, Any]:
    choices = {sample.relative_path: route(tree, sample) for sample in samples}
    return evaluate_choices(samples, choices)


def fold_for_sha(source_sha256: str, folds: int) -> int:
    if folds < 2:
        raise ValueError("fold count must be at least two")
    if not _valid_sha256(source_sha256):
        raise ValueError(f"invalid source SHA-256: {source_sha256!r}")
    return int(source_sha256[:16], 16) % folds


def tree_features(tree: Mapping[str, Any]) -> set[str]:
    if "action" in tree:
        return set()
    return {
        str(tree["feature"]),
        *tree_features(tree["left"]),
        *tree_features(tree["right"]),
    }


def cross_validate(
    samples: Sequence[Sample],
    folds: int,
    depth: int,
    min_leaf: int,
    max_thresholds: int,
) -> dict[str, Any]:
    assignments: dict[str, str] = {}
    fold_reports = []
    for fold in range(folds):
        train = [
            sample
            for sample in samples
            if fold_for_sha(sample.source_sha256, folds) != fold
        ]
        test = [
            sample
            for sample in samples
            if fold_for_sha(sample.source_sha256, folds) == fold
        ]
        if not train or not test:
            return {
                "depth": depth,
                "min_leaf": min_leaf,
                "valid": False,
                "gate_failures": [f"empty_train_or_test_fold_{fold}"],
                "folds": fold_reports,
            }
        tree = train_tree(train, depth, min_leaf, max_thresholds)
        choices = {sample.relative_path: route(tree, sample) for sample in test}
        assignments.update(choices)
        fold_reports.append(
            {
                "fold": fold,
                "training_instances": len(train),
                "test_instances": len(test),
                "tree": tree,
                "evaluation": evaluate_choices(test, choices),
            }
        )

    evaluation = evaluate_choices(samples, assignments)
    return {
        "depth": depth,
        "min_leaf": min_leaf,
        "valid": evaluation["valid"],
        "gate_failures": evaluation["gate_failures"],
        "evaluation": evaluation,
        "folds": fold_reports,
    }


def _selection_key(report: Mapping[str, Any]) -> tuple[float, float, float, int, int]:
    evaluation = report["evaluation"]
    speedups = (
        float(evaluation["all_speedup"]),
        float(evaluation["common_speedup"]),
        float(evaluation["geometric_speedup"]),
    )
    return (
        min(speedups),
        speedups[0],
        speedups[2],
        -int(report["depth"]),
        -int(report["min_leaf"]),
    )


def train_router(
    samples: Sequence[Sample],
    folds: int,
    depths: Sequence[int],
    min_leaves: Sequence[int],
    max_thresholds: int,
) -> dict[str, Any]:
    reports = [
        cross_validate(samples, folds, depth, min_leaf, max_thresholds)
        for depth in depths
        for min_leaf in min_leaves
    ]
    valid = [report for report in reports if report["valid"]]
    base = {
        "schema_version": 1,
        "instances": len(samples),
        "features": list(FEATURES),
        "forbidden_features": sorted(FORBIDDEN_FEATURES),
        "forbidden_feature_usage": False,
        "fold_assignment": "first 64 source SHA-256 bits modulo fold count",
        "folds": folds,
        "max_thresholds": max_thresholds,
        "cross_validation": reports,
    }
    if not valid:
        return {
            **base,
            "status": "rejected",
            "reason": (
                "no cross-validated tree preserved baseline coverage while "
                "improving all three timing metrics"
            ),
        }

    selected = max(valid, key=_selection_key)
    tree = train_tree(
        samples,
        int(selected["depth"]),
        int(selected["min_leaf"]),
        max_thresholds,
    )
    used = tree_features(tree)
    forbidden_usage = bool(used & FORBIDDEN_FEATURES) or not used <= set(FEATURES)
    if forbidden_usage:
        raise AssertionError(f"router tree used forbidden features: {sorted(used)}")
    return {
        **base,
        "status": "candidate",
        "selection_objective": (
            "maximize the minimum of all/common/geometric cross-validated speedup"
        ),
        "selected_cross_validation": selected,
        "tree": tree,
        "tree_features": sorted(used),
        "full_training_evaluation": evaluate(tree, samples),
    }


def evaluate_router_payload(
    samples: Sequence[Sample], router_path: Path
) -> dict[str, Any]:
    source = json.loads(router_path.read_text(encoding="utf-8"))
    tree = source.get("tree")
    if not isinstance(tree, dict):
        raise ValueError(f"router JSON has no tree object: {router_path}")
    used = tree_features(tree)
    forbidden_usage = bool(used & FORBIDDEN_FEATURES) or not used <= set(FEATURES)
    if forbidden_usage:
        raise ValueError(f"router tree used forbidden features: {sorted(used)}")
    evaluation = evaluate(tree, samples)
    return {
        "schema_version": 1,
        "status": "passed" if evaluation["valid"] else "rejected",
        "mode": "independent_evaluation",
        "instances": len(samples),
        "features": list(FEATURES),
        "forbidden_features": sorted(FORBIDDEN_FEATURES),
        "forbidden_feature_usage": False,
        "tree_features": sorted(used),
        "router": str(router_path),
        "router_sha256": hashlib.sha256(router_path.read_bytes()).hexdigest(),
        "evaluation": evaluation,
    }


def main() -> int:
    args = parse_args()
    depths = sorted(set(args.depths or [1, 2, 3, 4]))
    min_leaves = sorted(set(args.min_leaves or [8, 16, 32, 64]))
    if args.folds < 2:
        raise ValueError("--folds must be at least two")
    if any(depth < 0 for depth in depths):
        raise ValueError("--depth must be non-negative")
    if any(min_leaf < 1 for min_leaf in min_leaves):
        raise ValueError("--min-leaf must be positive")
    if args.max_thresholds < 2:
        raise ValueError("--max-thresholds must be at least two")

    samples = load_samples(args.manifest, args.results, args.corpus_root)
    if args.router:
        payload = evaluate_router_payload(samples, args.router)
    else:
        payload = train_router(
            samples,
            folds=args.folds,
            depths=depths,
            min_leaves=min_leaves,
            max_thresholds=args.max_thresholds,
        )
    payload.update(
        {
            "manifest": str(args.manifest),
            "results": str(args.results),
            "corpus_root": str(args.corpus_root) if args.corpus_root else None,
            "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            "results_sha256": hashlib.sha256(args.results.read_bytes()).hexdigest(),
        }
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    selected = payload.get("selected_cross_validation")
    summary: dict[str, Any] = {
        "status": payload["status"],
        "instances": payload["instances"],
        "forbidden_feature_usage": payload["forbidden_feature_usage"],
    }
    if payload.get("mode") == "independent_evaluation":
        evaluation = payload["evaluation"]
        summary.update(
            {
                "candidate_routes": evaluation["candidate_routes"],
                "coverage_delta_vs_baseline": evaluation[
                    "coverage_delta_vs_baseline"
                ],
                "all_speedup": evaluation["all_speedup"],
                "common_speedup": evaluation["common_speedup"],
                "geometric_speedup": evaluation["geometric_speedup"],
            }
        )
    elif selected:
        evaluation = selected["evaluation"]
        summary.update(
            {
                "depth": selected["depth"],
                "min_leaf": selected["min_leaf"],
                "candidate_routes": evaluation["candidate_routes"],
                "coverage_delta_vs_baseline": evaluation[
                    "coverage_delta_vs_baseline"
                ],
                "all_speedup": evaluation["all_speedup"],
                "common_speedup": evaluation["common_speedup"],
                "geometric_speedup": evaluation["geometric_speedup"],
            }
        )
    else:
        summary["reason"] = payload["reason"]
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
