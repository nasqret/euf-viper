#!/usr/bin/env python3
"""Train and cross-validate a small euf-viper/Yices structural router."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


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


@dataclass(frozen=True)
class Sample:
    relative_path: str
    source_sha256: str
    features: dict[str, int]
    euf_time_s: float
    yices_time_s: float
    euf_correct: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("results", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--max-thresholds", type=int, default=32)
    return parser.parse_args()


def structural_features(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    depth = 0
    max_depth = 0
    for byte in data:
        if byte == ord("("):
            depth += 1
            max_depth = max(max_depth, depth)
        elif byte == ord(")"):
            depth -= 1
    if depth != 0:
        raise ValueError(f"unbalanced parentheses in {path}")
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


def load_samples(manifest_path: Path, results_path: Path) -> list[Sample]:
    manifest = {}
    with manifest_path.open() as handle:
        for line in handle:
            row = json.loads(line)
            manifest[row["relative_path"]] = row

    observations: dict[str, dict[str, dict[str, str]]] = {}
    with results_path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            observations.setdefault(row["relative_path"], {})[row["solver"]] = row

    samples = []
    for relative_path, solver_rows in observations.items():
        if "euf-viper" not in solver_rows or "yices2" not in solver_rows:
            raise ValueError(f"missing solver row for {relative_path}")
        manifest_row = manifest[relative_path]
        euf = solver_rows["euf-viper"]
        yices = solver_rows["yices2"]
        yices_correct = yices["result"] == yices["expected_status"]
        if not yices_correct:
            raise ValueError(f"Yices fallback is not correct for {relative_path}")
        samples.append(
            Sample(
                relative_path=relative_path,
                source_sha256=manifest_row["sha256"],
                features=structural_features(Path(manifest_row["path"])),
                euf_time_s=float(euf["time_s"]),
                yices_time_s=float(yices["time_s"]),
                euf_correct=euf["result"] == euf["expected_status"],
            )
        )
    return samples


def leaf(samples: list[Sample]) -> dict[str, Any]:
    euf_correct = all(sample.euf_correct for sample in samples)
    euf_total = sum(sample.euf_time_s for sample in samples)
    yices_total = sum(sample.yices_time_s for sample in samples)
    action = "euf-viper" if euf_correct and euf_total < yices_total else "yices2"
    return {
        "action": action,
        "count": len(samples),
        "training_cost_s": euf_total if action == "euf-viper" else yices_total,
        "training_euf_failures": sum(not sample.euf_correct for sample in samples),
    }


def threshold_candidates(
    samples: list[Sample], feature: str, maximum: int
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
    samples: list[Sample],
    depth: int,
    min_leaf: int,
    max_thresholds: int,
) -> dict[str, Any]:
    base = leaf(samples)
    if depth == 0 or len(samples) < 2 * min_leaf:
        return base

    best: tuple[float, str, int, list[Sample], list[Sample]] | None = None
    for feature in FEATURES:
        for threshold in threshold_candidates(samples, feature, max_thresholds):
            left = [s for s in samples if s.features[feature] <= threshold]
            if len(left) < min_leaf or len(samples) - len(left) < min_leaf:
                continue
            right = [s for s in samples if s.features[feature] > threshold]
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


def route(tree: dict[str, Any], sample: Sample) -> str:
    while "action" not in tree:
        branch = "left" if sample.features[tree["feature"]] <= tree["threshold"] else "right"
        tree = tree[branch]
    return tree["action"]


def evaluate(tree: dict[str, Any], samples: list[Sample]) -> dict[str, Any]:
    selected_total = 0.0
    yices_total = 0.0
    euf_routes = 0
    euf_route_paths = []
    euf_failures = []
    for sample in samples:
        yices_total += sample.yices_time_s
        if route(tree, sample) == "euf-viper":
            euf_routes += 1
            euf_route_paths.append(sample.relative_path)
            selected_total += sample.euf_time_s
            if not sample.euf_correct:
                euf_failures.append(sample.relative_path)
        else:
            selected_total += sample.yices_time_s
    return {
        "instances": len(samples),
        "euf_routes": euf_routes,
        "euf_route_paths": sorted(euf_route_paths),
        "euf_failures": euf_failures,
        "selected_total_time_s": selected_total,
        "yices_total_time_s": yices_total,
        "speedup": yices_total / selected_total,
        "saved_time_s": yices_total - selected_total,
    }


def cross_validate(
    samples: list[Sample],
    folds: int,
    depth: int,
    min_leaf: int,
    max_thresholds: int,
) -> dict[str, Any]:
    aggregate = {
        "instances": 0,
        "euf_routes": 0,
        "euf_route_paths": [],
        "euf_failures": [],
        "selected_total_time_s": 0.0,
        "yices_total_time_s": 0.0,
    }
    for fold in range(folds):
        train = [s for s in samples if int(s.source_sha256[:16], 16) % folds != fold]
        test = [s for s in samples if int(s.source_sha256[:16], 16) % folds == fold]
        tree = train_tree(train, depth, min_leaf, max_thresholds)
        result = evaluate(tree, test)
        for key in (
            "instances",
            "euf_routes",
            "selected_total_time_s",
            "yices_total_time_s",
        ):
            aggregate[key] += result[key]
        aggregate["euf_failures"].extend(result["euf_failures"])
        aggregate["euf_route_paths"].extend(result["euf_route_paths"])
    aggregate["speedup"] = (
        aggregate["yices_total_time_s"] / aggregate["selected_total_time_s"]
    )
    aggregate["saved_time_s"] = (
        aggregate["yices_total_time_s"] - aggregate["selected_total_time_s"]
    )
    aggregate["depth"] = depth
    aggregate["min_leaf"] = min_leaf
    aggregate["euf_route_paths"].sort()
    return aggregate


def main() -> int:
    args = parse_args()
    if args.folds < 2:
        raise ValueError("--folds must be at least 2")
    samples = load_samples(args.manifest, args.results)
    configurations = [
        (2, 50),
        (3, 50),
        (4, 50),
        (5, 50),
        (4, 25),
        (5, 25),
    ]
    cross_validation = [
        cross_validate(samples, args.folds, depth, min_leaf, args.max_thresholds)
        for depth, min_leaf in configurations
    ]
    valid = [result for result in cross_validation if not result["euf_failures"]]
    selected = max(valid, key=lambda result: result["speedup"], default=None)
    if selected is None:
        payload = {
            "status": "rejected",
            "reason": "every cross-validated router sent an unresolved case to euf-viper",
            "cross_validation": cross_validation,
        }
    else:
        tree = train_tree(
            samples,
            selected["depth"],
            selected["min_leaf"],
            args.max_thresholds,
        )
        payload = {
            "status": "candidate",
            "features": list(FEATURES),
            "fold_assignment": "first 64 source SHA-256 bits modulo fold count",
            "path_and_status_features": False,
            "selected_cross_validation": selected,
            "cross_validation": cross_validation,
            "full_training_evaluation": evaluate(tree, samples),
            "tree": tree,
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    summary = dict(payload.get("selected_cross_validation", payload))
    summary.pop("euf_route_paths", None)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
