from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "train_binary_router.py"
SPEC = importlib.util.spec_from_file_location("train_binary_router", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ROUTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ROUTER
SPEC.loader.exec_module(ROUTER)


def sample(
    name: str,
    baseline_time: float,
    candidate_time: float,
    *,
    baseline_correct: bool = True,
    candidate_correct: bool = True,
    feature_value: int = 0,
    sha: str | None = None,
) -> object:
    features = {feature: 0 for feature in ROUTER.FEATURES}
    features["bytes"] = feature_value
    return ROUTER.Sample(
        relative_path=name,
        source_sha256=sha or hashlib.sha256(name.encode()).hexdigest(),
        expected_status="unsat",
        features=features,
        baseline_time_s=baseline_time,
        candidate_time_s=candidate_time,
        baseline_correct=baseline_correct,
        candidate_correct=candidate_correct,
    )


class LoaderTests(unittest.TestCase):
    def test_aggregates_repeats_by_median_and_remaps_remote_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            source = corpus / "QF_UF" / "case.smt2"
            source.parent.mkdir(parents=True)
            source.write_text("(set-logic QF_UF)\n(check-sat)\n", encoding="ascii")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest = root / "manifest.jsonl"
            manifest.write_text(
                json.dumps(
                    {
                        "relative_path": "QF_UF/case.smt2",
                        "path": "/remote/missing/QF_UF/case.smt2",
                        "sha256": digest,
                        "status": "unsat",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            results = root / "results.csv"
            with results.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "relative_path",
                        "expected_status",
                        "label",
                        "repeat",
                        "result",
                        "time_s",
                    ],
                )
                writer.writeheader()
                for label, times in (
                    ("baseline", [9.0, 1.0, 5.0]),
                    ("candidate", [3.0, 2.0, 4.0]),
                ):
                    for repeat, time_s in enumerate(times):
                        writer.writerow(
                            {
                                "relative_path": "QF_UF/case.smt2",
                                "expected_status": "unsat",
                                "label": label,
                                "repeat": repeat,
                                "result": "unsat",
                                "time_s": time_s,
                            }
                        )

            loaded = ROUTER.load_samples(manifest, results, corpus)

            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].baseline_time_s, 5.0)
            self.assertEqual(loaded[0].candidate_time_s, 3.0)
            self.assertEqual(loaded[0].features["bytes"], len(source.read_bytes()))


class GateTests(unittest.TestCase):
    def test_candidate_route_cannot_drop_a_baseline_solve(self) -> None:
        case = sample(
            "loss.smt2",
            9.0,
            10.0,
            candidate_correct=False,
        )

        evaluation = ROUTER.evaluate_choices(
            [case], {case.relative_path: "candidate"}
        )

        self.assertFalse(evaluation["valid"])
        self.assertEqual(evaluation["coverage_delta_vs_baseline"], -1)
        self.assertEqual(
            evaluation["baseline_coverage_loss_paths"], ["loss.smt2"]
        )
        self.assertIn("baseline_coverage_loss", evaluation["gate_failures"])

    def test_computes_all_common_and_geometric_speedups(self) -> None:
        cases = [
            sample("a.smt2", 4.0, 2.0),
            sample("b.smt2", 9.0, 3.0),
        ]
        choices = {case.relative_path: "candidate" for case in cases}

        evaluation = ROUTER.evaluate_choices(cases, choices)

        self.assertTrue(evaluation["valid"])
        self.assertAlmostEqual(evaluation["all_speedup"], 13.0 / 5.0)
        self.assertAlmostEqual(evaluation["common_speedup"], 13.0 / 5.0)
        self.assertAlmostEqual(evaluation["geometric_speedup"], math.sqrt(6.0))
        self.assertEqual(evaluation["coverage_delta_vs_baseline"], 0)


class DeterminismTests(unittest.TestCase):
    def test_fold_assignment_depends_only_on_source_sha(self) -> None:
        digest = hashlib.sha256(b"same source").hexdigest()

        first = ROUTER.fold_for_sha(digest, 5)
        second = ROUTER.fold_for_sha(digest, 5)

        self.assertEqual(first, second)
        self.assertEqual(first, int(digest[:16], 16) % 5)

    def test_trained_tree_uses_only_declared_structural_features(self) -> None:
        cases = [
            sample(f"case-{index}.smt2", 4.0, 1.0 if index < 4 else 8.0,
                   feature_value=index)
            for index in range(8)
        ]

        tree = ROUTER.train_tree(cases, depth=2, min_leaf=2, max_thresholds=16)
        used = ROUTER.tree_features(tree)

        self.assertTrue(used)
        self.assertLessEqual(used, set(ROUTER.FEATURES))
        self.assertFalse(used & ROUTER.FORBIDDEN_FEATURES)

    def test_existing_router_evaluation_rejects_forbidden_features(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "router.json"
            path.write_text(
                json.dumps(
                    {
                        "tree": {
                            "feature": "relative_path",
                            "threshold": 1,
                            "left": {"action": "candidate"},
                            "right": {"action": "baseline"},
                        }
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "forbidden features"):
                ROUTER.evaluate_router_payload(
                    [sample("case.smt2", 2.0, 1.0)], path
                )


if __name__ == "__main__":
    unittest.main()
