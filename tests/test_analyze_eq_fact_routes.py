from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_eq_fact_routes.py"
SPEC = importlib.util.spec_from_file_location("analyze_eq_fact_routes", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ANALYZER
SPEC.loader.exec_module(ANALYZER)


def side(correct: bool, time_s: float) -> dict:
    return {
        "correct": correct,
        "median_time_s": time_s,
        "results": {"synthetic-outcome": 1},
    }


def summary(rows: dict[str, tuple[bool, float, bool, float]]) -> dict:
    return {
        "instances": len(rows),
        "paths": {
            path: {
                "baseline": side(baseline_correct, baseline_time),
                "candidate": side(candidate_correct, candidate_time),
            }
            for path, (
                baseline_correct,
                baseline_time,
                candidate_correct,
                candidate_time,
            ) in rows.items()
        },
    }


def shadow(path: str, value: int, **overrides: object) -> dict:
    record = {
        "relative_path": path,
        "profile_available": True,
        "applicable": True,
        "cap_reason": "none",
        "infeasible": False,
        "star_edges": value,
        "nodes": value + 1,
        "work": (value + 1) * 10,
        "memo_entries": value + 2,
        "partition_terms": value // 2,
        # Leakage bait: these fields must never enter a predicate.
        "expected_status": "candidate-wins" if value else "baseline-wins",
        "solver_result": "candidate-wins",
        "resolved_path": f"/families/secret/{path}",
    }
    record.update(overrides)
    return record


def finite_instance(path: str, value: int, **overrides: int) -> dict:
    metrics = {name: value for name in ANALYZER.FINITE_METRIC_FEATURES}
    metrics.update(overrides)
    return {"relative_path": path, "metrics": metrics}


def write_inputs(
    base: Path,
    comparisons: dict[str, tuple[bool, float, bool, float]],
    telemetry: list[dict],
) -> tuple[Path, Path]:
    summary_path = base / "summary.json"
    shadow_path = base / "shadow.jsonl"
    summary_path.write_text(json.dumps(summary(comparisons)), encoding="utf-8")
    shadow_path.write_text(
        "".join(json.dumps(record) + "\n" for record in telemetry),
        encoding="utf-8",
    )
    return summary_path, shadow_path


class InputTests(unittest.TestCase):
    def test_join_is_path_exact_and_sorted(self) -> None:
        comparisons = {
            "z/c.smt2": (True, 3.0, True, 1.0),
            "a/a.smt2": (True, 2.0, True, 1.0),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = write_inputs(
                Path(temp_dir),
                comparisons,
                [shadow("z/c.smt2", 2), shadow("a/a.smt2", 1)],
            )
            rows = ANALYZER.join_inputs(
                ANALYZER.load_summary(paths[0]), ANALYZER.load_shadow(paths[1])
            )

        self.assertEqual([row.relative_path for row in rows], sorted(comparisons))

    def test_rejects_duplicate_and_missing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            summary_path, shadow_path = write_inputs(
                base,
                {"a.smt2": (True, 1.0, True, 0.5)},
                [shadow("a.smt2", 1), shadow("a.smt2", 2)],
            )
            with self.assertRaisesRegex(ANALYZER.AnalyzerError, "duplicate shadow"):
                ANALYZER.analyze(summary_path, shadow_path)

            shadow_path.write_text(
                json.dumps(shadow("b.smt2", 1)) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ANALYZER.AnalyzerError, "join mismatch"):
                ANALYZER.analyze(summary_path, shadow_path)

    def test_rejects_duplicate_summary_json_path_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "summary.json"
            path.write_text(
                '{"paths":{"same.smt2":{},"same.smt2":{}}}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ANALYZER.AnalyzerError, "duplicate JSON"):
                ANALYZER.load_summary(path)

    def test_finite_join_rejects_duplicate_and_missing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "finite.json"
            path.write_text(
                json.dumps(
                    {
                        "instances": [
                            finite_instance("a.smt2", 1),
                            finite_instance("a.smt2", 2),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ANALYZER.AnalyzerError, "duplicate finite"):
                ANALYZER.load_finite_analysis(path)

            finite = {"b.smt2": finite_instance("b.smt2", 1)["metrics"]}
            comparisons = {
                "a.smt2": (
                    ANALYZER.Comparison(True, 1.0),
                    ANALYZER.Comparison(True, 0.5),
                )
            }
            with self.assertRaisesRegex(ANALYZER.AnalyzerError, "finite.*join mismatch"):
                ANALYZER.join_inputs(
                    comparisons,
                    {"a.smt2": ANALYZER.shadow_features(shadow("a.smt2", 1), "a")},
                    finite,
                )


class FeatureAndMetricTests(unittest.TestCase):
    def test_features_include_only_whitelist_and_integer_ratios(self) -> None:
        features = ANALYZER.shadow_features(
            shadow(
                "family/leak.smt2",
                5,
                nodes=2,
                work=11,
                memo_entries=3,
                partition_terms=0,
            ),
            "test",
        )

        expected = {
            "applicable",
            "cap_reason",
            "infeasible",
            *ANALYZER.RAW_COUNT_FEATURES,
            *ANALYZER.RATIO_FEATURES,
        }
        self.assertEqual(set(features), expected)
        self.assertEqual(features["work_per_node"], 5)
        self.assertEqual(features["work_per_partition_term"], 11)
        self.assertFalse(set(features) & set(ANALYZER.FORBIDDEN_PREDICATE_FIELDS))

    def test_route_metrics_use_candidate_only_when_selected(self) -> None:
        rows = [
            ANALYZER.Row(
                "selected.smt2",
                ANALYZER.shadow_features(shadow("selected.smt2", 1), "selected"),
                ANALYZER.Comparison(True, 4.0),
                ANALYZER.Comparison(True, 1.0),
            ),
            ANALYZER.Row(
                "fallback.smt2",
                ANALYZER.shadow_features(shadow("fallback.smt2", 0), "fallback"),
                ANALYZER.Comparison(True, 6.0),
                ANALYZER.Comparison(False, 20.0),
            ),
            ANALYZER.Row(
                "gain.smt2",
                ANALYZER.shadow_features(shadow("gain.smt2", 2), "gain"),
                ANALYZER.Comparison(False, 10.0),
                ANALYZER.Comparison(True, 2.0),
            ),
        ]

        result = ANALYZER.evaluate_selection(rows, 0b101)

        self.assertEqual(result["selected_count"], 2)
        self.assertEqual(result["coverage"], 3)
        self.assertEqual(result["coverage_delta_vs_all_baseline"], 1)
        self.assertEqual(result["route_timeout_charged_total_time_s"], 9.0)
        self.assertAlmostEqual(result["timeout_charged_all_total_speedup"], 20 / 9)
        self.assertEqual(result["common_correct"], 2)
        self.assertEqual(result["common_correct_total_speedup"], 10 / 7)
        self.assertAlmostEqual(result["geometric_speedup"], 2.0)
        self.assertEqual(result["candidate_wins"], 1)
        self.assertEqual(result["ties"], 1)
        self.assertEqual(result["selected_candidate_only_paths"], ["gain.smt2"])
        self.assertEqual(result["selected_baseline_only_paths"], [])
        loss = ANALYZER.evaluate_selection(rows, 0b010)
        self.assertEqual(loss["selected_candidate_only_paths"], [])
        self.assertEqual(loss["selected_baseline_only_paths"], ["fallback.smt2"])

    def test_predicates_cannot_use_family_path_or_outcomes(self) -> None:
        rows = [
            ANALYZER.Row(
                path,
                ANALYZER.shadow_features(shadow(path, value), path),
                ANALYZER.Comparison(True, 2.0),
                ANALYZER.Comparison(True, 1.0),
            )
            for value, path in enumerate(
                ["family-a/win.smt2", "family-b/loss.smt2", "x/other.smt2"]
            )
        ]
        clauses = ANALYZER.build_clauses(rows)

        self.assertTrue(clauses)
        self.assertTrue(
            all(clause.feature in ANALYZER.PREDICATE_FEATURES for clause in clauses)
        )
        self.assertFalse(
            {clause.feature for clause in clauses}
            & set(ANALYZER.FORBIDDEN_PREDICATE_FIELDS)
        )
        for route, _mask in ANALYZER.enumerate_routes(rows, clauses):
            self.assertLessEqual(len(route), 2)
            self.assertEqual(len({clause.feature for clause in route}), len(route))

    def test_finite_metrics_share_the_two_clause_grid_with_shadow(self) -> None:
        rows = []
        cases = [
            ("a.smt2", 0, 0),
            ("b.smt2", 0, 2),
            ("c.smt2", 2, 0),
            ("d.smt2", 2, 2),
        ]
        for path, shadow_value, domain_size in cases:
            features = ANALYZER.shadow_features(shadow(path, shadow_value), path)
            features.update(
                finite_instance(path, 0, domain_size=domain_size)["metrics"]
            )
            rows.append(
                ANALYZER.Row(
                    path,
                    features,
                    ANALYZER.Comparison(True, 2.0),
                    ANALYZER.Comparison(True, 1.0),
                )
            )

        clauses = ANALYZER.build_clauses(rows)
        routes = ANALYZER.enumerate_routes(rows, clauses)
        mixed = [
            route
            for route, _mask in routes
            if len(route) == 2
            and {clause.as_json()["source"] for clause in route}
            == {"shadow", "finite"}
        ]

        self.assertTrue(any(clause.feature == "domain_size" for clause in clauses))
        self.assertTrue(mixed)
        for route in mixed:
            self.assertEqual(len(route), 2)
            self.assertEqual(len({clause.feature for clause in route}), 2)


class FoldAndAnalysisTests(unittest.TestCase):
    def test_fold_assignment_is_stable_across_input_order(self) -> None:
        comparisons = {
            f"suite/case-{index}.smt2": (True, 2.0, True, 1.0)
            for index in range(20)
        }
        telemetry = [
            shadow(path, index % 4) for index, path in enumerate(comparisons)
        ]
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = write_inputs(Path(first_dir), comparisons, telemetry)
            second = write_inputs(
                Path(second_dir),
                dict(reversed(list(comparisons.items()))),
                list(reversed(telemetry)),
            )
            first_result = ANALYZER.analyze(*first, top=4)
            second_result = ANALYZER.analyze(*second, top=4)

        first_result.pop("sources")
        second_result.pop("sources")
        self.assertEqual(first_result, second_result)
        self.assertEqual(
            ANALYZER.fold_for_path("suite/case-7.smt2"),
            ANALYZER.fold_for_path("suite/case-7.smt2"),
        )
        self.assertEqual(len(first_result["routes"][0]["folds"]), 5)

    def test_no_common_correct_routes_are_not_ranked(self) -> None:
        rows = [
            ANALYZER.Row(
                "only.smt2",
                ANALYZER.shadow_features(shadow("only.smt2", 1), "only"),
                ANALYZER.Comparison(False, 4.0),
                ANALYZER.Comparison(True, 1.0),
            )
        ]

        evaluation = ANALYZER.evaluate_selection(rows, 1)
        result = ANALYZER.analyze_rows(rows)

        self.assertEqual(evaluation["common_correct"], 0)
        self.assertIsNone(evaluation["common_correct_total_speedup"])
        self.assertIsNone(evaluation["geometric_speedup"])
        self.assertEqual(result["search"]["eligible_routes"], 0)
        self.assertEqual(result["routes"], [])

    def test_cli_writes_json_and_prints_concise_summary(self) -> None:
        comparisons = {
            "a.smt2": (True, 4.0, True, 1.0),
            "b.smt2": (True, 2.0, True, 2.0),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            summary_path, shadow_path = write_inputs(
                base,
                comparisons,
                [shadow("a.smt2", 2), shadow("b.smt2", 0)],
            )
            output = base / "nested" / "routes.json"
            finite_path = base / "finite.json"
            finite_path.write_text(
                json.dumps(
                    {
                        "instances": [
                            finite_instance("a.smt2", 2, domain_size=8),
                            finite_instance("b.smt2", 0, domain_size=1),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(summary_path),
                    str(shadow_path),
                    "--out",
                    str(output),
                    "--top",
                    "1",
                    "--finite-analysis",
                    str(finite_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(len(completed.stdout.strip().splitlines()), 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["parameters"]["top"], 1)
            self.assertEqual(payload["sources"]["finite_analysis"], str(finite_path))
            self.assertIn(
                "domain_size", payload["predicate_contract"]["active_features"]
            )
            self.assertLessEqual(len(payload["routes"]), 1)
            self.assertTrue(output.read_bytes().endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
