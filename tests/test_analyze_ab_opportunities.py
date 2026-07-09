from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_ab_opportunities.py"
SPEC = importlib.util.spec_from_file_location("analyze_ab_opportunities", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


def side(correct: bool, time_s: float, result: str) -> dict:
    return {
        "correct": correct,
        "median_time_s": time_s,
        "results": {result: 1},
    }


def sample_summary() -> dict:
    paths = {
        "QF_UF/NEQ/gain.smt2": {
            "baseline": side(False, 10.1, "timeout"),
            "candidate": side(True, 2.0, "unsat"),
        },
        "QF_UF/PEQ/loss.smt2": {
            "baseline": side(True, 9.0, "unsat"),
            "candidate": side(False, 10.2, "timeout"),
        },
        "QF_UF/NEQ/a-slow.smt2": {
            "baseline": side(True, 2.0, "unsat"),
            "candidate": side(True, 5.0, "unsat"),
        },
        "QF_UF/NEQ/b-slow.smt2": {
            "baseline": side(True, 1.0, "unsat"),
            "candidate": side(True, 4.0, "unsat"),
        },
        "QF_UF/NEQ/fast.smt2": {
            "baseline": side(True, 7.0, "unsat"),
            "candidate": side(True, 0.875, "unsat"),
        },
        "QF_UF/PEQ/near.smt2": {
            "baseline": side(True, 8.0, "unsat"),
            "candidate": side(True, 7.0, "unsat"),
        },
        "other/fixed.smt2": {
            "baseline": side(True, 3.0, "sat"),
            "candidate": side(True, 3.0, "sat"),
        },
    }
    return {"instances": len(paths), "paths": paths}


class AnalyzeSummaryTests(unittest.TestCase):
    def test_reports_all_opportunity_categories(self) -> None:
        result = ANALYZER.analyze_summary(
            sample_summary(), top=2, timeout_s=10.0, timeout_fraction=0.8
        )

        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["overview"]["instances"], 7)
        self.assertEqual(result["overview"]["baseline_correct"], 6)
        self.assertEqual(result["overview"]["candidate_correct"], 6)
        self.assertEqual(result["overview"]["common_correct"], 5)
        self.assertEqual(result["overview"]["candidate_wins"], 2)
        self.assertEqual(result["overview"]["baseline_wins"], 2)
        self.assertEqual(result["overview"]["ties"], 1)

        baseline_only = result["coverage_only"]["baseline_only_correct"]
        candidate_only = result["coverage_only"]["candidate_only_correct"]
        self.assertEqual(
            [entry["relative_path"] for entry in baseline_only],
            ["QF_UF/PEQ/loss.smt2"],
        )
        self.assertEqual(
            [entry["relative_path"] for entry in candidate_only],
            ["QF_UF/NEQ/gain.smt2"],
        )

        self.assertEqual(
            [entry["relative_path"] for entry in result["largest_slowdowns"]],
            ["QF_UF/NEQ/a-slow.smt2", "QF_UF/NEQ/b-slow.smt2"],
        )
        self.assertEqual(
            [entry["relative_path"] for entry in result["largest_speedups"]],
            ["QF_UF/NEQ/fast.smt2", "QF_UF/PEQ/near.smt2"],
        )
        self.assertEqual(result["largest_slowdowns"][0]["delta_time_s"], 3.0)
        self.assertEqual(result["largest_speedups"][0]["candidate_speedup"], 8.0)

        adjacent = result["timeout_adjacent"]
        self.assertEqual(adjacent["count"], 3)
        self.assertEqual(
            [entry["relative_path"] for entry in adjacent["cases"]],
            ["QF_UF/PEQ/loss.smt2", "QF_UF/NEQ/gain.smt2"],
        )
        self.assertEqual(adjacent["cases"][0]["timeout_labels"], ["candidate"])

        neq = result["family_aggregates"]["NEQ"]
        peq = result["family_aggregates"]["PEQ"]
        self.assertEqual(neq["instances"], 4)
        self.assertEqual(neq["coverage_delta"], 1)
        self.assertEqual(peq["instances"], 2)
        self.assertEqual(peq["coverage_delta"], -1)
        self.assertIn("other", result["family_aggregates"])

        selection = result["experiment_selection"]
        self.assertEqual(
            selection["by_reason"]["baseline_only_correct"],
            ["QF_UF/PEQ/loss.smt2"],
        )
        selected_paths = [entry["relative_path"] for entry in selection["cases"]]
        self.assertEqual(len(selected_paths), len(set(selected_paths)))
        loss = next(
            entry
            for entry in selection["cases"]
            if entry["relative_path"] == "QF_UF/PEQ/loss.smt2"
        )
        self.assertEqual(
            loss["reasons"], ["baseline_only_correct", "timeout_adjacent"]
        )

    def test_timeout_is_inferred_from_observations(self) -> None:
        result = ANALYZER.analyze_summary(sample_summary(), top=10)

        self.assertEqual(
            result["parameters"]["timeout_source"],
            "inferred_from_timeout_results",
        )
        self.assertAlmostEqual(result["parameters"]["timeout_s"], 10.15)
        self.assertEqual(result["timeout_adjacent"]["count"], 2)

    def test_summary_timeout_metadata_precedes_inference(self) -> None:
        payload = sample_summary()
        payload["timeout_s"] = 20

        result = ANALYZER.analyze_summary(payload)

        self.assertEqual(result["parameters"]["timeout_s"], 20.0)
        self.assertEqual(result["parameters"]["timeout_source"], "summary.timeout_s")
        self.assertEqual(result["timeout_adjacent"]["count"], 2)

    def test_rejects_incompatible_summary_schema(self) -> None:
        cases = [
            {},
            {"paths": {"x.smt2": {"baseline": side(True, 1.0, "sat")}}},
            {
                "instances": 2,
                "paths": {
                    "x.smt2": {
                        "baseline": side(True, 1.0, "sat"),
                        "candidate": side(True, 1.0, "sat"),
                    }
                },
            },
            {
                "paths": {
                    "x.smt2": {
                        "baseline": side(True, float("inf"), "sat"),
                        "candidate": side(True, 1.0, "sat"),
                    }
                }
            },
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(ANALYZER.SummarySchemaError):
                    ANALYZER.analyze_summary(payload)


class CliTests(unittest.TestCase):
    def test_stdout_is_deterministic_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.json"
            summary_path.write_text(json.dumps(sample_summary()), encoding="utf-8")
            command = [
                sys.executable,
                str(SCRIPT),
                str(summary_path),
                "--top",
                "2",
                "--timeout",
                "10",
            ]

            first = subprocess.run(command, text=True, capture_output=True, check=False)
            second = subprocess.run(command, text=True, capture_output=True, check=False)

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first.stderr, "")
            self.assertEqual(first.stdout, second.stdout)
            payload = json.loads(first.stdout)
            self.assertEqual(payload["parameters"]["top"], 2)
            self.assertEqual(payload["source_summary"], str(summary_path))

    def test_can_write_json_to_an_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.json"
            output_path = Path(temp_dir) / "nested" / "analysis.json"
            summary_path.write_text(json.dumps(sample_summary()), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(summary_path),
                    "--out",
                    str(output_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["overview"]["instances"], 7)
            self.assertTrue(output_path.read_bytes().endswith(b"\n"))

    def test_invalid_json_exits_with_a_cli_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.json"
            summary_path.write_text("{", encoding="utf-8")

            completed = subprocess.run(
                [sys.executable, str(SCRIPT), str(summary_path)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("invalid JSON", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
