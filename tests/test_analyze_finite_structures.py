from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_finite_structures.py"
SPEC = importlib.util.spec_from_file_location("analyze_finite_structures", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


FAKE_VIPER = r"""#!/usr/bin/env python3
import json
import sys
import time
from pathlib import Path

if len(sys.argv) != 3 or sys.argv[1] != "stats":
    print("expected: stats FILE", file=sys.stderr)
    raise SystemExit(64)

payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
mode = payload.get("mode", "ok")
if mode == "timeout":
    time.sleep(payload.get("sleep", 1.0))
    raise SystemExit(0)
if mode == "failure":
    print("synthetic stats failure", file=sys.stderr)
    raise SystemExit(7)
if mode == "malformed":
    print("terms 1")
    print("finite_analysis domain_size=not-an-integer")
    raise SystemExit(0)

print("terms 1")
tokens = [f"{key}={value}" for key, value in sorted(payload["metrics"].items())]
print("finite_analysis " + " ".join(tokens))
print("contradiction false")
"""


def finite_metrics(**overrides: int) -> dict[str, int]:
    metrics = {name: 0 for name in ANALYZER.KNOWN_METRICS}
    metrics.update(overrides)
    return metrics


def write_case(root: Path, relative_path: str, payload: dict) -> None:
    path = root.joinpath(*Path(relative_path).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class OutputParserTests(unittest.TestCase):
    def record(self, **overrides: int) -> str:
        metrics = finite_metrics(**overrides)
        tokens = " ".join(f"{key}={value}" for key, value in metrics.items())
        return f"terms 2\nfinite_analysis {tokens}\ncontradiction false\n"

    def test_parses_one_complete_record_and_preserves_new_metrics(self) -> None:
        output = self.record(domain_size=4).replace(
            "\ncontradiction", " future_counter=12\ncontradiction"
        )

        metrics = ANALYZER.parse_finite_analysis(output)

        self.assertEqual(metrics["domain_size"], 4)
        self.assertEqual(metrics["future_counter"], 12)
        self.assertEqual(list(metrics), sorted(metrics))

    def test_rejects_missing_duplicate_and_malformed_records(self) -> None:
        valid = self.record()
        malformed_cases = [
            "terms 1\n",
            valid + valid,
            valid.replace("domain_size=0", "domain_size=-1"),
            valid.replace("domain_size=0", "domain_size=0 domain_size=1"),
            "finite_analysis domain_size=1\n",
        ]

        for output in malformed_cases:
            with self.subTest(output=output):
                with self.assertRaises(ANALYZER.FiniteAnalysisOutputError):
                    ANALYZER.parse_finite_analysis(output)

    def test_metric_predicates_compare_numbers_and_other_metrics(self) -> None:
        numeric = ANALYZER.parse_metric_predicate(" domain_size >= 4 ")
        structural = ANALYZER.parse_metric_predicate(
            "guarded_disequality_clique_lb >= domain_size"
        )

        metrics = finite_metrics(domain_size=4, guarded_disequality_clique_lb=5)
        self.assertEqual(numeric.text, "domain_size>=4")
        self.assertTrue(numeric.matches(metrics))
        self.assertTrue(structural.matches(metrics))
        self.assertFalse(structural.matches({"domain_size": 4}))


class AnalyzerCliTests(unittest.TestCase):
    def test_remaps_paths_reports_failures_and_selects_only_by_metrics(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finite analyzer ") as temp_dir:
            base = Path(temp_dir)
            benchmark_root = base / "benchmark root with spaces"
            fake_viper = base / "fake tools" / "euf viper fake"
            manifest = base / "manifest with spaces.jsonl"
            first_report = base / "first report.json"
            second_report = base / "second report.json"
            first_targets = base / "first targets.jsonl"
            second_targets = base / "second targets.jsonl"

            fake_viper.parent.mkdir(parents=True)
            fake_viper.write_text(FAKE_VIPER, encoding="utf-8")
            fake_viper.chmod(0o755)

            cases = {
                "z named guarded/low metric.smt2": {
                    "metrics": finite_metrics(
                        domain_size=2,
                        guarded_disequality_clique_lb=1,
                    )
                },
                "a selected/space case.smt2": {
                    "metrics": finite_metrics(
                        domain_size=4,
                        guarded_disequality_clique_lb=4,
                        one_hot_variables_est=12,
                        one_hot_clauses_est=80,
                        binary_table_apps=3,
                    )
                },
                "m selected/higher.smt2": {
                    "metrics": finite_metrics(
                        domain_size=3,
                        guarded_disequality_clique_lb=5,
                        one_hot_variables_est=9,
                        one_hot_clauses_est=30,
                        higher_arity_table_apps=2,
                    )
                },
                "b unary.smt2": {
                    "metrics": finite_metrics(
                        domain_size=1,
                        guarded_disequality_clique_lb=0,
                        one_hot_variables_est=2,
                        one_hot_clauses_est=2,
                        unary_table_apps=2,
                    )
                },
                "timeout case.smt2": {"mode": "timeout", "sleep": 2.0},
                "failure case.smt2": {"mode": "failure"},
                "malformed case.smt2": {"mode": "malformed"},
            }
            for relative_path, payload in cases.items():
                write_case(benchmark_root, relative_path, payload)

            rows = [
                {
                    "id": index,
                    "path": f"/stale remote corpus/{relative_path}",
                    "relative_path": relative_path,
                    "status": "unknown",
                }
                for index, relative_path in enumerate(cases)
            ]
            # Reverse source order so stable report ordering is observable.
            manifest.write_text(
                "".join(json.dumps(row) + "\n" for row in reversed(rows)),
                encoding="utf-8",
            )

            def run(report: Path, targets: Path) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        str(manifest),
                        "--viper",
                        str(fake_viper),
                        "--benchmark-root",
                        str(benchmark_root),
                        "--timeout",
                        "1",
                        "--jobs",
                        "3",
                        "--target-predicate",
                        "domain_size>=3",
                        "--target-predicate",
                        "guarded_disequality_clique_lb>=domain_size",
                        "--out",
                        str(report),
                        "--target-manifest",
                        str(targets),
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )

            first = run(first_report, first_targets)
            second = run(second_report, second_targets)

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first.stdout, "")
            self.assertEqual(first.stderr, "")
            self.assertEqual(first_report.read_bytes(), second_report.read_bytes())
            self.assertEqual(first_targets.read_bytes(), second_targets.read_bytes())

            report = json.loads(first_report.read_text(encoding="utf-8"))
            self.assertEqual(
                report["counts"],
                {
                    "failed_instances": 3,
                    "manifest_instances": 7,
                    "successful_instances": 4,
                    "target_instances": 2,
                },
            )
            self.assertEqual(
                [instance["relative_path"] for instance in report["instances"]],
                [
                    "a selected/space case.smt2",
                    "b unary.smt2",
                    "m selected/higher.smt2",
                    "z named guarded/low metric.smt2",
                ],
            )
            self.assertIn(
                "benchmark root with spaces",
                report["instances"][0]["resolved_path"],
            )
            self.assertEqual(
                [failure["kind"] for failure in report["failures"]],
                ["nonzero_exit", "malformed_output", "timeout"],
            )
            self.assertEqual(
                report["aggregates"]["failure_counts"],
                {"malformed_output": 1, "nonzero_exit": 1, "timeout": 1},
            )
            self.assertEqual(
                report["aggregates"]["metric_histograms"]["domain_size"],
                {"1": 1, "2": 1, "3": 1, "4": 1},
            )
            self.assertEqual(
                report["candidate_sets"]["guarded_clique_covers_domain"][
                    "relative_paths"
                ],
                ["a selected/space case.smt2", "m selected/higher.smt2"],
            )
            self.assertEqual(
                report["candidate_sets"]["one_hot_pressure"]["count"], 3
            )
            self.assertEqual(
                report["candidate_sets"]["unary_table_applications"]["count"],
                1,
            )
            self.assertEqual(
                report["candidate_sets"]["binary_table_applications"]["count"],
                1,
            )
            self.assertEqual(
                report["candidate_sets"]["higher_arity_table_applications"][
                    "count"
                ],
                1,
            )
            self.assertEqual(
                report["target_selection"]["relative_paths"],
                ["a selected/space case.smt2", "m selected/higher.smt2"],
            )

            target_rows = [
                json.loads(line)
                for line in first_targets.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [row["relative_path"] for row in target_rows],
                ["a selected/space case.smt2", "m selected/higher.smt2"],
            )
            self.assertTrue(
                all(row["path"].startswith("/stale remote corpus/") for row in target_rows)
            )
            self.assertNotIn(
                "z named guarded/low metric.smt2",
                {row["relative_path"] for row in target_rows},
            )


if __name__ == "__main__":
    unittest.main()
