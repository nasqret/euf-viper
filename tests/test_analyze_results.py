from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_results.py"


class AnalyzeResultsCliTests(unittest.TestCase):
    def test_subset_corpus_reports_empty_predefined_stratum(self) -> None:
        with tempfile.TemporaryDirectory(prefix="analyze results ") as temp_dir:
            base = Path(temp_dir)
            source = base / "subset.csv"
            report = base / "analysis.json"
            fieldnames = [
                "relative_path",
                "solver",
                "expected_status",
                "result",
                "time_s",
                "exit_code",
                "stderr",
            ]
            rows = [
                {
                    "relative_path": "QF_UF/qg7/example.smt2",
                    "solver": "first",
                    "expected_status": "sat",
                    "result": "sat",
                    "time_s": "0.25",
                    "exit_code": "0",
                    "stderr": "",
                },
                {
                    "relative_path": "QF_UF/qg7/example.smt2",
                    "solver": "second",
                    "expected_status": "sat",
                    "result": "unknown",
                    "time_s": "1.5",
                    "exit_code": "0",
                    "stderr": "timeout",
                },
            ]
            with source.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(source),
                    "--out",
                    str(report),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["strata"]["QG-classification"],
                {
                    "instances": 0,
                    "solvers": {
                        "first": {
                            "count": 0,
                            "correct": 0,
                            "coverage": None,
                            "results": {},
                            "total_time_s": 0,
                            "median_time_s": None,
                            "correct_total_time_s": 0,
                            "correct_median_time_s": None,
                        },
                        "second": {
                            "count": 0,
                            "correct": 0,
                            "coverage": None,
                            "results": {},
                            "total_time_s": 0,
                            "median_time_s": None,
                            "correct_total_time_s": 0,
                            "correct_median_time_s": None,
                        },
                    },
                },
            )
            self.assertEqual(
                payload["strata"]["non-QG"],
                {
                    "instances": 1,
                    "solvers": {
                        "first": {
                            "count": 1,
                            "correct": 1,
                            "coverage": 1.0,
                            "results": {"sat": 1},
                            "total_time_s": 0.25,
                            "median_time_s": 0.25,
                            "correct_total_time_s": 0.25,
                            "correct_median_time_s": 0.25,
                        },
                        "second": {
                            "count": 1,
                            "correct": 0,
                            "coverage": 0.0,
                            "results": {"unknown": 1},
                            "total_time_s": 1.5,
                            "median_time_s": 1.5,
                            "correct_total_time_s": 0,
                            "correct_median_time_s": None,
                        },
                    },
                },
            )


if __name__ == "__main__":
    unittest.main()
