from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_profile_log.py"
SPEC = importlib.util.spec_from_file_location("analyze_profile_log", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


PROFILE_LOG = """\
BEGIN label=baseline repeat=2 path=QF_UF/example.smt2
profile_parse_ns=30 count=6
profile_unconditional_quotient_mode=auto fallback=none
profile_unconditional_quotient_auto projected_terms=12 threshold=20 reason=below_threshold
sat
elapsed_ns=300
END label=baseline repeat=2 status=0 path=QF_UF/example.smt2
BEGIN label=baseline repeat=1 path=QF_UF/example.smt2
profile_parse_ns=10 count=2
fallback=none profile_unconditional_quotient_mode=auto
profile_unconditional_quotient_auto reason=below_threshold threshold=20 projected_terms=10
sat
elapsed_ns=100
END label=baseline repeat=1 status=0 path=QF_UF/example.smt2
"""


class ProfileArtifactTests(unittest.TestCase):
    def test_cli_preserves_metadata_separately_from_numeric_medians(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            log_path = root / "profile.log"
            first_output = root / "first.json"
            second_output = root / "second.json"
            log_path.write_text(PROFILE_LOG, encoding="utf-8")

            for output_path in (first_output, second_output):
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        str(log_path),
                        "--out",
                        str(output_path),
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
            payload = json.loads(first_output.read_text(encoding="utf-8"))
            baseline = payload["paths"]["QF_UF/example.smt2"]["labels"]["baseline"]

            self.assertEqual(
                baseline["median_metrics"],
                {
                    "elapsed_ns": 200.0,
                    "profile_parse_count": 4.0,
                    "profile_parse_ns": 20.0,
                    "projected_terms": 11.0,
                    "threshold": 20.0,
                },
            )
            self.assertEqual(
                baseline["metadata_summary"],
                [
                    {
                        "context": "profile_unconditional_quotient_auto",
                        "count": 2,
                        "fields": {"reason": "below_threshold"},
                    },
                    {
                        "context": "profile_unconditional_quotient_mode",
                        "count": 2,
                        "fields": {
                            "fallback": "none",
                            "profile_unconditional_quotient_mode": "auto",
                        },
                    },
                ],
            )

    def test_summarize_accepts_legacy_numeric_only_records(self) -> None:
        records = [
            {
                "label": "baseline",
                "path": "QF_UF/example.smt2",
                "result": "sat",
                "status": 0,
                "metrics": {"elapsed_ns": 30, "terms": 7},
            },
            {
                "label": "baseline",
                "path": "QF_UF/example.smt2",
                "result": "sat",
                "status": 0,
                "metrics": {"elapsed_ns": 10, "terms": 5},
            },
            {
                "label": "candidate",
                "path": "QF_UF/example.smt2",
                "result": "sat",
                "status": 0,
                "metrics": {"elapsed_ns": 10, "terms": 6},
            },
        ]

        summary = ANALYZER.summarize(records)
        labels = summary["paths"]["QF_UF/example.smt2"]["labels"]

        self.assertEqual(
            labels["baseline"]["median_metrics"],
            {"elapsed_ns": 20.0, "terms": 6.0},
        )
        self.assertEqual(labels["baseline"]["metadata_summary"], [])
        self.assertEqual(labels["candidate"]["metadata_summary"], [])
        self.assertEqual(
            summary["paths"]["QF_UF/example.smt2"]["comparison"],
            {
                "baseline_elapsed_ns": 20.0,
                "candidate_elapsed_ns": 10,
                "candidate_speedup": 2.0,
            },
        )


if __name__ == "__main__":
    unittest.main()
