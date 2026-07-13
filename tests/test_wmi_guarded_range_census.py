from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_guarded_range_census.sbatch"


class GuardedRangeCensusWmiTests(unittest.TestCase):
    def test_job_binds_revision_source_and_semantic_parser(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_EXPECTED_REVISION", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("census_guarded_adequate_ranges.py", text)
        self.assertIn("scripts/cert/independent_qfuf.py", text)
        self.assertIn('"records": root / "records.jsonl"', text)
        self.assertIn('"aggregate": root / "aggregate.json"', text)


if __name__ == "__main__":
    unittest.main()
