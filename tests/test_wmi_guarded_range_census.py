from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_guarded_range_census.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_guarded_range_census.sh"


class GuardedRangeCensusWmiTests(unittest.TestCase):
    def test_job_binds_revision_source_and_semantic_parser(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_EXPECTED_REVISION", text)
        self.assertIn("#SBATCH --ntasks=1", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("census_guarded_adequate_ranges.py", text)
        self.assertIn("scripts/cert/independent_qfuf.py", text)
        self.assertIn('"records": root / "records.jsonl"', text)
        self.assertIn('"aggregate": root / "aggregate.json"', text)
        self.assertIn("--max-structured-parse-errors 0", text)
        self.assertIn("EUF_VIPER_RANGE_CENSUS_EXPECTED_SOURCES", text)
        self.assertIn('"structured_parse_errors": parse_errors', text)
        self.assertIn("census source cardinality mismatch", text)

    def test_submitter_requires_published_exact_revision(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("git rev-parse origin/main", text)
        self.assertIn("EUF_VIPER_EXPECTED_REVISION", text)
        self.assertIn("EUF_VIPER_RANGE_CENSUS_EXPECTED_SOURCES", text)
        self.assertIn("EUF_VIPER_RANGE_CENSUS_WALL_TIME", text)
        self.assertIn("--time='$WALL_TIME'", text)
        self.assertIn("euf_viper_guarded_range_census.sbatch", text)
        self.assertIn("guarded-range-census-submission-$JOB_ID.json", text)
        self.assertIn('"expected_sources": int("$EXPECTED_SOURCES")', text)
        self.assertIn('"requested_wall_time": "$WALL_TIME"', text)


if __name__ == "__main__":
    unittest.main()
