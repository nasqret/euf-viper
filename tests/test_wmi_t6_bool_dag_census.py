from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JOB = ROOT / "scripts" / "wmi" / "euf_viper_t6_bool_dag_census.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_t6_bool_dag_census.sh"


class T6BooleanDagWmiTests(unittest.TestCase):
    def test_job_is_exact_revision_source_only_and_fail_closed(self) -> None:
        text = JOB.read_text(encoding="utf-8")
        self.assertIn("#SBATCH --ntasks=1", text)
        self.assertIn("#SBATCH --cpus-per-task=1", text)
        self.assertIn("EUF_VIPER_EXPECTED_REVISION", text)
        self.assertIn("EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("t6_bool_dag_census::tests::hard10_census_from_env", text)
        self.assertIn("--ignored --exact", text)
        self.assertIn("source_only_structural_projection", text)
        self.assertIn('"parser_source_cap_failures": 0', text)
        self.assertIn('gate.get("decision") not in {"pass", "reject"}', text)
        self.assertNotIn("euf-viper solve", text)
        self.assertNotIn("run_locked_campaign.py", text)

    def test_submitter_requires_the_published_isolated_branch(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("research-t6-theory-dag", text)
        self.assertIn('git rev-parse "origin/$REMOTE_BRANCH"', text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("EUF_VIPER_T6_REMOTE_CORPUS_ROOT", text)
        self.assertIn("EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256", text)
        self.assertIn("t6-bool-dag-census-submission-$JOB_ID.json", text)
        self.assertIn('"expected_sources": 10', text)


if __name__ == "__main__":
    unittest.main()
