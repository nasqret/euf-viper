from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JOB = ROOT / "scripts" / "wmi" / "euf_viper_t6_bool_dag_census.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_t6_bool_dag_census.sh"
MANIFEST = ROOT / "campaigns" / "t6-theory-dag-hard10-v1.json"


class T6BooleanDagWmiTests(unittest.TestCase):
    def test_shell_scripts_are_syntactically_valid(self) -> None:
        for script in (JOB, SUBMIT):
            subprocess.run(["bash", "-n", str(script)], check=True)

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
        self.assertIn("historical_58efe9d_developmental_8_of_10", text)
        self.assertIn("current P0 full-60 audit; hand-selected paths are forbidden", text)
        self.assertIn('"implementation_or_promotion_eligible": False', text)
        self.assertNotIn("euf-viper solve", text)
        self.assertNotIn("run_locked_campaign.py", text)

    def test_job_uses_only_a_resolved_hash_and_version_bound_cargo(self) -> None:
        text = JOB.read_text(encoding="utf-8")
        self.assertIn('EUF_VIPER_CARGO:-$HOME/.cargo/bin/cargo', text)
        self.assertIn("EUF_VIPER_CARGO_RESOLVED", text)
        self.assertIn("EUF_VIPER_CARGO_SHA256", text)
        self.assertIn("EUF_VIPER_CARGO_VERSION", text)
        self.assertIn('readlink -f -- "$CARGO"', text)
        self.assertIn('sha256sum "$ACTUAL_CARGO_RESOLVED"', text)
        self.assertIn('ACTUAL_CARGO_VERSION="$("$CARGO" --version)"', text)
        self.assertIn("cargo resolved-path mismatch", text)
        self.assertIn("cargo hash mismatch", text)
        self.assertIn("cargo version mismatch", text)
        self.assertIn('"$CARGO" test --release --locked --all-features', text)
        self.assertIn("cargo-toolchain.txt", text)
        self.assertNotIn("command -v cargo", text)
        self.assertIsNone(re.search(r"(?m)^\s*cargo\s", text))

    def test_submitter_requires_the_published_isolated_branch(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("research-t6-theory-dag", text)
        self.assertIn('git rev-parse "origin/$REMOTE_BRANCH"', text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("EUF_VIPER_T6_REMOTE_CORPUS_ROOT", text)
        self.assertIn("EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256", text)
        self.assertIn("EUF_VIPER_CARGO_REMOTE_PATH", text)
        self.assertIn("REMOTE_CARGO_RESOLVED", text)
        self.assertIn("REMOTE_CARGO_SHA256", text)
        self.assertIn("REMOTE_CARGO_VERSION", text)
        self.assertIn("\"'$REMOTE_CARGO' --version\"", text)
        self.assertIn("EUF_VIPER_CARGO_RESOLVED='$REMOTE_CARGO_RESOLVED'", text)
        self.assertIn("t6-bool-dag-census-submission-$JOB_ID.json", text)
        self.assertIn('"campaign_root": campaign_root', text)
        self.assertIn('"implementation_or_promotion_eligible": False', text)
        self.assertIn('"expected_sources": 10', text)

    def test_manifest_is_historical_and_requires_current_p0_confirmation(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="ascii"))
        selection = manifest["selection"]
        self.assertEqual(
            selection["performance_revision"],
            "58efe9d43dab65675530ad4f52b93df2bf73d729",
        )
        self.assertEqual(
            selection["selection_version"],
            "historical-58efe9d-full60-domain7-huge-intersection-v1",
        )
        self.assertEqual(
            selection["evidence_scope"],
            "historical_58efe9d_developmental_gate_not_current_p0",
        )
        self.assertNotIn("exact P0 full-60", selection["derivation"])
        self.assertEqual(manifest["gate"]["minimum_qualifying_sources"], 8)
        self.assertEqual(manifest["gate"]["required_d_reduction_from_a_ppm"], 250000)
        self.assertEqual(manifest["gate"]["required_increment_over_b_ppm"], 50000)
        self.assertEqual(manifest["gate"]["required_increment_over_c_ppm"], 50000)
        self.assertEqual(len(manifest["sources"]), 10)
        for source in manifest["sources"]:
            self.assertEqual(
                source["selection_tags"],
                ["DOMAIN7_HUGE", "HISTORICAL_58EFE9D_FULL60_PERSISTENT"],
            )
        confirmation = manifest["current_confirmation"]
        self.assertEqual(confirmation["status"], "not_materialized")
        self.assertEqual(confirmation["expected_source_count"], 12)
        self.assertTrue(confirmation["required_before_implementation_or_promotion"])
        self.assertFalse(confirmation["implementation_or_promotion_eligible"])
        self.assertEqual(
            confirmation["p0_revision"],
            "30828a4f0c1e7e478a9c6f406ccb245eeefc4961",
        )


if __name__ == "__main__":
    unittest.main()
