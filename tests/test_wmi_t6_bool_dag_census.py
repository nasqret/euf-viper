from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JOB = ROOT / "scripts" / "wmi" / "euf_viper_t6_bool_dag_census.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_t6_bool_dag_census.sh"
CONSUMER = ROOT / "src" / "t6_bool_dag_census.rs"
MANIFEST = ROOT / "campaigns" / "t6-theory-dag-p0-qg12-v1.json"
OLD_MANIFEST = ROOT / "campaigns" / "t6-theory-dag-hard10-v1.json"
MANIFEST_SHA256 = "33a9f0016570dc07dc4c9aed2f575633eb5a2ee10d21177c97a4e86b65507c78"
PATH_LIST_SHA256 = "1fd24c2c5fa8eafd07a39f28c96d828e0e0aa1072fd032db413c60f34270b6fa"
SOURCE_RECORDS_SHA256 = "f274424dcfdf3bd155fe12f7aedb99f8a80dfcb54c0625899dfba8377fff5b0b"


class T6BooleanDagWmiTests(unittest.TestCase):
    def test_shell_scripts_are_syntactically_valid(self) -> None:
        for script in (JOB, SUBMIT):
            subprocess.run(["bash", "-n", str(script)], check=True)

    def test_job_is_exact_revision_source_only_and_fail_closed(self) -> None:
        text = JOB.read_text(encoding="utf-8")
        self.assertIn("#SBATCH --ntasks=1", text)
        self.assertIn("#SBATCH --cpus-per-task=1", text)
        self.assertIn("EUF_VIPER_EXPECTED_REVISION", text)
        self.assertIn(MANIFEST_SHA256, text)
        self.assertNotIn("EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("t6-theory-dag-p0-qg12-v1.json", text)
        self.assertIn("t6_bool_dag_census::tests::p0_qg12_census_from_env", text)
        self.assertIn("--ignored --exact", text)
        self.assertIn("source_only_structural_projection", text)
        self.assertIn('"parser_source_cap_failures": 0', text)
        self.assertIn('gate.get("decision") not in {"pass", "reject"}', text)
        self.assertIn("current_p0_qg7_derived_10_of_12", text)
        self.assertIn(PATH_LIST_SHA256, text)
        self.assertIn(SOURCE_RECORDS_SHA256, text)
        self.assertIn('report.get("population_status") != "accepted"', text)
        self.assertIn('report.get("projection_status") != "completed"', text)
        self.assertIn('"implementation_or_promotion_eligible": False', text)
        self.assertIn("object_pairs_hook=reject_duplicate_keys", text)
        self.assertIn("parse_constant=reject_nonfinite", text)
        self.assertNotIn("t6-theory-dag-hard10-v1.json", text)
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
        self.assertIn('ACTUAL_CARGO_VERSION="$("$CARGO" +1.96.0 --version)"', text)
        self.assertIn("cargo resolved-path mismatch", text)
        self.assertIn("cargo hash mismatch", text)
        self.assertIn("cargo version mismatch", text)
        self.assertIn('"$CARGO" +1.96.0 test --release --locked --all-features', text)
        self.assertIn("cargo-toolchain.txt", text)
        self.assertNotIn("command -v cargo", text)
        self.assertIsNone(re.search(r"(?m)^\s*cargo\s", text))

    def test_submitter_requires_the_published_isolated_branch(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("research-t6-theory-dag", text)
        self.assertIn('git rev-parse "origin/$REMOTE_BRANCH"', text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("EUF_VIPER_T6_REMOTE_CORPUS_ROOT", text)
        self.assertIn(MANIFEST_SHA256, text)
        self.assertNotIn("EUF_VIPER_T6_EXPECTED_MANIFEST_SHA256", text)
        self.assertIn("t6-theory-dag-p0-qg12-v1.json", text)
        self.assertIn("EUF_VIPER_CARGO_REMOTE_PATH", text)
        self.assertIn("REMOTE_CARGO_RESOLVED", text)
        self.assertIn("REMOTE_CARGO_SHA256", text)
        self.assertIn("REMOTE_CARGO_VERSION", text)
        self.assertIn("\"'$REMOTE_CARGO' +1.96.0 --version\"", text)
        self.assertIn("EUF_VIPER_CARGO_RESOLVED='$REMOTE_CARGO_RESOLVED'", text)
        self.assertIn("t6-bool-dag-census-submission-$JOB_ID.json", text)
        self.assertIn('"campaign_root": campaign_root', text)
        self.assertIn('"implementation_or_promotion_eligible": False', text)
        self.assertIn('"population_status": "accepted"', text)
        self.assertIn('"projection_status": "not_executed"', text)
        self.assertIn('"required_qualifying_sources": 10', text)
        self.assertIn('"expected_sources": 12', text)
        self.assertNotIn("t6-theory-dag-hard10-v1.json", text)

    def test_manifest_is_exact_accepted_population_with_unexecuted_projection(self) -> None:
        raw = MANIFEST.read_bytes()
        import hashlib

        self.assertEqual(hashlib.sha256(raw).hexdigest(), MANIFEST_SHA256)
        manifest = json.loads(MANIFEST.read_text(encoding="ascii"))
        selection = manifest["selection"]
        self.assertEqual(
            selection["audit"]["revision"],
            "30828a4f0c1e7e478a9c6f406ccb245eeefc4961",
        )
        self.assertEqual(
            selection["selection_version"],
            "p0-30828a4-full60-qg7-shared-deficit-v1",
        )
        self.assertEqual(
            selection["evidence_scope"],
            "current_p0_full60_qg7_shared_z3_yices_deficit",
        )
        self.assertEqual(manifest["schema"], "euf-viper.t6-theory-dag-manifest.v2")
        self.assertEqual(manifest["population_status"], "accepted")
        self.assertEqual(manifest["projection_status"], "not_executed")
        self.assertEqual(manifest["gate"]["population_sources"], 12)
        self.assertEqual(manifest["gate"]["minimum_qualifying_sources"], 10)
        self.assertEqual(manifest["gate"]["threshold_derivation"], "ceil(8 * 12 / 10)")
        self.assertEqual(manifest["gate"]["required_d_reduction_from_a_ppm"], 250000)
        self.assertEqual(manifest["gate"]["required_increment_over_b_ppm"], 50000)
        self.assertEqual(manifest["gate"]["required_increment_over_c_ppm"], 50000)
        self.assertEqual(len(manifest["sources"]), 12)
        for source in manifest["sources"]:
            self.assertEqual(
                source["selection_tags"],
                [
                    "DOMAIN7_HUGE",
                    "P0_30828A4_FULL60_EUF_TIMEOUT",
                    "P0_30828A4_FULL60_Z3_YICES_SOLVED",
                ],
            )
        self.assertFalse(manifest["implementation_or_promotion_eligible"])

    def test_consumer_submission_and_job_share_every_frozen_binding(self) -> None:
        consumer = CONSUMER.read_text(encoding="utf-8")
        job = JOB.read_text(encoding="utf-8")
        submit = SUBMIT.read_text(encoding="utf-8")
        for digest in (MANIFEST_SHA256, PATH_LIST_SHA256, SOURCE_RECORDS_SHA256):
            self.assertIn(digest, consumer)
        self.assertIn(MANIFEST_SHA256, job)
        self.assertIn(MANIFEST_SHA256, submit)
        self.assertIn('const EXPECTED_SOURCES: usize = 12;', consumer)
        self.assertIn('const REQUIRED_QUALIFYING_SOURCES: usize = 10;', consumer)
        self.assertIn("duplicate JSON key", consumer)
        self.assertIn("non-finite JSON number", consumer)
        self.assertIn('include_bytes!("../campaigns/t6-theory-dag-hard10-v1.json")', consumer)
        self.assertTrue(OLD_MANIFEST.is_file())


if __name__ == "__main__":
    unittest.main()
