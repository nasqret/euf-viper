from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SBATCH = ROOT / "scripts" / "wmi" / "euf_viper_component_quotient_census.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_component_quotient_census.sh"
VERIFIER = (
    ROOT / "scripts" / "bench" / "verify_component_quotient_ram_bundle.py"
)


class ComponentQuotientWmiTests(unittest.TestCase):
    def test_shell_scripts_are_syntactically_valid(self) -> None:
        for path in (SBATCH, SUBMIT):
            completed = subprocess.run(
                ["bash", "-n", str(path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_job_is_revision_bound_source_only_and_exactly_7503(self) -> None:
        text = SBATCH.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_EXPECTED_REVISION", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn('if [ "$EXPECTED_SOURCES" != 7503 ]', text)
        self.assertIn("census_component_quotient_ram.py", text)
        self.assertIn("component-quotient-ram-census-v1.json", text)
        self.assertIn("scripts/cert/independent_qfuf.py", text)
        self.assertIn("scripts/bench/build_family_manifest.py", text)
        self.assertEqual(text.count("--require-validity"), 1)
        self.assertIn("verify_component_quotient_ram_bundle.py", text)
        self.assertIn('--receipt-out "$OUT/verification.json"', text)
        self.assertIn('"records": root / "records.jsonl"', text)
        self.assertIn('"targets": root / "targets.jsonl"', text)
        self.assertIn('"aggregate": root / "aggregate.json"', text)
        self.assertIn('"verification": verification_path', text)
        self.assertIn(
            '"implementation_allowed": verification["implementation_allowed"]', text
        )
        self.assertIn("component quotient strict bundle verification did not pass", text)
        self.assertIn(
            "7562fb7e9953604bd61a68689466e617013bb798bc2657d0c8522e488262af89",
            text,
        )
        self.assertIn(
            '"decoder_oracle_sha256": verification["decoder_oracle_sha256"]', text
        )
        self.assertNotIn("aggregate = json.loads", text)
        self.assertNotIn("gates = aggregate", text)
        for forbidden in ("cargo run", "target/release/euf-viper", " z3 ", "cvc5", "yices"):
            self.assertNotIn(forbidden, text)

    def test_independent_verifier_has_a_strict_receipt_contract(self) -> None:
        text = VERIFIER.read_text(encoding="utf-8")
        self.assertIn("verify_census_bundle", text)
        self.assertIn("--records", text)
        self.assertIn("--aggregate", text)
        self.assertIn("--targets", text)
        self.assertIn("--receipt-out", text)
        self.assertIn("--require-validity", text)
        self.assertIn("verified=true", text)

    def test_submitter_requires_clean_published_exact_revision(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_PUBLISHED_REF", text)
        self.assertIn(
            'PUBLISHED_REF="${EUF_VIPER_COMPONENT_QUOTIENT_PUBLISHED_REF:-origin/main}"',
            text,
        )
        self.assertIn('PUBLISHED_REVISION="$(git rev-parse "$PUBLISHED_REF")"', text)
        self.assertIn("HEAD $REVISION is not published", text)
        self.assertIn("fetch --quiet origin '$REVISION'", text)
        self.assertIn("euf_viper_component_quotient_census.sbatch", text)
        self.assertIn("component-quotient-census-submission-$JOB_ID.json", text)
        self.assertIn('if [ "$EXPECTED_SOURCES" != 7503 ]', text)


if __name__ == "__main__":
    unittest.main()
