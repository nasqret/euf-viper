from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
COMMON = WMI / "t1_timing_common.sh"
PREPARE = WMI / "euf_viper_t1_timing_prepare.sbatch"
ARRAY = WMI / "euf_viper_t1_timing_array.sbatch"
AUDIT = WMI / "euf_viper_t1_timing_audit.sbatch"
SUBMIT = WMI / "submit_t1_timing.sh"
SCRIPTS = (COMMON, PREPARE, ARRAY, AUDIT, SUBMIT)


class WmiT1TimingTests(unittest.TestCase):
    def test_shell_scripts_are_executable_and_parse(self) -> None:
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                self.assertTrue(script.stat().st_mode & 0o111)
                subprocess.run(["bash", "-n", script], check=True)

    def test_every_job_revalidates_revision_tools_and_published_ref(self) -> None:
        for script in (PREPARE, ARRAY, AUDIT):
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                self.assertIn("t1_verify_checkout", text)
                self.assertIn("t1_verify_pinned_tool Python", text)
                self.assertIn("t1_verify_pinned_tool Cargo", text)
                self.assertIn("t1_verify_pinned_tool Rustc", text)
                self.assertIn("EUF_VIPER_T1_PUBLISHED_REF", text)
                self.assertIn("set -euo pipefail", text)

    def test_checkout_guard_rejects_hidden_state_and_binds_runtime_blobs(self) -> None:
        text = COMMON.read_text(encoding="utf-8")
        for required in (
            "git ls-files -v",
            "tracked index has nonnormal flags",
            "git diff --quiet",
            "git diff --cached --quiet",
            "git write-tree",
            "git hash-object --no-filters",
            "published ref",
            "src/main.rs",
            "src/smt2_stream.rs",
            "campaigns/t1-typed-parser-timing-v1.json",
            "scripts/bench/typed_parser_timing.py",
        ):
            self.assertIn(required, text)

    def test_prepare_builds_one_release_binary_and_uses_fixed_contract(self) -> None:
        text = PREPARE.read_text(encoding="utf-8")
        self.assertEqual(text.count(" build --release --locked"), 1)
        self.assertNotIn("--all-features", text)
        self.assertIn("campaigns/t1-typed-parser-timing-v1.json", text)
        self.assertIn("typed_parser_timing.py prepare", text)

    def test_submit_chain_is_prepare_then_array_then_audit(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("--dependency=afterok:$PREPARE_JOB", text)
        self.assertIn("--dependency=afterok:$ARRAY_JOB", text)
        self.assertIn("--array=0-$LAST_SHARD%$MAX_PARALLEL", text)
        self.assertIn("t1_verify_checkout \"$REVISION\" \"$PUBLISHED_REF\"", text)
        self.assertIn("test ! -e '$CAMPAIGN_ROOT'", text)
        self.assertIn('ln "$TEMPORARY" "$RECEIPT"', text)
        self.assertNotIn('mv "$TEMPORARY" "$RECEIPT"', text)
        self.assertNotIn("git push", text)


if __name__ == "__main__":
    unittest.main()
