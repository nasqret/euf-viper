from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
PREPARE = WMI / "euf_viper_typed_parser_parity_prepare.sbatch"
ARRAY = WMI / "euf_viper_typed_parser_parity_array.sbatch"
AUDIT = WMI / "euf_viper_typed_parser_parity_audit.sbatch"
SUBMIT = WMI / "submit_typed_parser_parity.sh"


class TypedParserParityWmiTests(unittest.TestCase):
    def test_shell_scripts_are_syntactically_valid(self) -> None:
        for script in (PREPARE, ARRAY, AUDIT, SUBMIT):
            subprocess.run(["bash", "-n", str(script)], check=True)

    def test_prepare_binds_exact_revision_binary_manifest_and_preflight(self) -> None:
        text = PREPARE.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_EXPECTED_REVISION", text)
        self.assertIn("#SBATCH --cpus-per-task=1", text)
        self.assertIn("#SBATCH --mem=8G", text)
        self.assertIn('EUF_VIPER_CARGO:-$HOME/.cargo/bin/cargo', text)
        self.assertIn("EUF_VIPER_CARGO", text)
        self.assertIn("EUF_VIPER_CARGO_SHA256", text)
        self.assertIn("EUF_VIPER_CARGO_VERSION", text)
        self.assertIn('sha256sum "$CARGO"', text)
        self.assertIn("cargo hash mismatch", text)
        self.assertIn("cargo version mismatch", text)
        self.assertNotIn("command -v cargo", text)
        self.assertIn('"$CARGO" build --release --locked', text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("parse-check", text)
        self.assertIn('"fallback": False', text)
        self.assertIn("typed_parser_parity.py prepare", text)
        self.assertIn("EUF_VIPER_TYPED_PARSER_EXPECTED_SOURCES", text)
        self.assertNotIn("EUF_VIPER_PARSER_MODE", text)

    def test_all_stages_sanitize_ambient_parser_configuration(self) -> None:
        for script in (PREPARE, ARRAY, AUDIT):
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                self.assertIn("export EUF_VIPER_SCOPED_LET=auto", text)
                self.assertIn(
                    "export EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024", text
                )
                self.assertIn("unset EUF_VIPER_PROFILE", text)

    def test_array_is_parse_only_and_writes_one_owned_shard(self) -> None:
        text = ARRAY.read_text(encoding="utf-8")
        self.assertIn("SLURM_ARRAY_TASK_ID", text)
        self.assertIn("typed_parser_parity.py run-shard", text)
        self.assertIn("EUF_VIPER_TYPED_PARSER_ROOT", text)
        self.assertNotIn(" solve ", text)
        self.assertNotIn("EUF_VIPER_PARSER_MODE", text)

    def test_audit_preregisters_full_7503_source_gate(self) -> None:
        text = AUDIT.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_TYPED_PARSER_EXPECTED_SOURCES:-7503", text)
        self.assertIn("typed_parser_parity.py audit", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)

    def test_submitter_requires_published_branch_and_dependency_chain(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("origin/research-typed-stream-parity", text)
        self.assertIn("EUF_VIPER_CARGO_REMOTE_PATH", text)
        self.assertIn("REMOTE_CARGO_SHA256", text)
        self.assertIn("EUF_VIPER_TYPED_PARSER_PARTITION", text)
        self.assertIn("--partition='$PARTITION'", text)
        self.assertIn('PUBLISHED_REVISION="$(git rev-parse "$PUBLISHED_REF")"', text)
        self.assertIn("--dependency=afterok:$PREPARE_JOB", text)
        self.assertIn("--dependency=afterok:$ARRAY_JOB", text)
        self.assertIn("--array=0-$LAST_SHARD%$MAX_PARALLEL", text)
        self.assertIn("typed-parser-parity-submission-$PREPARE_JOB.json", text)
        self.assertIn('"expected_sources": int("$EXPECTED_SOURCES")', text)
        self.assertEqual(
            text.count(
                "--export=ALL,EUF_VIPER_SCOPED_LET=auto,"
                "EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024"
            ),
            3,
        )
        self.assertEqual(text.count("unset EUF_VIPER_PROFILE && sbatch"), 3)
        self.assertIn('"EUF_VIPER_PROFILE": None', text)


if __name__ == "__main__":
    unittest.main()
