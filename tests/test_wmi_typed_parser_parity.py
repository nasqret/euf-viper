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
DRIVER = ROOT / "scripts" / "bench" / "typed_parser_parity.py"


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
        self.assertNotIn('"$BINARY" parse-check -', text)
        self.assertNotIn("validate-payload", text)
        self.assertIn("typed_parser_parity.py prepare", text)
        self.assertIn("--preflight-source", text)
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

    def test_all_stages_fail_closed_on_pinned_python_identity_drift(self) -> None:
        for script in (PREPARE, ARRAY, AUDIT):
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                self.assertIn('${EUF_VIPER_PYTHON:?set EUF_VIPER_PYTHON}', text)
                self.assertIn('readlink -f -- "$CONFIGURED_PYTHON"', text)
                self.assertIn('[ "$PYTHON" != "$CONFIGURED_PYTHON" ]', text)
                self.assertIn("must be its canonical realpath", text)
                self.assertIn("cannot canonicalize pinned python", text)
                self.assertIn("EUF_VIPER_PYTHON_SHA256", text)
                self.assertIn("EUF_VIPER_PYTHON_VERSION", text)
                self.assertIn('sha256sum "$PYTHON"', text)
                self.assertIn('"$PYTHON" --version', text)
                self.assertIn("python hash mismatch", text)
                self.assertIn("python version mismatch", text)
                self.assertIn('"$PYTHON" scripts/bench/typed_parser_parity.py', text)
                self.assertNotIn(
                    "python3 scripts/bench/typed_parser_parity.py", text
                )

        prepare_text = PREPARE.read_text(encoding="utf-8")
        self.assertIn("python-version.txt", prepare_text)
        self.assertIn("python-sha256.txt", prepare_text)

    def test_array_is_parse_only_and_writes_one_owned_shard(self) -> None:
        text = ARRAY.read_text(encoding="utf-8")
        self.assertIn("SLURM_ARRAY_TASK_ID", text)
        self.assertIn("typed_parser_parity.py run-shard", text)
        self.assertIn("EUF_VIPER_TYPED_PARSER_ROOT", text)
        self.assertNotIn(" solve ", text)
        self.assertNotIn("EUF_VIPER_PARSER_MODE", text)

    def test_campaign_driver_pipes_the_captured_source_bytes_to_stdin(self) -> None:
        text = DRIVER.read_text(encoding="utf-8")
        self.assertIn('[executable.execution_path, "parse-check", "-"]', text)
        self.assertIn("input=source", text)
        self.assertIn('f"/proc/self/fd/{descriptor}"', text)
        self.assertIn("pass_fds=(executable.descriptor,)", text)
        self.assertIn("os.O_NOFOLLOW", text)
        self.assertIn("sha256_descriptor(descriptor)", text)
        self.assertNotIn('[str(binary), "parse-check", str(source)]', text)
        self.assertNotIn("source_hash = sha256_file(source)", text)

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
        self.assertIn("EUF_VIPER_PYTHON_REMOTE_PATH", text)
        self.assertIn("REQUESTED_REMOTE_PYTHON", text)
        self.assertIn("readlink -f -- '$REQUESTED_REMOTE_PYTHON'", text)
        self.assertIn("REMOTE_PYTHON_SHA256", text)
        self.assertIn("REMOTE_PYTHON_VERSION", text)
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
        self.assertIn('"schema": "euf-viper.typed-parser-parity-submission.v3"', text)
        self.assertIn('"byte_binding": "single-open-buffer.v1"', text)
        self.assertIn('"executable_binding": "inherited-descriptor.v1"', text)
        self.assertEqual(text.count("EUF_VIPER_PYTHON='$REMOTE_PYTHON'"), 3)
        self.assertEqual(
            text.count("EUF_VIPER_PYTHON_SHA256='$REMOTE_PYTHON_SHA256'"), 3
        )
        self.assertEqual(
            text.count("EUF_VIPER_PYTHON_VERSION='$REMOTE_PYTHON_VERSION'"), 3
        )
        self.assertIn('"python": {', text)
        self.assertIn('"path": "$REMOTE_PYTHON"', text)
        self.assertIn('"sha256": "$REMOTE_PYTHON_SHA256"', text)
        self.assertIn('"version": "$REMOTE_PYTHON_VERSION"', text)
        self.assertIn("remote python target drifted before receipt", text)
        self.assertIn("remote python version drifted before receipt", text)
        self.assertIn(
            'ssh "$REMOTE_HOST" "\'$REMOTE_PYTHON\' -" > "$RECEIPT_TEMPORARY"',
            text,
        )
        self.assertNotIn("python3 - ", text)
        self.assertIn("allow_nan=False", text)


if __name__ == "__main__":
    unittest.main()
