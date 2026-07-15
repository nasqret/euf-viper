from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.bench import component_quotient_contract as contract


ROOT = Path(__file__).resolve().parents[1]


class T5LinuxEndToEndTests(unittest.TestCase):
    def test_prepare_analyze_finalize_consume_with_synthetic_scheduler_evidence(self) -> None:
        corpus_text = os.environ.get("EUF_VIPER_T5_E2E_CORPUS")
        if not corpus_text:
            self.skipTest(
                "set EUF_VIPER_T5_E2E_CORPUS to the extracted smtlib-2025 corpus"
            )
        if not sys.platform.startswith("linux"):
            self.fail("a supplied T5 semantic corpus requires real Linux")
        if (
            os.environ.get("EUF_VIPER_T5_E2E_SCHEDULER_EVIDENCE")
            != "synthetic_injected_root_row"
        ):
            self.fail(
                "the provisioned integration must explicitly label its synthetic "
                "scheduler evidence"
            )
        corpus = Path(corpus_text)
        manifest = corpus / "qf_uf_manifest.jsonl"
        if not manifest.is_file():
            self.fail(f"external T5 manifest is absent: {manifest}")
        contract.require_campaign_manifest_bytes(manifest.read_bytes())
        artifact_text = os.environ.get("EUF_VIPER_T5_E2E_ARTIFACT_DIR")
        artifact_directory = Path(artifact_text) if artifact_text else None
        if artifact_directory is not None and (
            not artifact_directory.is_absolute() or not artifact_directory.is_dir()
        ):
            self.fail("semantic artifact directory must already exist and be absolute")
        for command in ("git",):
            resolved = shutil.which(command, path="/usr/bin:/bin")
            if resolved is None:
                self.fail(f"provisioned Linux integration requires /usr/bin/{command}")

        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "t5-e2e-clone"
            subprocess.run(
                ["git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(clone)],
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/nonexistent",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_SYSTEM": "/dev/null",
                },
                check=True,
            )
            (clone / "benchmarks/smtlib-2025").symlink_to(
                corpus.resolve(strict=True), target_is_directory=True
            )
            python = Path(sys.executable).resolve(strict=True)
            driver_environment = {
                "PATH": f"{python.parent}:/usr/bin:/bin",
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "EUF_VIPER_T5_E2E_SCHEDULER_EVIDENCE": (
                    "synthetic_injected_root_row"
                ),
            }
            if artifact_directory is not None:
                driver_environment["EUF_VIPER_T5_E2E_ARTIFACT_DIR"] = str(
                    artifact_directory
                )
            completed = subprocess.run(
                [str(python), "-B", "tests/t5_linux_e2e_driver.py"],
                cwd=clone,
                env=driver_environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=6 * 60 * 60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn('"manifest_rows": 7503', completed.stdout)
            self.assertIn(contract.MANIFEST_SHA256, completed.stdout)
            if artifact_directory is not None:
                self.assertTrue(
                    (artifact_directory / "semantic-consumer-receipt.json").is_file()
                )
                self.assertTrue(
                    (artifact_directory / "semantic-pipeline-result.json").is_file()
                )


if __name__ == "__main__":
    unittest.main()
