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


@unittest.skipUnless(sys.platform.startswith("linux"), "real Linux required")
class T5LinuxEndToEndTests(unittest.TestCase):
    def test_prepare_analyze_finalize_consume_real_7503_manifest(self) -> None:
        corpus_text = os.environ.get("EUF_VIPER_T5_E2E_CORPUS")
        if not corpus_text:
            self.skipTest(
                "set EUF_VIPER_T5_E2E_CORPUS to the extracted smtlib-2025 corpus"
            )
        corpus = Path(corpus_text)
        manifest = corpus / "qf_uf_manifest.jsonl"
        if not manifest.is_file():
            self.fail(f"external T5 manifest is absent: {manifest}")
        contract.require_campaign_manifest_bytes(manifest.read_bytes())
        for command in ("git", "scontrol", "sacct"):
            resolved = shutil.which(command, path="/usr/bin:/bin")
            if resolved is None:
                self.fail(f"real Linux end-to-end requires /usr/bin/{command}")

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
            completed = subprocess.run(
                [str(python), "-B", "tests/t5_linux_e2e_driver.py"],
                cwd=clone,
                env={
                    "PATH": f"{python.parent}:/usr/bin:/bin",
                    "HOME": "/nonexistent",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                },
                check=False,
                capture_output=True,
                text=True,
                timeout=6 * 60 * 60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn('"manifest_rows": 7503', completed.stdout)
            self.assertIn(contract.MANIFEST_SHA256, completed.stdout)


if __name__ == "__main__":
    unittest.main()
