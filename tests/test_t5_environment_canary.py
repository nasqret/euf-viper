from __future__ import annotations

import ast
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.bench import t5_environment_canary as canary


ROOT = Path(__file__).resolve().parents[1]
SBATCH = ROOT / "scripts/wmi/euf_viper_t5_environment_canary.sbatch"
SUBMIT = ROOT / "scripts/wmi/submit_t5_environment_canary.sh"
VALIDATE = ROOT / "scripts/wmi/validate_t5_environment_canary.sh"


class EnvironmentCanaryStaticTests(unittest.TestCase):
    def test_canary_is_tiny_shard_free_and_environment_only(self) -> None:
        sbatch = SBATCH.read_text(encoding="utf-8")
        submit = SUBMIT.read_text(encoding="utf-8")
        validate = VALIDATE.read_text(encoding="utf-8")
        emitter = (
            ROOT / "scripts/bench/t5_environment_canary.py"
        ).read_text(encoding="utf-8")
        self.assertIn("#SBATCH --time=00:02:00", sbatch)
        self.assertIn("#SBATCH --mem=256M", sbatch)
        self.assertIn("#SBATCH --ntasks=1", sbatch)
        self.assertIn("#SBATCH --cpus-per-task=1", sbatch)
        self.assertNotIn("#SBATCH --array", sbatch)
        self.assertIn("mode=dry-run", submit)
        self.assertIn("sbatch --parsable", submit)
        self.assertIn("sacct-root-allocation", emitter)
        self.assertIn("SACCT_FORMAT", emitter)
        self.assertIn("sbatch_parsable", emitter)
        prohibited = (
            "qf_uf_manifest",
            "census_component_quotient_ram",
            "finalize_component_quotient_ram_metadata",
            "independent_component_quotient_verifier",
            "--array",
        )
        for token in prohibited:
            self.assertNotIn(token, emitter)
            self.assertNotIn(token, submit)
            self.assertNotIn(token, validate)
            self.assertNotIn(token, sbatch)
        tree = ast.parse(emitter)
        project_imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module is not None
            and node.module.startswith("scripts.")
        }
        self.assertEqual(project_imports, {"scripts.bench"})

    def test_canary_shell_files_are_valid_without_execution(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(SBATCH), str(SUBMIT), str(VALIDATE)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


@unittest.skipUnless(sys.platform.startswith("linux"), "real Linux canary required")
class LinuxEnvironmentCanaryTests(unittest.TestCase):
    def test_emit_and_validate_real_procfs_o_tmpfile_artifacts(self) -> None:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        executable_identity = canary._regular_file_identity(
            Path(sys.executable).resolve(strict=True)
        )

        def command_identity(name: str) -> dict[str, object]:
            return {
                **executable_identity,
                "available": True,
                "version": f"{name} test identity",
            }

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            environment = {
                "SLURM_JOB_ID": "987650001",
                "SLURM_CLUSTER_NAME": "linux-canary-test",
                "SLURM_JOB_NAME": "euf-t5-env-canary",
                "SLURM_JOB_USER": "runner",
                "SLURM_SUBMIT_DIR": str(ROOT),
            }
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(
                    canary, "_command_identity", side_effect=command_identity
                ),
            ):
                value, emission = canary.emit_canary(
                    repository_root=ROOT,
                    output_directory=output,
                    expected_revision=revision,
                )
            canary_path = output / emission["canary"]["name"]
            scheduler = canary.RootSchedulerRow(
                987650001,
                "linux-canary-test:987650001",
                "linux-canary-test",
                "2026-07-15T12:00:00",
                "euf-t5-env-canary",
                "runner",
                str(ROOT),
                "COMPLETED",
                "0:0",
            )
            receipt = canary.validate_canary_file(
                canary_path=canary_path,
                sbatch_parsable="987650001;linux-canary-test",
                scheduler_query=lambda job_id, cluster: scheduler,
            )
            self.assertEqual(value["procfs_fd"]["procfs"]["type"], 0x9FA0)
            self.assertEqual(value["o_tmpfile_probe"]["links"], 1)
            self.assertEqual(value["o_tmpfile_probe"]["mode"], "0444")
            self.assertEqual(stat.S_IMODE(canary_path.stat().st_mode), 0o444)
            self.assertEqual(receipt["scheduler"]["source"], "sacct-root-allocation")
            self.assertEqual(
                receipt["submission"]["sbatch_parsable"],
                "987650001;linux-canary-test",
            )


if __name__ == "__main__":
    unittest.main()
