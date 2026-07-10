from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "compare_viper_ab.py"
SPEC = importlib.util.spec_from_file_location("compare_viper_ab", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


class ArtifactMetadataTests(unittest.TestCase):
    def test_hashes_each_artifact_and_records_runtime_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "manifest.jsonl"
            baseline = root / "baseline"
            candidate = root / "candidate"
            manifest.write_bytes(b"manifest\n")
            baseline.write_bytes(b"same binary")
            candidate.write_bytes(b"same binary")
            environment = {
                "EUF_VIPER_GIT_REVISION": "58efe9d",
                "SLURM_JOB_ID": "123",
                "SLURM_ARRAY_JOB_ID": "120",
                "SLURM_ARRAY_TASK_ID": "3",
                "SLURM_JOB_NODELIST": "c3n1",
            }

            metadata = COMPARE.artifact_metadata(
                manifest,
                baseline,
                candidate,
                timeout_s=2.0,
                warmups=1,
                environment=environment,
                hostname="test-host",
            )

            self.assertEqual(
                metadata["manifest_sha256"],
                hashlib.sha256(b"manifest\n").hexdigest(),
            )
            expected_binary_hash = hashlib.sha256(b"same binary").hexdigest()
            self.assertEqual(metadata["baseline_sha256"], expected_binary_hash)
            self.assertEqual(metadata["candidate_sha256"], expected_binary_hash)
            self.assertEqual(metadata["timeout_s"], 2.0)
            self.assertEqual(metadata["warmups"], 1)
            self.assertEqual(metadata["runtime_host"], "test-host")
            self.assertEqual(metadata["git_revision"], "58efe9d")
            self.assertEqual(metadata["slurm_job_id"], "123")
            self.assertEqual(metadata["slurm_array_job_id"], "120")
            self.assertEqual(metadata["slurm_array_task_id"], "3")
            self.assertEqual(metadata["slurm_node_list"], "c3n1")


if __name__ == "__main__":
    unittest.main()
