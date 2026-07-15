from __future__ import annotations

import ast
import re
import tempfile
import unittest
from pathlib import Path

from scripts.bench import record_t5_ci_identity as identity


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/campaign-contract.yml"


class T5CiContractTests(unittest.TestCase):
    def test_identity_is_explicitly_non_evidence_and_records_image_python(self) -> None:
        value = identity.capture_identity(
            scope="ordinary_linux_publication_procfs_diagnostic",
            scheduler_evidence="not_queried",
            environment={
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "RUNNER_NAME": "hosted",
                "ImageOS": "ubuntu24",
                "ImageVersion": "20260701.1",
                "GITHUB_ACTIONS": "true",
            },
            require_hosted_image=True,
        )
        self.assertEqual(value["status"], "execution_identity_non_evidence")
        self.assertFalse(value["decisive"])
        self.assertFalse(value["authoritative"])
        self.assertFalse(value["scheduler_query_performed"])
        self.assertEqual(value["runner"]["image_os"], "ubuntu24")
        self.assertEqual(len(value["python"]["sha256"]), 64)

    def test_identity_write_is_no_replace_and_canonical(self) -> None:
        value = identity.capture_identity(
            scope="provisioned_7503_semantic_pipeline_integration",
            scheduler_evidence="synthetic_injected_root_row",
            environment={},
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "identity.json"
            identity.write_identity_no_replace(path, value)
            with self.assertRaises(FileExistsError):
                identity.write_identity_no_replace(path, value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o444)

    def test_mandatory_runner_cannot_silently_skip_or_query_scheduler(self) -> None:
        path = ROOT / "scripts/bench/run_t5_linux_diagnostic.py"
        text = path.read_text(encoding="utf-8")
        self.assertIn("if result.skipped:", text)
        self.assertIn("requires Linux", text)
        tree = ast.parse(text)
        names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("subprocess", names)
        self.assertNotIn("sacct", text)

    def test_workflow_pins_actions_and_splits_semantic_integration(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("ubuntu-latest", text)
        self.assertNotRegex(text, r"uses:\s+[^\s]+@v[0-9]")
        action_references = re.findall(r"^\s*- uses:\s+[^@\s]+@([^\s]+)", text, re.M)
        self.assertTrue(action_references)
        self.assertTrue(
            all(re.fullmatch(r"[0-9a-f]{40}", item) for item in action_references)
        )
        self.assertIn("t5-linux-publication-diagnostic", text)
        self.assertIn("t5-semantic-pipeline-integration", text)
        self.assertIn("synthetic_injected_root_row", text)
        self.assertIn("inputs.t5_corpus_path != ''", text)
        self.assertIn("--require-hosted-image", text)


if __name__ == "__main__":
    unittest.main()
