from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "campaign-contract.yml"
SMOKE = ROOT / "scripts" / "ci" / "release_evidence_smoke.py"
CLI_CONTRACT = ROOT / "scripts" / "ci" / "check_ordinary_cli_contract.py"


class ReleaseEvidenceWorkflowTests(unittest.TestCase):
    def test_hosted_rust_matrix_is_complete_and_sequential(self) -> None:
        text = WORKFLOW.read_text(encoding="ascii")
        commands = [
            "cargo fmt --all -- --check",
            "cargo test --locked\n",
            "cargo test --locked --no-default-features\n",
            "cargo test --locked --no-default-features --features certificates\n",
            "cargo test --locked --no-default-features --features production-evidence\n",
            "cargo test --locked --no-default-features --features certificates,production-evidence\n",
            "cargo test --locked --all-features\n",
            "sealed_linux_build.py build",
            "python3 -B scripts/ci/build_cli_baseline.py",
        ]
        positions = []
        for command in commands:
            self.assertEqual(text.count(command), 1, command)
            positions.append(text.index(command))
        self.assertEqual(positions, sorted(positions))
        self.assertIn("euf-viper-build-features", text)
        self.assertIn("release_evidence_smoke.py", text)
        self.assertIn("check_ordinary_cli_contract.py", text)

    def test_release_smoke_uses_real_artifacts_and_full_locked_path(self) -> None:
        text = SMOKE.read_text(encoding="ascii")
        for required in (
            "record_solver_config.py",
            "check_production_evidence.py",
            "freeze_campaign.py",
            "run_locked_campaign.py",
            "analyze_campaign.py",
            "--smoke-instance",
            "--evidence-out",
            "accepted_decisive_statuses",
            "subprocess.Popen",
        ):
            self.assertIn(required, text)
        self.assertNotIn("#!/bin/sh", text)
        self.assertNotIn("fake solver", text.lower())
        self.assertIn("allowed={1}", text)
        self.assertIn("evidence status mismatch: expected 'sat', got 'unsupported'", text)

    def test_cli_contract_uses_an_independently_built_baseline(self) -> None:
        text = CLI_CONTRACT.read_text(encoding="ascii")
        self.assertIn("f8d9205", text)
        self.assertIn("--baseline-binary", text)
        self.assertIn("--baseline-receipt", text)
        self.assertIn("cli-baseline-build.v1", text)
        self.assertIn("completed.stdout", text)
        self.assertIn("completed.stderr", text)
        self.assertNotIn("BASE_USAGE", text)
        self.assertNotIn("CERTIFICATE_USAGE", text)
        for case in (
            "no arguments",
            "unknown top-level command",
            "legacy unknown and extra solve arguments",
            "parse-check stdin",
            "missing file",
        ):
            self.assertIn(case, text)


if __name__ == "__main__":
    unittest.main()
