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
            "cargo test\n",
            "cargo test --no-default-features\n",
            "cargo test --no-default-features --features certificates\n",
            "cargo test --no-default-features --features production-evidence\n",
            "cargo test --no-default-features --features certificates,production-evidence\n",
            "cargo test --all-features\n",
            "cargo build --release --features certificates,production-evidence",
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

    def test_cli_contract_locks_baseline_bytes_not_weak_statuses(self) -> None:
        text = CLI_CONTRACT.read_text(encoding="ascii")
        self.assertIn("f8d9205", text)
        self.assertIn("BASE_USAGE", text)
        self.assertIn("CERTIFICATE_USAGE", text)
        self.assertIn("completed.stdout", text)
        self.assertIn("completed.stderr", text)
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
