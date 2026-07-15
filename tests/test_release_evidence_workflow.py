from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "campaign-contract.yml"
SMOKE = ROOT / "scripts" / "ci" / "release_evidence_smoke.py"
CLI_CONTRACT = ROOT / "scripts" / "ci" / "check_ordinary_cli_contract.py"
CLI_BASELINE = ROOT / "scripts" / "ci" / "build_cli_baseline.py"
CLI_CASES = ROOT / "scripts" / "ci" / "ordinary_cli_cases.py"
CLI_ORACLE = ROOT / "scripts" / "ci" / "record_cli_oracle.py"
CLI_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "check_ordinary_cli_contract_test", CLI_CONTRACT
)
assert CLI_CONTRACT_SPEC is not None and CLI_CONTRACT_SPEC.loader is not None
CLI_CONTRACT_MODULE = importlib.util.module_from_spec(CLI_CONTRACT_SPEC)
CLI_CONTRACT_SPEC.loader.exec_module(CLI_CONTRACT_MODULE)
CLI_BASELINE_SPEC = importlib.util.spec_from_file_location(
    "build_cli_baseline_test", CLI_BASELINE
)
assert CLI_BASELINE_SPEC is not None and CLI_BASELINE_SPEC.loader is not None
CLI_BASELINE_MODULE = importlib.util.module_from_spec(CLI_BASELINE_SPEC)
CLI_BASELINE_SPEC.loader.exec_module(CLI_BASELINE_MODULE)


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
        case_text = CLI_CASES.read_text(encoding="ascii")
        oracle_text = CLI_ORACLE.read_text(encoding="ascii")
        self.assertIn("f8d9205", text)
        self.assertIn("--baseline-binary", text)
        self.assertIn("--baseline-receipt", text)
        self.assertIn("--oracle", text)
        self.assertIn("cli-baseline-build.v2", text)
        self.assertIn("f8d9205e8a18e3496d236fb9b94ed181add93e80", text)
        self.assertIn("effective_compiler", text)
        self.assertIn("completed.stdout", text)
        self.assertIn("completed.stderr", text)
        self.assertNotIn("BASE_USAGE", text)
        self.assertNotIn("CERTIFICATE_USAGE", text)
        self.assertIn("ordinary-cli-oracle.v1", text)
        self.assertIn("open_verified_sealed_memfd", oracle_text)
        self.assertNotIn("execute(baseline", text)
        for case in (
            "no arguments",
            "unknown top-level command",
            "legacy unknown and extra solve arguments",
            "parse-check stdin",
            "missing file",
        ):
            self.assertIn(case, case_text)

    def test_hosted_dependencies_are_pinned_and_non_attesting(self) -> None:
        text = WORKFLOW.read_text(encoding="ascii")
        self.assertIn(
            "actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8",
            text,
        )
        self.assertIn(
            "actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c",
            text,
        )
        self.assertIn('python-version: "3.12.11"', text)
        self.assertIn("diagnostic", text)
        self.assertIn("not production attestation", text)
        self.assertNotIn("ubuntu-latest", text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', text)

    def test_cli_baseline_forces_effective_compiler_and_sanitizes_ambient_controls(self) -> None:
        text = CLI_BASELINE.read_text(encoding="ascii")
        self.assertIn(
            'REVISION = "f8d9205e8a18e3496d236fb9b94ed181add93e80"',
            text,
        )
        self.assertIn('"RUSTC": str(rustc_path)', text)
        self.assertIn("effective_rustc_invocations", text)
        self.assertIn("verbose_invocations", text)
        self.assertIn("EXPECTED_TREE", text)
        self.assertIn("EXPECTED_CARGO_LOCK_SHA256", text)
        self.assertIn("reject_ambient_cargo_configs", text)
        self.assertNotIn("**os.environ", text)
        for control in (
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
        ):
            self.assertIn(control, text)

    def test_cli_baseline_rejects_cargo_config_in_a_checkout_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "output" / "source"
            checkout.mkdir(parents=True)
            CLI_BASELINE_MODULE.reject_ambient_cargo_configs(checkout)
            cargo_directory = root / "output" / ".cargo"
            cargo_directory.mkdir()
            (cargo_directory / "config.toml").write_text(
                "[build]\nrustc-wrapper = '/attacker'\n", encoding="ascii"
            )
            with self.assertRaisesRegex(SystemExit, "config search path"):
                CLI_BASELINE_MODULE.reject_ambient_cargo_configs(checkout)

    def test_cli_checker_reparses_the_bound_effective_compiler_log(self) -> None:
        rustc = Path("/bound/toolchain/bin/rustc")
        build_log = b"Running `/bound/toolchain/bin/rustc --crate-name baseline`\n"
        self.assertEqual(
            CLI_CONTRACT_MODULE.effective_rustc_invocations(build_log, rustc),
            1,
        )
        with self.assertRaisesRegex(SystemExit, "other than supplied RUSTC"):
            CLI_CONTRACT_MODULE.effective_rustc_invocations(
                b"Running `/attacker/bin/rustc --crate-name baseline`\n",
                rustc,
            )


if __name__ == "__main__":
    unittest.main()
