from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_t9_projection_census.sbatch"


class T9ProjectionWmiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="ascii")

    def test_job_is_single_core_bounded_and_uses_rust_193(self) -> None:
        self.assertIn("#SBATCH --cpus-per-task=1", self.text)
        self.assertIn("#SBATCH --mem=8G", self.text)
        self.assertIn("#SBATCH --time=04:00:00", self.text)
        self.assertIn("export RUSTUP_TOOLCHAIN=1.93.0", self.text)
        self.assertIn("build --locked --all-features --release", self.text)

    def test_exact_revision_manifest_and_tool_bytes_are_mandatory(self) -> None:
        self.assertIn("EUF_VIPER_EXPECTED_REVISION:?", self.text)
        self.assertIn("EUF_VIPER_T9_EXPECTED_MANIFEST_SHA256:?", self.text)
        self.assertIn("EUF_VIPER_CARGO_SHA256:?", self.text)
        self.assertIn("EUF_VIPER_RUSTC_SHA256:?", self.text)
        self.assertIn("EUF_VIPER_PYTHON_SHA256:?", self.text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", self.text)
        self.assertIn("manifest SHA-256 mismatch", self.text)
        self.assertIn("rustc version mismatch", self.text)

    def test_census_is_no_sat_and_requires_independent_audit(self) -> None:
        self.assertIn("run_t9_projection_census.py", self.text)
        self.assertIn("audit_t9_projection_census.py", self.text)
        self.assertIn("--expected-sources \"$EXPECTED_SOURCES\"", self.text)
        self.assertIn("audit-receipt.json", self.text)
        self.assertNotIn("compare_solvers.py", self.text)
        self.assertNotIn("EUF_VIPER_T9_ACKERMANN=", self.text)

    def test_metadata_binds_code_binary_and_all_evidence(self) -> None:
        for key in (
            '"binary"',
            '"cargo_lock"',
            '"runner"',
            '"auditor"',
            '"records"',
            '"summary"',
            '"audit_receipt"',
        ):
            self.assertIn(key, self.text)
        self.assertIn('"euf-viper.t9-projection-wmi-run.v1"', self.text)
        self.assertIn("os.link(temporary, metadata_path)", self.text)


if __name__ == "__main__":
    unittest.main()
