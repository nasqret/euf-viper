from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_t10_projection.sbatch"


class T10ProjectionWmiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="ascii")

    def test_job_is_single_cpu_bounded_and_builds_with_one_job(self) -> None:
        self.assertIn("#SBATCH --ntasks=1", self.text)
        self.assertIn("#SBATCH --cpus-per-task=1", self.text)
        self.assertIn("#SBATCH --mem=8G", self.text)
        self.assertIn("#SBATCH --time=04:00:00", self.text)
        self.assertIn('SLURM_CPUS_PER_TASK must be exactly 1', self.text)
        self.assertIn("sched_getaffinity", self.text)
        self.assertIn("expected one logical CPU", self.text)
        self.assertIn("export CARGO_BUILD_JOBS=1", self.text)
        self.assertIn("build --locked --all-features --release --jobs 1", self.text)

    def test_checkout_build_and_run_state_are_confined_to_work(self) -> None:
        self.assertIn("EUF_VIPER_T10_REPO_ROOT:?", self.text)
        self.assertIn("EUF_VIPER_T10_RUN_BASE:?", self.text)
        self.assertIn("/work/*:/work/*:/work/*", self.text)
        self.assertIn("must resolve under /work", self.text)
        self.assertIn('RUN_ROOT="$RUN_BASE/t10-projection-census-${SLURM_JOB_ID}"', self.text)
        self.assertIn('export CARGO_TARGET_DIR="$RUN_ROOT/target"', self.text)
        self.assertIn('cd "$REPO_ROOT"', self.text)
        self.assertNotIn('RUN_ROOT="$PWD/results/', self.text)

    def test_exact_revision_tree_design_and_tool_bytes_are_required(self) -> None:
        for token in (
            "EUF_VIPER_EXPECTED_REVISION:?",
            "EUF_VIPER_EXPECTED_TREE:?",
            "EUF_VIPER_CARGO_SHA256:?",
            "EUF_VIPER_RUSTC_SHA256:?",
            "EUF_VIPER_PYTHON_SHA256:?",
            'ACTUAL_REVISION="$(git rev-parse HEAD^{commit})"',
            'ACTUAL_TREE="$(git rev-parse HEAD^{tree})"',
            "repository state is dirty",
            "cargo version mismatch",
            "rustc version mismatch",
            "Python version mismatch",
        ):
            self.assertIn(token, self.text)
        self.assertIn("05de7841ac005e2a251d71e1a2394f8980cbdd17", self.text)
        self.assertIn("4bde59e6aca9f89a8dae305e129e77febbefc1ca", self.text)
        self.assertIn("8d42a123a5a08b880701e6be0fe9e037da98d49d569fadcba567c3c37f033d8c", self.text)
        self.assertIn('git cat-file blob "$DESIGN_BLOB"', self.text)

    def test_manifest_population_target_and_binary_are_frozen(self) -> None:
        self.assertIn("EXPECTED_SOURCES=7503", self.text)
        self.assertIn("EXPECTED_QG_SOURCES=6396", self.text)
        self.assertIn("32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4", self.text)
        self.assertIn("6b3c316cd90d8093bba184522dd3238892e06b6215fc2a8e8b510e1b5b19ba60", self.text)
        self.assertIn("cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112", self.text)
        self.assertIn('BINARY_SHA256="$(sha256sum "$BINARY"', self.text)
        self.assertIn('BINARY_BYTES="$(wc -c < "$BINARY"', self.text)
        self.assertNotIn("EUF_VIPER_T10_EXPECTED_SOURCES", self.text)

    def test_only_no_sat_projection_and_independent_audit_are_reachable(self) -> None:
        self.assertIn("run_t10_projection_census.py", self.text)
        self.assertIn("audit_t10_projection_census.py", self.text)
        self.assertIn('["project-t10", "FILE"]', self.text)
        self.assertIn('"sat_calls": 0', self.text)
        self.assertIn("replayed_selected_count", self.text)
        self.assertIn("selected_projection_sha256", self.text)
        self.assertNotIn("run_t10_stage1", self.text)
        self.assertNotIn("compare_solvers.py", self.text)
        self.assertNotIn("--expected-sources", self.text)
        for variable in (
            "EUF_VIPER_T10_ACKERMANN",
            "EUF_VIPER_T9_ACKERMANN",
            "EUF_VIPER_T10_STAGE1",
            "EUF_VIPER_TIMING_MODE",
            "EUF_VIPER_SOLVER_MODE",
        ):
            self.assertIn(variable, self.text)

    def test_scientific_failure_preserves_and_finalizes_evidence(self) -> None:
        self.assertIn("umask 077", self.text)
        self.assertIn("trap finalize_evidence EXIT", self.text)
        self.assertIn('RUN_STATUS="scientific_fail"', self.text)
        self.assertIn('SCIENTIFIC_STATUS="census_fail"', self.text)
        self.assertIn('SCIENTIFIC_STATUS="audit_fail"', self.text)
        self.assertIn('SCIENTIFIC_STATUS="gate_fail"', self.text)
        self.assertIn('"census_stderr": run_root / "census.stderr"', self.text)
        self.assertIn('"audit_stderr": run_root / "audit.stderr"', self.text)
        self.assertIn('"records": run_root / "records.jsonl"', self.text)
        self.assertIn('"summary": run_root / "summary.json"', self.text)
        self.assertIn('"audit_receipt": run_root / "audit-receipt.json"', self.text)
        self.assertIn("os.O_RDWR | os.O_CREAT | os.O_EXCL", self.text)
        self.assertIn("os.fchmod(descriptor, 0o400)", self.text)
        self.assertIn("final binary SHA-256 differs", self.text)
        self.assertNotIn("rm -", self.text)
        self.assertNotIn("unlink(", self.text)

    def test_metadata_binds_cpu_environment_toolchain_and_artifacts(self) -> None:
        for token in (
            '"euf-viper.t10-projection-wmi-run.v1"',
            '"cpu_affinity"',
            '"environment_contract"',
            '"toolchain"',
            '"cargo_sha256"',
            '"rustc_sha256"',
            '"python_sha256"',
            '"binary_sha256"',
            '"manifest"',
            '"control_manifest"',
            '"design_contract"',
            '"runner"',
            '"auditor"',
            '"hardened_stage0"',
            '"wmi_wrapper"',
            '"cargo_lock"',
            '"pinned_cargo"',
            '"pinned_rustc"',
            '"pinned_python"',
            '"records"',
            '"summary"',
            '"audit_receipt"',
        ):
            self.assertIn(token, self.text)
        self.assertIn('export LANG=C', self.text)
        self.assertIn('export LC_ALL=C', self.text)
        self.assertIn('export TZ=UTC', self.text)
        self.assertIn('export RUSTUP_TOOLCHAIN=1.93.0', self.text)
        self.assertIn("differs from its preflight binding", self.text)


if __name__ == "__main__":
    unittest.main()
