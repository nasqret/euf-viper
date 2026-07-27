from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SBATCH = ROOT / "slurm" / "helios" / "euf_viper_staged_qg7_matrix.sbatch"
TASK = ROOT / "scripts" / "helios" / "run_staged_qg7_matrix_task.sh"


class StagedQG7MatrixContractTests(unittest.TestCase):
    def test_slurm_contract_is_single_core_and_bound(self) -> None:
        source = SBATCH.read_text(encoding="utf-8")
        self.assertIn("#SBATCH --cpus-per-task=1", source)
        self.assertIn("#SBATCH --hint=nomultithread", source)
        self.assertIn("--cpu-bind=cores", source)
        self.assertIn("SLURM_ARRAY_TASK_ID", source)
        self.assertIn("set -euo pipefail", source)

    def test_task_is_hash_bound_and_uses_complete_williams_block(self) -> None:
        source = TASK.read_text(encoding="utf-8")
        for required in (
            "EXPECTED_SOLVER_SHA256",
            "EXPECTED_SELECTION_SHA256",
            "EXPECTED_MANIFEST_SHA256",
            "EXPECTED_TASK_SHA256",
            "EXPECTED_SBATCH_SHA256",
            "EXPECTED_RUNNER_SHA256",
            "EXPECTED_TOOLCHAIN_SHA256",
            'TASK_SCRIPT="$EXPERIMENT_ROOT/run_staged_qg7_matrix_task.sh"',
            'SBATCH_SCRIPT="$EXPERIMENT_ROOT/euf_viper_staged_qg7_matrix.sbatch"',
            "compare_multiarm_williams.py",
            "run_with_resources.py",
            "--blocks 1",
            "--timeout 2",
            "AMD EPYC 9654",
        ):
            self.assertIn(required, source)

    def test_threshold_arms_keep_direct_dense_seven_disabled(self) -> None:
        source = TASK.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_FINITE_DENSE7=0", source)
        self.assertIn("threshold|confirm-stage10|braid-threshold|confirm-braid", source)
        self.assertIn("EUF_VIPER_MATRIX_MODE", source)
        self.assertIn("add_arm baseline 0 0 1000 1000 0", source)
        for budget in (0, 10, 100, 1000, 10000):
            self.assertIn(f"add_arm staged-{budget} 1 0 1000 {budget} 0", source)

    def test_braided_arms_sweep_plain_prefix_before_fixed_unsat_sprint(self) -> None:
        source = TASK.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_FINITE_DENSE7_BRAIDED=$braided", source)
        self.assertIn(
            "EUF_VIPER_FINITE_DENSE7_CADICAL_PREFIX_CONFLICTS=$cadical_prefix",
            source,
        )
        self.assertIn(
            "EUF_VIPER_FINITE_DENSE7_CADICAL_SPRINT_CONFLICTS=$cadical_sprint",
            source,
        )
        for budget in (0, 10, 100, 1000, 10000):
            self.assertIn(f"add_arm braid-{budget} 0 1 {budget} 0 70000", source)
        self.assertIn('add_arm "braid-$BRAIDED_CADICAL_PREFIX"', source)


if __name__ == "__main__":
    unittest.main()
