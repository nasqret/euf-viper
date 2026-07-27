from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "project_structural_matrix_selector.py"
SPEC = importlib.util.spec_from_file_location("project_structural_matrix_selector", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROJECT)


def observation(covered: bool, elapsed: float) -> dict:
    return {"covered": covered, "median_time_s": elapsed}


def fixture() -> tuple[dict, dict]:
    matrix = {
        "status": "complete",
        "audit_sha256": "",
        "reference_arm": "baseline",
        "arm_order": ["baseline", "candidate"],
        "accounting": {"wrong_answers": 0, "execution_errors": 0},
        "paths": [
            {
                "relative_path": "gain.smt2",
                "expected_status": "unsat",
                "arms": {
                    "baseline": observation(False, 2.0),
                    "candidate": observation(True, 1.0),
                },
            },
            {
                "relative_path": "loss.smt2",
                "expected_status": "sat",
                "arms": {
                    "baseline": observation(True, 1.0),
                    "candidate": observation(False, 2.0),
                },
            },
            {
                "relative_path": "common.smt2",
                "expected_status": "sat",
                "arms": {
                    "baseline": observation(True, 2.0),
                    "candidate": observation(True, 1.0),
                },
            },
        ],
    }
    matrix["audit_sha256"] = hashlib.sha256(PROJECT.canonical_bytes(matrix)).hexdigest()
    census = {
        "counts": {"failed_instances": 0, "successful_instances": 3},
        "instances": [
            {"relative_path": "gain.smt2", "metrics": {"size": 1}},
            {"relative_path": "loss.smt2", "metrics": {"size": 2}},
            {"relative_path": "common.smt2", "metrics": {"size": 1}},
        ],
    }
    return matrix, census


class StructuralMatrixProjectionTests(unittest.TestCase):
    def test_threshold_routes_only_selected_paths(self) -> None:
        matrix, census = fixture()
        report = PROJECT.project(
            matrix, census, "size", 1, "candidate", "a" * 64, "b" * 64
        )

        projection = report["projection"]
        self.assertEqual(projection["selected_paths"], 2)
        self.assertEqual(projection["covered_paths"], 3)
        self.assertEqual(projection["coverage_delta_vs_reference"], 1)
        self.assertEqual(projection["gain_relative_paths"], ["gain.smt2"])
        self.assertEqual(projection["loss_relative_paths"], [])
        self.assertEqual(projection["common_aggregate_speedup_vs_reference"], 1.5)

        broad = report["threshold_frontier"][-1]
        self.assertEqual(broad["coverage_delta_vs_reference"], 0)
        self.assertEqual(broad["losses_vs_reference"], 1)

    def test_rejects_hash_and_path_set_drift(self) -> None:
        matrix, census = fixture()
        matrix["paths"][0]["expected_status"] = "sat"
        with self.assertRaisesRegex(PROJECT.ProjectionError, "self-hash mismatch"):
            PROJECT.project(
                matrix, census, "size", 1, "candidate", "a" * 64, "b" * 64
            )

        matrix, census = fixture()
        census["instances"][0]["relative_path"] = "different.smt2"
        with self.assertRaisesRegex(PROJECT.ProjectionError, "path sets differ"):
            PROJECT.project(
                matrix, census, "size", 1, "candidate", "a" * 64, "b" * 64
            )


if __name__ == "__main__":
    unittest.main()
