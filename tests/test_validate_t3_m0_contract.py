from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "validate_t3_m0_contract.py"
CONTRACT = ROOT / "campaigns" / "t3-m0-component-pressure-v1.json"
MODULE_SPEC = importlib.util.spec_from_file_location("validate_t3_m0_contract", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(VALIDATOR)


def load_contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="ascii"))


class T3M0ContractTests(unittest.TestCase):
    def test_repository_contract_is_valid_and_migration_stays_forbidden(self) -> None:
        result = VALIDATOR.validate_contract(load_contract())

        self.assertTrue(result["valid"])
        self.assertFalse(result["migration_authorized"])
        self.assertEqual(result["preliminary_oracle_headroom"], 0.0374)

    def test_weakened_headroom_and_accuracy_gates_are_rejected(self) -> None:
        contract = load_contract()
        contract["prerequisites"]["minimum_oracle_headroom_lcb"] = 0.03
        contract["gates"]["balanced_accuracy_cluster_bootstrap_lcb"] = 0.7

        with self.assertRaises(VALIDATOR.T3M0ContractError) as caught:
            VALIDATOR.validate_contract(contract)

        self.assertTrue(any("headroom" in item for item in caught.exception.errors))
        self.assertTrue(any("balanced_accuracy" in item for item in caught.exception.errors))

    def test_removing_leakage_denials_is_rejected(self) -> None:
        contract = load_contract()
        contract["forbidden_runtime_features"].remove("family")
        contract["forbidden_runtime_features"].remove("final_runtime")

        with self.assertRaises(VALIDATOR.T3M0ContractError) as caught:
            VALIDATOR.validate_contract(contract)

        message = "\n".join(caught.exception.errors)
        self.assertIn("family", message)
        self.assertIn("final_runtime", message)

    def test_post_checkpoint_feature_and_trace_drift_are_rejected(self) -> None:
        contract = load_contract()
        contract["checkpoints"]["S1"]["excluded"].remove("post_checkpoint_events")
        contract["gates"]["semantic_trace"] = "same_result_only"

        with self.assertRaises(VALIDATOR.T3M0ContractError) as caught:
            VALIDATOR.validate_contract(contract)

        message = "\n".join(caught.exception.errors)
        self.assertIn("post_checkpoint_events", message)
        self.assertIn("semantic_trace", message)

    def test_inconsistent_preliminary_headroom_is_rejected(self) -> None:
        contract = load_contract()
        contract["preliminary_evidence"]["oracle_headroom"] = 0.09

        with self.assertRaises(VALIDATOR.T3M0ContractError) as caught:
            VALIDATOR.validate_contract(contract)

        self.assertTrue(any("does not match" in item for item in caught.exception.errors))

    def test_cli_writes_machine_readable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "summary.json"
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), str(CONTRACT), "--out", str(output)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output.read_text(encoding="ascii"))
            self.assertTrue(result["valid"])
            self.assertFalse(result["migration_authorized"])


if __name__ == "__main__":
    unittest.main()
