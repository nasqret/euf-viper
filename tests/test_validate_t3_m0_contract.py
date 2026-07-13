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

    def test_boolean_integer_type_confusion_is_rejected(self) -> None:
        contract = load_contract()
        contract["checkpoints"]["S1"]["stop_at_first"][
            "invalid_complete_model"
        ] = True
        contract["measurement"]["unique_label_rule"]["blocks"] = True
        contract["gates"]["wrong_or_missing_or_hash_failures_allowed"] = False

        with self.assertRaises(VALIDATOR.T3M0ContractError) as caught:
            VALIDATOR.validate_contract(contract)

        message = "\n".join(caught.exception.errors)
        self.assertIn("invalid_complete_model", message)
        self.assertIn("blocks", message)
        self.assertIn("wrong_or_missing", message)

    def test_duplicate_keys_and_non_finite_constants_are_rejected(self) -> None:
        original = CONTRACT.read_text(encoding="ascii")
        duplicate = original.replace(
            '  "schema_version": 1,',
            '  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        non_finite = original.replace(
            '"oracle_headroom": 0.0374', '"oracle_headroom": NaN'
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            duplicate_path = Path(temp_dir) / "duplicate.json"
            duplicate_path.write_text(duplicate, encoding="ascii")
            with self.assertRaises(VALIDATOR.T3M0ContractError) as duplicate_error:
                VALIDATOR.load_and_validate(duplicate_path)
            self.assertIn("duplicate JSON key", str(duplicate_error.exception))

            non_finite_path = Path(temp_dir) / "non-finite.json"
            non_finite_path.write_text(non_finite, encoding="ascii")
            with self.assertRaises(VALIDATOR.T3M0ContractError) as non_finite_error:
                VALIDATOR.load_and_validate(non_finite_path)
            self.assertIn("non-finite JSON constant", str(non_finite_error.exception))

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
