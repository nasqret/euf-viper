from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "validate_viper_fabric_contract.py"
CONTRACT = ROOT / "campaigns" / "viper-fabric-2026-07.json"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "validate_viper_fabric_contract", SCRIPT
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(VALIDATOR)


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT.read_text(encoding="ascii"))


class ViperFabricContractTests(unittest.TestCase):
    def validation_errors(self, contract: Any) -> list[str]:
        with self.assertRaises(VALIDATOR.ViperFabricContractError) as caught:
            VALIDATOR.validate_contract(contract)
        return caught.exception.errors

    def test_repository_contract_is_valid_and_authorizations_remain_false(self) -> None:
        result = VALIDATOR.load_and_validate(CONTRACT)

        self.assertTrue(result["valid"])
        self.assertFalse(result["migration_authorized"])
        self.assertFalse(result["default_behavior_change_authorized"])
        self.assertEqual(result["stages"], ["F0", "F1", "F2", "F3", "F4", "F5"])

    def test_unknown_top_level_fields_are_rejected(self) -> None:
        contract = load_contract()
        contract["approval_note"] = "not part of the contract schema"

        errors = self.validation_errors(contract)

        self.assertIn("contract.approval_note is not allowed", errors)

    def test_boolean_integer_confusion_is_rejected_at_all_numeric_layers(self) -> None:
        contract = load_contract()
        contract["schema_version"] = True
        contract["reference"]["full_instances"] = True
        contract["stages"][1]["gates"]["generated_differential_cases"] = True
        contract["victory"]["cpu_classes_required"] = True

        message = "\n".join(self.validation_errors(contract))

        self.assertIn("schema_version", message)
        self.assertIn("reference.full_instances", message)
        self.assertIn("generated_differential_cases", message)
        self.assertIn("victory.cpu_classes_required", message)
        self.assertIn("boolean", message)

    def test_changed_reference_metrics_are_rejected(self) -> None:
        contract = load_contract()
        contract["reference"]["yices2"]["full_solves"]["60"] -= 1
        contract["reference"]["euf_viper"]["full_60_p95_s"] = 1.0

        message = "\n".join(self.validation_errors(contract))

        self.assertIn("reference.yices2.full_solves.60", message)
        self.assertIn("reference.euf_viper.full_60_p95_s", message)

    def test_weakened_victory_gates_are_rejected(self) -> None:
        contract = load_contract()
        contract["victory"]["full_min_solves"]["2"] = 7445
        contract["victory"][
            "minimum_common_geometric_speedup_over_every_comparator"
        ] = 1.04
        contract["victory"]["wrong_answers_allowed"] = 1
        contract["victory"]["independent_sat_model_checks_required"] = False
        contract["victory"]["cpu_classes_required"] = 1

        message = "\n".join(self.validation_errors(contract))

        self.assertIn("victory.full_min_solves.2", message)
        self.assertIn("minimum_common_geometric_speedup", message)
        self.assertIn("wrong_answers_allowed", message)
        self.assertIn("independent_sat_model_checks_required", message)
        self.assertIn("cpu_classes_required", message)
        self.assertIn("weakens the gate", message)

    def test_weakened_mechanism_and_migration_gates_are_rejected(self) -> None:
        contract = load_contract()
        contract["stages"][1]["gates"]["target_geometric_speedup_lcb"] = 1.19
        contract["stages"][1]["gates"]["anti_target_p95_overhead_ucb"] = 1.02
        contract["stages"][3]["gates"]["generic_factoring_control_required"] = False
        contract["stages"][5]["prerequisites"]["oracle_headroom_lcb_min"] = 0.09
        contract["stages"][5]["gates"]["beats_every_fixed_engine"] = False

        message = "\n".join(self.validation_errors(contract))

        self.assertIn("target_geometric_speedup_lcb", message)
        self.assertIn("anti_target_p95_overhead_ucb", message)
        self.assertIn("generic_factoring_control_required", message)
        self.assertIn("oracle_headroom_lcb_min", message)
        self.assertIn("beats_every_fixed_engine", message)

    def test_stronger_thresholds_and_additional_prohibitions_are_allowed(self) -> None:
        contract = load_contract()
        contract["stages"][1]["gates"]["generated_differential_cases"] += 1
        contract["stages"][1]["gates"]["target_geometric_speedup_lcb"] = 1.21
        contract["stages"][1]["gates"]["anti_target_p95_overhead_ucb"] = 1.00
        contract["stages"][5]["prerequisites"]["oracle_headroom_lcb_min"] = 0.11
        contract["victory"]["full_min_solves"]["2"] = 7447
        contract["victory"][
            "minimum_common_total_speedup_over_every_comparator"
        ] = 1.06
        contract["victory"]["independent_full_runs_required"] = 3
        contract["forbidden"].append("new_identity_route")

        result = VALIDATOR.validate_contract(contract)

        self.assertTrue(result["valid"])
        self.assertEqual(result["forbidden_count"], 12)

    def test_default_or_migration_authorization_is_rejected(self) -> None:
        contract = load_contract()
        contract["implementation"]["default_behavior_change_authorized"] = True
        contract["implementation"]["migration_authorized"] = True

        message = "\n".join(self.validation_errors(contract))

        self.assertIn("default_behavior_change_authorized", message)
        self.assertIn("migration_authorized", message)

    def test_forbidden_entries_cannot_be_removed_or_duplicated(self) -> None:
        contract = load_contract()
        contract["forbidden"].remove("family_routing")
        contract["forbidden"].append("source_path_routing")

        message = "\n".join(self.validation_errors(contract))

        self.assertIn("family_routing", message)
        self.assertIn("duplicate entries", message)

    def test_stage_ids_must_be_unique_complete_and_ordered(self) -> None:
        reordered = load_contract()
        reordered["stages"][0], reordered["stages"][1] = (
            reordered["stages"][1],
            reordered["stages"][0],
        )
        duplicate = load_contract()
        duplicate["stages"][1]["id"] = "F0"

        reordered_message = "\n".join(self.validation_errors(reordered))
        duplicate_message = "\n".join(self.validation_errors(duplicate))

        self.assertIn("in that order", reordered_message)
        self.assertIn("duplicate id 'F0'", duplicate_message)
        self.assertIn("in that order", duplicate_message)

    def test_duplicate_keys_non_finite_numbers_and_non_ascii_are_rejected(self) -> None:
        original = CONTRACT.read_text(encoding="ascii")
        invalid_documents = {
            "duplicate": original.replace(
                '  "schema_version": 1,',
                '  "schema_version": 1,\n  "schema_version": 1,',
                1,
            ),
            "nan": original.replace('"p95_overhead_ucb": 1.01', '"p95_overhead_ucb": NaN', 1),
            "infinity": original.replace(
                '"p95_overhead_ucb": 1.01', '"p95_overhead_ucb": Infinity', 1
            ),
            "negative-infinity": original.replace(
                '"p95_overhead_ucb": 1.01', '"p95_overhead_ucb": -Infinity', 1
            ),
            "overflow": original.replace(
                '"p95_overhead_ucb": 1.01', '"p95_overhead_ucb": 1e9999', 1
            ),
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            for name, document in invalid_documents.items():
                with self.subTest(name=name):
                    path = Path(temp_dir) / f"{name}.json"
                    path.write_text(document, encoding="ascii")
                    with self.assertRaises(VALIDATOR.ViperFabricContractError):
                        VALIDATOR.load_and_validate(path)

            non_ascii_path = Path(temp_dir) / "non-ascii.json"
            non_ascii_path.write_text(
                original.replace("standalone", "standalon\N{LATIN SMALL LETTER E WITH ACUTE}", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VALIDATOR.ViperFabricContractError, "ascii"
            ):
                VALIDATOR.load_and_validate(non_ascii_path)

    def test_cli_emits_machine_readable_summaries_and_fails_closed(self) -> None:
        valid_run = subprocess.run(
            [sys.executable, str(SCRIPT), str(CONTRACT)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(valid_run.returncode, 0, valid_run.stderr)
        self.assertTrue(json.loads(valid_run.stdout)["valid"])

        contract = load_contract()
        contract["implementation"]["migration_authorized"] = True
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid_path = Path(temp_dir) / "invalid.json"
            invalid_path.write_text(json.dumps(contract), encoding="ascii")
            invalid_run = subprocess.run(
                [sys.executable, str(SCRIPT), str(invalid_path)],
                check=False,
                capture_output=True,
                text=True,
            )

        failure = json.loads(invalid_run.stdout)
        self.assertEqual(invalid_run.returncode, 2)
        self.assertFalse(failure["valid"])
        self.assertEqual(failure["error_count"], len(failure["errors"]))
        self.assertTrue(any("migration_authorized" in item for item in failure["errors"]))


if __name__ == "__main__":
    unittest.main()
