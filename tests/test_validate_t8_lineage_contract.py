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
SCRIPT = ROOT / "scripts" / "bench" / "validate_t8_lineage_contract.py"
CONTRACT_PATH = ROOT / "campaigns" / "t8-assertion-lineage-census-v1.json"
SPEC = importlib.util.spec_from_file_location("validate_t8_lineage_contract_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


def contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="ascii"))


class T8LineageContractTests(unittest.TestCase):
    def test_repository_contract_is_valid_and_not_submitted(self) -> None:
        result = VALIDATOR.load_and_validate(CONTRACT_PATH, ROOT)
        self.assertTrue(result["valid"])
        self.assertTrue(result["source_only"])
        self.assertFalse(result["submitted"])
        self.assertEqual(result["expected_physical_sources"], 7503)

    def test_cli_emits_canonical_validation_record(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--contract",
                str(CONTRACT_PATH),
                "--root",
                str(ROOT),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = json.loads(completed.stdout)
        self.assertEqual(completed.stdout, VALIDATOR.canonical_bytes(value))
        self.assertEqual(value["status"], "preregistered_not_submitted")

    def test_no_solve_no_local_corpus_and_exact_population_are_frozen(self) -> None:
        mutations = [
            (("execution", "allowed_binary_subcommand"), "solve"),
            (("execution", "local_full_corpus_allowed"), True),
            (("execution", "solver_invocation_allowed"), True),
            (("execution", "sat_or_unsat_result_fields_allowed"), True),
            (("execution", "shard_count"), 1),
            (("execution", "slurm_submission_status"), "submitted"),
            (("population", "expected_physical_sources"), 7502),
            (("population", "expected_records"), 7502),
            (("population", "expected_unique_device_inode_pairs"), 7502),
            (("population", "expected_unique_relative_paths"), 7502),
            (("scope", "frontier_search_allowed"), True),
            (("scope", "performance_claims_allowed"), True),
            (("scope", "simd_allowed"), True),
            (("scope", "source_only"), False),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                value = contract()
                value[path[0]][path[1]] = replacement
                with self.assertRaises(VALIDATOR.ContractError) as caught:
                    VALIDATOR.validate_contract(value)
                self.assertIn(".".join(("contract", *path)), str(caught.exception))

    def test_all_zero_error_gates_and_identity_guards_are_frozen(self) -> None:
        for name in (
            "hash_errors_allowed",
            "lineage_errors_allowed",
            "missing_records_allowed",
            "parse_errors_allowed",
            "solver_invocations_allowed",
            "unsupported_accounting_errors_allowed",
            "verifier_errors_allowed",
        ):
            with self.subTest(name=name):
                value = contract()
                value["gates"][name] = 1
                with self.assertRaises(VALIDATOR.ContractError):
                    VALIDATOR.validate_contract(value)

        for name, replacement in (
            ("build_git_dirty_allowed", True),
            ("build_git_revision_must_equal_campaign_revision", False),
            ("canonical_json_required", False),
            ("duplicate_json_keys_allowed", True),
            ("non_finite_json_values_allowed", True),
            ("stale_source_allowed", True),
        ):
            with self.subTest(name=name):
                value = contract()
                value["identity"][name] = replacement
                with self.assertRaises(VALIDATOR.ContractError):
                    VALIDATOR.validate_contract(value)

    def test_release_metadata_hash_and_count_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            destination = root / "benchmarks" / "qf_uf_2025_metadata.json"
            destination.parent.mkdir(parents=True)
            destination.write_bytes(
                (ROOT / "benchmarks" / "qf_uf_2025_metadata.json").read_bytes()
                + b" "
            )
            with self.assertRaises(VALIDATOR.ContractError) as caught:
                VALIDATOR.validate_release_metadata(root, contract())
            self.assertIn("SHA-256 mismatch", str(caught.exception))

    def test_duplicate_keys_and_nonfinite_contract_values_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            duplicate = directory / "duplicate.json"
            duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="ascii")
            with self.assertRaises(VALIDATOR.ContractError) as caught:
                VALIDATOR.load_contract(duplicate)
            self.assertIn("duplicate JSON key", str(caught.exception))

            nonfinite = directory / "nonfinite.json"
            nonfinite.write_text('{"schema_version":NaN}', encoding="ascii")
            with self.assertRaises(VALIDATOR.ContractError) as caught:
                VALIDATOR.load_contract(nonfinite)
            self.assertIn("non-finite JSON number", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
