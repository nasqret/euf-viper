from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "validate_t8_scalar_contract.py"
CONTRACT = ROOT / "campaigns" / "t8-scalar-frontier-census-v1.json"
P12_SUMMARY = (
    ROOT
    / "results"
    / "wmi"
    / "guarded-range-census-146071"
    / "p12-range-summary.json"
)
MODULE_SPEC = importlib.util.spec_from_file_location(
    "validate_t8_scalar_contract", SCRIPT
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(VALIDATOR)


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT.read_text(encoding="ascii"))


def set_field(contract: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    target: Any = contract
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


class T8ScalarContractTests(unittest.TestCase):
    def assert_rejected(
        self,
        contract: dict[str, Any],
        expected_message: str,
    ) -> None:
        with self.assertRaises(VALIDATOR.T8ScalarContractError) as caught:
            VALIDATOR.validate_contract(contract)
        self.assertIn(expected_message, "\n".join(caught.exception.errors))

    def test_repository_contract_is_valid_but_authorizes_no_implementation(
        self,
    ) -> None:
        result = VALIDATOR.load_and_validate(CONTRACT, P12_SUMMARY)

        self.assertEqual(result["campaign_id"], "t8-scalar-frontier-census-v1")
        self.assertEqual(
            result["status"],
            "preregistered_design_blocked_on_prerequisites",
        )
        self.assertTrue(result["valid"])
        self.assertFalse(result["implementation_authorized"])
        self.assertFalse(result["simd_authorized"])

    def test_campaign_status_and_no_solver_no_simd_scope_are_bound(self) -> None:
        mutations = [
            (("schema_version",), 2, "schema_version"),
            (("campaign_id",), "t8-scalar-frontier-census-v2", "campaign_id"),
            (("status",), "ready", "status"),
            (("scope", "logic"), "ALL", "scope.logic"),
            (("scope", "heavy_compute_site"), "local", "heavy_compute_site"),
            (("scope", "mode"), "solver", "scope.mode"),
            (
                ("scope", "solver_result_claim_allowed"),
                True,
                "solver_result_claim_allowed",
            ),
            (("scope", "simd_allowed"), True, "simd_allowed"),
        ]

        for path, value, message in mutations:
            with self.subTest(path=path):
                contract = load_contract()
                set_field(contract, path, value)
                self.assert_rejected(contract, message)

    def test_current_prerequisite_identities_statuses_and_hashes_are_bound(
        self,
    ) -> None:
        mutations = [
            (("prerequisites", "typed_parser_revision"), "0" * 40),
            (("prerequisites", "typed_parser_audit_sha256"), "0" * 64),
            (("prerequisites", "typed_parser_independent_review"), "accepted"),
            (
                ("prerequisites", "command_and_auxiliary_assertion_lineage"),
                "complete",
            ),
            (("prerequisites", "corrected_finite_range_job"), 146072),
            (("prerequisites", "corrected_finite_range_status"), "accepted"),
            (
                ("prerequisites", "corrected_finite_range_aggregate_sha256"),
                "0" * 64,
            ),
            (
                ("prerequisites", "corrected_finite_range_records_sha256"),
                "0" * 64,
            ),
            (
                ("prerequisites", "corrected_finite_range_p12_summary_sha256"),
                "0" * 64,
            ),
            (
                ("prerequisites", "p12_sources_with_proven_non_bool_range"),
                12,
            ),
            (
                ("prerequisites", "p12_checked_finite_domain_certificate"),
                "verified",
            ),
        ]

        for path, value in mutations:
            with self.subTest(path=path):
                contract = load_contract()
                set_field(contract, path, value)
                self.assert_rejected(contract, ".".join(path))

    def test_source_lineage_and_no_forget_state_cannot_be_weakened(self) -> None:
        contract = load_contract()
        contract["source_ledger"]["required_bindings"].remove("raw_source_sha256")
        self.assert_rejected(contract, "source_ledger.required_bindings")

        mutations = [
            (
                ("source_ledger", "all_assertions_and_live_symbols_required"),
                False,
            ),
            (("state", "schedule"), "input_order"),
            (("state", "anonymous_value_canonicalization"), "untyped"),
            (("state", "named_value_permutation"), "unchecked"),
            (("state", "m0_forgetting"), "eager"),
            (("state", "retain_all_value_tokens_and_function_memos"), False),
            (("state", "full_key_compare_after_hash_match"), False),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                contract = load_contract()
                set_field(contract, path, value)
                self.assert_rejected(contract, ".".join(path))

        contract = load_contract()
        contract["state"]["key"].remove("ghost_tokens")
        self.assert_rejected(contract, "state.key")

    def test_transition_vocabulary_and_right_translation_boundary_are_exact(
        self,
    ) -> None:
        contract = load_contract()
        contract["transitions"][4] = "forget_value"
        self.assert_rejected(contract, "transitions[4]")

        contract = load_contract()
        contract["transitions"].append("solve_residual")
        self.assert_rejected(contract, "transitions")

        contract = load_contract()
        contract["right_translation_macro"]["authoritative_semantics"] = True
        self.assert_rejected(contract, "authoritative_semantics")

    def test_oracle_evidence_and_cap_abstain_rules_are_exact(self) -> None:
        mutations = [
            (("independent_oracle", "separate_parser_and_evaluator"), False),
            (("independent_oracle", "domain_sizes"), [1, 2]),
            (("independent_oracle", "maximum_total_interpretations"), 2000000),
            (("independent_oracle", "comparison"), "sat_status"),
            (("independent_oracle", "shared_lowering_or_state_code_allowed"), True),
            (("evidence", "sat"), "accepting_path_only"),
            (("evidence", "unsat"), "producer_claim"),
            (("evidence", "capped_graph_can_prove_unsat"), True),
            (("evidence", "independent_checker_required"), False),
            (
                ("state_cap", "maximum_unique_reachable_canonical_states"),
                1000001,
            ),
            (("state_cap", "includes"), ["root"]),
            (("state_cap", "excludes"), []),
            (("state_cap", "overflow_status"), "UNSAT"),
            (("state_cap", "partial_result_disposition"), "retain"),
        ]

        for path, value in mutations:
            with self.subTest(path=path):
                contract = load_contract()
                set_field(contract, path, value)
                self.assert_rejected(contract, ".".join(path))

    def test_all_frozen_population_counts_and_hashes_are_bound(self) -> None:
        population_fields = {
            "P12": ("count", "sorted_path_stream_sha256", "source_bound_tsv_sha256"),
            "DOMAIN7_ONE_TABLE": ("count", "selector_manifest_sha256"),
            "DOMAIN7_TABLE": ("count", "selector_manifest_sha256"),
            "historical_sat_controls": ("count", "source_bound_tsv_sha256"),
            "historical_residual_controls": ("count", "source_bound_tsv_sha256"),
        }

        for population, fields in population_fields.items():
            for field in fields:
                with self.subTest(population=population, field=field):
                    contract = load_contract()
                    original = contract["populations"][population][field]
                    replacement = original + 1 if type(original) is int else "0" * 64
                    contract["populations"][population][field] = replacement
                    self.assert_rejected(
                        contract,
                        f"populations.{population}.{field}",
                    )

        contract = load_contract()
        contract["populations"]["P12"][
            "path_or_expected_status_is_runtime_feature"
        ] = True
        self.assert_rejected(contract, "path_or_expected_status_is_runtime_feature")

    def test_every_scalar_gate_and_stop_rule_are_exact(self) -> None:
        weakened_gates = {
            "tiny_oracle_mismatches_allowed": 1,
            "source_or_auxiliary_lineage_gaps_allowed": 1,
            "minimum_source_complete_domain7_one_table": 199,
            "minimum_p12_below_state_cap": 9,
            "maximum_build_cost_fraction_of_yices2": 0.11,
            "minimum_p12_meeting_build_cost": 6,
            "minimum_broader_population_build_cost_fraction": 0.49,
            "sat_and_unsat_evidence_check_failures_allowed": 1,
            "minimum_direct_yices2_speedup_after_census": 1.09,
            "minimum_useful_simd_lane_occupancy_after_scalar_pass": 0.69,
        }

        for field, value in weakened_gates.items():
            with self.subTest(field=field):
                contract = load_contract()
                contract["gates"][field] = value
                self.assert_rejected(contract, f"gates.{field}")

        contract = load_contract()
        contract["stop_rule"] = "warn_and_continue"
        self.assert_rejected(contract, "stop_rule")

    def test_boolean_integer_confusion_is_rejected(self) -> None:
        mutations = [
            (("schema_version",), True),
            (("prerequisites", "corrected_finite_range_job"), True),
            (("prerequisites", "p12_sources_with_proven_non_bool_range"), True),
            (("independent_oracle", "domain_sizes", 0), True),
            (("state_cap", "maximum_unique_reachable_canonical_states"), True),
            (("populations", "DOMAIN7_TABLE", "count"), True),
            (("gates", "tiny_oracle_mismatches_allowed"), False),
            (("scope", "solver_result_claim_allowed"), 0),
            (("evidence", "capped_graph_can_prove_unsat"), 0),
        ]

        for path, value in mutations:
            with self.subTest(path=path):
                contract = load_contract()
                set_field(contract, path, value)
                expected_path = ".".join(
                    str(part) for part in path if not isinstance(part, int)
                )
                self.assert_rejected(contract, expected_path)

    def test_duplicate_keys_non_finite_values_and_non_ascii_are_rejected(self) -> None:
        original = CONTRACT.read_text(encoding="ascii")
        malformed_cases = {
            "duplicate": original.replace(
                '  "schema_version": 1,',
                '  "schema_version": 1,\n  "schema_version": 1,',
                1,
            ).encode("ascii"),
            "nan": original.replace("0.1,", "NaN,", 1).encode("ascii"),
            "positive-infinity": original.replace(
                "0.1,", "Infinity,", 1
            ).encode("ascii"),
            "negative-infinity": original.replace(
                "0.1,", "-Infinity,", 1
            ).encode("ascii"),
            "overflow-infinity": original.replace("0.1,", "1e9999,", 1).encode(
                "ascii"
            ),
            "non-ascii": original.replace(
                "QF_UF",
                "QF_\N{LATIN SMALL LETTER U WITH DIAERESIS}F",
                1,
            ).encode("utf-8"),
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            for name, payload in malformed_cases.items():
                with self.subTest(name=name):
                    path = Path(temp_dir) / f"{name}.json"
                    path.write_bytes(payload)
                    with self.assertRaises(VALIDATOR.T8ScalarContractError) as caught:
                        VALIDATOR.load_and_validate(path)
                    message = str(caught.exception)
                    if name == "duplicate":
                        self.assertIn("duplicate JSON key", message)
                    elif name == "non-ascii":
                        self.assertIn("ascii", message.lower())
                    else:
                        self.assertIn("non-finite JSON", message)

    def test_missing_and_unknown_fields_are_rejected(self) -> None:
        contract = load_contract()
        del contract["source_ledger"]["auxiliary_id"]
        contract["state_cap"]["cap_is_advisory"] = True

        with self.assertRaises(VALIDATOR.T8ScalarContractError) as caught:
            VALIDATOR.validate_contract(contract)

        message = "\n".join(caught.exception.errors)
        self.assertIn("source_ledger.auxiliary_id is required", message)
        self.assertIn("state_cap.cap_is_advisory is not allowed", message)

    def test_p12_summary_bytes_and_semantics_are_bound(self) -> None:
        original = json.loads(P12_SUMMARY.read_text(encoding="ascii"))
        original["sources_with_certified_domain"] = 1

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "p12-range-summary.json"
            path.write_text(json.dumps(original), encoding="ascii")
            with self.assertRaises(VALIDATOR.T8ScalarContractError) as caught:
                VALIDATOR.load_and_validate(CONTRACT, path)

        message = "\n".join(caught.exception.errors)
        self.assertIn("p12_summary SHA-256", message)
        self.assertIn("p12_summary.sources_with_certified_domain", message)

    def test_cli_is_executable_and_emits_a_compact_machine_readable_summary(
        self,
    ) -> None:
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        completed = subprocess.run(
            [str(SCRIPT), str(CONTRACT), "--p12-summary", str(P12_SUMMARY)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout.count("\n"), 1)
        self.assertNotIn(" ", completed.stdout)
        result = json.loads(completed.stdout)
        self.assertTrue(result["valid"])
        self.assertFalse(result["implementation_authorized"])
        self.assertFalse(result["simd_authorized"])


if __name__ == "__main__":
    unittest.main()
