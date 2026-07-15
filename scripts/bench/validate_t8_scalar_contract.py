#!/usr/bin/env python3
"""Validate the frozen T8 source-exact scalar frontier contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any


EXPECTED_CONTRACT: dict[str, Any] = {
    "schema_version": 1,
    "campaign_id": "t8-scalar-frontier-census-v1",
    "status": "preregistered_design_blocked_on_prerequisites",
    "scope": {
        "logic": "QF_UF",
        "heavy_compute_site": "WMI",
        "mode": "source_only_opportunity_census",
        "solver_result_claim_allowed": False,
        "simd_allowed": False,
    },
    "prerequisites": {
        "typed_parser_revision": "7214d6396905466b459ca7d614bc2e1c6c85ec93",
        "typed_parser_audit_sha256": (
            "fea1b2ec59df0187e62d38bd7a996f3fa30c9cbdecee6520dca485364c59d355"
        ),
        "typed_parser_independent_review": "rejected_evidence_integrity",
        "command_and_auxiliary_assertion_lineage": (
            "implemented_pending_7503_source_census"
        ),
        "corrected_finite_range_job": 146071,
        "corrected_finite_range_status": (
            "completed_zero_error_no_p12_ranges"
        ),
        "corrected_finite_range_aggregate_sha256": (
            "b37b95509c36b29c1f6ab5f55d5754ce1aab0b4ec2efe447488ecfacc8cc4e42"
        ),
        "corrected_finite_range_records_sha256": (
            "4cfb2d1da7f2691485978d33b5a7a39b586246ade226d455b9516e8c74ff961c"
        ),
        "corrected_finite_range_p12_summary_sha256": (
            "68d4d44bf17a1c674bbfbc416335a8e2bf302d3ccf632430cbba378e17d35b51"
        ),
        "corrected_finite_range_receipt_sha256": (
            "2f54e37e125d5da69a971ed88a8444cb414e38bb7df49869dad81753a9ca8d80"
        ),
        "p12_sources_with_proven_non_bool_range": 0,
        "p12_checked_finite_domain_certificate": "missing",
    },
    "source_ledger": {
        "source_assertion_id": [
            "source_ordinal",
            "exact_byte_span",
            "raw_ast_sha256",
        ],
        "auxiliary_id": [
            "origin_assertion",
            "kind",
            "local_index",
        ],
        "required_bindings": [
            "raw_source_sha256",
            "declarations_and_definitions",
            "parser_revision_and_mode",
            "checked_finite_range_certificate",
            "active_check_sat",
        ],
        "all_assertions_and_live_symbols_required": True,
    },
    "state": {
        "schedule": "deterministic_min_fill_source_incidence",
        "key": [
            "layer",
            "live_typed_term_partition",
            "ghost_tokens",
            "function_memos",
            "live_atom_and_gate_values",
            "derived_specialized_summaries",
        ],
        "anonymous_value_canonicalization": "typed_restricted_growth",
        "named_value_permutation": (
            "checked_complete_source_prefix_automorphism_only"
        ),
        "m0_forgetting": "term_id_after_final_incidence_only",
        "retain_all_value_tokens_and_function_memos": True,
        "full_key_compare_after_hash_match": True,
    },
    "transitions": [
        "introduce_term",
        "introduce_application",
        "evaluate_source_atom",
        "evaluate_boolean_gate",
        "forget_term_after_final_incidence",
    ],
    "right_translation_macro": {
        "allowed": True,
        "primitive_table_cell_transitions": 7,
        "complete_source_derived_partition_required": True,
        "authoritative_semantics": False,
    },
    "independent_oracle": {
        "separate_parser_and_evaluator": True,
        "domain_sizes": [1, 2, 3],
        "maximum_total_interpretations": 1000000,
        "comparison": "exact_satisfying_total_model_set_sha256",
        "shared_lowering_or_state_code_allowed": False,
    },
    "evidence": {
        "sat": "total_interpretation_accepting_path_and_per_assertion_replay",
        "unsat": "checked_disjoint_cube_cover_decision_dag",
        "capped_graph_can_prove_unsat": False,
        "independent_checker_required": True,
    },
    "state_cap": {
        "maximum_unique_reachable_canonical_states": 1000000,
        "includes": ["root", "accepting_states"],
        "excludes": ["immediately_rejected_transitions"],
        "overflow_status": "ABSTAIN_STATE_CAP",
        "partial_result_disposition": "discard",
    },
    "populations": {
        "P12": {
            "count": 12,
            "sorted_path_stream_sha256": (
                "1fd24c2c5fa8eafd07a39f28c96d828e0e0aa1072fd032db413c60f34270b6fa"
            ),
            "source_bound_tsv_sha256": (
                "78e09b9437525c77f61014f865a5e91242a713c54d1550550903500c970753c3"
            ),
            "path_or_expected_status_is_runtime_feature": False,
        },
        "DOMAIN7_ONE_TABLE": {
            "count": 261,
            "selector_manifest_sha256": (
                "feaee694c894b899938494ca70b9c1641e032452e217c21233bd12e4c688fbe5"
            ),
        },
        "DOMAIN7_TABLE": {
            "count": 431,
            "selector_manifest_sha256": (
                "3c40aa2d1a6a7a2751a73af3a1b20a589f23b601644dbcc3321c85fdf723f758"
            ),
        },
        "historical_sat_controls": {
            "count": 12,
            "source_bound_tsv_sha256": (
                "8a4ca8e5464abd2964788b3e151603b0e37d7c2497655a9d01de0dca0886e6be"
            ),
        },
        "historical_residual_controls": {
            "count": 19,
            "source_bound_tsv_sha256": (
                "1f98164da78bb7783a8dcfe1e8a1f094b0841f24b315968100d935e102c6c3f7"
            ),
        },
    },
    "gates": {
        "tiny_oracle_mismatches_allowed": 0,
        "source_or_auxiliary_lineage_gaps_allowed": 0,
        "minimum_source_complete_domain7_one_table": 200,
        "minimum_p12_below_state_cap": 10,
        "maximum_build_cost_fraction_of_yices2": 0.1,
        "minimum_p12_meeting_build_cost": 7,
        "minimum_broader_population_build_cost_fraction": 0.5,
        "sat_and_unsat_evidence_check_failures_allowed": 0,
        "minimum_direct_yices2_speedup_after_census": 1.1,
        "minimum_useful_simd_lane_occupancy_after_scalar_pass": 0.7,
    },
    "stop_rule": (
        "any_prerequisite_or_gate_failure_stops_before_solver_or_simd_implementation"
    ),
}

EXPECTED_P12_SUMMARY: dict[str, Any] = {
    "schema": "euf-viper.guard-range-hall-p12-summary.v1",
    "records_sha256": (
        "4cfb2d1da7f2691485978d33b5a7a39b586246ade226d455b9516e8c74ff961c"
    ),
    "sorted_path_stream_sha256": (
        "1fd24c2c5fa8eafd07a39f28c96d828e0e0aa1072fd032db413c60f34270b6fa"
    ),
    "source_count": 12,
    "sources_with_proven_non_bool_range": 0,
    "sources_with_certified_domain": 0,
    "total_proven_range_facts": 0,
    "ineligibility_reason": "no_proven_non_bool_range",
    "paths": [
        "QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen002.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen003.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen004.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen005.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen007.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk001.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk002.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk003.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk004.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk005.smt2",
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk007.smt2",
    ],
    "interpretation": "evidence_only_paths_forbidden_as_runtime_features",
}

EXPECTED_T4_RECEIPT: dict[str, Any] = {
    "schema": "euf-viper.guard-range-hall-decision.v1",
    "status": "reject",
    "decision": "stop_before_hall_pb_implementation",
    "revision": "8f785437830e9ae25ba3d0eb96e2f4c9ef66daa3",
    "job": {
        "job_id": 146071,
        "slurm_state": "COMPLETED",
        "exit_code": "0:0",
        "elapsed": "01:53:20",
        "hostname": "c1n1.cluster.wmi.amu.edu.pl",
    },
    "validation": {
        "expected_sources": 7503,
        "observed_sources": 7503,
        "structured_parse_errors": 0,
        "eligible_sources": 0,
        "ineligible_sources": 7503,
    },
    "opportunity": {
        "uniform_value_cells": 124698,
        "non_uniform_value_cells": 124698,
        "value_cell_savings": 0,
        "value_cell_savings_fraction": 0.0,
        "minimum_required_savings_fraction": 0.3,
        "certified_uniform_domains": 157,
        "effective_candidate_ranges": 25760,
        "proven_range_facts": 24365,
        "hall_subsets_checked": 24,
        "hall_checked_conflicts": 0,
        "gate_passed": False,
    },
    "p12_t8_prerequisite": {
        "source_count": 12,
        "sources_with_proven_non_bool_range": 0,
        "sources_with_certified_domain": 0,
        "total_proven_range_facts": 0,
        "status": "not_satisfied",
    },
    "artifacts": {
        "aggregate": {
            "path": "aggregate.json",
            "sha256": (
                "b37b95509c36b29c1f6ab5f55d5754ce1aab0b4ec2efe447488ecfacc8cc4e42"
            ),
        },
        "metadata": {
            "path": "metadata.json",
            "sha256": (
                "f4efbe5a08f85c59d7aa44150064a835233a66f1853b2b1a5c642cc505df474e"
            ),
        },
        "records": {
            "remote_path": (
                "/home/bnaskrecki/euf-viper-campaigns/8f785437830e/results/"
                "guarded-range-census-146071/records.jsonl"
            ),
            "sha256": (
                "4cfb2d1da7f2691485978d33b5a7a39b586246ade226d455b9516e8c74ff961c"
            ),
            "locally_preserved": False,
        },
        "p12_range_summary": {
            "path": "p12-range-summary.json",
            "sha256": (
                "68d4d44bf17a1c674bbfbc416335a8e2bf302d3ccf632430cbba378e17d35b51"
            ),
        },
        "run": {
            "path": "run.txt",
            "sha256": (
                "2a00ce36ee11b00c7bf3fa45b9a9cd34bc448da3dff8a8e2a6a07df825961021"
            ),
        },
        "stdout": {
            "path": "guarded-range-census-146071.out",
            "sha256": (
                "4f612d41f2712c2a67f6bff7a15bf4b5445640e316b4b3c6646b42ccbcbd9a06"
            ),
        },
        "stderr": {
            "path": "guarded-range-census-146071.err",
            "sha256": (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
        },
    },
    "released_certificate_chains": {
        "full": [146076, 146077, 146078],
        "official": [146079, 146080, 146081],
    },
}


class T8ScalarContractError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(errors[0] if errors else "invalid T8 scalar contract")


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant {value!r} is forbidden")


def _finite_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"non-finite JSON number {value!r} is forbidden")
    return result


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _json_type_name(value: Any) -> str:
    return {
        dict: "object",
        list: "array",
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        type(None): "null",
    }.get(type(value), type(value).__name__)


def _field_path(parent: str, child: Any) -> str:
    rendered = child if isinstance(child, str) else repr(child)
    return f"{parent}.{rendered}" if parent else str(rendered)


def _validate_exact(
    actual: Any,
    expected: Any,
    path: str,
    errors: list[str],
) -> None:
    if type(actual) is not type(expected):
        errors.append(
            f"{path or 'contract'} must have JSON type {_json_type_name(expected)}, "
            f"not {_json_type_name(actual)}"
        )
        return

    if isinstance(expected, dict):
        actual_keys = set(actual)
        expected_keys = set(expected)
        for key in sorted(expected_keys - actual_keys):
            errors.append(f"{_field_path(path, key)} is required")
        for key in sorted(actual_keys - expected_keys, key=repr):
            errors.append(f"{_field_path(path, key)} is not allowed")
        for key in expected:
            if key in actual:
                _validate_exact(
                    actual[key],
                    expected[key],
                    _field_path(path, key),
                    errors,
                )
        return

    if isinstance(expected, list):
        if len(actual) != len(expected):
            errors.append(f"{path} must contain exactly {len(expected)} entries")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            _validate_exact(
                actual_item,
                expected_item,
                f"{path}[{index}]",
                errors,
            )
        return

    if isinstance(actual, float) and not math.isfinite(actual):
        errors.append(f"{path} must be finite")
    elif actual != expected:
        errors.append(f"{path} must be {expected!r}, not {actual!r}")


def validate_contract(contract: Any) -> dict[str, Any]:
    if type(contract) is not dict:
        raise T8ScalarContractError(["contract root must be an object"])

    errors: list[str] = []
    _validate_exact(contract, EXPECTED_CONTRACT, "", errors)
    if errors:
        raise T8ScalarContractError(errors)

    return {
        "campaign_id": EXPECTED_CONTRACT["campaign_id"],
        "implementation_authorized": False,
        "simd_authorized": False,
        "status": EXPECTED_CONTRACT["status"],
        "valid": True,
    }


def _load_json(path: Path) -> tuple[bytes, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise T8ScalarContractError([f"cannot load {path}: {error}"]) from error
    return raw, value


def validate_p12_summary(raw: bytes, summary: Any) -> None:
    errors: list[str] = []
    expected_sha256 = EXPECTED_CONTRACT["prerequisites"][
        "corrected_finite_range_p12_summary_sha256"
    ]
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        errors.append(
            "p12_summary SHA-256 must be "
            f"{expected_sha256!r}, not {actual_sha256!r}"
        )
    _validate_exact(summary, EXPECTED_P12_SUMMARY, "p12_summary", errors)
    if errors:
        raise T8ScalarContractError(errors)


def validate_t4_receipt(raw: bytes, receipt: Any) -> None:
    errors: list[str] = []
    expected_sha256 = EXPECTED_CONTRACT["prerequisites"][
        "corrected_finite_range_receipt_sha256"
    ]
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        errors.append(
            "t4_receipt SHA-256 must be "
            f"{expected_sha256!r}, not {actual_sha256!r}"
        )
    _validate_exact(receipt, EXPECTED_T4_RECEIPT, "t4_receipt", errors)
    if errors:
        raise T8ScalarContractError(errors)


def load_and_validate(
    path: Path,
    p12_summary_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    _, contract = _load_json(path)
    result = validate_contract(contract)
    raw, summary = _load_json(p12_summary_path)
    validate_p12_summary(raw, summary)
    raw, receipt = _load_json(receipt_path)
    validate_t4_receipt(raw, receipt)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the frozen T8 scalar frontier contract."
    )
    parser.add_argument("contract", type=Path)
    parser.add_argument("--p12-summary", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    try:
        result = load_and_validate(args.contract, args.p12_summary, args.receipt)
    except T8ScalarContractError as error:
        for message in error.errors:
            print(f"error: {message}", file=sys.stderr)
        return 2

    rendered = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.out is None:
        print(rendered, end="")
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
