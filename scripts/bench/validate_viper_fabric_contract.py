#!/usr/bin/env python3
"""Validate the frozen Viper Fabric execution contract."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


TOP_LEVEL_FIELDS = {
    "schema_version",
    "campaign_id",
    "status",
    "objective",
    "implementation",
    "reference",
    "architecture",
    "stages",
    "promotion_ladder",
    "victory",
    "forbidden",
    "user_control",
}

EXPECTED_IMPLEMENTATION: dict[str, Any] = {
    "branch": "perf-viper-fabric",
    "base_revision": "27b3ff4",
    "audited_comparator_revision": "30828a4f0c1e7e478a9c6f406ccb245eeefc4961",
    "language": "Rust",
    "default_behavior_change_authorized": False,
    "migration_authorized": False,
}

EXPECTED_REFERENCE: dict[str, Any] = {
    "full_instances": 7503,
    "official_instances": 3521,
    "budgets_s": [2, 60, 1200],
    "yices2": {
        "version": "2.7.0",
        "full_solves": {"2": 7445, "60": 7500, "1200": 7503},
        "official_solves": {"2": 3490, "60": 3518, "1200": 3521},
        "full_60_median_s": 0.01714645099127665,
        "full_60_p95_s": 0.18972565890871912,
    },
    "euf_viper": {
        "full_solves": {"2": 7269, "60": 7480, "1200": 7502},
        "official_solves": {"2": 3400, "60": 3508, "1200": 3520},
        "full_60_median_s": 0.026773738994961604,
        "full_60_p95_s": 1.2338475229160384,
    },
}

EXPECTED_ARCHITECTURE: dict[str, Any] = {
    "stable_unit": "typed_formula_local_interference_component",
    "shared_state": [
        "stable_term_ids",
        "stable_atom_ids",
        "stable_component_ids",
        "source_boolean_roots",
        "typed_function_applications",
        "representation_neutral_proof_events",
    ],
    "fixed_engines": [
        {"id": "E0", "name": "sparse_eager_sat", "status": "audited_control"},
        {
            "id": "E1",
            "name": "rollback_euf",
            "status": "fixed_reference_required",
        },
        {
            "id": "E2",
            "name": "canonical_partition_cdcl",
            "status": "implementation_active",
        },
        {
            "id": "E3",
            "name": "canonical_quotient_frontier",
            "status": "scalar_census_required",
        },
    ],
    "cross_layer_mechanisms": [
        {
            "id": "X1",
            "name": "theory_extended_resolution",
            "status": "opportunity_census_required",
        },
        {
            "id": "X2",
            "name": "repeated_semantic_symmetry_simplification",
            "status": "opportunity_census_required",
        },
        {
            "id": "X3",
            "name": "component_local_proof_system_migration",
            "status": "forbidden_until_fixed_arm_gate",
        },
    ],
}

EXPECTED_STAGE_NAMES = {
    "F0": "semantic_substrate",
    "F1": "canonical_partition_cdcl",
    "F2": "canonical_quotient_frontier",
    "F3": "theory_extended_resolution",
    "F4": "repeated_semantic_symmetry_simplification",
    "F5": "component_local_migration",
}

EXPECTED_STAGE_DELIVERABLES = {
    "F0": [
        "compact_typed_ir_adapter",
        "stable_component_decomposition",
        "representation_neutral_telemetry",
        "independent_event_checker",
    ],
    "F1": [
        "canonical_existing_or_new_class_decisions",
        "rollback_partition_and_disequality_state",
        "watched_native_clauses",
        "congruence_table_propagation",
        "first_uip_native_nogood_learning",
        "sat_model_reconstruction",
        "unsat_partition_proof",
    ],
    "F2": [
        "canonical_residual_state_key",
        "memoized_frontier_transitions",
        "checked_sat_model",
        "checked_unsat_cover_dag",
    ],
    "F3": [
        "repeated_explanation_motif_census",
        "checked_extension_definitions",
        "factored_learned_clauses",
        "proof_elaboration",
    ],
    "F4": [
        "typed_semantic_automorphism_witness",
        "connectivity_ordered_unit_binary_breaks",
        "simplify_break_repeat_schedule",
        "proof_replay",
    ],
    "F5": [
        "deterministic_semantic_tick_scheduler",
        "one_way_component_migration",
        "checked_bridge_lemmas",
        "fixed_arm_and_oracle_ablation",
    ],
}

# A minimum may increase and a maximum may decrease. Exact gates encode
# zero-tolerance, required booleans, corpus sizes, or fixed semantics.
STAGE_GATE_POLICIES: dict[str, dict[str, tuple[str, Any]]] = {
    "F0": {
        "full_shadow_sources": ("minimum", 7503),
        "semantic_mismatches_allowed": ("exact", 0),
        "off_mode_trace": ("exact", "byte_identical"),
        "p95_overhead_ucb": ("maximum", 1.01),
    },
    "F1": {
        "exhaustive_domain_max": ("minimum", 4),
        "generated_differential_cases": ("minimum", 1000000),
        "wrong_or_unchecked_results_allowed": ("exact", 0),
        "target_geometric_speedup_lcb": ("minimum", 1.20),
        "anti_target_p95_overhead_ucb": ("maximum", 1.01),
        "unique_timeout_conversions_min": ("minimum", 1),
    },
    "F2": {
        "qg7_targets_within_state_cap_min": ("minimum", 10),
        "qg7_targets": ("exact", 12),
        "state_cap": ("maximum", 1000000),
        "source_complete_population_min": ("minimum", 200),
        "source_complete_population_total": ("exact", 261),
        "build_cost_ratio_max": ("maximum", 0.10),
        "simd_lane_occupancy_before_simd_min": ("minimum", 0.70),
    },
    "F3": {
        "conflict_weighted_motif_coverage_min": ("minimum", 0.25),
        "projected_literal_reduction_min": ("minimum", 0.20),
        "target_geometric_speedup_lcb": ("minimum", 1.10),
        "anti_target_p95_overhead_ucb": ("maximum", 1.01),
        "generic_factoring_control_required": ("exact", True),
    },
    "F4": {
        "all_emitted_clause_width_max": ("maximum", 2),
        "target_par2_speedup_lcb": ("minimum", 1.10),
        "anti_target_p95_overhead_ucb": ("maximum", 1.01),
        "generic_sat_symmetry_control_required": ("exact", True),
    },
    "F5": {
        "beats_every_fixed_engine": ("exact", True),
        "bridge_replay_failures_allowed": ("exact", 0),
        "family_or_identity_features_allowed": ("exact", 0),
    },
}

F5_PREREQUISITE_POLICIES: dict[str, tuple[str, Any]] = {
    "migration_eligible_fixed_engines_min": ("minimum", 2),
    "oracle_headroom_lcb_min": ("minimum", 0.10),
    "balanced_accuracy_lcb_min": ("minimum", 0.80),
    "telemetry_p95_overhead_ucb": ("maximum", 1.01),
}

EXPECTED_PROMOTION_LADDER = [
    "unit_and_exhaustive",
    "generated_differential",
    "target_abba",
    "anti_target_controls",
    "hot_400",
    "full_7503_first_cpu",
    "full_7503_second_cpu",
    "official_3521",
    "sealed_holdout",
]

VICTORY_GATE_POLICIES: dict[str, tuple[str, Any]] = {
    "minimum_common_geometric_speedup_over_every_comparator": ("minimum", 1.05),
    "minimum_common_total_speedup_over_every_comparator": ("minimum", 1.05),
    "minimum_timeout_charged_speedup_over_every_comparator": ("minimum", 1.05),
    "wrong_answers_allowed": ("exact", 0),
    "errors_allowed": ("exact", 0),
    "missing_rows_allowed": ("exact", 0),
    "independent_sat_model_checks_required": ("exact", True),
    "independent_unsat_proof_checks_required": ("exact", True),
    "cpu_classes_required": ("minimum", 2),
    "independent_full_runs_required": ("minimum", 2),
    "held_out_required": ("exact", True),
}

EXPECTED_FULL_SOLVE_FLOORS = {"2": 7446, "60": 7501, "1200": 7503}
EXPECTED_OFFICIAL_SOLVE_FLOORS = {"2": 3491, "60": 3519, "1200": 3521}

REQUIRED_FORBIDDEN = {
    "external_solver_fallback_as_victory",
    "source_path_routing",
    "family_routing",
    "benchmark_name_routing",
    "content_hash_routing",
    "expected_status_routing",
    "prior_runtime_routing",
    "unvalidated_sat",
    "unchecked_unsat",
    "partial_corpus_promotion",
    "combining_failed_or_unmeasured_mechanisms",
}

EXPECTED_USER_CONTROL: dict[str, Any] = {
    "decision_packet_after_each_isolated_mechanism": True,
    "user_approval_before_composition": True,
    "user_approval_before_default_change": True,
}


class ViperFabricContractError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(errors[0] if errors else "invalid Viper Fabric contract")


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
    rendered = child if type(child) is str else repr(child)
    return f"{parent}.{rendered}" if parent else str(rendered)


def _validate_object_fields(
    value: Any,
    expected_fields: set[str],
    path: str,
    errors: list[str],
) -> dict[str, Any] | None:
    if type(value) is not dict:
        errors.append(f"{path} must be an object, not {_json_type_name(value)}")
        return None

    actual_fields = set(value)
    for field in sorted(expected_fields - actual_fields):
        errors.append(f"{_field_path(path, field)} is required")
    for field in sorted(actual_fields - expected_fields, key=repr):
        errors.append(f"{_field_path(path, field)} is not allowed")
    return value


def _validate_exact(
    actual: Any,
    expected: Any,
    path: str,
    errors: list[str],
) -> None:
    if type(actual) is not type(expected):
        errors.append(
            f"{path} must have JSON type {_json_type_name(expected)}, "
            f"not {_json_type_name(actual)}"
        )
        return

    if type(expected) is dict:
        actual_fields = set(actual)
        expected_fields = set(expected)
        for field in sorted(expected_fields - actual_fields):
            errors.append(f"{_field_path(path, field)} is required")
        for field in sorted(actual_fields - expected_fields, key=repr):
            errors.append(f"{_field_path(path, field)} is not allowed")
        for field, expected_value in expected.items():
            if field in actual:
                _validate_exact(
                    actual[field],
                    expected_value,
                    _field_path(path, field),
                    errors,
                )
        return

    if type(expected) is list:
        if len(actual) != len(expected):
            errors.append(f"{path} must contain exactly {len(expected)} entries")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            _validate_exact(actual_item, expected_item, f"{path}[{index}]", errors)
        return

    if type(actual) is float and not math.isfinite(actual):
        errors.append(f"{path} must be finite")
    elif actual != expected:
        errors.append(f"{path} must be {expected!r}, not {actual!r}")


def _validate_policy_value(
    actual: Any,
    policy: str,
    baseline: Any,
    path: str,
    errors: list[str],
) -> None:
    if type(actual) is not type(baseline):
        errors.append(
            f"{path} must have JSON type {_json_type_name(baseline)}, "
            f"not {_json_type_name(actual)}"
        )
        return
    if type(actual) is float and not math.isfinite(actual):
        errors.append(f"{path} must be finite")
        return

    if policy == "exact":
        if actual != baseline:
            errors.append(f"{path} must be {baseline!r}, not {actual!r}")
    elif policy == "minimum":
        if actual < baseline:
            errors.append(
                f"{path} must be at least {baseline!r}; {actual!r} weakens the gate"
            )
    elif policy == "maximum":
        if actual > baseline:
            errors.append(
                f"{path} must be at most {baseline!r}; {actual!r} weakens the gate"
            )
    else:  # pragma: no cover - policies are module constants
        raise AssertionError(f"unknown validation policy {policy!r}")


def _validate_gate_object(
    value: Any,
    policies: dict[str, tuple[str, Any]],
    path: str,
    errors: list[str],
) -> None:
    gate = _validate_object_fields(value, set(policies), path, errors)
    if gate is None:
        return
    for field, (policy, baseline) in policies.items():
        if field in gate:
            _validate_policy_value(
                gate[field], policy, baseline, _field_path(path, field), errors
            )


def _validate_stages(value: Any, errors: list[str]) -> list[str]:
    expected_ids = list(EXPECTED_STAGE_NAMES)
    if type(value) is not list:
        errors.append(f"stages must be an array, not {_json_type_name(value)}")
        return []

    records_by_id: dict[str, dict[str, Any]] = {}
    observed_ids: list[str] = []
    for index, stage in enumerate(value):
        path = f"stages[{index}]"
        if type(stage) is not dict:
            errors.append(f"{path} must be an object, not {_json_type_name(stage)}")
            continue
        stage_id = stage.get("id")
        if type(stage_id) is not str or not stage_id:
            errors.append(f"{path}.id must be a non-empty string")
            continue
        observed_ids.append(stage_id)
        if stage_id in records_by_id:
            errors.append(f"stages contains duplicate id {stage_id!r}")
        else:
            records_by_id[stage_id] = stage

    if observed_ids != expected_ids:
        errors.append(f"stage ids must equal {expected_ids!r} in that order")

    for stage_id in expected_ids:
        stage = records_by_id.get(stage_id)
        if stage is None:
            continue
        path = f"stages[{stage_id}]"
        expected_fields = {"id", "name", "deliverables", "gates"}
        if stage_id == "F5":
            expected_fields.add("prerequisites")
        _validate_object_fields(stage, expected_fields, path, errors)
        _validate_exact(stage.get("id"), stage_id, f"{path}.id", errors)
        _validate_exact(
            stage.get("name"), EXPECTED_STAGE_NAMES[stage_id], f"{path}.name", errors
        )
        _validate_exact(
            stage.get("deliverables"),
            EXPECTED_STAGE_DELIVERABLES[stage_id],
            f"{path}.deliverables",
            errors,
        )
        _validate_gate_object(
            stage.get("gates"),
            STAGE_GATE_POLICIES[stage_id],
            f"{path}.gates",
            errors,
        )
        if stage_id == "F5":
            _validate_gate_object(
                stage.get("prerequisites"),
                F5_PREREQUISITE_POLICIES,
                f"{path}.prerequisites",
                errors,
            )

    f0 = records_by_id.get("F0")
    if type(f0) is dict and type(f0.get("gates")) is dict:
        shadow_sources = f0["gates"].get("full_shadow_sources")
        if type(shadow_sources) is int and shadow_sources > EXPECTED_REFERENCE[
            "full_instances"
        ]:
            errors.append(
                "stages[F0].gates.full_shadow_sources cannot exceed "
                "reference.full_instances"
            )

    f2 = records_by_id.get("F2")
    if type(f2) is dict and type(f2.get("gates")) is dict:
        gates = f2["gates"]
        _validate_minimum_not_above_total(
            gates,
            "qg7_targets_within_state_cap_min",
            "qg7_targets",
            "stages[F2].gates",
            errors,
        )
        _validate_minimum_not_above_total(
            gates,
            "source_complete_population_min",
            "source_complete_population_total",
            "stages[F2].gates",
            errors,
        )

    return observed_ids


def _validate_minimum_not_above_total(
    container: dict[str, Any],
    minimum_field: str,
    total_field: str,
    path: str,
    errors: list[str],
) -> None:
    minimum = container.get(minimum_field)
    total = container.get(total_field)
    if type(minimum) is int and type(total) is int and minimum > total:
        errors.append(
            f"{_field_path(path, minimum_field)} cannot exceed "
            f"{_field_path(path, total_field)}"
        )


def _validate_solve_floors(
    value: Any,
    expected: dict[str, int],
    total: int,
    path: str,
    errors: list[str],
) -> None:
    floors = _validate_object_fields(value, set(expected), path, errors)
    if floors is None:
        return
    for budget, baseline in expected.items():
        if budget not in floors:
            continue
        actual = floors[budget]
        field_path = _field_path(path, budget)
        _validate_policy_value(actual, "minimum", baseline, field_path, errors)
        if type(actual) is int and actual > total:
            errors.append(f"{field_path} cannot exceed corpus size {total}")


def _validate_victory(value: Any, errors: list[str]) -> None:
    expected_fields = set(VICTORY_GATE_POLICIES) | {
        "full_min_solves",
        "official_min_solves",
    }
    victory = _validate_object_fields(value, expected_fields, "victory", errors)
    if victory is None:
        return

    _validate_solve_floors(
        victory.get("full_min_solves"),
        EXPECTED_FULL_SOLVE_FLOORS,
        EXPECTED_REFERENCE["full_instances"],
        "victory.full_min_solves",
        errors,
    )
    _validate_solve_floors(
        victory.get("official_min_solves"),
        EXPECTED_OFFICIAL_SOLVE_FLOORS,
        EXPECTED_REFERENCE["official_instances"],
        "victory.official_min_solves",
        errors,
    )
    for field, (policy, baseline) in VICTORY_GATE_POLICIES.items():
        if field in victory:
            _validate_policy_value(
                victory[field], policy, baseline, f"victory.{field}", errors
            )


def _validate_forbidden(value: Any, errors: list[str]) -> None:
    if type(value) is not list:
        errors.append(f"forbidden must be an array, not {_json_type_name(value)}")
        return
    if any(type(item) is not str or not item for item in value):
        errors.append("forbidden must contain only non-empty strings")
        return
    observed = set(value)
    if len(observed) != len(value):
        errors.append("forbidden must not contain duplicate entries")
    missing = REQUIRED_FORBIDDEN - observed
    if missing:
        errors.append(f"forbidden is missing required entries {sorted(missing)!r}")


def validate_contract(contract: Any) -> dict[str, Any]:
    errors: list[str] = []
    root = _validate_object_fields(contract, TOP_LEVEL_FIELDS, "contract", errors)
    if root is None:
        raise ViperFabricContractError(errors)

    exact_top_level = {
        "schema_version": 1,
        "campaign_id": "viper-fabric-2026-07",
        "status": "implementation_active_migration_forbidden",
        "objective": (
            "Build a standalone single-core proof-reconfigurable QF_UF solver that "
            "beats Yices2, Z3, cvc5, and OpenSMT without external fallback or "
            "benchmark-identity routing."
        ),
    }
    for field, expected in exact_top_level.items():
        if field in root:
            _validate_exact(root[field], expected, field, errors)

    for field, expected in (
        ("implementation", EXPECTED_IMPLEMENTATION),
        ("reference", EXPECTED_REFERENCE),
        ("architecture", EXPECTED_ARCHITECTURE),
        ("promotion_ladder", EXPECTED_PROMOTION_LADDER),
        ("user_control", EXPECTED_USER_CONTROL),
    ):
        if field in root:
            _validate_exact(root[field], expected, field, errors)

    stage_ids = _validate_stages(root.get("stages"), errors)
    _validate_victory(root.get("victory"), errors)
    _validate_forbidden(root.get("forbidden"), errors)

    if errors:
        raise ViperFabricContractError(errors)

    implementation = root["implementation"]
    return {
        "campaign_id": root["campaign_id"],
        "default_behavior_change_authorized": implementation[
            "default_behavior_change_authorized"
        ],
        "forbidden_count": len(root["forbidden"]),
        "migration_authorized": implementation["migration_authorized"],
        "stages": stage_ids,
        "status": root["status"],
        "valid": True,
    }


def load_and_validate(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        contract = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise ViperFabricContractError([f"cannot load {path}: {error}"]) from error
    return validate_contract(contract)


def _render_summary(summary: dict[str, Any]) -> str:
    return json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def _write_summary(summary: dict[str, Any], output: Path | None) -> None:
    rendered = _render_summary(summary)
    if output is None:
        print(rendered, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the frozen Viper Fabric execution contract."
    )
    parser.add_argument("contract", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    try:
        summary = load_and_validate(args.contract)
    except ViperFabricContractError as error:
        summary = {
            "error_count": len(error.errors),
            "errors": error.errors,
            "valid": False,
        }
        try:
            _write_summary(summary, args.out)
        except OSError as output_error:
            print(
                _render_summary(
                    {
                        "error_count": 1,
                        "errors": [f"cannot write summary: {output_error}"],
                        "valid": False,
                    }
                ),
                end="",
            )
        return 2

    try:
        _write_summary(summary, args.out)
    except OSError as error:
        print(
            _render_summary(
                {
                    "error_count": 1,
                    "errors": [f"cannot write summary: {error}"],
                    "valid": False,
                }
            ),
            end="",
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
