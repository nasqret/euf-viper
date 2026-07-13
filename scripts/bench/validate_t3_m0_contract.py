#!/usr/bin/env python3
"""Validate the frozen T3 M0 component-pressure telemetry contract."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


REQUIRED_ARMS = {
    "current_eager",
    "whole_instance_conflict_only_rollback",
    "dynamic_ackermann",
    "model_directed_cuts",
}
REQUIRED_S0_BEFORE = {
    "finite_routing",
    "ackermann_expansion",
    "refinement",
    "rollback_setup",
    "sat_search",
}
REQUIRED_S0_FEATURES = {
    "typed_term_application_function_constant_counts",
    "arity_and_depth_histograms",
    "equality_graph_statistics",
    "base_cnf_size_and_cross_component_sharing",
    "projected_ackermann_cost",
    "capped_chordal_fill",
    "proved_domain_table_clique_and_hall_statistics",
}
REQUIRED_S1_FEATURES = {
    "component_attributed_assignments_levels_backtracks_conflicts",
    "invalid_models_and_repeated_signatures",
    "bounded_validator_cpu_share",
    "refinement_cuts_emitted_and_accepted",
    "projected_versus_realized_fill",
}
REQUIRED_FORBIDDEN = {
    "source_path",
    "family",
    "lineage",
    "taxonomy",
    "manifest_index",
    "raw_or_normalized_hash",
    "benchmark_or_symbol_name",
    "expected_status",
    "final_result",
    "final_runtime",
    "winning_arm",
    "post_checkpoint_events",
}
REQUIRED_LABEL_STRATA = {
    "GRAPH_32",
    "DOMAIN7_TABLE",
    "FINITE_HALL",
    "DEEP_LET_512",
}
REQUIRED_SPLIT_CLOSURE = {
    "family",
    "generator_lineage",
    "raw_duplicates",
    "normalized_duplicates",
}


class T3M0ContractError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(errors[0] if errors else "invalid T3 M0 contract")


def _matches(actual: Any, expected: Any) -> bool:
    return type(actual) is type(expected) and actual == expected


def _object(root: dict[str, Any], field: str, errors: list[str]) -> dict[str, Any]:
    value = root.get(field)
    if not isinstance(value, dict):
        errors.append(f"{field} must be an object")
        return {}
    return value


def _exact_set(value: Any, expected: set[str], field: str, errors: list[str]) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        errors.append(f"{field} must be a list of strings")
        return
    observed = set(value)
    if len(observed) != len(value):
        errors.append(f"{field} must not contain duplicates")
    if observed != expected:
        errors.append(f"{field} must equal {sorted(expected)!r}")


def _minimum_set(value: Any, required: set[str], field: str, errors: list[str]) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        errors.append(f"{field} must be a list of strings")
        return
    observed = set(value)
    if len(observed) != len(value):
        errors.append(f"{field} must not contain duplicates")
    missing = required - observed
    if missing:
        errors.append(f"{field} is missing required entries {sorted(missing)!r}")


def validate_contract(contract: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(contract, dict):
        raise T3M0ContractError(["contract root must be an object"])

    if not _matches(contract.get("schema_version"), 1):
        errors.append("schema_version must be 1")
    if contract.get("campaign_id") != "t3-m0-component-pressure-v1":
        errors.append("campaign_id must be t3-m0-component-pressure-v1")
    if contract.get("status") != "preregistered_design_migration_forbidden":
        errors.append("status must keep migration forbidden")

    scope = _object(contract, "scope", errors)
    expected_scope = {
        "logic": "QF_UF",
        "source_census": 7503,
        "heavy_compute_site": "WMI",
        "timeout_s": 60,
        "par2_miss_s": 120,
    }
    for field, expected in expected_scope.items():
        if not _matches(scope.get(field), expected):
            errors.append(f"scope.{field} must be {expected!r}")

    prerequisites = _object(contract, "prerequisites", errors)
    if not _matches(prerequisites.get("minimum_migration_eligible_fixed_arms"), 2):
        errors.append("M0 requires exactly two or more migration-eligible fixed arms")
    if prerequisites.get("fixed_arm_correctness_and_timing_gate_required") is not True:
        errors.append("fixed-arm correctness and timing gates must be required")
    if not _matches(prerequisites.get("minimum_oracle_headroom_lcb"), 0.1):
        errors.append("minimum oracle-headroom LCB must be 0.1")
    if not _matches(prerequisites.get("confidence"), 0.95):
        errors.append("prerequisite confidence must be 0.95")

    evidence = _object(contract, "preliminary_evidence", errors)
    if not _matches(evidence.get("source_count"), 24):
        errors.append("preliminary evidence must remain the frozen 24-source panel")
    if evidence.get("family_confounded") is not True:
        errors.append("preliminary evidence must remain marked family-confounded")
    if evidence.get("decision") != "insufficient_and_below_gate":
        errors.append("preliminary evidence cannot authorize M0")
    best_fixed = evidence.get("best_fixed_par2_s")
    oracle = evidence.get("oracle_par2_s")
    headroom = evidence.get("oracle_headroom")
    if not all(type(value) in {int, float} for value in (best_fixed, oracle, headroom)):
        errors.append("preliminary PAR-2 values and headroom must be numeric")
    elif oracle <= 0:
        errors.append("preliminary oracle PAR-2 must be positive")
    else:
        computed = best_fixed / oracle - 1.0
        if not math.isclose(headroom, computed, rel_tol=0.0, abs_tol=5e-5):
            errors.append("preliminary oracle_headroom does not match PAR-2 totals")
        if headroom >= 0.1:
            errors.append("preliminary evidence must remain below the M0 headroom gate")

    _exact_set(contract.get("arms"), REQUIRED_ARMS, "arms", errors)

    unit = _object(contract, "stable_unit", errors)
    if unit.get("kind") != "typed_formula_local_component":
        errors.append("stable_unit.kind must be typed_formula_local_component")
    if unit.get("ownership_freeze") != (
        "after_typed_parse_before_representation_rewrite"
    ):
        errors.append("stable component ownership must freeze before representation rewrite")
    if unit.get("content_hash_is_runtime_feature") is not False:
        errors.append("content hashes must not be runtime features")

    checkpoints = _object(contract, "checkpoints", errors)
    s0 = _object(checkpoints, "S0", errors)
    if s0.get("position") != "after_typed_parse_and_representation_neutral_base_cnf":
        errors.append("S0 position is not representation-neutral")
    _exact_set(s0.get("before"), REQUIRED_S0_BEFORE, "checkpoints.S0.before", errors)
    _exact_set(
        s0.get("feature_groups"),
        REQUIRED_S0_FEATURES,
        "checkpoints.S0.feature_groups",
        errors,
    )

    s1 = _object(checkpoints, "S1", errors)
    if s1.get("position") != "identical_fixed_eager_shadow_prefix":
        errors.append("S1 must use an identical fixed eager shadow prefix")
    stop = _object(s1, "stop_at_first", errors)
    expected_caps = {
        "invalid_complete_model": 1,
        "conflicts": 4096,
        "theory_events": 65536,
        "budget_fraction": 0.005,
    }
    for field, expected in expected_caps.items():
        if not _matches(stop.get(field), expected):
            errors.append(f"checkpoints.S1.stop_at_first.{field} must be {expected!r}")
    _exact_set(
        s1.get("feature_groups"),
        REQUIRED_S1_FEATURES,
        "checkpoints.S1.feature_groups",
        errors,
    )
    _minimum_set(
        s1.get("excluded"),
        {"backend_lbd", "post_checkpoint_events"},
        "checkpoints.S1.excluded",
        errors,
    )

    _minimum_set(
        contract.get("forbidden_runtime_features"),
        REQUIRED_FORBIDDEN,
        "forbidden_runtime_features",
        errors,
    )

    measurement = _object(contract, "measurement", errors)
    if not _matches(measurement.get("repeats"), 4):
        errors.append("measurement.repeats must be 4")
    if measurement.get("order") != "balanced_williams":
        errors.append("measurement.order must be balanced_williams")
    labels = _object(measurement, "unique_label_rule", errors)
    expected_labels = {
        "coverage_dominance": True,
        "equal_coverage_minimum_median_advantage": 0.05,
        "minimum_same_direction_blocks": 3,
        "blocks": 4,
        "otherwise": "unresolved",
    }
    for field, expected in expected_labels.items():
        if not _matches(labels.get(field), expected):
            errors.append(f"measurement.unique_label_rule.{field} must be {expected!r}")
    if measurement.get("oracle_headroom_formula") != (
        "min_arm(sum_i_PAR2_i_arm)/sum_i(min_arm_PAR2_i_arm)-1"
    ):
        errors.append("coverage-aware oracle-headroom formula changed")

    population = _object(contract, "population", errors)
    if not _matches(population.get("s0_all_sources"), 7503):
        errors.append("S0 must cover all 7503 sources")
    _exact_set(
        population.get("label_strata"),
        REQUIRED_LABEL_STRATA,
        "population.label_strata",
        errors,
    )
    if not _matches(population.get("semantic_quantile_lineage_controls"), 512):
        errors.append("population must include 512 semantic lineage controls")
    if not _matches(population.get("maximum_label_panel_before_overlap"), 1762):
        errors.append("maximum pre-overlap label panel must be 1762")
    _exact_set(
        population.get("split_group_closure"),
        REQUIRED_SPLIT_CLOSURE,
        "population.split_group_closure",
        errors,
    )
    if not _matches(population.get("minimum_lineages_per_class_per_split"), 64):
        errors.append("every retained class needs 64 lineages per split")
    if population.get("sealed_evaluation_minimum") != "max(256,64*K)":
        errors.append("sealed evaluation minimum changed")
    if not _matches(population.get("sealed_unseen_families_minimum"), 3):
        errors.append("sealed evaluation needs at least three unseen families")

    classifier = _object(contract, "classifier", errors)
    if classifier.get("kind") != "deterministic_decision_tree":
        errors.append("M0 classifier must be a deterministic decision tree")
    if not _matches(classifier.get("maximum_depth"), 4):
        errors.append("M0 classifier maximum depth must be 4")
    if classifier.get("sealed_feature_selection") is not False:
        errors.append("sealed-set feature selection must be disabled")

    gates = _object(contract, "gates", errors)
    expected_gates = {
        "balanced_accuracy_cluster_bootstrap_lcb": 0.8,
        "telemetry_p95_ratio_ucb": 1.01,
        "telemetry_paired_blocks": 8,
        "semantic_trace": "byte_identical_off_on",
        "wrong_or_missing_or_hash_failures_allowed": 0,
        "leaked_split_groups_allowed": 0,
    }
    for field, expected in expected_gates.items():
        if not _matches(gates.get(field), expected):
            errors.append(f"gates.{field} must be {expected!r}")
    if contract.get("stop_rule") != "any_failed_prerequisite_or_gate_stops_before_migration":
        errors.append("stop_rule must stop before migration on any failed gate")

    if errors:
        raise T3M0ContractError(errors)
    return {
        "campaign_id": contract["campaign_id"],
        "status": contract["status"],
        "arms": sorted(REQUIRED_ARMS),
        "preliminary_oracle_headroom": headroom,
        "migration_authorized": False,
        "valid": True,
    }


def load_and_validate(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="ascii") as handle:
            contract = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise T3M0ContractError([f"cannot load {path}: {error}"]) from error
    return validate_contract(contract)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = load_and_validate(args.contract)
    except T3M0ContractError as error:
        for message in error.errors:
            print(f"error: {message}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        print(rendered, end="")
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
