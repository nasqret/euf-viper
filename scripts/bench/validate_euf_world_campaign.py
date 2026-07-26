#!/usr/bin/env python3
"""Validate the machine-readable EUF world-leader campaign contract."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "euf-viper.world-leader-campaign.v1"
TOP_LEVEL_KEYS = {
    "schema_version",
    "campaign_id",
    "status",
    "objective",
    "scope",
    "comparators",
    "benchmark_space",
    "metric_taxonomy",
    "score_policy",
    "agile_funnel",
    "technical_lanes",
    "compute_policy",
    "victory_contract",
    "reporting",
    "forbidden",
}
MANDATORY_COMPARATORS = {
    "yices2",
    "z3-default",
    "z3-sat-euf",
    "cvc5",
    "opensmt",
}
METRIC_GROUPS = {
    "validity",
    "coverage",
    "latency",
    "tail",
    "resources",
    "proof_and_model_quality",
    "robustness",
    "feature_surface",
}
VICTORY_GATES = {
    "V0_validity",
    "V1_official_coverage",
    "V2_full_coverage",
    "V3_time",
    "V4_resources",
    "V5_generalization",
    "V6_quality",
    "claim",
}


class ContractError(ValueError):
    """Raised when the campaign contract is incomplete or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_exact_keys(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    require(type(value) is dict, f"{context} must be an object")
    actual = set(value)
    require(actual == keys, f"{context} keys differ: {sorted(actual ^ keys)}")
    return value


def require_string(value: Any, context: str) -> str:
    require(type(value) is str and value == value.strip() and value, f"{context} must be a non-empty trimmed string")
    return value


def require_string_list(value: Any, context: str, *, minimum: int = 1) -> list[str]:
    require(type(value) is list and len(value) >= minimum, f"{context} must contain at least {minimum} entries")
    result = [require_string(item, f"{context}[{index}]") for index, item in enumerate(value)]
    require(len(set(result)) == len(result), f"{context} contains duplicates")
    return result


def validate_contract(data: Any) -> dict[str, Any]:
    root = require_exact_keys(data, TOP_LEVEL_KEYS, "contract")
    require(root["schema_version"] == SCHEMA_VERSION, "unsupported schema_version")
    require_string(root["campaign_id"], "campaign_id")
    require_string(root["status"], "status")
    require_string(root["objective"], "objective")

    scope = root["scope"]
    require(type(scope) is dict, "scope must be an object")
    for key in ("primary_logic", "primary_mode", "candidate_branch", "candidate_revision", "language"):
        require_string(scope.get(key), f"scope.{key}")
    require(scope["primary_logic"] == "QF_UF", "scope.primary_logic must be QF_UF")
    revision = scope["candidate_revision"]
    require(len(revision) == 40 and all(c in "0123456789abcdef" for c in revision), "candidate_revision must be a lowercase 40-digit SHA-1")
    require_string_list(scope.get("secondary_modes"), "scope.secondary_modes")
    require_string_list(scope.get("explicitly_separate"), "scope.explicitly_separate")

    comparators = root["comparators"]
    require(type(comparators) is dict, "comparators must be an object")
    mandatory = comparators.get("mandatory")
    require(type(mandatory) is list, "comparators.mandatory must be a list")
    comparator_ids: list[str] = []
    for index, comparator in enumerate(mandatory):
        require(type(comparator) is dict, f"comparators.mandatory[{index}] must be an object")
        require(set(comparator) == {"id", "version", "role"}, f"comparators.mandatory[{index}] has invalid keys")
        comparator_ids.append(require_string(comparator["id"], f"comparators.mandatory[{index}].id"))
        require_string(comparator["version"], f"comparators.mandatory[{index}].version")
        require_string(comparator["role"], f"comparators.mandatory[{index}].role")
    require(set(comparator_ids) == MANDATORY_COMPARATORS, "mandatory comparator set is incomplete")
    require(len(comparator_ids) == len(set(comparator_ids)), "mandatory comparator ids are not unique")
    require_string_list(comparators.get("census_before_final_claim"), "comparators.census_before_final_claim")
    require_string(comparators.get("pinning"), "comparators.pinning")

    benchmark = root["benchmark_space"]
    require(type(benchmark) is dict, "benchmark_space must be an object")
    budgets = benchmark.get("budgets_s")
    require(type(budgets) is list and budgets, "benchmark_space.budgets_s must be a non-empty list")
    normalized_budgets: list[float] = []
    for index, budget in enumerate(budgets):
        require(type(budget) in {int, float}, f"budgets_s[{index}] must be numeric")
        value = float(budget)
        require(math.isfinite(value) and value > 0, f"budgets_s[{index}] must be finite and positive")
        normalized_budgets.append(value)
    require(normalized_budgets == sorted(set(normalized_budgets)), "budgets_s must be unique and increasing")
    require({2.0, 60.0, 1200.0}.issubset(normalized_budgets), "primary 2/60/1200 second budgets are mandatory")
    corpora = benchmark.get("corpora")
    require(type(corpora) is list and len(corpora) >= 5, "benchmark_space.corpora is incomplete")
    corpus_ids = [require_string(item.get("id") if type(item) is dict else None, f"benchmark_space.corpora[{i}].id") for i, item in enumerate(corpora)]
    require(len(corpus_ids) == len(set(corpus_ids)), "corpus ids are not unique")
    require_string_list(benchmark.get("required_families"), "benchmark_space.required_families")
    require(set(require_string_list(benchmark.get("required_status_strata"), "benchmark_space.required_status_strata")) == {"sat", "unsat"}, "status strata must be sat and unsat")
    require_string_list(benchmark.get("required_structural_strata"), "benchmark_space.required_structural_strata", minimum=10)

    metrics = root["metric_taxonomy"]
    require(type(metrics) is dict and set(metrics) == METRIC_GROUPS, "metric_taxonomy groups are incomplete")
    all_metrics: list[str] = []
    for group in sorted(METRIC_GROUPS):
        all_metrics.extend(require_string_list(metrics[group], f"metric_taxonomy.{group}"))
    require(len(all_metrics) == len(set(all_metrics)), "metric identifiers must be globally unique")

    score = root["score_policy"]
    require(type(score) is dict, "score_policy must be an object")
    for key in (
        "candidate_id",
        "coverage_index",
        "lower_is_better_index",
        "candidate_speedup_over_comparator",
        "candidate_required_improvement",
        "primary_performance_index",
        "common_speed_index",
        "resource_index",
        "feature_index",
        "no_compensation_rule",
        "world_leader_label",
    ):
        require_string(score.get(key), f"score_policy.{key}")
    require_string_list(score.get("panel_identity"), "score_policy.panel_identity", minimum=8)

    funnel = root["agile_funnel"]
    require(type(funnel) is list and len(funnel) == 7, "agile_funnel must contain A0 through A6")
    require([item.get("id") for item in funnel if type(item) is dict] == [f"A{i}" for i in range(7)], "agile_funnel ids must be ordered A0 through A6")
    for index, stage in enumerate(funnel):
        require(type(stage) is dict, f"agile_funnel[{index}] must be an object")
        require(set(stage) == {"id", "name", "maximum_wall_minutes", "requirements"}, f"agile_funnel[{index}] has invalid keys")
        require_string(stage["name"], f"agile_funnel[{index}].name")
        cap = stage["maximum_wall_minutes"]
        require(cap is None or (type(cap) is int and cap > 0), f"agile_funnel[{index}].maximum_wall_minutes is invalid")
        require_string_list(stage["requirements"], f"agile_funnel[{index}].requirements")

    lanes = root["technical_lanes"]
    require(type(lanes) is list and len(lanes) == 11, "technical_lanes must contain L0 through L10")
    require([lane.get("id") for lane in lanes if type(lane) is dict] == [f"L{i}" for i in range(11)], "technical_lanes ids must be ordered L0 through L10")
    require([lane.get("rank") for lane in lanes if type(lane) is dict] == list(range(11)), "technical_lanes ranks must be contiguous")
    for index, lane in enumerate(lanes):
        require(type(lane) is dict, f"technical_lanes[{index}] must be an object")
        require(set(lane) == {"id", "rank", "name", "status", "targets", "mechanisms", "next_falsifier", "promotion_gate"}, f"technical_lanes[{index}] has invalid keys")
        require_string(lane["name"], f"technical_lanes[{index}].name")
        require_string(lane["status"], f"technical_lanes[{index}].status")
        require_string_list(lane["targets"], f"technical_lanes[{index}].targets")
        require_string_list(lane["mechanisms"], f"technical_lanes[{index}].mechanisms")
        require_string(lane["next_falsifier"], f"technical_lanes[{index}].next_falsifier")
        require_string(lane["promotion_gate"], f"technical_lanes[{index}].promotion_gate")

    compute = root["compute_policy"]
    require(type(compute) is dict and type(compute.get("Helios")) is dict, "compute_policy.Helios must be an object")
    require(compute["Helios"].get("account") == "plgccaiautore2026-cpu", "Helios CPU account is not the active project account")
    require("No GPU timing claims" in str(compute["Helios"].get("GPU_policy")), "Helios GPU timing separation is mandatory")
    require_string_list(compute.get("resource_rules"), "compute_policy.resource_rules")

    require_exact_keys(root["victory_contract"], VICTORY_GATES, "victory_contract")
    for key, value in root["victory_contract"].items():
        require_string(value, f"victory_contract.{key}")
    require(type(root["reporting"]) is dict, "reporting must be an object")
    require_string_list(root["reporting"].get("after_each_broad_step"), "reporting.after_each_broad_step", minimum=7)
    forbidden = require_string_list(root["forbidden"], "forbidden", minimum=10)
    require(any("routing" in item and "family" in item for item in forbidden), "identity-routing prohibition is missing")
    require(any("mixing_revisions" in item for item in forbidden), "revision-isolation prohibition is missing")
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", type=Path)
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.contract.read_text(encoding="utf-8"))
        validate_contract(data)
    except (OSError, json.JSONDecodeError, ContractError) as error:
        print(f"invalid campaign contract: {error}", file=sys.stderr)
        return 1
    print(f"valid campaign contract: {args.contract}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
