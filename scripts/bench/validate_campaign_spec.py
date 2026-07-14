#!/usr/bin/env python3
"""Validate the preregistered best-overall QF_UF campaign specification."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


CERT_DIR = Path(__file__).resolve().parents[1] / "cert"
if str(CERT_DIR) not in sys.path:
    sys.path.insert(0, str(CERT_DIR))

from strict_artifacts import (  # noqa: E402
    StrictArtifactError,
    read_regular_nofollow,
    strict_json_loads,
)


REQUIRED_COMPARATORS = {"z3", "cvc5", "yices2", "opensmt"}
REQUIRED_BUDGETS = [2, 60, 1200]
REQUIRED_OBJECTIVES = {"V0", "V1", "V2", "V3", "V4"}
REQUIRED_STAGES = {"P0", "P1", "P2", "P3", "P4", "P5"}
REQUIRED_TRACKS = {
    "F0",
    "T0",
    "T1",
    "T2",
    "T3",
    "T4",
    "T5",
    "T6",
    "T7",
    "T8",
}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TOP_LEVEL_KEYS = {
    "schema_version",
    "campaign_id",
    "status",
    "scope",
    "baseline",
    "release_lock",
    "comparators",
    "corpora",
    "budgets_s",
    "objectives",
    "promotion_policy",
    "tracks",
    "stages",
    "unresolved_plan_disposition",
    "required_artifacts",
}


class CampaignSpecError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(errors[0] if errors else "invalid campaign specification")


def _keys(
    value: dict[str, Any],
    required: set[str],
    allowed: set[str],
    field: str,
    errors: list[str],
) -> None:
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - allowed)
    if missing or unknown:
        errors.append(
            f"{field} has incompatible keys: missing={missing!r}, unknown={unknown!r}"
        )


def _finite_number(value: Any) -> bool:
    return type(value) in {int, float} and math.isfinite(value)


def _objects(value: Any, field: str, errors: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        errors.append(f"{field} must be a list")
        return []
    result = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"{field}[{index}] must be an object")
        else:
            result.append(item)
    return result


def _unique_ids(
    records: list[dict[str, Any]], field: str, errors: list[str]
) -> set[str]:
    ids: set[str] = set()
    for index, record in enumerate(records):
        value = record.get("id")
        if not isinstance(value, str) or not value:
            errors.append(f"{field}[{index}].id must be a non-empty string")
        elif value in ids:
            errors.append(f"{field} contains duplicate id {value!r}")
        else:
            ids.add(value)
    return ids


def validate_spec(spec: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(spec, dict):
        raise CampaignSpecError(["campaign root must be an object"])

    _keys(spec, TOP_LEVEL_KEYS, TOP_LEVEL_KEYS, "campaign root", errors)

    if type(spec.get("schema_version")) is not int or spec["schema_version"] != 1:
        errors.append("schema_version must be 1")
    if not isinstance(spec.get("campaign_id"), str) or not spec["campaign_id"]:
        errors.append("campaign_id must be a non-empty string")
    if spec.get("status") not in {"draft", "ready_for_phase_0", "active", "closed"}:
        errors.append("status is not recognized")

    scope = spec.get("scope")
    if not isinstance(scope, dict):
        errors.append("scope must be an object")
    else:
        scope_keys = {
            "logic",
            "standalone_solver",
            "primary_resource_model",
            "heavy_compute_site",
            "cas_site",
        }
        _keys(scope, scope_keys, scope_keys, "scope", errors)
        if scope.get("logic") != "QF_UF":
            errors.append("scope.logic must be QF_UF")
        if scope.get("standalone_solver") is not True:
            errors.append("scope.standalone_solver must be true")
        if scope.get("primary_resource_model") != "single_core_cold_process":
            errors.append("primary resource model must be single_core_cold_process")

    baseline = spec.get("baseline")
    if not isinstance(baseline, dict):
        errors.append("baseline must be an object")
    else:
        baseline_keys = {
            "repository_head",
            "solver_revision",
            "binary_sha256",
            "reference_campaign",
            "reference_corpus",
            "reference_timeout_s",
            "sat_backend",
        }
        _keys(baseline, baseline_keys, baseline_keys, "baseline", errors)
        if not HEX40.fullmatch(str(baseline.get("repository_head", ""))):
            errors.append("baseline.repository_head must be a 40-digit Git hash")
        if not HEX40.fullmatch(str(baseline.get("solver_revision", ""))):
            errors.append("baseline.solver_revision must be a 40-digit Git hash")
        if not HEX64.fullmatch(str(baseline.get("binary_sha256", ""))):
            errors.append("baseline.binary_sha256 must be a SHA-256 digest")

    release_lock = spec.get("release_lock")
    if not isinstance(release_lock, dict):
        errors.append("release_lock must be an object")
    else:
        _keys(
            release_lock,
            {"path", "sha256"},
            {"path", "sha256"},
            "release_lock",
            errors,
        )
        if not isinstance(release_lock.get("path"), str) or not release_lock["path"]:
            errors.append("release_lock.path must be a non-empty string")
        if not HEX64.fullmatch(str(release_lock.get("sha256", ""))):
            errors.append("release_lock.sha256 must be a SHA-256 digest")

    comparators = _objects(spec.get("comparators"), "comparators", errors)
    comparator_ids = _unique_ids(comparators, "comparators", errors)
    missing_comparators = sorted(REQUIRED_COMPARATORS - comparator_ids)
    if missing_comparators:
        errors.append(f"missing required comparators: {missing_comparators!r}")
    for comparator in comparators:
        identifier = comparator.get("id", "<unknown>")
        _keys(
            comparator,
            {"id", "version", "pin_status", "source"},
            {"id", "version", "pin_status", "source", "configurations"},
            f"comparator {identifier!r}",
            errors,
        )
        for field in ("version", "pin_status", "source"):
            if not isinstance(comparator.get(field), str) or not comparator[field]:
                errors.append(f"comparator {identifier!r} requires {field}")

    corpora = _objects(spec.get("corpora"), "corpora", errors)
    corpus_ids = _unique_ids(corpora, "corpora", errors)
    for required in (
        "smtlib-2025-full",
        "smtcomp-2025-qf-uf",
        "source-family-holdout",
    ):
        if required not in corpus_ids:
            errors.append(f"missing required corpus {required!r}")
    for corpus in corpora:
        identifier = corpus.get("id", "<unknown>")
        _keys(
            corpus,
            {"id", "instances", "role", "status"},
            {
                "id",
                "instances",
                "role",
                "status",
                "manifest",
                "manifest_sha256",
                "source",
                "source_commit",
                "source_sha256",
                "split_rule",
            },
            f"corpus {identifier!r}",
            errors,
        )
        count = corpus.get("instances")
        if count is not None and (type(count) is not int or count <= 0):
            errors.append(f"corpus {corpus.get('id')!r} has invalid instances")

    budgets = spec.get("budgets_s")
    if budgets != REQUIRED_BUDGETS:
        errors.append(f"budgets_s must equal {REQUIRED_BUDGETS!r}")

    objectives = _objects(spec.get("objectives"), "objectives", errors)
    objective_ids = _unique_ids(objectives, "objectives", errors)
    if objective_ids != REQUIRED_OBJECTIVES:
        errors.append(f"objective ids must equal {sorted(REQUIRED_OBJECTIVES)!r}")
    for objective in objectives:
        _keys(
            objective,
            {"id", "title", "gate"},
            {"id", "title", "gate"},
            f"objective {objective.get('id')!r}",
            errors,
        )
        if not objective.get("title") or not objective.get("gate"):
            errors.append(f"objective {objective.get('id')!r} requires title and gate")

    policy = spec.get("promotion_policy")
    if not isinstance(policy, dict):
        errors.append("promotion_policy must be an object")
    else:
        policy_keys = {
            "wrong_answers_allowed",
            "execution_errors_allowed",
            "coverage_loss_allowed",
            "minimum_speedup",
            "confidence_level",
            "superiority_confidence_level",
            "family_cluster_bootstrap",
            "coverage_test",
            "multiplicity_correction",
            "primary_ranking",
            "paired_order",
            "required_cpu_classes",
            "required_independent_full_runs",
            "required_primary_speedups",
            "full_corpus_gate_before_default",
            "held_out_gate_before_superiority_claim",
            "family_identity_as_runtime_feature",
            "path_or_content_hash_as_runtime_feature",
        }
        _keys(policy, policy_keys, policy_keys, "promotion_policy", errors)
        for field in (
            "wrong_answers_allowed",
            "execution_errors_allowed",
            "coverage_loss_allowed",
        ):
            if type(policy.get(field)) is not int or policy[field] != 0:
                errors.append(f"promotion_policy.{field} must be 0")
        if not _finite_number(policy.get("minimum_speedup")) or policy["minimum_speedup"] < 1.0:
            errors.append("promotion_policy.minimum_speedup must be at least 1.0")
        if (
            not _finite_number(policy.get("superiority_confidence_level"))
            or policy["superiority_confidence_level"] < 0.99
        ):
            errors.append("superiority confidence level must be at least 0.99")
        if (
            not _finite_number(policy.get("confidence_level"))
            or not 0.0 < policy["confidence_level"] < 1.0
        ):
            errors.append("confidence_level must be a finite probability")
        speedups = policy.get("required_primary_speedups")
        if (
            type(speedups) is not list
            or not speedups
            or any(type(item) is not str or not item for item in speedups)
            or len(speedups) != len(set(speedups))
        ):
            errors.append("required_primary_speedups must be unique strings")
        if type(policy.get("paired_order")) is not str or not policy["paired_order"]:
            errors.append("paired_order must be a non-empty string")
        if policy.get("family_cluster_bootstrap") is not True:
            errors.append("final analysis must use family-cluster bootstrap")
        if policy.get("coverage_test") != "exact_McNemar":
            errors.append("coverage_test must be exact_McNemar")
        if policy.get("multiplicity_correction") != "Holm":
            errors.append("multiplicity_correction must be Holm")
        if (
            policy.get("primary_ranking")
            != "zero_invalid_then_solved_then_PAR2_then_CPU"
        ):
            errors.append("primary_ranking is not the preregistered lexicographic rule")
        if (
            type(policy.get("required_cpu_classes")) is not int
            or policy["required_cpu_classes"] < 2
        ):
            errors.append("promotion requires at least two CPU classes")
        if (
            type(policy.get("required_independent_full_runs")) is not int
            or policy["required_independent_full_runs"] < 2
        ):
            errors.append("promotion requires at least two independent full runs")
        for field in (
            "full_corpus_gate_before_default",
            "held_out_gate_before_superiority_claim",
        ):
            if policy.get(field) is not True:
                errors.append(f"promotion_policy.{field} must be true")
        for field in (
            "family_identity_as_runtime_feature",
            "path_or_content_hash_as_runtime_feature",
        ):
            if policy.get(field) is not False:
                errors.append(f"promotion_policy.{field} must be false")

    tracks = _objects(spec.get("tracks"), "tracks", errors)
    track_ids = _unique_ids(tracks, "tracks", errors)
    if track_ids != REQUIRED_TRACKS:
        errors.append(f"track ids must equal {sorted(REQUIRED_TRACKS)!r}")
    ranks = [track.get("rank") for track in tracks]
    if any(type(rank) is not int or rank < 0 for rank in ranks):
        errors.append("every track rank must be a non-negative integer")
    elif len(set(ranks)) != len(ranks):
        errors.append("track ranks must be unique")
    for track in tracks:
        identifier = track.get("id", "<unknown>")
        track_keys = {
            "id",
            "rank",
            "title",
            "status",
            "prerequisites",
            "first_gate",
            "kill_condition",
        }
        _keys(track, track_keys, track_keys, f"track {identifier!r}", errors)
        prerequisites = track.get("prerequisites")
        if not isinstance(prerequisites, list) or any(
            not isinstance(item, str) for item in prerequisites
        ):
            errors.append(f"track {identifier!r} prerequisites must be string ids")
        else:
            unknown = sorted(set(prerequisites) - track_ids)
            if unknown:
                errors.append(
                    f"track {identifier!r} has unknown prerequisites {unknown!r}"
                )
            if identifier in prerequisites:
                errors.append(f"track {identifier!r} cannot depend on itself")
        for field in ("title", "status", "first_gate", "kill_condition"):
            if not isinstance(track.get(field), str) or not track[field]:
                errors.append(f"track {identifier!r} requires {field}")

    stages = _objects(spec.get("stages"), "stages", errors)
    stage_ids = _unique_ids(stages, "stages", errors)
    if stage_ids != REQUIRED_STAGES:
        errors.append(f"stage ids must equal {sorted(REQUIRED_STAGES)!r}")
    for stage in stages:
        stage_keys = {"id", "title", "tracks", "exit"}
        _keys(
            stage,
            stage_keys,
            stage_keys,
            f"stage {stage.get('id')!r}",
            errors,
        )
        stage_tracks = stage.get("tracks")
        if not isinstance(stage_tracks, list) or any(
            not isinstance(item, str) for item in stage_tracks
        ):
            errors.append(f"stage {stage.get('id')!r} tracks must be string ids")
        else:
            unknown = sorted(set(stage_tracks) - track_ids)
            if unknown:
                errors.append(
                    f"stage {stage.get('id')!r} has unknown tracks {unknown!r}"
                )
        if not stage.get("title") or not stage.get("exit"):
            errors.append(f"stage {stage.get('id')!r} requires title and exit")

    dispositions = _objects(
        spec.get("unresolved_plan_disposition"),
        "unresolved_plan_disposition",
        errors,
    )
    for index, disposition in enumerate(dispositions):
        disposition_keys = {"item", "owner", "disposition"}
        _keys(
            disposition,
            disposition_keys,
            disposition_keys,
            f"unresolved_plan_disposition[{index}]",
            errors,
        )
        owner = disposition.get("owner")
        if owner is not None and owner not in track_ids:
            errors.append(
                f"unresolved_plan_disposition[{index}] has unknown owner {owner!r}"
            )
        if not disposition.get("item") or not disposition.get("disposition"):
            errors.append(
                f"unresolved_plan_disposition[{index}] requires item and disposition"
            )

    artifacts = spec.get("required_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) < 8 or any(
        not isinstance(item, str) or not item for item in artifacts
    ):
        errors.append("required_artifacts must contain at least eight named artifacts")

    if errors:
        raise CampaignSpecError(errors)
    return {
        "campaign_id": spec["campaign_id"],
        "status": spec["status"],
        "comparators": sorted(comparator_ids),
        "corpora": sorted(corpus_ids),
        "budgets_s": budgets,
        "objectives": sorted(objective_ids),
        "tracks": [
            track["id"] for track in sorted(tracks, key=lambda item: item["rank"])
        ],
        "stages": sorted(stage_ids),
        "valid": True,
    }


def load_and_validate(path: Path) -> dict[str, Any]:
    try:
        canonical_path, spec_bytes = read_regular_nofollow(path, "campaign specification")
        spec = strict_json_loads(
            spec_bytes.decode("utf-8"), f"campaign specification {canonical_path}"
        )
    except (OSError, UnicodeError, StrictArtifactError) as error:
        raise CampaignSpecError([f"cannot load {path}: {error}"]) from error
    summary = validate_spec(spec)
    root = canonical_path.parent.parent
    bound_errors: list[str] = []

    def verify_bound_file(record: dict[str, Any], label: str) -> None:
        relative = record.get("path", record.get("manifest"))
        expected = record.get("sha256", record.get("manifest_sha256"))
        if not isinstance(relative, str) or not isinstance(expected, str):
            bound_errors.append(f"{label} lacks a path and SHA-256 binding")
            return
        artifact = Path(relative)
        if not artifact.is_absolute():
            artifact = root / artifact
        try:
            _, artifact_bytes = read_regular_nofollow(artifact, label)
        except StrictArtifactError as error:
            bound_errors.append(f"cannot hash {label} file {artifact}: {error}")
            return
        actual = hashlib.sha256(artifact_bytes).hexdigest()
        if actual != expected:
            bound_errors.append(
                f"{label} SHA-256 mismatch: expected {expected}, got {actual}"
            )

    verify_bound_file(spec["release_lock"], "release_lock")
    for corpus in spec["corpora"]:
        if corpus.get("status") == "present" and "manifest_sha256" in corpus:
            verify_bound_file(corpus, f"corpus {corpus.get('id')!r}")
    if bound_errors:
        raise CampaignSpecError(bound_errors)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = load_and_validate(args.spec)
    except CampaignSpecError as error:
        for message in error.errors:
            print(f"error: {message}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        print(rendered, end="")
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
