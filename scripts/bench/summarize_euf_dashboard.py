#!/usr/bin/env python3
"""Produce a compact, claim-safe campaign scorecard from dashboard model v1.

The dashboard is already the metric authority.  This program strictly reads its
model schema, selects only broad whole-corpus and targeted structural-combined
panels, and copies a compact subset without pooling claim boundaries.  Victory
gates are evaluated only when the model contains enough exact-candidate
evidence; missing evidence is ``unknown``, never an inferred pass.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


MODEL_SCHEMA_VERSION = "euf-viper.dashboard-model.v1"
REGISTRY_SCHEMA_VERSION = "euf-viper.dashboard-evidence.v1"
CONTRACT_SCHEMA_VERSION = "euf-viper.world-leader-campaign.v1"
SCORECARD_SCHEMA_VERSION = "euf-viper.campaign-scorecard.v1"

EVIDENCE_STATUSES = {
    "verified",
    "provisional",
    "incomplete",
    "rejected",
    "superseded",
}
RESULT_STATUSES = {
    "solved",
    "timeout",
    "unknown",
    "error",
    "invalid",
    "wrong-answer",
    "unavailable",
}
METRIC_STATUSES = {"available", "unavailable"}
SCOPES = {"broad", "targeted"}
EXPECTED_STATUSES = {"all", "sat", "unsat"}
REVISION_RE = re.compile(r"[0-9a-f]{7,64}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

MODEL_KEYS = {
    "schema_version",
    "registry",
    "viper_solver_id",
    "solvers",
    "panels",
    "filter_options",
    "metric_definitions",
}
REGISTRY_KEYS = {"id", "schema_version", "sha256", "title", "updated_at"}
NAMED_ID_KEYS = {"id", "label"}
LEGACY_FILTER_KEYS = {
    "corpora",
    "evidence_classes",
    "evidence_statuses",
    "families",
    "hosts",
    "revisions",
    "timeouts",
}
FILTER_KEYS = LEGACY_FILTER_KEYS | {
    "expected_statuses",
}
TIMEOUT_FILTER_KEYS = {"label", "value"}
METRIC_DEFINITION_KEYS = {
    "coverage",
    "leader_relative_coverage",
    "par2",
    "common_geometric",
    "common_total",
    "median",
    "p95",
    "signed_performance_index",
    "required_improvement",
}
PANEL_KEYS = {
    "id",
    "claim_boundary",
    "evidence_ids",
    "sources",
    "instances",
    "complete",
    "incomplete_solver_ids",
    "leader_solver_ids",
    "leader_solved",
    "solvers",
    "comparisons",
}
LEGACY_BOUNDARY_KEYS = {
    "scope",
    "corpus",
    "timeout_s",
    "family",
    "solver_ids",
    "evidence_status",
    "revision",
    "host",
    "evidence_class",
}
BOUNDARY_KEYS = LEGACY_BOUNDARY_KEYS | {"expected_status"}
SOURCE_KEYS = {"path", "sha256"}
SOLVER_SUMMARY_KEYS = {
    "solver_id",
    "label",
    "instances",
    "available_observations",
    "unavailable_observations",
    "solved",
    "result_counts",
    "coverage",
    "leader_relative_coverage",
    "par2_s",
    "median_s",
    "p95_s",
}
VALUE_METRIC_KEYS = {"status", "value", "reason"}
COMPARISON_KEYS = {
    "competitor_id",
    "competitor_label",
    "common_solved",
    "instances",
    "performance_index",
    "metrics",
}
COMPARISON_METRIC_NAMES = {
    "par2",
    "common_geometric",
    "common_total",
    "median",
    "p95",
}
COMPARISON_METRIC_KEYS = {
    "status",
    "viper_time_s",
    "competitor_time_s",
    "ratio",
    "signed_performance_index",
    "required_viper_time_reduction",
    "required_viper_speedup",
    "reason",
}
PERFORMANCE_INDEX_KEYS = COMPARISON_METRIC_KEYS | {"basis"}
VICTORY_KEYS = {
    "V0_validity",
    "V1_official_coverage",
    "V2_full_coverage",
    "V3_time",
    "V4_resources",
    "V5_generalization",
    "V6_quality",
    "claim",
}
PRIMARY_TIME_METRICS = ("par2", "common_total", "common_geometric")
FIXED_FULL_BUDGETS = (2.0, 60.0, 1200.0)


class ScorecardInputError(ValueError):
    """Raised when an input cannot support a trustworthy scorecard."""


def _object(value: object, keys: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ScorecardInputError(f"{context} must be an object")
    if not all(type(key) is str for key in value):
        raise ScorecardInputError(f"{context} keys must be strings")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        details = []
        if missing:
            details.append(f"missing keys {missing!r}")
        if extra:
            details.append(f"unexpected keys {extra!r}")
        raise ScorecardInputError(f"{context}: {'; '.join(details)}")
    return value


def _mapping(value: object, context: str) -> dict[str, Any]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise ScorecardInputError(f"{context} must be an object with string keys")
    return value


def _array(value: object, context: str, *, nonempty: bool = False) -> list[Any]:
    if type(value) is not list:
        raise ScorecardInputError(f"{context} must be an array")
    if nonempty and not value:
        raise ScorecardInputError(f"{context} must not be empty")
    return value


def _text(value: object, context: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        qualifier = "non-empty " if nonempty else ""
        raise ScorecardInputError(f"{context} must be a {qualifier}string")
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ScorecardInputError(f"{context} must be trimmed and contain no controls")
    return value


def _number(
    value: object,
    context: str,
    *,
    minimum: float | None = None,
    positive: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScorecardInputError(f"{context} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ScorecardInputError(f"{context} must be finite")
    if positive and result <= 0.0:
        raise ScorecardInputError(f"{context} must be positive")
    if minimum is not None and result < minimum:
        raise ScorecardInputError(f"{context} must be at least {minimum:g}")
    return result


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ScorecardInputError(f"{context} must be an integer >= {minimum}")
    return value


def _boolean(value: object, context: str) -> bool:
    if type(value) is not bool:
        raise ScorecardInputError(f"{context} must be a boolean")
    return value


def _nullable_text(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _text(value, context)


def _nullable_number(value: object, context: str) -> float | None:
    if value is None:
        return None
    return _number(value, context)


def _unique_texts(
    value: object, context: str, *, nonempty: bool = False
) -> list[str]:
    items = [
        _text(item, f"{context}[{index}]")
        for index, item in enumerate(_array(value, context, nonempty=nonempty))
    ]
    duplicates = sorted(item for item, count in Counter(items).items() if count > 1)
    if duplicates:
        raise ScorecardInputError(f"{context} contains duplicates {duplicates!r}")
    return items


def _named_id(value: object, context: str) -> dict[str, str]:
    item = _object(value, NAMED_ID_KEYS, context)
    return {
        "id": _text(item["id"], f"{context}.id"),
        "label": _text(item["label"], f"{context}.label"),
    }


def _value_metric(value: object, context: str) -> dict[str, Any]:
    item = _object(value, VALUE_METRIC_KEYS, context)
    status = _text(item["status"], f"{context}.status")
    if status not in METRIC_STATUSES:
        raise ScorecardInputError(f"{context}.status is not supported")
    if status == "available":
        metric_value = _number(item["value"], f"{context}.value")
        if item["reason"] is not None:
            raise ScorecardInputError(f"{context}.reason must be null when available")
        reason = None
    else:
        if item["value"] is not None:
            raise ScorecardInputError(f"{context}.value must be null when unavailable")
        metric_value = None
        reason = _text(item["reason"], f"{context}.reason")
    return {"status": status, "value": metric_value, "reason": reason}


def _comparison_metric(
    value: object, context: str, *, performance_index: bool = False
) -> dict[str, Any]:
    keys = PERFORMANCE_INDEX_KEYS if performance_index else COMPARISON_METRIC_KEYS
    item = _object(value, keys, context)
    status = _text(item["status"], f"{context}.status")
    if status not in METRIC_STATUSES:
        raise ScorecardInputError(f"{context}.status is not supported")
    numeric_keys = (
        "viper_time_s",
        "competitor_time_s",
        "ratio",
        "signed_performance_index",
        "required_viper_time_reduction",
        "required_viper_speedup",
    )
    if status == "available":
        values = {
            key: _number(
                item[key],
                f"{context}.{key}",
                positive=key in {"viper_time_s", "competitor_time_s", "ratio"},
                minimum=0.0
                if key
                in {"required_viper_time_reduction", "required_viper_speedup"}
                else None,
            )
            for key in numeric_keys
        }
        if item["reason"] is not None:
            raise ScorecardInputError(f"{context}.reason must be null when available")
        if not math.isclose(
            values["signed_performance_index"],
            values["ratio"] - 1.0,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            raise ScorecardInputError(
                f"{context}.signed_performance_index is inconsistent with ratio"
            )
        expected_reduction = max(0.0, 1.0 - values["ratio"])
        if not math.isclose(
            values["required_viper_time_reduction"],
            expected_reduction,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            raise ScorecardInputError(
                f"{context}.required_viper_time_reduction is inconsistent with ratio"
            )
        reason = None
    else:
        if any(item[key] is not None for key in numeric_keys):
            raise ScorecardInputError(
                f"{context} numeric fields must be null when unavailable"
            )
        values = {key: None for key in numeric_keys}
        reason = _text(item["reason"], f"{context}.reason")
    result: dict[str, Any] = {"status": status, **values, "reason": reason}
    if performance_index:
        basis = _text(item["basis"], f"{context}.basis")
        if basis != "common_geometric":
            raise ScorecardInputError(
                f"{context}.basis must remain 'common_geometric'"
            )
        result["basis"] = basis
    return result


def _validate_solver_summary(
    value: object,
    context: str,
    *,
    instances: int,
    declared_solvers: Mapping[str, str],
) -> dict[str, Any]:
    item = _object(value, SOLVER_SUMMARY_KEYS, context)
    solver_id = _text(item["solver_id"], f"{context}.solver_id")
    if solver_id not in declared_solvers:
        raise ScorecardInputError(f"{context}.solver_id is not in the panel boundary")
    label = _text(item["label"], f"{context}.label")
    if label != declared_solvers[solver_id]:
        raise ScorecardInputError(f"{context}.label conflicts with model.solvers")
    summary_instances = _integer(item["instances"], f"{context}.instances", minimum=1)
    if summary_instances != instances:
        raise ScorecardInputError(f"{context}.instances conflicts with panel.instances")
    available = _integer(
        item["available_observations"], f"{context}.available_observations"
    )
    unavailable = _integer(
        item["unavailable_observations"], f"{context}.unavailable_observations"
    )
    solved = _integer(item["solved"], f"{context}.solved")
    if available + unavailable != instances or solved > available:
        raise ScorecardInputError(f"{context} observation counts are inconsistent")
    raw_counts = _mapping(item["result_counts"], f"{context}.result_counts")
    unknown_statuses = sorted(set(raw_counts) - RESULT_STATUSES)
    if unknown_statuses:
        raise ScorecardInputError(
            f"{context}.result_counts has unknown statuses {unknown_statuses!r}"
        )
    counts = {
        status: _integer(count, f"{context}.result_counts.{status}")
        for status, count in raw_counts.items()
    }
    if sum(counts.values()) != instances or counts.get("solved", 0) != solved:
        raise ScorecardInputError(f"{context}.result_counts is inconsistent")
    if counts.get("unavailable", 0) != unavailable:
        raise ScorecardInputError(
            f"{context}.unavailable_observations is inconsistent"
        )
    return {
        "solver_id": solver_id,
        "label": label,
        "instances": instances,
        "available_observations": available,
        "unavailable_observations": unavailable,
        "solved": solved,
        "result_counts": dict(sorted(counts.items())),
        "coverage": _value_metric(item["coverage"], f"{context}.coverage"),
        "leader_relative_coverage": _value_metric(
            item["leader_relative_coverage"],
            f"{context}.leader_relative_coverage",
        ),
        "par2_s": _value_metric(item["par2_s"], f"{context}.par2_s"),
        "median_s": _value_metric(item["median_s"], f"{context}.median_s"),
        "p95_s": _value_metric(item["p95_s"], f"{context}.p95_s"),
    }


def _validate_comparison(
    value: object,
    context: str,
    *,
    instances: int,
    competitor_ids: set[str],
    labels: Mapping[str, str],
) -> dict[str, Any]:
    item = _object(value, COMPARISON_KEYS, context)
    competitor_id = _text(item["competitor_id"], f"{context}.competitor_id")
    if competitor_id not in competitor_ids:
        raise ScorecardInputError(f"{context}.competitor_id is not in the boundary")
    competitor_label = _text(
        item["competitor_label"], f"{context}.competitor_label"
    )
    if competitor_label != labels[competitor_id]:
        raise ScorecardInputError(f"{context}.competitor_label is inconsistent")
    comparison_instances = _integer(
        item["instances"], f"{context}.instances", minimum=1
    )
    if comparison_instances != instances:
        raise ScorecardInputError(f"{context}.instances conflicts with panel.instances")
    common_solved = _integer(item["common_solved"], f"{context}.common_solved")
    if common_solved > instances:
        raise ScorecardInputError(f"{context}.common_solved exceeds panel.instances")
    raw_metrics = _object(item["metrics"], COMPARISON_METRIC_NAMES, f"{context}.metrics")
    metrics = {
        name: _comparison_metric(raw_metrics[name], f"{context}.metrics.{name}")
        for name in sorted(COMPARISON_METRIC_NAMES)
    }
    performance = _comparison_metric(
        item["performance_index"],
        f"{context}.performance_index",
        performance_index=True,
    )
    expected_performance = dict(metrics["common_geometric"])
    expected_performance["basis"] = "common_geometric"
    if performance != expected_performance:
        raise ScorecardInputError(
            f"{context}.performance_index conflicts with common_geometric"
        )
    return {
        "competitor_id": competitor_id,
        "competitor_label": competitor_label,
        "common_solved": common_solved,
        "instances": instances,
        "performance_index": performance,
        "metrics": metrics,
    }


def _validate_panel(
    value: object,
    context: str,
    *,
    model_solvers: Mapping[str, str],
    viper_solver_id: str,
    has_expected_status: bool,
) -> dict[str, Any]:
    item = _object(value, PANEL_KEYS, context)
    boundary_raw = _object(
        item["claim_boundary"],
        BOUNDARY_KEYS if has_expected_status else LEGACY_BOUNDARY_KEYS,
        f"{context}.claim_boundary",
    )
    scope = _text(boundary_raw["scope"], f"{context}.claim_boundary.scope")
    if scope not in SCOPES:
        raise ScorecardInputError(f"{context}.claim_boundary.scope is not supported")
    solver_ids = _unique_texts(
        boundary_raw["solver_ids"],
        f"{context}.claim_boundary.solver_ids",
        nonempty=True,
    )
    if len(solver_ids) < 2 or viper_solver_id not in solver_ids:
        raise ScorecardInputError(
            f"{context}.claim_boundary.solver_ids must contain Viper and a competitor"
        )
    undeclared = sorted(set(solver_ids) - set(model_solvers))
    if undeclared:
        raise ScorecardInputError(
            f"{context}.claim_boundary.solver_ids has undeclared IDs {undeclared!r}"
        )
    evidence_status = _text(
        boundary_raw["evidence_status"],
        f"{context}.claim_boundary.evidence_status",
    )
    if evidence_status not in EVIDENCE_STATUSES:
        raise ScorecardInputError(
            f"{context}.claim_boundary.evidence_status is not supported"
        )
    revision = _text(boundary_raw["revision"], f"{context}.claim_boundary.revision")
    if REVISION_RE.fullmatch(revision) is None:
        raise ScorecardInputError(f"{context}.claim_boundary.revision is invalid")
    timeout_s = _number(
        boundary_raw["timeout_s"],
        f"{context}.claim_boundary.timeout_s",
        positive=True,
    )
    boundary = {
        "scope": scope,
        "corpus": _named_id(
            boundary_raw["corpus"], f"{context}.claim_boundary.corpus"
        ),
        "timeout_s": timeout_s,
        "family": _named_id(
            boundary_raw["family"], f"{context}.claim_boundary.family"
        ),
        "expected_status": (
            _text(
                boundary_raw["expected_status"],
                f"{context}.claim_boundary.expected_status",
            )
            if has_expected_status
            else "legacy-unstratified"
        ),
        "solver_ids": solver_ids,
        "evidence_status": evidence_status,
        "revision": revision,
        "host": _named_id(boundary_raw["host"], f"{context}.claim_boundary.host"),
        "evidence_class": _text(
            boundary_raw["evidence_class"],
            f"{context}.claim_boundary.evidence_class",
        ),
    }
    if has_expected_status and boundary["expected_status"] not in EXPECTED_STATUSES:
        raise ScorecardInputError(
            f"{context}.claim_boundary.expected_status is not supported"
        )
    panel_id = _text(item["id"], f"{context}.id")
    evidence_ids = _unique_texts(
        item["evidence_ids"], f"{context}.evidence_ids", nonempty=True
    )
    sources = []
    for index, raw_source in enumerate(_array(item["sources"], f"{context}.sources", nonempty=True)):
        source_context = f"{context}.sources[{index}]"
        source = _object(raw_source, SOURCE_KEYS, source_context)
        digest = _text(source["sha256"], f"{source_context}.sha256")
        if SHA256_RE.fullmatch(digest) is None:
            raise ScorecardInputError(f"{source_context}.sha256 is invalid")
        sources.append(
            {"path": _text(source["path"], f"{source_context}.path"), "sha256": digest}
        )
    instances = _integer(item["instances"], f"{context}.instances", minimum=1)
    complete = _boolean(item["complete"], f"{context}.complete")
    incomplete_solver_ids = _unique_texts(
        item["incomplete_solver_ids"], f"{context}.incomplete_solver_ids"
    )
    if not set(incomplete_solver_ids) <= set(solver_ids):
        raise ScorecardInputError(f"{context}.incomplete_solver_ids is inconsistent")
    if complete == bool(incomplete_solver_ids):
        raise ScorecardInputError(f"{context}.complete is inconsistent")
    leader_solver_ids = _unique_texts(
        item["leader_solver_ids"], f"{context}.leader_solver_ids"
    )
    if not set(leader_solver_ids) <= set(solver_ids):
        raise ScorecardInputError(f"{context}.leader_solver_ids is inconsistent")
    leader_solved = item["leader_solved"]
    if leader_solved is not None:
        leader_solved = _integer(leader_solved, f"{context}.leader_solved")
        if leader_solved > instances:
            raise ScorecardInputError(f"{context}.leader_solved exceeds instances")
    labels = {solver_id: model_solvers[solver_id] for solver_id in solver_ids}
    summaries = [
        _validate_solver_summary(
            summary,
            f"{context}.solvers[{index}]",
            instances=instances,
            declared_solvers=labels,
        )
        for index, summary in enumerate(
            _array(item["solvers"], f"{context}.solvers", nonempty=True)
        )
    ]
    summary_ids = [summary["solver_id"] for summary in summaries]
    if len(summary_ids) != len(set(summary_ids)) or set(summary_ids) != set(solver_ids):
        raise ScorecardInputError(f"{context}.solvers must cover boundary solver_ids")
    competitor_ids = set(solver_ids) - {viper_solver_id}
    comparisons = [
        _validate_comparison(
            comparison,
            f"{context}.comparisons[{index}]",
            instances=instances,
            competitor_ids=competitor_ids,
            labels=labels,
        )
        for index, comparison in enumerate(
            _array(item["comparisons"], f"{context}.comparisons", nonempty=True)
        )
    ]
    comparison_ids = [comparison["competitor_id"] for comparison in comparisons]
    if len(comparison_ids) != len(set(comparison_ids)) or set(comparison_ids) != competitor_ids:
        raise ScorecardInputError(
            f"{context}.comparisons must cover each competitor exactly once"
        )
    return {
        "id": panel_id,
        "claim_boundary": boundary,
        "evidence_ids": sorted(evidence_ids),
        "sources": sorted(sources, key=lambda source: (source["path"], source["sha256"])),
        "instances": instances,
        "complete": complete,
        "incomplete_solver_ids": sorted(incomplete_solver_ids),
        "leader_solver_ids": sorted(leader_solver_ids),
        "leader_solved": leader_solved,
        "solvers": sorted(summaries, key=lambda summary: summary["solver_id"]),
        "comparisons": sorted(comparisons, key=lambda comparison: comparison["competitor_id"]),
    }


def validate_model(value: object) -> dict[str, Any]:
    """Strictly validate and normalize ``euf-viper.dashboard-model.v1``."""

    item = _object(value, MODEL_KEYS, "model")
    if item["schema_version"] != MODEL_SCHEMA_VERSION:
        raise ScorecardInputError(
            f"model.schema_version must be {MODEL_SCHEMA_VERSION!r}"
        )
    registry_raw = _object(item["registry"], REGISTRY_KEYS, "model.registry")
    if registry_raw["schema_version"] != REGISTRY_SCHEMA_VERSION:
        raise ScorecardInputError(
            f"model.registry.schema_version must be {REGISTRY_SCHEMA_VERSION!r}"
        )
    digest = _text(registry_raw["sha256"], "model.registry.sha256")
    if SHA256_RE.fullmatch(digest) is None:
        raise ScorecardInputError("model.registry.sha256 is invalid")
    registry = {
        "id": _text(registry_raw["id"], "model.registry.id"),
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "sha256": digest,
        "title": _text(registry_raw["title"], "model.registry.title"),
        "updated_at": _text(registry_raw["updated_at"], "model.registry.updated_at"),
    }
    solvers = [
        _named_id(solver, f"model.solvers[{index}]")
        for index, solver in enumerate(
            _array(item["solvers"], "model.solvers", nonempty=True)
        )
    ]
    solver_ids = [solver["id"] for solver in solvers]
    if len(solver_ids) != len(set(solver_ids)):
        raise ScorecardInputError("model.solvers contains duplicate IDs")
    solver_labels = {solver["id"]: solver["label"] for solver in solvers}
    viper_solver_id = _text(item["viper_solver_id"], "model.viper_solver_id")
    if viper_solver_id not in solver_labels:
        raise ScorecardInputError("model.viper_solver_id is undeclared")

    raw_filters = _mapping(item["filter_options"], "model.filter_options")
    if set(raw_filters) == FILTER_KEYS:
        has_expected_status = True
        filters = _object(raw_filters, FILTER_KEYS, "model.filter_options")
    elif set(raw_filters) == LEGACY_FILTER_KEYS:
        has_expected_status = False
        filters = _object(raw_filters, LEGACY_FILTER_KEYS, "model.filter_options")
    else:
        # Report the current schema as the target while still recognizing the
        # exact frozen legacy v1 dialect above.
        filters = _object(raw_filters, FILTER_KEYS, "model.filter_options")
    for plural in ("corpora", "families", "hosts"):
        for index, named in enumerate(_array(filters[plural], f"model.filter_options.{plural}")):
            _named_id(named, f"model.filter_options.{plural}[{index}]")
    text_filter_names = [
        "evidence_classes",
        "evidence_statuses",
        "revisions",
    ]
    if has_expected_status:
        text_filter_names.append("expected_statuses")
    for plural in text_filter_names:
        _unique_texts(filters[plural], f"model.filter_options.{plural}")
    for index, raw_timeout in enumerate(_array(filters["timeouts"], "model.filter_options.timeouts")):
        context = f"model.filter_options.timeouts[{index}]"
        timeout = _object(raw_timeout, TIMEOUT_FILTER_KEYS, context)
        _text(timeout["label"], f"{context}.label")
        raw_value = _text(timeout["value"], f"{context}.value")
        try:
            parsed_value = float(raw_value)
        except ValueError as error:
            raise ScorecardInputError(f"{context}.value is not numeric") from error
        _number(parsed_value, f"{context}.value", positive=True)

    definitions = _object(
        item["metric_definitions"],
        METRIC_DEFINITION_KEYS,
        "model.metric_definitions",
    )
    for key in sorted(METRIC_DEFINITION_KEYS):
        _text(definitions[key], f"model.metric_definitions.{key}")

    panels = [
        _validate_panel(
            panel,
            f"model.panels[{index}]",
            model_solvers=solver_labels,
            viper_solver_id=viper_solver_id,
            has_expected_status=has_expected_status,
        )
        for index, panel in enumerate(_array(item["panels"], "model.panels"))
    ]
    panel_ids = [panel["id"] for panel in panels]
    if len(panel_ids) != len(set(panel_ids)):
        raise ScorecardInputError("model.panels contains duplicate IDs")
    return {
        "schema_version": MODEL_SCHEMA_VERSION,
        "registry": registry,
        "viper_solver_id": viper_solver_id,
        "solvers": sorted(solvers, key=lambda solver: solver["id"]),
        "panels": sorted(panels, key=_panel_sort_key),
        "expected_status_dimension": (
            "explicit" if has_expected_status else "legacy-unstratified"
        ),
    }


def _strict_json(path: Path, context: str) -> object:
    def reject_constant(token: str) -> None:
        raise ScorecardInputError(f"{context}: non-finite JSON number {token!r}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ScorecardInputError(f"{context}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ScorecardInputError(f"cannot read {context} {path}: {error}") from error
    try:
        return json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        raise ScorecardInputError(
            f"{path}:{error.lineno}:{error.colno}: invalid JSON: {error.msg}"
        ) from error


def load_model(path: Path) -> dict[str, Any]:
    value = _strict_json(path, "dashboard model")
    validate_model(value)
    assert type(value) is dict
    return value


def validate_campaign_contract(value: object) -> dict[str, Any]:
    """Validate the contract fields needed to evaluate the scorecard."""

    root = _mapping(value, "campaign contract")
    if root.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise ScorecardInputError(
            f"campaign contract.schema_version must be {CONTRACT_SCHEMA_VERSION!r}"
        )
    campaign_id = _text(root.get("campaign_id"), "campaign contract.campaign_id")
    scope = _mapping(root.get("scope"), "campaign contract.scope")
    candidate_revision = _text(
        scope.get("candidate_revision"), "campaign contract.scope.candidate_revision"
    )
    if REVISION_RE.fullmatch(candidate_revision) is None:
        raise ScorecardInputError(
            "campaign contract.scope.candidate_revision is invalid"
        )
    score_policy = _mapping(root.get("score_policy"), "campaign contract.score_policy")
    candidate_id = _text(
        score_policy.get("candidate_id"), "campaign contract.score_policy.candidate_id"
    )
    comparators = _mapping(root.get("comparators"), "campaign contract.comparators")
    mandatory_raw = _array(
        comparators.get("mandatory"),
        "campaign contract.comparators.mandatory",
        nonempty=True,
    )
    mandatory_ids = []
    for index, raw_comparator in enumerate(mandatory_raw):
        comparator = _mapping(
            raw_comparator, f"campaign contract.comparators.mandatory[{index}]"
        )
        mandatory_ids.append(
            _text(
                comparator.get("id"),
                f"campaign contract.comparators.mandatory[{index}].id",
            )
        )
    if len(mandatory_ids) != len(set(mandatory_ids)):
        raise ScorecardInputError(
            "campaign contract.comparators.mandatory contains duplicate IDs"
        )
    if candidate_id in mandatory_ids:
        raise ScorecardInputError("campaign candidate cannot also be a comparator")
    benchmark = _mapping(
        root.get("benchmark_space"), "campaign contract.benchmark_space"
    )
    corpora_raw = _array(
        benchmark.get("corpora"),
        "campaign contract.benchmark_space.corpora",
        nonempty=True,
    )
    corpora_by_role: dict[str, list[str]] = {}
    corpus_ids: set[str] = set()
    for index, raw_corpus in enumerate(corpora_raw):
        corpus = _mapping(
            raw_corpus, f"campaign contract.benchmark_space.corpora[{index}]"
        )
        corpus_id = _text(
            corpus.get("id"), f"campaign contract.benchmark_space.corpora[{index}].id"
        )
        role = _text(
            corpus.get("role"),
            f"campaign contract.benchmark_space.corpora[{index}].role",
        )
        if corpus_id in corpus_ids:
            raise ScorecardInputError(
                "campaign contract.benchmark_space.corpora has duplicate IDs"
            )
        corpus_ids.add(corpus_id)
        corpora_by_role.setdefault(role, []).append(corpus_id)
    budgets = [
        _number(
            budget,
            f"campaign contract.benchmark_space.budgets_s[{index}]",
            positive=True,
        )
        for index, budget in enumerate(
            _array(
                benchmark.get("budgets_s"),
                "campaign contract.benchmark_space.budgets_s",
                nonempty=True,
            )
        )
    ]
    if len(budgets) != len(set(budgets)):
        raise ScorecardInputError(
            "campaign contract.benchmark_space.budgets_s contains duplicates"
        )
    victory_raw = _object(
        root.get("victory_contract"), VICTORY_KEYS, "campaign contract.victory_contract"
    )
    victory = {
        key: _text(victory_raw[key], f"campaign contract.victory_contract.{key}")
        for key in sorted(VICTORY_KEYS)
    }
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "candidate_id": candidate_id,
        "candidate_revision": candidate_revision,
        "mandatory_comparator_ids": sorted(mandatory_ids),
        "corpora_by_role": {
            role: sorted(ids) for role, ids in sorted(corpora_by_role.items())
        },
        "budgets_s": sorted(budgets),
        "victory_contract": victory,
    }


def load_campaign_contract(path: Path) -> dict[str, Any]:
    value = _strict_json(path, "campaign contract")
    validate_campaign_contract(value)
    assert type(value) is dict
    return value


def _panel_sort_key(panel: Mapping[str, Any]) -> tuple[Any, ...]:
    boundary = panel["claim_boundary"]
    return (
        boundary["scope"],
        boundary["corpus"]["id"],
        boundary["family"]["id"],
        boundary["expected_status"],
        float(boundary["timeout_s"]),
        boundary["revision"],
        boundary["evidence_status"],
        boundary["host"]["id"],
        boundary["evidence_class"],
        tuple(boundary["solver_ids"]),
        panel["id"],
    )


def _selected_kind(panel: Mapping[str, Any]) -> str | None:
    boundary = panel["claim_boundary"]
    if (
        boundary["scope"] == "broad"
        and boundary["family"]["id"] == "all"
        and boundary["expected_status"] in {"all", "legacy-unstratified"}
    ):
        return "broad_whole_corpus"
    if (
        boundary["scope"] == "targeted"
        and boundary["family"]["id"] == "structural-combined"
    ):
        return "targeted_structural_combined"
    return None


def _compact_value_metric(metric: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": metric["status"],
        "value": metric["value"],
        "reason": metric["reason"],
    }


def _compact_comparison_metric(metric: Mapping[str, Any]) -> dict[str, Any]:
    signed = metric["signed_performance_index"]
    reduction = metric["required_viper_time_reduction"]
    speedup = metric["required_viper_speedup"]
    return {
        "status": metric["status"],
        "ratio": metric["ratio"],
        "signed_percent": None if signed is None else 100.0 * signed,
        "required_viper_reduction_percent": (
            None if reduction is None else 100.0 * reduction
        ),
        "required_viper_speedup_percent": (
            None if speedup is None else 100.0 * speedup
        ),
        "reason": metric["reason"],
    }


def _compact_panel(panel: Mapping[str, Any], kind: str) -> dict[str, Any]:
    boundary = panel["claim_boundary"]
    return {
        "id": panel["id"],
        "kind": kind,
        "claim_boundary": {
            "scope": boundary["scope"],
            "revision": boundary["revision"],
            "evidence_status": boundary["evidence_status"],
            "evidence_class": boundary["evidence_class"],
            "host": dict(boundary["host"]),
            "corpus": dict(boundary["corpus"]),
            "family": dict(boundary["family"]),
            "expected_status": boundary["expected_status"],
            "timeout_s": boundary["timeout_s"],
            "solver_ids": sorted(boundary["solver_ids"]),
        },
        "instances": panel["instances"],
        "complete": panel["complete"],
        "leader_solver_ids": sorted(panel["leader_solver_ids"]),
        "leader_solved": panel["leader_solved"],
        "solvers": [
            {
                "solver_id": summary["solver_id"],
                "label": summary["label"],
                "solved": summary["solved"],
                "coverage": _compact_value_metric(summary["coverage"]),
                "par2_s": _compact_value_metric(summary["par2_s"]),
            }
            for summary in sorted(panel["solvers"], key=lambda row: row["solver_id"])
        ],
        "comparisons": [
            {
                "competitor_id": comparison["competitor_id"],
                "competitor_label": comparison["competitor_label"],
                "common_solved": comparison["common_solved"],
                "metrics": {
                    name: _compact_comparison_metric(comparison["metrics"][name])
                    for name in PRIMARY_TIME_METRICS
                },
            }
            for comparison in sorted(
                panel["comparisons"], key=lambda row: row["competitor_id"]
            )
        ],
    }


def _candidate_broad_panels(
    model: Mapping[str, Any], contract: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    return [
        panel
        for panel in model["panels"]
        if panel["claim_boundary"]["scope"] == "broad"
        and panel["claim_boundary"]["family"]["id"] == "all"
        and panel["claim_boundary"]["expected_status"]
        in {"all", "legacy-unstratified"}
        and panel["claim_boundary"]["revision"] == contract["candidate_revision"]
    ]


def _gate(
    gate_id: str,
    state: str,
    requirement: str,
    reason: str,
    panel_ids: Sequence[str] = (),
) -> dict[str, Any]:
    if state not in {"unknown", "fail", "pass"}:
        raise AssertionError(f"invalid gate state {state!r}")
    return {
        "id": gate_id,
        "state": state,
        "requirement": requirement,
        "reason": reason,
        "evidence_panel_ids": sorted(set(panel_ids)),
    }


def _eligible_panel(
    panel: Mapping[str, Any],
    *,
    contract: Mapping[str, Any],
    corpus_id: str,
    timeout_s: float,
) -> bool:
    boundary = panel["claim_boundary"]
    return (
        boundary["scope"] == "broad"
        and boundary["family"]["id"] == "all"
        and boundary["expected_status"] == "all"
        and boundary["revision"] == contract["candidate_revision"]
        and boundary["evidence_status"] == "verified"
        and boundary["corpus"]["id"] == corpus_id
        and math.isclose(float(boundary["timeout_s"]), timeout_s, rel_tol=0.0, abs_tol=1e-12)
        and panel["complete"]
    )


def _coverage_gate(
    gate_id: str,
    requirement: str,
    model: Mapping[str, Any],
    contract: Mapping[str, Any],
    corpus_ids: Sequence[str],
    budgets: Sequence[float],
) -> dict[str, Any]:
    mandatory = set(contract["mandatory_comparator_ids"])
    all_panels = model["panels"]
    evidence_ids: list[str] = []
    missing: list[str] = []
    for corpus_id in corpus_ids:
        for budget in budgets:
            panels = [
                panel
                for panel in all_panels
                if _eligible_panel(
                    panel,
                    contract=contract,
                    corpus_id=corpus_id,
                    timeout_s=budget,
                )
            ]
            negative_panels = []
            qualifying_panels = []
            for panel in panels:
                summaries = {
                    summary["solver_id"]: summary for summary in panel["solvers"]
                }
                if contract["candidate_id"] not in summaries:
                    continue
                included_mandatory = mandatory & set(summaries)
                if any(
                    summaries[contract["candidate_id"]]["solved"]
                    < summaries[competitor_id]["solved"]
                    for competitor_id in included_mandatory
                ):
                    negative_panels.append(panel)
                if mandatory <= set(summaries):
                    qualifying_panels.append(panel)
            if negative_panels:
                ids = [panel["id"] for panel in negative_panels]
                return _gate(
                    gate_id,
                    "fail",
                    requirement,
                    f"Viper loses coverage on {corpus_id} at {budget:g} s.",
                    ids,
                )
            if not qualifying_panels:
                missing.append(f"{corpus_id}@{budget:g}s")
            else:
                evidence_ids.extend(panel["id"] for panel in qualifying_panels)
    if missing:
        return _gate(
            gate_id,
            "unknown",
            requirement,
            "Missing complete verified exact-candidate all-comparator panels: "
            + ", ".join(missing),
            evidence_ids,
        )
    return _gate(
        gate_id,
        "pass",
        requirement,
        "Viper equals or exceeds every mandatory comparator on every required panel.",
        evidence_ids,
    )


def _time_gate(
    model: Mapping[str, Any], contract: Mapping[str, Any], corpus_ids: Sequence[str], budgets: Sequence[float]
) -> dict[str, Any]:
    requirement = contract["victory_contract"]["V3_time"]
    mandatory = set(contract["mandatory_comparator_ids"])
    evidence_ids: list[str] = []
    missing: list[str] = []
    for corpus_id in corpus_ids:
        for budget in budgets:
            panels = [
                panel
                for panel in model["panels"]
                if _eligible_panel(
                    panel,
                    contract=contract,
                    corpus_id=corpus_id,
                    timeout_s=budget,
                )
            ]
            complete_comparator_sets = []
            for panel in panels:
                comparisons = {
                    comparison["competitor_id"]: comparison
                    for comparison in panel["comparisons"]
                }
                included = mandatory & set(comparisons)
                for competitor_id in sorted(included):
                    comparison = comparisons[competitor_id]
                    for metric_name in PRIMARY_TIME_METRICS:
                        metric = comparison["metrics"][metric_name]
                        if metric["status"] == "available" and metric["ratio"] < 1.05:
                            return _gate(
                                "V3",
                                "fail",
                                requirement,
                                f"{competitor_id} ratio is {metric['ratio']:.6g} for "
                                f"{metric_name} on {corpus_id}@{budget:g}s; 1.05 is required.",
                                [panel["id"]],
                            )
                if mandatory <= set(comparisons) and all(
                    comparisons[competitor_id]["metrics"][metric_name]["status"]
                    == "available"
                    and comparisons[competitor_id]["metrics"][metric_name]["ratio"]
                    >= 1.05
                    for competitor_id in mandatory
                    for metric_name in PRIMARY_TIME_METRICS
                ):
                    complete_comparator_sets.append(panel)
            if not complete_comparator_sets:
                missing.append(f"{corpus_id}@{budget:g}s")
            else:
                evidence_ids.extend(panel["id"] for panel in complete_comparator_sets)
    if missing:
        return _gate(
            "V3",
            "unknown",
            requirement,
            "Missing complete verified exact-candidate timing panels: "
            + ", ".join(missing),
            evidence_ids,
        )
    return _gate(
        "V3",
        "pass",
        requirement,
        "Every required PAR2, common-total, and common-geometric ratio is at least 1.05.",
        evidence_ids,
    )


def _victory_state(
    model: Mapping[str, Any], contract: Mapping[str, Any]
) -> dict[str, Any]:
    candidate_revision_panels = [
        panel
        for panel in model["panels"]
        if panel["claim_boundary"]["revision"] == contract["candidate_revision"]
    ]
    bad_statuses = {"wrong-answer", "error", "invalid", "unavailable"}
    bad_panels = []
    for panel in candidate_revision_panels:
        if not panel["complete"] or any(
            summary["result_counts"].get(status, 0) > 0
            for summary in panel["solvers"]
            for status in bad_statuses
        ):
            bad_panels.append(panel["id"])
    if bad_panels:
        v0 = _gate(
            "V0",
            "fail",
            contract["victory_contract"]["V0_validity"],
            "Exact-candidate evidence contains an error, invalid or wrong answer, unavailable row, or incomplete panel.",
            bad_panels,
        )
    else:
        v0 = _gate(
            "V0",
            "unknown",
            contract["victory_contract"]["V0_validity"],
            "Dashboard model v1 does not attest independent model/proof checks, hash drift, or missing-row audits.",
            [panel["id"] for panel in candidate_revision_panels],
        )

    official_ids = contract["corpora_by_role"].get("official_primary", [])
    full_ids = contract["corpora_by_role"].get("full_library_regression", [])
    if official_ids:
        v1 = _coverage_gate(
            "V1",
            contract["victory_contract"]["V1_official_coverage"],
            model,
            contract,
            official_ids,
            contract["budgets_s"],
        )
    else:
        v1 = _gate(
            "V1",
            "unknown",
            contract["victory_contract"]["V1_official_coverage"],
            "The campaign contract declares no official_primary corpus.",
        )
    if full_ids:
        v2 = _coverage_gate(
            "V2",
            contract["victory_contract"]["V2_full_coverage"],
            model,
            contract,
            full_ids,
            FIXED_FULL_BUDGETS,
        )
    else:
        v2 = _gate(
            "V2",
            "unknown",
            contract["victory_contract"]["V2_full_coverage"],
            "The campaign contract declares no full_library_regression corpus.",
        )
    time_corpora = sorted(set(official_ids) | set(full_ids))
    time_budgets = sorted(set(contract["budgets_s"]) | set(FIXED_FULL_BUDGETS))
    v3 = (
        _time_gate(model, contract, time_corpora, time_budgets)
        if time_corpora
        else _gate(
            "V3",
            "unknown",
            contract["victory_contract"]["V3_time"],
            "No official or full corpus is identified by the campaign contract.",
        )
    )
    v4 = _gate(
        "V4",
        "unknown",
        contract["victory_contract"]["V4_resources"],
        "Dashboard model v1 contains no RSS, instruction, or cache metrics.",
    )
    v5 = _gate(
        "V5",
        "unknown",
        contract["victory_contract"]["V5_generalization"],
        "Dashboard model v1 does not attest CPU classes or sealed-holdout status.",
    )
    v6 = _gate(
        "V6",
        "unknown",
        contract["victory_contract"]["V6_quality"],
        "Dashboard model v1 contains no independent proof/model checks or novelty ablation record.",
    )
    gates = [v0, v1, v2, v3, v4, v5, v6]
    states = {gate["state"] for gate in gates}
    overall = "pass" if states == {"pass"} else "fail" if "fail" in states else "unknown"
    return {
        "claim": contract["victory_contract"]["claim"],
        "state": overall,
        "gates": gates,
    }


def build_scorecard(
    model_value: object, contract_value: object
) -> dict[str, Any]:
    """Build a deterministic compact scorecard from validated input objects."""

    model = validate_model(model_value)
    contract = validate_campaign_contract(contract_value)
    if model["viper_solver_id"] != contract["candidate_id"]:
        raise ScorecardInputError(
            "campaign candidate_id does not match model.viper_solver_id"
        )
    undeclared = sorted(
        set(contract["mandatory_comparator_ids"])
        - {solver["id"] for solver in model["solvers"]}
    )
    if undeclared:
        raise ScorecardInputError(
            f"campaign mandatory comparators are absent from model.solvers: {undeclared!r}"
        )
    selected = [
        (panel, kind)
        for panel in model["panels"]
        if (kind := _selected_kind(panel)) is not None
    ]
    selected.sort(key=lambda pair: _panel_sort_key(pair[0]))
    current_broad = _candidate_broad_panels(model, contract)
    if not current_broad:
        baseline = {
            "state": "missing",
            "candidate_revision": contract["candidate_revision"],
            "panel_ids": [],
            "reason": "No broad whole-corpus panel uses the campaign candidate revision.",
        }
    elif any(
        panel["complete"]
        and panel["claim_boundary"]["evidence_status"] == "verified"
        and panel["claim_boundary"]["expected_status"] == "all"
        for panel in current_broad
    ):
        baseline = {
            "state": "available",
            "candidate_revision": contract["candidate_revision"],
            "panel_ids": sorted(panel["id"] for panel in current_broad),
            "reason": "At least one complete verified broad whole-corpus panel is available.",
        }
    else:
        legacy = any(
            panel["claim_boundary"]["expected_status"] == "legacy-unstratified"
            for panel in current_broad
        )
        baseline = {
            "state": "incomplete",
            "candidate_revision": contract["candidate_revision"],
            "panel_ids": sorted(panel["id"] for panel in current_broad),
            "reason": (
                "Broad candidate panels use the legacy model without an explicit "
                "expected-status dimension."
                if legacy
                else "Broad candidate panels exist, but none is complete and verified."
            ),
        }
    scorecard = {
        "schema_version": SCORECARD_SCHEMA_VERSION,
        "campaign": {
            "id": contract["campaign_id"],
            "candidate_id": contract["candidate_id"],
            "candidate_revision": contract["candidate_revision"],
            "mandatory_comparator_ids": contract["mandatory_comparator_ids"],
        },
        "source_model": {
            "schema_version": model["schema_version"],
            "registry_id": model["registry"]["id"],
            "registry_sha256": model["registry"]["sha256"],
            "updated_at": model["registry"]["updated_at"],
            "expected_status_dimension": model["expected_status_dimension"],
        },
        "selection": {
            "policy": ["broad_whole_corpus", "targeted_structural_combined"],
            "selected_panels": len(selected),
            "excluded_panels": len(model["panels"]) - len(selected),
            "claim_boundaries_pooled": False,
        },
        "broad_current_route_baseline": baseline,
        "victory": _victory_state(model, contract),
        "panels": [_compact_panel(panel, kind) for panel, kind in selected],
    }
    _assert_finite(scorecard)
    return scorecard


def _assert_finite(value: object, context: str = "scorecard") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ArithmeticError(f"{context} contains a non-finite number")
    if type(value) is dict:
        for key, child in value.items():
            _assert_finite(child, f"{context}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _assert_finite(child, f"{context}[{index}]")


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _format_number(value: float | None, *, digits: int = 4) -> str:
    return "n/a" if value is None else f"{value:.{digits}g}"


def _format_percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:+.2f}%"


def _format_reduction(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}%"


def render_markdown(scorecard: Mapping[str, Any]) -> str:
    """Render the compact scorecard as deterministic Markdown."""

    campaign = scorecard["campaign"]
    baseline = scorecard["broad_current_route_baseline"]
    lines = [
        "# EUF Campaign Scorecard",
        "",
        f"- Campaign: `{campaign['id']}`",
        f"- Candidate: `{campaign['candidate_id']}` at `{campaign['candidate_revision']}`",
        f"- Source registry: `{scorecard['source_model']['registry_id']}` "
        f"(`{scorecard['source_model']['registry_sha256']}`)",
        f"- Broad current-route baseline: **{baseline['state'].upper()}**. {baseline['reason']}",
        f"- Selected panels: {scorecard['selection']['selected_panels']} "
        f"({scorecard['selection']['excluded_panels']} excluded; claim boundaries are not pooled)",
        "",
        "## Victory Gates",
        "",
        "| Gate | State | Evidence | Reason |",
        "|---|---:|---|---|",
    ]
    for gate in scorecard["victory"]["gates"]:
        evidence = ", ".join(f"`{panel_id}`" for panel_id in gate["evidence_panel_ids"]) or "none"
        lines.append(
            f"| {gate['id']} | **{gate['state'].upper()}** | {evidence} | {gate['reason']} |"
        )
    lines.extend(
        [
            "",
            f"Overall `{scorecard['victory']['claim']}` state: "
            f"**{scorecard['victory']['state'].upper()}**.",
            "",
        ]
    )
    for panel in scorecard["panels"]:
        boundary = panel["claim_boundary"]
        lines.extend(
            [
                f"## {panel['kind'].replace('_', ' ').title()}: {boundary['corpus']['label']}",
                "",
                f"`{panel['id']}` | revision `{boundary['revision']}` | "
                f"status `{boundary['evidence_status']}` | family `{boundary['family']['id']}` | "
                f"expected `{boundary['expected_status']}` | "
                f"timeout `{boundary['timeout_s']:g}s` | host `{boundary['host']['id']}` | "
                f"class `{boundary['evidence_class']}`",
                "",
                f"Instances: {panel['instances']}; complete: `{str(panel['complete']).lower()}`; "
                f"leader solves: {panel['leader_solved'] if panel['leader_solved'] is not None else 'n/a'}.",
                "",
                "| Solver | Solved | Coverage | PAR2 (s) |",
                "|---|---:|---:|---:|",
            ]
        )
        for solver in panel["solvers"]:
            coverage = solver["coverage"]["value"]
            coverage_text = "n/a" if coverage is None else f"{100.0 * coverage:.2f}%"
            lines.append(
                f"| {solver['label']} (`{solver['solver_id']}`) | {solver['solved']} | "
                f"{coverage_text} | {_format_number(solver['par2_s']['value'], digits=6)} |"
            )
        lines.extend(
            [
                "",
                "| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |",
                "|---|---|---:|---:|---:|---:|",
            ]
        )
        for comparison in panel["comparisons"]:
            for metric_name in PRIMARY_TIME_METRICS:
                metric = comparison["metrics"][metric_name]
                lines.append(
                    f"| {comparison['competitor_label']} (`{comparison['competitor_id']}`) | "
                    f"{metric_name.replace('_', ' ')} | {comparison['common_solved']} | "
                    f"{_format_number(metric['ratio'], digits=6)} | "
                    f"{_format_percent(metric['signed_percent'])} | "
                    f"{_format_reduction(metric['required_viper_reduction_percent'])} |"
                )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_artifacts_atomic(artifacts: Sequence[tuple[Path, bytes]]) -> None:
    """Stage all outputs, then publish each with a same-directory replace."""

    destinations = [path.resolve() for path, _ in artifacts]
    if len(destinations) != len(set(destinations)):
        raise ScorecardInputError("output paths must be distinct")
    staged: list[tuple[Path, Path]] = []
    try:
        for destination, (_, payload) in zip(destinations, artifacts):
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
                temporary = Path(handle.name)
            staged.append((temporary, destination))
        for temporary, destination in staged:
            os.replace(temporary, destination)
    finally:
        for temporary, _ in staged:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path, help="dashboard model v1 JSON")
    parser.add_argument("--campaign-contract", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        options = parse_args(argv)
        model_path = options.model.expanduser().resolve()
        contract_path = options.campaign_contract.expanduser().resolve()
        json_out = options.json_out.expanduser().resolve()
        markdown_out = options.markdown_out.expanduser().resolve()
        if json_out in {model_path, contract_path} or markdown_out in {
            model_path,
            contract_path,
        }:
            raise ScorecardInputError("outputs must not overwrite inputs")
        scorecard = build_scorecard(
            _strict_json(model_path, "dashboard model"),
            _strict_json(contract_path, "campaign contract"),
        )
        markdown = render_markdown(scorecard).encode("utf-8")
        write_artifacts_atomic(
            [(json_out, canonical_json_bytes(scorecard)), (markdown_out, markdown)]
        )
    except (ScorecardInputError, ArithmeticError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
