#!/usr/bin/env python3
"""Build the static EUF performance dashboard from a strict evidence registry.

The input schema is ``euf-viper.dashboard-evidence.v1``.  It is deliberately
small and adapter-oriented: campaign importers should normalize their evidence
to this schema instead of teaching the dashboard about every campaign format.
All objects are closed (unknown keys are errors), all solver observations are
explicit, and provenance that defines a performance claim lives on each
evidence record.

Example registry shape::

    {
      "schema_version": "euf-viper.dashboard-evidence.v1",
      "registry_id": "qf-uf-progress",
      "title": "EUF Viper evidence",
      "updated_at": "2026-07-26T00:00:00Z",
      "viper_solver_id": "viper",
      "solvers": [
        {"id": "viper", "label": "Viper"},
        {"id": "z3", "label": "Z3"}
      ],
      "evidence": [
        {
          "id": "official-2s-part-1",
          "scope": "broad",
          "evidence_class": "official-campaign",
          "evidence_status": "verified",
          "revision": "0123456789abcdef0123456789abcdef01234567",
          "solver_ids": ["viper", "z3"],
          "host": {"id": "wmi-c3n1", "label": "WMI c3n1"},
          "corpus": {"id": "smtcomp-qf-uf", "label": "SMT-COMP QF_UF"},
          "timeout_s": 2.0,
          "family": {"id": "all", "label": "All families"},
          "expected_status": "all",
          "source": {"path": "results/run.json", "sha256": "...64 hex..."},
          "instances": [
            {
              "id": "QF_UF/example.smt2",
              "results": [
                {"solver_id": "viper", "status": "solved", "time_s": 0.1},
                {"solver_id": "z3", "status": "timeout", "time_s": null}
              ]
            }
          ]
        }
      ]
    }

Evidence records are merged into a panel only when scope, corpus, timeout,
family, solver set, evidence status, revision, host, and evidence class all
match.  This prevents the renderer from producing a claim that pools
incompatible evidence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import html
import json
import math
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REGISTRY_SCHEMA_VERSION = "euf-viper.dashboard-evidence.v1"
MODEL_SCHEMA_VERSION = "euf-viper.dashboard-model.v1"
SCOPES = ("broad", "targeted")
EVIDENCE_STATUSES = (
    "verified",
    "provisional",
    "incomplete",
    "rejected",
    "superseded",
)
RESULT_STATUSES = (
    "solved",
    "timeout",
    "unknown",
    "error",
    "invalid",
    "wrong-answer",
    "unavailable",
)
EXPECTED_STATUSES = ("all", "sat", "unsat")
ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
REVISION_PATTERN = re.compile(r"[0-9a-f]{7,64}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
MAX_TIMEOUT_S = sys.float_info.max / 4.0

TOP_LEVEL_KEYS = {
    "schema_version",
    "registry_id",
    "title",
    "updated_at",
    "viper_solver_id",
    "solvers",
    "evidence",
}
SOLVER_KEYS = {"id", "label"}
EVIDENCE_KEYS = {
    "id",
    "scope",
    "evidence_class",
    "evidence_status",
    "revision",
    "solver_ids",
    "host",
    "corpus",
    "timeout_s",
    "family",
    "expected_status",
    "source",
    "instances",
}
NAMED_ID_KEYS = {"id", "label"}
SOURCE_KEYS = {"path", "sha256"}
INSTANCE_KEYS = {"id", "results"}
RESULT_KEYS = {"solver_id", "status", "time_s"}


class DashboardInputError(ValueError):
    """Raised when registry data cannot support a trustworthy dashboard."""


def _require_exact_keys(value: object, expected: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise DashboardInputError(f"{context} must be an object")
    mapping = value
    if not all(type(key) is str for key in mapping):
        raise DashboardInputError(f"{context}: object keys must be strings")
    actual = set(mapping)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing keys {missing!r}")
        if extra:
            details.append(f"unexpected keys {extra!r}")
        raise DashboardInputError(f"{context}: {'; '.join(details)}")
    return mapping


def _require_list(value: object, context: str, *, nonempty: bool = True) -> list[Any]:
    if type(value) is not list:
        raise DashboardInputError(f"{context} must be an array")
    result = value
    if nonempty and not result:
        raise DashboardInputError(f"{context} must not be empty")
    return result


def _require_text(value: object, context: str, *, maximum: int = 240) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise DashboardInputError(f"{context} must be a non-empty trimmed string")
    if len(value) > maximum:
        raise DashboardInputError(f"{context} exceeds {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise DashboardInputError(f"{context} contains a control character")
    return value


def _require_id(value: object, context: str) -> str:
    result = _require_text(value, context, maximum=128)
    if ID_PATTERN.fullmatch(result) is None:
        raise DashboardInputError(
            f"{context} must match {ID_PATTERN.pattern!r}"
        )
    return result


def _require_number(
    value: object,
    context: str,
    *,
    positive: bool = False,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DashboardInputError(f"{context} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise DashboardInputError(f"{context} must be finite")
    if positive and result <= 0.0:
        raise DashboardInputError(f"{context} must be positive")
    if maximum is not None and result > maximum:
        raise DashboardInputError(f"{context} exceeds the supported maximum")
    return result


def _validate_timestamp(value: object, context: str) -> str:
    result = _require_text(value, context, maximum=64)
    if not (result.endswith("Z") or result.endswith("+00:00")):
        raise DashboardInputError(f"{context} must be an RFC 3339 UTC timestamp")
    try:
        parsed_text = result[:-1] + "+00:00" if result.endswith("Z") else result
        parsed = dt.datetime.fromisoformat(parsed_text)
    except ValueError as error:
        raise DashboardInputError(
            f"{context} must be an RFC 3339 UTC timestamp"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise DashboardInputError(f"{context} must use UTC")
    return result


def _validate_named_id(value: object, context: str) -> dict[str, str]:
    mapping = _require_exact_keys(value, NAMED_ID_KEYS, context)
    return {
        "id": _require_id(mapping["id"], f"{context}.id"),
        "label": _require_text(mapping["label"], f"{context}.label"),
    }


def _validate_source(value: object, context: str) -> dict[str, str]:
    mapping = _require_exact_keys(value, SOURCE_KEYS, context)
    path = _require_text(mapping["path"], f"{context}.path", maximum=2048)
    digest = _require_text(mapping["sha256"], f"{context}.sha256", maximum=64)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise DashboardInputError(f"{context}.sha256 is not a canonical SHA-256")
    return {"path": path, "sha256": digest}


def _validate_result(
    value: object,
    context: str,
    *,
    solver_ids: set[str],
    timeout_s: float,
) -> dict[str, Any]:
    mapping = _require_exact_keys(value, RESULT_KEYS, context)
    solver_id = _require_id(mapping["solver_id"], f"{context}.solver_id")
    if solver_id not in solver_ids:
        raise DashboardInputError(
            f"{context}.solver_id references undeclared solver {solver_id!r}"
        )
    status = _require_text(mapping["status"], f"{context}.status", maximum=32)
    if status not in RESULT_STATUSES:
        raise DashboardInputError(
            f"{context}.status must be one of {list(RESULT_STATUSES)!r}"
        )
    raw_time = mapping["time_s"]
    if status == "solved":
        time_s = _require_number(raw_time, f"{context}.time_s", positive=True)
    else:
        if raw_time is not None:
            raise DashboardInputError(
                f"{context}.time_s must be null when status is {status!r}"
            )
        time_s = None
    return {"solver_id": solver_id, "status": status, "time_s": time_s}


def _validate_instance(
    value: object,
    context: str,
    *,
    solver_ids: set[str],
    timeout_s: float,
) -> dict[str, Any]:
    mapping = _require_exact_keys(value, INSTANCE_KEYS, context)
    identifier = _require_text(mapping["id"], f"{context}.id", maximum=1024)
    results = [
        _validate_result(
            result,
            f"{context}.results[{index}]",
            solver_ids=solver_ids,
            timeout_s=timeout_s,
        )
        for index, result in enumerate(
            _require_list(mapping["results"], f"{context}.results")
        )
    ]
    seen = [result["solver_id"] for result in results]
    duplicates = sorted(
        solver_id for solver_id, count in Counter(seen).items() if count > 1
    )
    if duplicates:
        raise DashboardInputError(
            f"{context}.results contains duplicate solvers {duplicates!r}"
        )
    actual = set(seen)
    if actual != solver_ids:
        raise DashboardInputError(
            f"{context}.results must contain every declared solver exactly once; "
            f"missing={sorted(solver_ids - actual)!r}, "
            f"unexpected={sorted(actual - solver_ids)!r}"
        )
    return {
        "id": identifier,
        "results": sorted(results, key=lambda result: result["solver_id"]),
    }


def _validate_evidence(
    value: object,
    context: str,
    *,
    solver_ids: set[str],
) -> dict[str, Any]:
    mapping = _require_exact_keys(value, EVIDENCE_KEYS, context)
    scope = _require_text(mapping["scope"], f"{context}.scope", maximum=16)
    if scope not in SCOPES:
        raise DashboardInputError(f"{context}.scope must be one of {list(SCOPES)!r}")
    evidence_status = _require_text(
        mapping["evidence_status"], f"{context}.evidence_status", maximum=32
    )
    if evidence_status not in EVIDENCE_STATUSES:
        raise DashboardInputError(
            f"{context}.evidence_status must be one of {list(EVIDENCE_STATUSES)!r}"
        )
    evidence_class = _require_id(
        mapping["evidence_class"], f"{context}.evidence_class"
    )
    revision = _require_text(mapping["revision"], f"{context}.revision", maximum=64)
    if REVISION_PATTERN.fullmatch(revision) is None:
        raise DashboardInputError(
            f"{context}.revision must be a lowercase hexadecimal revision of 7-64 digits"
        )
    evidence_solver_ids = [
        _require_id(solver_id, f"{context}.solver_ids[{index}]")
        for index, solver_id in enumerate(
            _require_list(mapping["solver_ids"], f"{context}.solver_ids")
        )
    ]
    duplicate_solver_ids = sorted(
        solver_id
        for solver_id, count in Counter(evidence_solver_ids).items()
        if count > 1
    )
    if duplicate_solver_ids:
        raise DashboardInputError(
            f"{context}.solver_ids contains duplicate IDs {duplicate_solver_ids!r}"
        )
    evidence_solver_set = set(evidence_solver_ids)
    undeclared_solver_ids = sorted(evidence_solver_set - solver_ids)
    if undeclared_solver_ids:
        raise DashboardInputError(
            f"{context}.solver_ids references undeclared solvers "
            f"{undeclared_solver_ids!r}"
        )
    if len(evidence_solver_set) < 2:
        raise DashboardInputError(
            f"{context}.solver_ids must contain Viper and at least one competitor"
        )
    timeout_s = _require_number(
        mapping["timeout_s"],
        f"{context}.timeout_s",
        positive=True,
        maximum=MAX_TIMEOUT_S,
    )
    expected_status = _require_text(
        mapping["expected_status"], f"{context}.expected_status", maximum=16
    )
    if expected_status not in EXPECTED_STATUSES:
        raise DashboardInputError(
            f"{context}.expected_status must be one of {list(EXPECTED_STATUSES)!r}"
        )
    instances = [
        _validate_instance(
            instance,
            f"{context}.instances[{index}]",
            solver_ids=evidence_solver_set,
            timeout_s=timeout_s,
        )
        for index, instance in enumerate(
            _require_list(mapping["instances"], f"{context}.instances")
        )
    ]
    instance_ids = [instance["id"] for instance in instances]
    duplicates = sorted(
        identifier for identifier, count in Counter(instance_ids).items() if count > 1
    )
    if duplicates:
        raise DashboardInputError(
            f"{context}.instances contains duplicate IDs {duplicates!r}"
        )
    return {
        "id": _require_id(mapping["id"], f"{context}.id"),
        "scope": scope,
        "evidence_class": evidence_class,
        "evidence_status": evidence_status,
        "revision": revision,
        "solver_ids": sorted(evidence_solver_ids),
        "host": _validate_named_id(mapping["host"], f"{context}.host"),
        "corpus": _validate_named_id(mapping["corpus"], f"{context}.corpus"),
        "timeout_s": timeout_s,
        "family": _validate_named_id(mapping["family"], f"{context}.family"),
        "expected_status": expected_status,
        "source": _validate_source(mapping["source"], f"{context}.source"),
        "instances": sorted(instances, key=lambda instance: instance["id"]),
    }


def _remember_label(
    labels: dict[str, str], named: Mapping[str, str], context: str
) -> None:
    existing = labels.get(named["id"])
    if existing is not None and existing != named["label"]:
        raise DashboardInputError(
            f"{context}: ID {named['id']!r} has conflicting labels "
            f"{existing!r} and {named['label']!r}"
        )
    labels[named["id"]] = named["label"]


def validate_registry(value: object) -> dict[str, Any]:
    """Validate and normalize a dashboard evidence registry."""

    mapping = _require_exact_keys(value, TOP_LEVEL_KEYS, "registry")
    if mapping["schema_version"] != REGISTRY_SCHEMA_VERSION:
        raise DashboardInputError(
            "registry.schema_version must be " f"{REGISTRY_SCHEMA_VERSION!r}"
        )
    solvers = [
        _validate_named_id(solver, f"registry.solvers[{index}]")
        for index, solver in enumerate(
            _require_list(mapping["solvers"], "registry.solvers")
        )
    ]
    if len(solvers) < 2:
        raise DashboardInputError("registry.solvers must declare Viper and a competitor")
    solver_id_list = [solver["id"] for solver in solvers]
    duplicate_solvers = sorted(
        solver_id for solver_id, count in Counter(solver_id_list).items() if count > 1
    )
    if duplicate_solvers:
        raise DashboardInputError(
            f"registry.solvers contains duplicate IDs {duplicate_solvers!r}"
        )
    solver_ids = set(solver_id_list)
    viper_solver_id = _require_id(
        mapping["viper_solver_id"], "registry.viper_solver_id"
    )
    if viper_solver_id not in solver_ids:
        raise DashboardInputError(
            "registry.viper_solver_id must reference a declared solver"
        )
    evidence = [
        _validate_evidence(
            item,
            f"registry.evidence[{index}]",
            solver_ids=solver_ids,
        )
        for index, item in enumerate(
            _require_list(mapping["evidence"], "registry.evidence")
        )
    ]
    for index, item in enumerate(evidence):
        if viper_solver_id not in item["solver_ids"]:
            raise DashboardInputError(
                f"registry.evidence[{index}].solver_ids must contain "
                "registry.viper_solver_id"
            )
    evidence_ids = [item["id"] for item in evidence]
    duplicate_evidence = sorted(
        identifier for identifier, count in Counter(evidence_ids).items() if count > 1
    )
    if duplicate_evidence:
        raise DashboardInputError(
            f"registry.evidence contains duplicate IDs {duplicate_evidence!r}"
        )

    host_labels: dict[str, str] = {}
    corpus_labels: dict[str, str] = {}
    family_labels: dict[str, str] = {}
    for index, item in enumerate(evidence):
        _remember_label(host_labels, item["host"], f"registry.evidence[{index}].host")
        _remember_label(
            corpus_labels, item["corpus"], f"registry.evidence[{index}].corpus"
        )
        _remember_label(
            family_labels, item["family"], f"registry.evidence[{index}].family"
        )

    solver_by_id = {solver["id"]: solver for solver in solvers}
    ordered_solvers = [solver_by_id[viper_solver_id]] + sorted(
        (
            solver
            for solver_id, solver in solver_by_id.items()
            if solver_id != viper_solver_id
        ),
        key=lambda solver: (solver["label"].casefold(), solver["id"]),
    )
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "registry_id": _require_id(mapping["registry_id"], "registry.registry_id"),
        "title": _require_text(mapping["title"], "registry.title"),
        "updated_at": _validate_timestamp(mapping["updated_at"], "registry.updated_at"),
        "viper_solver_id": viper_solver_id,
        "solvers": ordered_solvers,
        "evidence": sorted(evidence, key=lambda item: item["id"]),
    }


def _reject_json_constant(token: str) -> None:
    raise DashboardInputError(f"non-finite JSON number {token!r} is forbidden")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DashboardInputError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_registry(path: Path) -> dict[str, Any]:
    """Load strict JSON and return a validated registry."""

    try:
        payload = path.read_bytes()
        if path.suffix == ".gz":
            payload = gzip.decompress(payload)
        raw = payload.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise DashboardInputError(f"cannot read registry {path}: {error}") from error
    except gzip.BadGzipFile as error:
        raise DashboardInputError(f"cannot decompress registry {path}: {error}") from error
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise DashboardInputError(
            f"{path}:{error.lineno}:{error.colno}: invalid JSON: {error.msg}"
        ) from error
    return validate_registry(value)


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def pretty_json_bytes(value: object) -> bytes:
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


def _metric(value: float) -> dict[str, Any]:
    if not math.isfinite(value):
        return _unavailable("calculation is outside the finite numeric range")
    return {"status": "available", "value": value, "reason": None}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "value": None, "reason": reason}


def _quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise ValueError("cannot compute a quantile of an empty sample")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = probability * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _geometric_mean(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("cannot compute a geometric mean of an empty sample")
    result = math.exp(math.fsum(math.log(value) for value in values) / len(values))
    if not math.isfinite(result) or result <= 0.0:
        raise ArithmeticError("geometric mean is outside the finite positive range")
    return result


def _safe_sum(values: Sequence[float]) -> float | None:
    try:
        result = math.fsum(values)
    except OverflowError:
        return None
    if not math.isfinite(result):
        return None
    return result


def _solver_summary(
    solver: Mapping[str, str],
    results: Sequence[Mapping[str, Any]],
    timeout_s: float,
) -> dict[str, Any]:
    counts = Counter(result["status"] for result in results)
    unavailable_count = counts["unavailable"]
    solved_times = [
        float(result["time_s"])
        for result in results
        if result["status"] == "solved"
    ]
    complete = unavailable_count == 0
    if complete:
        coverage = _metric(len(solved_times) / len(results))
        charges = [
            float(result["time_s"])
            if result["status"] == "solved"
            else 2.0 * timeout_s
            for result in results
        ]
        # Dividing before summing avoids overflowing merely because a panel is large.
        par2_value = _safe_sum([charge / len(charges) for charge in charges])
        par2 = (
            _metric(par2_value)
            if par2_value is not None
            else _unavailable("PAR2 is outside the finite numeric range")
        )
    else:
        reason = f"{unavailable_count} of {len(results)} observations are unavailable"
        coverage = _unavailable(reason)
        par2 = _unavailable(reason)
    if not complete:
        latency_reason = (
            f"{unavailable_count} of {len(results)} observations are unavailable"
        )
        median = _unavailable(latency_reason)
        p95 = _unavailable(latency_reason)
    elif not solved_times:
        median = _unavailable("solver has no solved instances in this panel")
        p95 = _unavailable("solver has no solved instances in this panel")
    else:
        median = _metric(_quantile(solved_times, 0.5))
        p95 = _metric(_quantile(solved_times, 0.95))
    return {
        "solver_id": solver["id"],
        "label": solver["label"],
        "instances": len(results),
        "available_observations": len(results) - unavailable_count,
        "unavailable_observations": unavailable_count,
        "solved": len(solved_times),
        "result_counts": {
            status: counts[status] for status in RESULT_STATUSES if counts[status]
        },
        "coverage": coverage,
        "leader_relative_coverage": _unavailable("leader not computed yet"),
        "par2_s": par2,
        "median_s": median,
        "p95_s": p95,
    }


def _comparison_value(
    viper_time_s: float | None,
    competitor_time_s: float | None,
    unavailable_reason: str | None = None,
) -> dict[str, Any]:
    if unavailable_reason is not None:
        return {
            "status": "unavailable",
            "viper_time_s": None,
            "competitor_time_s": None,
            "ratio": None,
            "signed_performance_index": None,
            "required_viper_time_reduction": None,
            "required_viper_speedup": None,
            "reason": unavailable_reason,
        }
    assert viper_time_s is not None and competitor_time_s is not None
    if viper_time_s <= 0.0 or competitor_time_s <= 0.0:
        return _comparison_value(None, None, "timing values must be positive")
    ratio = competitor_time_s / viper_time_s
    if not math.isfinite(ratio) or ratio <= 0.0:
        return _comparison_value(None, None, "timing ratio is outside the finite range")
    signed_index = ratio - 1.0
    if signed_index == -0.0 or abs(signed_index) < 1e-15:
        signed_index = 0.0
    required_reduction = max(0.0, 1.0 - ratio)
    if ratio < 1.0:
        required_speedup = (1.0 / ratio) - 1.0
        if not math.isfinite(required_speedup):
            return _comparison_value(
                None, None, "required speedup is outside the finite range"
            )
    else:
        required_speedup = 0.0
    return {
        "status": "available",
        "viper_time_s": viper_time_s,
        "competitor_time_s": competitor_time_s,
        "ratio": ratio,
        "signed_performance_index": signed_index,
        "required_viper_time_reduction": required_reduction,
        "required_viper_speedup": required_speedup,
        "reason": None,
    }


def _comparison_from_metrics(
    viper_metric: Mapping[str, Any], competitor_metric: Mapping[str, Any]
) -> dict[str, Any]:
    if viper_metric["status"] != "available":
        return _comparison_value(
            None, None, f"Viper metric unavailable: {viper_metric['reason']}"
        )
    if competitor_metric["status"] != "available":
        return _comparison_value(
            None,
            None,
            f"competitor metric unavailable: {competitor_metric['reason']}",
        )
    return _comparison_value(
        float(viper_metric["value"]), float(competitor_metric["value"])
    )


def _pairwise_comparison(
    competitor: Mapping[str, str],
    instance_results: Mapping[str, Mapping[str, Mapping[str, Any]]],
    summaries: Mapping[str, Mapping[str, Any]],
    viper_solver_id: str,
) -> dict[str, Any]:
    competitor_id = competitor["id"]
    incomplete = [
        instance_id
        for instance_id, solver_results in instance_results.items()
        if solver_results[viper_solver_id]["status"] == "unavailable"
        or solver_results[competitor_id]["status"] == "unavailable"
    ]
    common_pairs = [
        (
            float(solver_results[viper_solver_id]["time_s"]),
            float(solver_results[competitor_id]["time_s"]),
        )
        for _, solver_results in sorted(instance_results.items())
        if solver_results[viper_solver_id]["status"] == "solved"
        and solver_results[competitor_id]["status"] == "solved"
    ]
    metrics: dict[str, dict[str, Any]] = {
        "par2": _comparison_from_metrics(
            summaries[viper_solver_id]["par2_s"],
            summaries[competitor_id]["par2_s"],
        )
    }
    if incomplete:
        reason = (
            f"pair has unavailable observations on {len(incomplete)} of "
            f"{len(instance_results)} instances"
        )
        for name in ("common_geometric", "common_total", "median", "p95"):
            metrics[name] = _comparison_value(None, None, reason)
    elif not common_pairs:
        reason = "Viper and competitor have no commonly solved instances"
        for name in ("common_geometric", "common_total", "median", "p95"):
            metrics[name] = _comparison_value(None, None, reason)
    else:
        viper_times = [pair[0] for pair in common_pairs]
        competitor_times = [pair[1] for pair in common_pairs]
        viper_total = _safe_sum(viper_times)
        competitor_total = _safe_sum(competitor_times)
        metrics.update(
            {
                "common_geometric": _comparison_value(
                    _geometric_mean(viper_times),
                    _geometric_mean(competitor_times),
                ),
                "common_total": (
                    _comparison_value(viper_total, competitor_total)
                    if viper_total is not None and competitor_total is not None
                    else _comparison_value(
                        None, None, "common total is outside the finite range"
                    )
                ),
                "median": _comparison_value(
                    _quantile(viper_times, 0.5),
                    _quantile(competitor_times, 0.5),
                ),
                "p95": _comparison_value(
                    _quantile(viper_times, 0.95),
                    _quantile(competitor_times, 0.95),
                ),
            }
        )
    primary = dict(metrics["common_geometric"])
    primary["basis"] = "common_geometric"
    return {
        "competitor_id": competitor_id,
        "competitor_label": competitor["label"],
        "common_solved": len(common_pairs),
        "instances": len(instance_results),
        "performance_index": primary,
        "metrics": metrics,
    }


def _claim_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        item["scope"],
        item["corpus"]["id"],
        item["timeout_s"],
        item["family"]["id"],
        item["expected_status"],
        tuple(item["solver_ids"]),
        item["evidence_status"],
        item["revision"],
        item["host"]["id"],
        item["evidence_class"],
    )


def _panel_sort_key(panel: Mapping[str, Any]) -> tuple[Any, ...]:
    boundary = panel["claim_boundary"]
    status_rank = EVIDENCE_STATUSES.index(boundary["evidence_status"])
    return (
        SCOPES.index(boundary["scope"]),
        boundary["corpus"]["label"].casefold(),
        boundary["corpus"]["id"],
        boundary["timeout_s"],
        boundary["family"]["label"].casefold(),
        boundary["family"]["id"],
        EXPECTED_STATUSES.index(boundary["expected_status"]),
        status_rank,
        boundary["evidence_class"],
        boundary["revision"],
        boundary["host"]["id"],
    )


def _build_panel(
    items: Sequence[Mapping[str, Any]],
    solvers: Sequence[Mapping[str, str]],
    viper_solver_id: str,
) -> dict[str, Any]:
    first = items[0]
    key = _claim_key(first)
    if any(_claim_key(item) != key for item in items[1:]):
        raise AssertionError("panel construction attempted to mix claim boundaries")
    instances: dict[str, dict[str, Mapping[str, Any]]] = {}
    evidence_by_instance: dict[str, str] = {}
    for item in items:
        for instance in item["instances"]:
            identifier = instance["id"]
            if identifier in instances:
                raise DashboardInputError(
                    f"claim-safe panel contains duplicate instance {identifier!r} "
                    f"in evidence {evidence_by_instance[identifier]!r} and {item['id']!r}"
                )
            instances[identifier] = {
                result["solver_id"]: result for result in instance["results"]
            }
            evidence_by_instance[identifier] = item["id"]
    panel_solver_ids = set(first["solver_ids"])
    panel_solvers = [
        solver for solver in solvers if solver["id"] in panel_solver_ids
    ]
    solver_summaries = {
        solver["id"]: _solver_summary(
            solver,
            [instances[identifier][solver["id"]] for identifier in sorted(instances)],
            float(first["timeout_s"]),
        )
        for solver in panel_solvers
    }
    incomplete_solvers = [
        solver_id
        for solver_id, summary in solver_summaries.items()
        if summary["unavailable_observations"]
    ]
    if incomplete_solvers:
        leader_ids: list[str] = []
        leader_solved: int | None = None
        reason = "leader cannot be established while any solver has unavailable data"
        for summary in solver_summaries.values():
            summary["leader_relative_coverage"] = _unavailable(reason)
    else:
        leader_solved = max(summary["solved"] for summary in solver_summaries.values())
        leader_ids = sorted(
            solver_id
            for solver_id, summary in solver_summaries.items()
            if summary["solved"] == leader_solved
        )
        for summary in solver_summaries.values():
            summary["leader_relative_coverage"] = (
                _metric(summary["solved"] / leader_solved)
                if leader_solved
                else _unavailable("no solver solved an instance in this panel")
            )
    comparisons = [
        _pairwise_comparison(
            competitor,
            instances,
            solver_summaries,
            viper_solver_id,
        )
        for competitor in panel_solvers
        if competitor["id"] != viper_solver_id
    ]
    claim_boundary = {
        "scope": first["scope"],
        "corpus": first["corpus"],
        "timeout_s": first["timeout_s"],
        "family": first["family"],
        "expected_status": first["expected_status"],
        "solver_ids": first["solver_ids"],
        "evidence_status": first["evidence_status"],
        "revision": first["revision"],
        "host": first["host"],
        "evidence_class": first["evidence_class"],
    }
    panel_token = canonical_json_bytes(claim_boundary)
    panel_id = "panel-" + hashlib.sha256(panel_token).hexdigest()[:16]
    return {
        "id": panel_id,
        "claim_boundary": claim_boundary,
        "evidence_ids": sorted(item["id"] for item in items),
        "sources": sorted(
            (dict(item["source"]) for item in items),
            key=lambda source: (source["path"], source["sha256"]),
        ),
        "instances": len(instances),
        "complete": not incomplete_solvers,
        "incomplete_solver_ids": sorted(incomplete_solvers),
        "leader_solver_ids": leader_ids,
        "leader_solved": leader_solved,
        "solvers": [solver_summaries[solver["id"]] for solver in panel_solvers],
        "comparisons": comparisons,
    }


def _filter_options(panels: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    named_fields = (
        ("corpus", "corpora"),
        ("family", "families"),
        ("host", "hosts"),
    )
    result: dict[str, Any] = {}
    for field, output_key in named_fields:
        unique = {
            panel["claim_boundary"][field]["id"]: panel["claim_boundary"][field]
            for panel in panels
        }
        result[output_key] = sorted(
            (dict(named) for named in unique.values()),
            key=lambda named: (named["label"].casefold(), named["id"]),
        )
    result["timeouts"] = [
        {"value": repr(timeout), "label": _format_timeout(timeout)}
        for timeout in sorted(
            {float(panel["claim_boundary"]["timeout_s"]) for panel in panels}
        )
    ]
    result["evidence_statuses"] = [
        status
        for status in EVIDENCE_STATUSES
        if any(panel["claim_boundary"]["evidence_status"] == status for panel in panels)
    ]
    result["expected_statuses"] = [
        status
        for status in EXPECTED_STATUSES
        if any(
            panel["claim_boundary"]["expected_status"] == status
            for panel in panels
        )
    ]
    result["evidence_classes"] = sorted(
        {panel["claim_boundary"]["evidence_class"] for panel in panels}
    )
    result["revisions"] = sorted(
        {panel["claim_boundary"]["revision"] for panel in panels}
    )
    return result


def _assert_finite_json(value: object, context: str = "model") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ArithmeticError(f"{context} contains a non-finite number")
    if type(value) is dict:
        for key, child in value.items():
            _assert_finite_json(child, f"{context}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _assert_finite_json(child, f"{context}[{index}]")


def build_dashboard(registry: object) -> dict[str, Any]:
    """Validate a registry and compute a deterministic dashboard model."""

    normalized = validate_registry(registry)
    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for item in normalized["evidence"]:
        grouped[_claim_key(item)].append(item)
    panels = [
        _build_panel(items, normalized["solvers"], normalized["viper_solver_id"])
        for _, items in sorted(grouped.items(), key=lambda pair: pair[0])
    ]
    panels.sort(key=_panel_sort_key)
    model = {
        "schema_version": MODEL_SCHEMA_VERSION,
        "registry": {
            "id": normalized["registry_id"],
            "schema_version": normalized["schema_version"],
            "sha256": hashlib.sha256(canonical_json_bytes(normalized)).hexdigest(),
            "title": normalized["title"],
            "updated_at": normalized["updated_at"],
        },
        "viper_solver_id": normalized["viper_solver_id"],
        "solvers": normalized["solvers"],
        "panels": panels,
        "filter_options": _filter_options(panels),
        "metric_definitions": {
            "coverage": "Solved instances divided by the complete panel population.",
            "leader_relative_coverage": "Solver coverage divided by the highest solved count in the panel.",
            "par2": "Mean runtime with every non-solve charged at twice the panel timeout.",
            "common_geometric": "Geometric mean time on instances solved by both Viper and the competitor.",
            "common_total": "Total time on instances solved by both Viper and the competitor.",
            "median": "Interpolated median time on the pairwise common-solved set.",
            "p95": "Interpolated 95th-percentile time on the pairwise common-solved set.",
            "signed_performance_index": "competitor_time / viper_time - 1 for lower-is-better metrics; positive favors Viper.",
            "required_improvement": "Viper time reduction and speedup still required to reach parity when the signed index is negative.",
        },
    }
    _assert_finite_json(model)
    return model


def _format_timeout(value: float) -> str:
    if value >= 60.0 and value % 60.0 == 0.0:
        minutes = value / 60.0
        return f"{minutes:g} min"
    return f"{value:g} s"


def _format_time(value: float) -> str:
    if value < 0.001:
        return f"{value * 1_000_000:.2f} us"
    if value < 1.0:
        return f"{value * 1_000:.2f} ms"
    if value < 60.0:
        return f"{value:.3f} s"
    return f"{value / 60.0:.2f} min"


def _format_metric_time(metric: Mapping[str, Any]) -> str:
    if metric["status"] != "available":
        reason = html.escape(str(metric["reason"]), quote=True)
        return f'<span class="unavailable" title="{reason}">Unavailable</span>'
    return html.escape(_format_time(float(metric["value"])))


def _format_comparison(metric: Mapping[str, Any]) -> str:
    if metric["status"] != "available":
        reason = html.escape(str(metric["reason"]), quote=True)
        return f'<span class="unavailable" title="{reason}">Unavailable</span>'
    index = float(metric["signed_performance_index"])
    ratio = float(metric["ratio"])
    css_class = "ahead" if index > 0.0 else "behind" if index < 0.0 else "parity"
    reduction = float(metric["required_viper_time_reduction"])
    requirement = (
        f"{reduction * 100.0:.1f}% time reduction needed"
        if reduction > 0.0
        else "Parity met"
    )
    return (
        f'<span class="index {css_class}">{index:+.1%}</span>'
        f'<span class="ratio">{ratio:.3f}x</span>'
        f'<span class="requirement">{html.escape(requirement)}</span>'
    )


def _coverage_cell(summary: Mapping[str, Any]) -> str:
    metric = summary["leader_relative_coverage"]
    if metric["status"] != "available":
        reason = html.escape(str(metric["reason"]), quote=True)
        return f'<span class="unavailable" title="{reason}">Unavailable</span>'
    percentage = max(0.0, min(100.0, float(metric["value"]) * 100.0))
    return (
        '<span class="coverage-value">'
        f'{percentage:.1f}%'
        '</span>'
        '<span class="coverage-track" aria-hidden="true">'
        f'<span style="width: {percentage:.3f}%"></span>'
        '</span>'
    )


def _select(
    identifier: str, label: str, options: Iterable[tuple[str, str]]
) -> str:
    rendered = [f'<label for="{identifier}">{html.escape(label)}</label>']
    rendered.append(f'<select id="{identifier}"><option value="">All</option>')
    rendered.extend(
        f'<option value="{html.escape(value, quote=True)}">{html.escape(text)}</option>'
        for value, text in options
    )
    rendered.append("</select>")
    return "".join(rendered)


def _render_panel(panel: Mapping[str, Any], model: Mapping[str, Any]) -> str:
    boundary = panel["claim_boundary"]
    attrs = {
        "scope": boundary["scope"],
        "corpus": boundary["corpus"]["id"],
        "timeout": repr(float(boundary["timeout_s"])),
        "family": boundary["family"]["id"],
        "expected": boundary["expected_status"],
        "status": boundary["evidence_status"],
        "class": boundary["evidence_class"],
        "revision": boundary["revision"],
        "host": boundary["host"]["id"],
    }
    data_attrs = " ".join(
        f'data-{name}="{html.escape(str(value), quote=True)}"'
        for name, value in attrs.items()
    )
    status_class = html.escape(boundary["evidence_status"], quote=True)
    solver_rows: list[str] = []
    for summary in panel["solvers"]:
        availability = (
            "Complete"
            if summary["unavailable_observations"] == 0
            else f"{summary['unavailable_observations']} unavailable"
        )
        solver_rows.append(
            "<tr>"
            f'<th scope="row">{html.escape(summary["label"])}</th>'
            f'<td class="numeric">{summary["solved"]} / {summary["instances"]}</td>'
            f'<td class="coverage-cell">{_coverage_cell(summary)}</td>'
            f'<td class="numeric">{_format_metric_time(summary["par2_s"])}</td>'
            f'<td class="numeric">{_format_metric_time(summary["median_s"])}</td>'
            f'<td class="numeric">{_format_metric_time(summary["p95_s"])}</td>'
            f'<td>{html.escape(availability)}</td>'
            "</tr>"
        )
    comparison_rows: list[str] = []
    for comparison in panel["comparisons"]:
        metrics = comparison["metrics"]
        comparison_rows.append(
            "<tr>"
            f'<th scope="row">{html.escape(comparison["competitor_label"])}</th>'
            f'<td class="numeric">{comparison["common_solved"]} / {comparison["instances"]}</td>'
            f'<td class="metric-index">{_format_comparison(metrics["par2"])}</td>'
            f'<td class="metric-index primary-index">{_format_comparison(metrics["common_geometric"])}</td>'
            f'<td class="metric-index">{_format_comparison(metrics["common_total"])}</td>'
            f'<td class="metric-index">{_format_comparison(metrics["median"])}</td>'
            f'<td class="metric-index">{_format_comparison(metrics["p95"])}</td>'
            "</tr>"
        )
    sources = "".join(
        "<li>"
        f'<code>{html.escape(source["path"])}</code> '
        f'<span class="digest">sha256:{html.escape(source["sha256"][:12])}</span>'
        "</li>"
        for source in panel["sources"]
    )
    completeness = "Complete matrix" if panel["complete"] else "Incomplete matrix"
    return f"""
<article class="panel" id="{html.escape(panel['id'], quote=True)}" {data_attrs}>
  <header class="panel-header">
    <div>
      <div class="panel-kicker">
        <span class="status {status_class}">{html.escape(boundary['evidence_status'])}</span>
        <span>{html.escape(boundary['scope'].title())}</span>
        <span>{html.escape(boundary['evidence_class'])}</span>
      </div>
      <h2>{html.escape(boundary['corpus']['label'])}</h2>
      <p>{html.escape(boundary['family']['label'])} &middot; {html.escape(boundary['expected_status'].upper())} &middot; {_format_timeout(float(boundary['timeout_s']))}</p>
    </div>
    <dl class="provenance">
      <div><dt>Revision</dt><dd><code>{html.escape(boundary['revision'][:12])}</code></dd></div>
      <div><dt>Host</dt><dd>{html.escape(boundary['host']['label'])}</dd></div>
      <div><dt>Instances</dt><dd>{panel['instances']}</dd></div>
      <div><dt>Matrix</dt><dd>{completeness}</dd></div>
    </dl>
  </header>
  <div class="table-region" role="region" aria-label="Solver metrics" tabindex="0">
    <table class="solver-table">
      <caption>Panel metrics</caption>
      <thead><tr>
        <th>Solver</th><th class="numeric">Solved</th>
        <th title="{html.escape(model['metric_definitions']['leader_relative_coverage'], quote=True)}">Leader-relative</th>
        <th class="numeric" title="{html.escape(model['metric_definitions']['par2'], quote=True)}">PAR2</th>
        <th class="numeric">Median</th><th class="numeric">p95</th><th>Data</th>
      </tr></thead>
      <tbody>{''.join(solver_rows)}</tbody>
    </table>
  </div>
  <div class="table-region" role="region" aria-label="Viper competitor comparisons" tabindex="0">
    <table class="comparison-table">
      <caption>Signed Viper performance index</caption>
      <thead><tr>
        <th>Competitor</th><th class="numeric">Common</th><th>PAR2</th>
        <th title="{html.escape(model['metric_definitions']['common_geometric'], quote=True)}">Common geometric</th>
        <th title="{html.escape(model['metric_definitions']['common_total'], quote=True)}">Common total</th>
        <th>Median</th><th>p95</th>
      </tr></thead>
      <tbody>{''.join(comparison_rows)}</tbody>
    </table>
  </div>
  <details class="evidence-detail">
    <summary>Evidence provenance</summary>
    <p>Registry records: {', '.join(f'<code>{html.escape(identifier)}</code>' for identifier in panel['evidence_ids'])}</p>
    <ul>{sources}</ul>
  </details>
</article>"""


def render_html(model: Mapping[str, Any]) -> str:
    """Render a self-contained deterministic operational dashboard."""

    options = model["filter_options"]
    filters = "".join(
        [
            _select(
                "corpus-filter",
                "Corpus",
                ((item["id"], item["label"]) for item in options["corpora"]),
            ),
            _select(
                "timeout-filter",
                "Timeout",
                ((item["value"], item["label"]) for item in options["timeouts"]),
            ),
            _select(
                "family-filter",
                "Family",
                ((item["id"], item["label"]) for item in options["families"]),
            ),
            _select(
                "expected-filter",
                "Expected",
                ((status, status.upper()) for status in options["expected_statuses"]),
            ),
            _select(
                "status-filter",
                "Evidence status",
                ((status, status.title()) for status in options["evidence_statuses"]),
            ),
            _select(
                "class-filter",
                "Evidence class",
                ((value, value) for value in options["evidence_classes"]),
            ),
            _select(
                "revision-filter",
                "Revision",
                ((value, value[:12]) for value in options["revisions"]),
            ),
            _select(
                "host-filter",
                "Host",
                ((item["id"], item["label"]) for item in options["hosts"]),
            ),
        ]
    )
    panels = "".join(_render_panel(panel, model) for panel in model["panels"])
    panel_count = len(model["panels"])
    broad_count = sum(
        panel["claim_boundary"]["scope"] == "broad" for panel in model["panels"]
    )
    targeted_count = panel_count - broad_count
    embedded_model = json.dumps(
        model,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    embedded_model = (
        embedded_model.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    title = html.escape(model["registry"]["title"])
    updated_at = html.escape(model["registry"]["updated_at"])
    registry_digest = html.escape(model["registry"]["sha256"][:12])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4f6f7;
      --surface: #ffffff;
      --surface-subtle: #f8faf9;
      --ink: #172126;
      --muted: #5f6e74;
      --line: #d7dfe1;
      --line-strong: #b9c5c8;
      --accent: #176b65;
      --accent-soft: #dff1ed;
      --good: #17663a;
      --good-soft: #e2f2e8;
      --warn: #885b08;
      --warn-soft: #fff0cc;
      --bad: #a23b35;
      --bad-soft: #f8e5e2;
      --neutral-soft: #e9edef;
      font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 15px;
      line-height: 1.45;
      letter-spacing: 0;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); }}
    button, select {{ font: inherit; letter-spacing: 0; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .topbar {{
      background: var(--surface); border-bottom: 1px solid var(--line);
      padding: 18px clamp(16px, 4vw, 48px);
    }}
    .topbar-inner {{ max-width: 1500px; margin: 0 auto; display: flex; gap: 24px; align-items: end; justify-content: space-between; }}
    h1 {{ margin: 0; font-size: 1.55rem; line-height: 1.2; letter-spacing: 0; }}
    .topbar p {{ margin: 5px 0 0; color: var(--muted); font-size: .88rem; }}
    .registry-meta {{ text-align: right; white-space: nowrap; }}
    main {{ max-width: 1500px; margin: 0 auto; padding: 20px clamp(12px, 3vw, 36px) 48px; }}
    .controls {{
      display: grid; grid-template-columns: minmax(250px, 1.35fr) repeat(8, minmax(120px, 1fr));
      gap: 10px; align-items: end; padding: 0 0 18px;
    }}
    .scope-tabs {{ display: grid; grid-template-columns: repeat(3, 1fr); border: 1px solid var(--line-strong); border-radius: 6px; overflow: hidden; min-height: 38px; }}
    .scope-tabs button {{ border: 0; border-right: 1px solid var(--line-strong); background: var(--surface); color: var(--muted); padding: 8px 11px; cursor: pointer; }}
    .scope-tabs button:last-child {{ border-right: 0; }}
    .scope-tabs button[aria-selected="true"] {{ background: var(--accent); color: #fff; }}
    .controls label {{ display: block; color: var(--muted); font-size: .72rem; font-weight: 700; margin: 0 0 4px; text-transform: uppercase; }}
    .controls select {{ width: 100%; min-height: 38px; border: 1px solid var(--line-strong); border-radius: 5px; background: var(--surface); color: var(--ink); padding: 7px 28px 7px 9px; }}
    .result-line {{ display: flex; justify-content: space-between; gap: 16px; align-items: center; color: var(--muted); font-size: .86rem; padding: 0 1px 10px; }}
    .legend {{ display: flex; flex-wrap: wrap; gap: 12px; }}
    .legend span::before {{ content: ""; display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; background: var(--line-strong); }}
    .legend .positive::before {{ background: var(--good); }}
    .legend .negative::before {{ background: var(--bad); }}
    .panels {{ display: grid; gap: 16px; }}
    .panel {{ background: var(--surface); border: 1px solid var(--line); border-radius: 7px; overflow: hidden; box-shadow: 0 1px 2px rgba(20, 34, 40, .04); }}
    .panel[hidden] {{ display: none; }}
    .panel-header {{ display: flex; justify-content: space-between; gap: 24px; padding: 18px 20px 15px; border-bottom: 1px solid var(--line); }}
    .panel-kicker {{ display: flex; align-items: center; flex-wrap: wrap; gap: 8px; color: var(--muted); font-size: .76rem; text-transform: uppercase; font-weight: 700; }}
    .status {{ border-radius: 999px; padding: 3px 7px; text-transform: none; }}
    .status.verified {{ background: var(--good-soft); color: var(--good); }}
    .status.provisional {{ background: var(--warn-soft); color: var(--warn); }}
    .status.incomplete, .status.superseded {{ background: var(--neutral-soft); color: var(--muted); }}
    .status.rejected {{ background: var(--bad-soft); color: var(--bad); }}
    h2 {{ margin: 7px 0 2px; font-size: 1.18rem; line-height: 1.25; letter-spacing: 0; }}
    .panel-header p {{ margin: 0; color: var(--muted); }}
    .provenance {{ margin: 0; display: grid; grid-template-columns: repeat(2, minmax(100px, auto)); gap: 7px 22px; align-content: start; }}
    .provenance div {{ min-width: 0; }}
    .provenance dt {{ color: var(--muted); font-size: .68rem; font-weight: 700; text-transform: uppercase; }}
    .provenance dd {{ margin: 1px 0 0; font-size: .86rem; overflow-wrap: anywhere; }}
    .table-region {{ overflow-x: auto; border-bottom: 1px solid var(--line); }}
    table {{ width: 100%; min-width: 850px; border-collapse: collapse; font-size: .84rem; }}
    caption {{ text-align: left; padding: 13px 20px 7px; color: var(--muted); font-size: .72rem; font-weight: 800; text-transform: uppercase; }}
    th, td {{ padding: 9px 12px; border-top: 1px solid var(--line); text-align: left; vertical-align: middle; }}
    thead th {{ color: var(--muted); background: var(--surface-subtle); font-size: .71rem; text-transform: uppercase; white-space: nowrap; }}
    tbody th {{ font-weight: 700; }}
    .numeric {{ text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }}
    .coverage-cell {{ min-width: 145px; }}
    .coverage-value {{ display: inline-block; width: 48px; text-align: right; font-variant-numeric: tabular-nums; }}
    .coverage-track {{ display: inline-block; width: 72px; height: 5px; margin-left: 7px; vertical-align: middle; background: var(--neutral-soft); overflow: hidden; }}
    .coverage-track span {{ display: block; height: 100%; background: var(--accent); }}
    .metric-index {{ min-width: 140px; font-variant-numeric: tabular-nums; }}
    .metric-index span {{ display: block; }}
    .index {{ font-weight: 800; }}
    .index.ahead {{ color: var(--good); }}
    .index.behind {{ color: var(--bad); }}
    .index.parity {{ color: var(--muted); }}
    .ratio, .requirement {{ color: var(--muted); font-size: .73rem; }}
    .primary-index {{ background: color-mix(in srgb, var(--accent-soft) 45%, transparent); }}
    .unavailable {{ color: var(--muted); font-style: italic; font-weight: 500; }}
    .evidence-detail {{ padding: 10px 20px 13px; color: var(--muted); font-size: .79rem; }}
    .evidence-detail summary {{ cursor: pointer; color: var(--ink); font-weight: 700; }}
    .evidence-detail p {{ margin: 9px 0 5px; }}
    .evidence-detail ul {{ margin: 0; padding-left: 18px; }}
    .digest {{ font-variant-numeric: tabular-nums; }}
    .empty {{ display: none; border: 1px dashed var(--line-strong); padding: 38px 20px; text-align: center; color: var(--muted); background: var(--surface); }}
    .empty.visible {{ display: block; }}
    @media (max-width: 1180px) {{
      .controls {{ grid-template-columns: repeat(4, minmax(140px, 1fr)); }}
      .scope-wrap {{ grid-column: span 2; }}
    }}
    @media (max-width: 720px) {{
      .topbar-inner, .panel-header {{ align-items: flex-start; flex-direction: column; }}
      .registry-meta {{ text-align: left; white-space: normal; }}
      .controls {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .scope-wrap {{ grid-column: 1 / -1; }}
      .provenance {{ width: 100%; grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .result-line {{ align-items: flex-start; flex-direction: column; }}
      .panel-header {{ padding: 15px; gap: 14px; }}
      caption {{ padding-left: 15px; }}
      .evidence-detail {{ padding-left: 15px; padding-right: 15px; }}
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        color-scheme: dark; --bg: #111719; --surface: #182124; --surface-subtle: #1d282b;
        --ink: #edf3f2; --muted: #aab8ba; --line: #334144; --line-strong: #4a5b5e;
        --accent: #5fb8ad; --accent-soft: #193c38; --good: #73c991; --good-soft: #1c3827;
        --warn: #e5b95d; --warn-soft: #3c3018; --bad: #ef8981; --bad-soft: #442522;
        --neutral-soft: #293538;
      }}
      .scope-tabs button[aria-selected="true"] {{ color: #10201e; }}
      .panel {{ box-shadow: none; }}
    }}
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div><h1>{title}</h1><p>Claim-isolated EUF benchmark evidence</p></div>
      <p class="registry-meta">Updated <time datetime="{updated_at}">{updated_at}</time><br><code>registry:{registry_digest}</code></p>
    </div>
  </header>
  <main>
    <section class="controls" aria-label="Dashboard filters">
      <div class="scope-wrap">
        <label>Scope</label>
        <div class="scope-tabs" role="tablist" aria-label="Evidence scope">
          <button type="button" role="tab" data-scope-value="" aria-selected="true">All ({panel_count})</button>
          <button type="button" role="tab" data-scope-value="broad" aria-selected="false">Broad ({broad_count})</button>
          <button type="button" role="tab" data-scope-value="targeted" aria-selected="false">Targeted ({targeted_count})</button>
        </div>
      </div>
      {filters}
    </section>
    <div class="result-line">
      <span id="result-count" aria-live="polite">Showing {panel_count} of {panel_count} panels</span>
      <span class="legend"><span class="positive">Positive favors Viper</span><span class="negative">Negative is required improvement</span></span>
    </div>
    <section class="panels" aria-label="Evidence panels">{panels}</section>
    <div class="empty" id="empty-state">No panels match the current filters.</div>
  </main>
  <script type="application/json" id="dashboard-data">{embedded_model}</script>
  <script>
    (() => {{
      "use strict";
      const panels = Array.from(document.querySelectorAll(".panel"));
      const tabs = Array.from(document.querySelectorAll("[data-scope-value]"));
      const controls = {{
        corpus: document.getElementById("corpus-filter"),
        timeout: document.getElementById("timeout-filter"),
        family: document.getElementById("family-filter"),
        expected: document.getElementById("expected-filter"),
        status: document.getElementById("status-filter"),
        class: document.getElementById("class-filter"),
        revision: document.getElementById("revision-filter"),
        host: document.getElementById("host-filter")
      }};
      let scope = "";
      const update = () => {{
        let visible = 0;
        for (const panel of panels) {{
          const matches = (!scope || panel.dataset.scope === scope) &&
            Object.entries(controls).every(([name, control]) =>
              !control.value || panel.dataset[name] === control.value);
          panel.hidden = !matches;
          if (matches) visible += 1;
        }}
        document.getElementById("result-count").textContent =
          `Showing ${{visible}} of ${{panels.length}} panels`;
        document.getElementById("empty-state").classList.toggle("visible", visible === 0);
      }};
      for (const tab of tabs) {{
        tab.addEventListener("click", () => {{
          scope = tab.dataset.scopeValue;
          for (const item of tabs) item.setAttribute("aria-selected", String(item === tab));
          update();
        }});
      }}
      for (const control of Object.values(controls)) control.addEventListener("change", update);
    }})();
  </script>
</body>
</html>
"""


def write_artifacts_atomic(artifacts: Sequence[tuple[Path, bytes]]) -> None:
    """Stage every artifact, then publish each with an atomic same-dir replace."""

    if not artifacts:
        raise ValueError("at least one output artifact is required")
    resolved = [path.resolve() for path, _ in artifacts]
    if len(resolved) != len(set(resolved)):
        raise ValueError("output artifact paths must be distinct")
    staged: list[tuple[Path, Path]] = []
    try:
        for path, payload in artifacts:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary.chmod(0o644)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
            staged.append((temporary, path))
        for temporary, path in staged:
            os.replace(temporary, path)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry", type=Path, help="versioned evidence registry JSON")
    parser.add_argument(
        "--html-out",
        type=Path,
        default=Path("docs/dashboard/euf-progress.html"),
        help="self-contained HTML output (default: docs/dashboard/euf-progress.html)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="optional computed dashboard model JSON output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        registry = load_registry(args.registry)
        model = build_dashboard(registry)
        html_bytes = render_html(model).encode("utf-8")
        artifacts = [(args.html_out, html_bytes)]
        if args.json_out is not None:
            artifacts.insert(0, (args.json_out, pretty_json_bytes(model)))
        write_artifacts_atomic(artifacts)
    except (DashboardInputError, ArithmeticError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    receipt = {
        "html": str(args.html_out),
        "html_sha256": hashlib.sha256(html_bytes).hexdigest(),
        "json": str(args.json_out) if args.json_out is not None else None,
        "panels": len(model["panels"]),
        "registry_sha256": model["registry"]["sha256"],
        "schema_version": MODEL_SCHEMA_VERSION,
    }
    print(
        json.dumps(
            receipt,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
