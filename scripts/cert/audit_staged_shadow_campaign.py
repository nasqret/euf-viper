#!/usr/bin/env python3
"""Bind physical-stage certificate audits to one final staged campaign report."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
SHADOW_PATH = ROOT / "scripts" / "cert" / "shadow_campaign.py"


class StagedShadowAuditError(ValueError):
    """Raised when staged timing and certificate evidence do not match exactly."""


def _load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise StagedShadowAuditError(f"cannot import {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


shadow = _load_module("staged_shadow_audit_runner", SHADOW_PATH)


def _load_json(path: Path, label: str, *, canonical: bool) -> tuple[dict[str, Any], str]:
    try:
        path = path.expanduser().resolve(strict=True)
        if path.is_symlink() or not path.is_file():
            raise StagedShadowAuditError(f"{label} must be a regular file")
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        value = shadow._strict_json(text, label)
    except (OSError, RuntimeError, UnicodeError, shadow.ShadowError) as error:
        raise StagedShadowAuditError(f"cannot load {label}: {error}") from error
    if type(value) is not dict:
        raise StagedShadowAuditError(f"{label} must be one JSON object")
    if canonical and shadow.canonical_bytes(value) != raw:
        raise StagedShadowAuditError(f"{label} is not canonical immutable JSON")
    return value, hashlib.sha256(raw).hexdigest()


def _budget_key(value: object, label: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise StagedShadowAuditError(f"{label} is not a finite budget")
    budget = float(value)
    if budget <= 0:
        raise StagedShadowAuditError(f"{label} must be positive")
    return budget


def _expected_by_origin(
    analysis: Mapping[str, Any], candidate_id: str
) -> tuple[float, dict[float, dict[str, str]]]:
    if analysis.get("schema_version") != 1:
        raise StagedShadowAuditError("staged analysis has an incompatible schema")
    if analysis.get("status") not in {"promoted", "rejected"}:
        raise StagedShadowAuditError("staged analysis status is invalid")
    assumptions = analysis.get("assumptions")
    inputs = analysis.get("inputs")
    if (
        type(assumptions) is not dict
        or assumptions.get("complete_declared_budget_ladder") is not True
        or type(inputs) is not dict
    ):
        raise StagedShadowAuditError("staged analysis is not a complete budget ladder")
    budgets = inputs.get("budgets_s")
    if type(budgets) is not list or not budgets:
        raise StagedShadowAuditError("staged analysis has no budgets")
    normalized_budgets = [_budget_key(value, "analysis budget") for value in budgets]
    if normalized_budgets != sorted(set(normalized_budgets)):
        raise StagedShadowAuditError("analysis budgets are not strictly increasing")
    final_budget = normalized_budgets[-1]
    provenance = inputs.get("observation_provenance")
    if type(provenance) is not list:
        raise StagedShadowAuditError("staged analysis lacks observation provenance")
    input_hashes = analysis.get("input_hashes")
    if type(input_hashes) is not dict:
        raise StagedShadowAuditError("staged analysis lacks input hashes")
    declared_provenance_hash = input_hashes.get("observation_provenance_sha256")
    actual_provenance_hash = hashlib.sha256(
        shadow.canonical_bytes(provenance)
    ).hexdigest()
    if (
        not shadow._is_sha256(declared_provenance_hash)
        or declared_provenance_hash != actual_provenance_hash
    ):
        raise StagedShadowAuditError("observation provenance SHA-256 mismatch")
    expected: dict[float, dict[str, str]] = {}
    seen_final: set[tuple[str, str]] = set()
    for index, row in enumerate(provenance):
        if type(row) is not dict:
            raise StagedShadowAuditError(f"observation provenance {index} is invalid")
        if row.get("solver_id") != candidate_id:
            continue
        budget = _budget_key(row.get("budget_s"), f"observation {index} budget")
        if budget != final_budget:
            continue
        relative_path = row.get("relative_path")
        result = row.get("result")
        if type(relative_path) is not str or not relative_path:
            raise StagedShadowAuditError(f"observation {index} path is invalid")
        key = (relative_path, candidate_id)
        if key in seen_final:
            raise StagedShadowAuditError(f"duplicate final candidate row {relative_path!r}")
        seen_final.add(key)
        if result not in {"sat", "unsat"}:
            continue
        origin = _budget_key(
            row.get("origin_budget_s"), f"observation {index} origin budget"
        )
        if origin not in normalized_budgets or origin > final_budget:
            raise StagedShadowAuditError(
                f"observation {index} has an invalid physical origin budget"
            )
        by_path = expected.setdefault(origin, {})
        if relative_path in by_path:
            raise StagedShadowAuditError(
                f"candidate path has duplicate origin {relative_path!r}"
            )
        by_path[relative_path] = result
    return final_budget, expected


def audit_staged_shadow_campaign(
    analysis_path: Path,
    stage_audits: Sequence[Path],
    *,
    candidate_id: str = "euf-viper",
) -> dict[str, Any]:
    """Require exact certificate coverage for every final candidate solve."""

    analysis, analysis_sha256 = _load_json(
        analysis_path, "staged analysis", canonical=False
    )
    final_budget, expected_by_origin = _expected_by_origin(analysis, candidate_id)
    audits_by_budget: dict[float, dict[str, Any]] = {}
    audit_records: list[dict[str, Any]] = []
    actual_paths: set[str] = set()
    for audit_path in stage_audits:
        audit, audit_sha256 = _load_json(
            audit_path, "physical-stage certificate audit", canonical=True
        )
        if audit.get("schema_version") != 1 or audit.get("status") != "complete":
            raise StagedShadowAuditError("physical-stage audit is not complete")
        budget = _budget_key(audit.get("budget_s"), "certificate audit budget")
        if budget in audits_by_budget:
            raise StagedShadowAuditError(f"duplicate certificate audit budget {budget:g}")
        verified = audit.get("verified")
        if type(verified) is not list:
            raise StagedShadowAuditError("certificate audit lacks verified records")
        if audit.get("verified_instances") != len(verified):
            raise StagedShadowAuditError("certificate audit verified count mismatch")
        declared_selection_hash = audit.get("selection_sha256")
        actual_selection_hash = hashlib.sha256(
            shadow.canonical_bytes(
                [
                    {
                        "relative_path": record.get("relative_path"),
                        "result": record.get("result"),
                        "work_sha256": record.get("work_sha256"),
                    }
                    for record in verified
                ]
            )
        ).hexdigest()
        if (
            not shadow._is_sha256(declared_selection_hash)
            or declared_selection_hash != actual_selection_hash
        ):
            raise StagedShadowAuditError("certificate audit selection SHA-256 mismatch")
        actual: dict[str, str] = {}
        for record in verified:
            if type(record) is not dict:
                raise StagedShadowAuditError("certificate verified record is invalid")
            path = record.get("relative_path")
            result = record.get("result")
            if type(path) is not str or result not in {"sat", "unsat"}:
                raise StagedShadowAuditError("certificate verified identity is invalid")
            if path in actual or path in actual_paths:
                raise StagedShadowAuditError(f"duplicate certificate for {path!r}")
            actual[path] = result
            actual_paths.add(path)
        expected = expected_by_origin.get(budget, {})
        if actual != expected:
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            mismatched = sorted(
                path
                for path in set(actual) & set(expected)
                if actual[path] != expected[path]
            )
            raise StagedShadowAuditError(
                f"certificate origin budget {budget:g} mismatch: "
                f"missing={missing!r}, extra={extra!r}, mismatched={mismatched!r}"
            )
        audits_by_budget[budget] = audit
        resolved = audit_path.expanduser().resolve(strict=True)
        audit_records.append(
            {
                "budget_s": budget,
                "path": str(resolved),
                "sha256": audit_sha256,
                "verified_instances": len(actual),
                "source_shard_bundle_sha256": audit[
                    "source_shard_bundle_sha256"
                ],
                "selection_sha256": declared_selection_hash,
            }
        )

    required_budgets = {
        budget for budget, expected in expected_by_origin.items() if expected
    }
    if set(audits_by_budget) != required_budgets:
        missing = sorted(required_budgets - set(audits_by_budget))
        extra = sorted(set(audits_by_budget) - required_budgets)
        raise StagedShadowAuditError(
            f"physical-stage audit set mismatch: missing={missing!r}, extra={extra!r}"
        )
    expected_total = sum(len(expected) for expected in expected_by_origin.values())
    if len(actual_paths) != expected_total:
        raise StagedShadowAuditError("global staged certificate count mismatch")
    audit_records.sort(key=lambda record: record["budget_s"])
    selection = [
        {
            "relative_path": path,
            "result": result,
            "origin_budget_s": budget,
        }
        for budget, expected in sorted(expected_by_origin.items())
        for path, result in sorted(expected.items())
    ]
    return {
        "schema_version": 1,
        "status": "complete",
        "candidate_id": candidate_id,
        "final_budget_s": final_budget,
        "analysis": {
            "path": str(analysis_path.expanduser().resolve(strict=True)),
            "sha256": analysis_sha256,
            "staged_evidence_sha256": analysis["input_hashes"][
                "staged_evidence_sha256"
            ],
            "observation_provenance_sha256": analysis["input_hashes"][
                "observation_provenance_sha256"
            ],
        },
        "verified_instances": expected_total,
        "verified_by_origin_budget": {
            format(budget, ".17g"): len(expected)
            for budget, expected in sorted(expected_by_origin.items())
            if expected
        },
        "selection_sha256": hashlib.sha256(
            shadow.canonical_bytes(selection)
        ).hexdigest(),
        "stage_audits": audit_records,
    }


def _stage_path(raw: str) -> Path:
    return Path(raw)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--stage-audit", type=_stage_path, action="append", default=[])
    parser.add_argument("--candidate", default="euf-viper")
    parser.add_argument("--out", type=Path, required=True)
    return parser


def _atomic_write(path: Path, payload: bytes) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() or path.is_symlink():
            if path.read_bytes() != payload:
                raise StagedShadowAuditError(f"refuse to replace staged audit {path}")
            temporary.unlink()
        else:
            os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = audit_staged_shadow_campaign(
            args.analysis, args.stage_audit, candidate_id=args.candidate
        )
        _atomic_write(args.out, shadow.canonical_bytes(result))
    except (StagedShadowAuditError, OSError) as error:
        parser.exit(2, f"staged certificate audit failed: {error}\n")
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
