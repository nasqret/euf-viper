#!/usr/bin/env python3
"""Import one audited build-once sharded campaign into dashboard evidence.

The importer independently replays the portable Helios audit and the strict
locked-campaign validator before constructing any dashboard observation.  A
promotion rejection is performance evidence; an integrity failure is not.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import analyze_campaign as analyzer  # noqa: E402
import build_euf_dashboard as dashboard  # noqa: E402


DEFAULT_LABELS = {
    "euf-viper": "Viper",
    "yices2": "Yices2",
    "z3-default": "Z3 default",
    "z3-sat-euf": "Z3 sat.euf",
    "cvc5": "cvc5",
    "opensmt": "OpenSMT",
}
DECISIVE_RESULTS = {"sat", "unsat"}
NONDECISIVE_STATUS = {
    "timeout": "timeout",
    "unknown": "unknown",
    "error": "error",
    "invalid": "invalid",
}


class ShardedDashboardImportError(ValueError):
    """Raised when sharded evidence cannot support a dashboard claim."""


def _load_auditor() -> ModuleType:
    path = SCRIPT_DIR.parent / "helios" / "audit_sharded_campaign.py"
    specification = importlib.util.spec_from_file_location(
        "_euf_viper_shard_auditor", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load shard auditor from {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


AUDITOR = _load_auditor()


def _load_json(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ShardedDashboardImportError(f"cannot read {context} {path}: {error}") from error
    if type(value) is not dict:
        raise ShardedDashboardImportError(f"{context} {path} must be an object")
    return value


def _text(value: object, context: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ShardedDashboardImportError(f"{context} must be non-empty trimmed text")
    return value


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.casefold()).strip("-._")
    if not slug:
        slug = "item"
    if len(slug) > 96:
        suffix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        slug = f"{slug[:83].rstrip('-._')}-{suffix}"
    return slug


def _shard_pairs(campaign_root: Path, shard_count: int) -> list[tuple[Path, Path]]:
    return [
        (
            campaign_root / "bound-locks" / f"bound-{index:04d}.json",
            campaign_root / "results" / f"shard-{index:04d}" / "raw.jsonl",
        )
        for index in range(shard_count)
    ]


def load_verified_campaign(
    preparation_root: Path,
    campaign_root: Path,
    *,
    shard_count: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Replay both audit layers and return campaign, audit, and analysis."""

    preparation_root = preparation_root.expanduser().resolve()
    campaign_root = campaign_root.expanduser().resolve()
    analysis_path = campaign_root / "analysis.json"
    audit_path = campaign_root / "audit-index.json"
    try:
        replayed_audit = AUDITOR.audit(
            preparation_root,
            campaign_root,
            shard_count,
            analysis_path,
        )
        published = audit_path.read_bytes()
    except (AUDITOR.AuditError, OSError) as error:
        raise ShardedDashboardImportError(f"shard audit failed: {error}") from error
    expected = AUDITOR.canonical_bytes(replayed_audit)
    if published != expected:
        raise ShardedDashboardImportError(
            "published audit-index.json is not byte-identical to the local replay"
        )

    try:
        campaign = analyzer.load_sharded_locked_campaign(
            preparation_root / "campaign-lock.json",
            _shard_pairs(campaign_root, shard_count),
        )
    except analyzer.CampaignInputError as error:
        raise ShardedDashboardImportError(
            "locked-campaign replay failed: " + "; ".join(error.errors)
        ) from error
    if campaign["raw_records"] != replayed_audit["completed_runs"]:
        raise ShardedDashboardImportError("audit and locked replay disagree on raw rows")
    if campaign["lock"]["lock_sha256"] != replayed_audit["parent_lock_sha256"]:
        raise ShardedDashboardImportError("audit and locked replay disagree on parent lock")

    analysis = _load_json(analysis_path, "analysis")
    inputs = analysis.get("inputs")
    if type(inputs) is not dict:
        raise ShardedDashboardImportError("analysis.inputs must be an object")
    solver_ids = [solver["id"] for solver in campaign["lock"]["solvers"]]
    analysis_solver_ids = [
        _text(inputs.get("candidate_id"), "analysis.inputs.candidate_id"),
        *[
            _text(value, f"analysis.inputs.baseline_ids[{index}]")
            for index, value in enumerate(inputs.get("baseline_ids", []))
        ],
    ]
    if Counter(solver_ids) != Counter(analysis_solver_ids):
        raise ShardedDashboardImportError(
            "analysis solver rectangle disagrees with the parent campaign lock"
        )
    return campaign, replayed_audit, analysis


def build_registry(
    campaign: Mapping[str, Any],
    audit: Mapping[str, Any],
    analysis: Mapping[str, Any],
    *,
    registry_id: str,
    title: str,
    updated_at: str,
    evidence_prefix: str,
    corpus_id_override: str | None,
    corpus_label: str,
    host_id: str,
    host_label: str,
    evidence_class: str,
    evidence_status: str,
    source_path: str,
    source_sha256: str,
    solver_label_overrides: Mapping[str, str] | None = None,
    include_family_panels: bool = True,
    include_expected_status_panels: bool = True,
) -> dict[str, Any]:
    """Normalize a verified sharded campaign to dashboard schema v1."""

    lock = campaign["lock"]
    analysis_inputs = analysis["inputs"]
    candidate_id = _text(
        analysis_inputs.get("candidate_id"), "analysis.inputs.candidate_id"
    )
    solver_ids = [solver["id"] for solver in lock["solvers"]]
    if candidate_id not in solver_ids:
        raise ShardedDashboardImportError("candidate solver is absent from the lock")
    revision = _text(audit.get("solver_revision"), "audit.solver_revision")
    corpus_id = (
        _text(lock["corpus"]["id"], "lock.corpus.id")
        if corpus_id_override is None
        else _text(corpus_id_override, "corpus_id_override")
    )
    budgets = [float(value) for value in lock["budgets_s"]]
    if budgets != sorted(set(budgets)) or any(value <= 0.0 for value in budgets):
        raise ShardedDashboardImportError("campaign budgets must be positive and unique")

    instance_metadata: dict[str, dict[str, str]] = {}
    for index, instance in enumerate(lock["corpus"]["instances"]):
        path = _text(instance.get("relative_path"), f"instance[{index}].relative_path")
        if path in instance_metadata:
            raise ShardedDashboardImportError(f"duplicate instance path {path!r}")
        instance_metadata[path] = {
            "family": _text(instance.get("family"), f"instance[{index}].family"),
            "expected_status": _text(
                instance.get("status"), f"instance[{index}].status"
            ),
        }

    observations: dict[tuple[str, float, str], dict[str, Any]] = {}
    for key, observation in campaign["observations"].items():
        relative_path, budget, solver_id = key
        result = observation["result"]
        if result in DECISIVE_RESULTS:
            status = "solved"
            time_s: float | None = float(observation["wall_time_s"])
            if time_s <= 0.0:
                raise ShardedDashboardImportError(f"non-positive solve time for {key!r}")
        else:
            try:
                status = NONDECISIVE_STATUS[result]
            except KeyError as error:
                raise ShardedDashboardImportError(
                    f"unsupported observation result {result!r} for {key!r}"
                ) from error
            time_s = None
        observations[(relative_path, float(budget), solver_id)] = {
            "solver_id": solver_id,
            "status": status,
            "time_s": time_s,
        }

    expected_keys = {
        (path, budget, solver_id)
        for path in instance_metadata
        for budget in budgets
        for solver_id in solver_ids
    }
    if set(observations) != expected_keys:
        raise ShardedDashboardImportError(
            "verified observation rectangle is incomplete: "
            f"missing={len(expected_keys - set(observations))}, "
            f"unexpected={len(set(observations) - expected_keys)}"
        )

    family_ids: dict[str, str] = {}
    for family in sorted({item["family"] for item in instance_metadata.values()}):
        identifier = _slug(family)
        if identifier in family_ids.values():
            identifier = f"{identifier}-{hashlib.sha256(family.encode()).hexdigest()[:8]}"
        family_ids[family] = identifier

    solver_ids_sorted = sorted(solver_ids)
    evidence: list[dict[str, Any]] = []
    for budget in budgets:
        all_instances: list[dict[str, Any]] = []
        by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for relative_path in sorted(instance_metadata):
            item = {
                "id": relative_path,
                "results": [
                    observations[(relative_path, budget, solver_id)]
                    for solver_id in solver_ids_sorted
                ],
            }
            all_instances.append(item)
            by_family[instance_metadata[relative_path]["family"]].append(item)
        panels: list[tuple[str, str, list[dict[str, Any]]]] = [
            ("all", "All families", all_instances)
        ]
        if include_family_panels:
            panels.extend(
                (family_ids[family], family, by_family[family])
                for family in sorted(by_family)
            )
        budget_token = format(budget, ".17g").replace(".", "p")
        for family_id, family_label, panel_instances in panels:
            status_panels = [("all", panel_instances)]
            if include_expected_status_panels:
                status_panels.extend(
                    (expected_status, selected)
                    for expected_status in ("sat", "unsat")
                    if (
                        selected := [
                            item
                            for item in panel_instances
                            if instance_metadata[item["id"]]["expected_status"]
                            == expected_status
                        ]
                    )
                )
            for expected_status, selected in status_panels:
                evidence.append(
                    {
                        "id": (
                            f"{evidence_prefix}-{budget_token}s-{family_id}-"
                            f"{expected_status}"
                        ),
                        "scope": "broad",
                        "evidence_class": evidence_class,
                        "evidence_status": evidence_status,
                        "revision": revision,
                        "solver_ids": solver_ids_sorted,
                        "host": {"id": host_id, "label": host_label},
                        "corpus": {"id": corpus_id, "label": corpus_label},
                        "timeout_s": budget,
                        "family": {"id": family_id, "label": family_label},
                        "expected_status": expected_status,
                        "source": {"path": source_path, "sha256": source_sha256},
                        "instances": selected,
                    }
                )

    overrides = {} if solver_label_overrides is None else solver_label_overrides
    unknown_labels = sorted(set(overrides) - set(solver_ids))
    if unknown_labels:
        raise ShardedDashboardImportError(
            f"solver label overrides reference absent solvers {unknown_labels!r}"
        )
    registry = {
        "schema_version": dashboard.REGISTRY_SCHEMA_VERSION,
        "registry_id": registry_id,
        "title": title,
        "updated_at": updated_at,
        "viper_solver_id": candidate_id,
        "solvers": [
            {
                "id": solver_id,
                "label": overrides.get(
                    solver_id,
                    DEFAULT_LABELS.get(solver_id, solver_id.replace("-", " ").title()),
                ),
            }
            for solver_id in solver_ids
        ],
        "evidence": evidence,
    }
    return dashboard.validate_registry(registry)


def _parse_label(raw: str) -> tuple[str, str]:
    solver_id, separator, label = raw.partition("=")
    if not separator or not solver_id or not label:
        raise argparse.ArgumentTypeError("must have the form SOLVER_ID=LABEL")
    return solver_id, label


def _atomic_write(path: Path, payload: bytes) -> None:
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
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("preparation_root", type=Path)
    parser.add_argument("campaign_root", type=Path)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--updated-at", required=True)
    parser.add_argument("--evidence-prefix", required=True)
    parser.add_argument("--corpus-id")
    parser.add_argument("--corpus-label", required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--host-label", required=True)
    parser.add_argument("--evidence-class", default="audited-build-once-sharded-locked")
    parser.add_argument(
        "--evidence-status",
        choices=dashboard.EVIDENCE_STATUSES,
        default="verified",
    )
    parser.add_argument("--source-path")
    parser.add_argument("--solver-label", action="append", type=_parse_label, default=[])
    parser.add_argument("--no-family-panels", action="store_true")
    parser.add_argument("--no-status-panels", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    arguments = parser.parse_args(argv)
    if arguments.shard_count < 1:
        parser.error("--shard-count must be positive")
    labels = dict(arguments.solver_label)
    if len(labels) != len(arguments.solver_label):
        parser.error("--solver-label contains a duplicate solver ID")
    preparation = arguments.preparation_root.expanduser().resolve()
    campaign_root = arguments.campaign_root.expanduser().resolve()
    audit_path = campaign_root / "audit-index.json"
    try:
        campaign, audit, analysis = load_verified_campaign(
            preparation, campaign_root, shard_count=arguments.shard_count
        )
        registry = build_registry(
            campaign,
            audit,
            analysis,
            registry_id=arguments.registry_id,
            title=arguments.title,
            updated_at=arguments.updated_at,
            evidence_prefix=arguments.evidence_prefix,
            corpus_id_override=arguments.corpus_id,
            corpus_label=arguments.corpus_label,
            host_id=arguments.host_id,
            host_label=arguments.host_label,
            evidence_class=arguments.evidence_class,
            evidence_status=arguments.evidence_status,
            source_path=(
                arguments.source_path
                if arguments.source_path is not None
                else str(audit_path)
            ),
            source_sha256=analyzer.sha256_file(audit_path),
            solver_label_overrides=labels,
            include_family_panels=not arguments.no_family_panels,
            include_expected_status_panels=not arguments.no_status_panels,
        )
        payload = dashboard.pretty_json_bytes(registry)
        _atomic_write(arguments.output.expanduser().resolve(), payload)
    except (
        ShardedDashboardImportError,
        dashboard.DashboardInputError,
        OSError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    receipt = {
        "audit_sha256": analyzer.sha256_file(audit_path),
        "evidence": len(registry["evidence"]),
        "output": str(arguments.output.expanduser().resolve()),
        "output_sha256": hashlib.sha256(payload).hexdigest(),
        "solvers": len(registry["solvers"]),
    }
    print(json.dumps(receipt, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
