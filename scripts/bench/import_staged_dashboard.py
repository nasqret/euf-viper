#!/usr/bin/env python3
"""Import an audited staged campaign into dashboard evidence.

The staged analysis contains an observation-provenance index, while timings
remain in immutable raw shards.  This importer verifies the analysis, parent
lock, shard hashes, and record hashes before reconstructing each final
observation.  It emits whole-corpus and per-family panels without treating a
promotion rejection as an evidence-integrity failure.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_euf_dashboard as dashboard  # noqa: E402


SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
DECISIVE_RESULTS = {"sat", "unsat"}
NONDECISIVE_STATUS = {
    "timeout": "timeout",
    "unknown": "unknown",
    "error": "error",
    "invalid": "invalid",
}
DEFAULT_LABELS = {
    "euf-viper": "Viper",
    "yices2": "Yices2",
    "z3-default": "Z3 default",
    "z3-sat-euf": "Z3 sat.euf",
    "cvc5": "cvc5",
    "opensmt": "OpenSMT",
}


class StagedDashboardImportError(ValueError):
    """Raised when staged evidence cannot be imported exactly."""


def canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise StagedDashboardImportError(
            f"value is not canonical JSON: {error}"
        ) from error
    return (rendered + "\n").encode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise StagedDashboardImportError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _reject_constant(token: str) -> None:
    raise StagedDashboardImportError(f"non-finite JSON number {token!r} is forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StagedDashboardImportError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path, context: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise StagedDashboardImportError(f"cannot read {context} {path}: {error}") from error
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise StagedDashboardImportError(
            f"{path}:{error.lineno}:{error.colno}: invalid JSON: {error.msg}"
        ) from error
    if type(value) is not dict:
        raise StagedDashboardImportError(f"{context} {path} must be an object")
    return value


def _mapping(value: object, context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise StagedDashboardImportError(f"{context} must be an object")
    return value


def _array(value: object, context: str, *, nonempty: bool = True) -> list[Any]:
    if type(value) is not list:
        raise StagedDashboardImportError(f"{context} must be an array")
    if nonempty and not value:
        raise StagedDashboardImportError(f"{context} must not be empty")
    return value


def _text(value: object, context: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise StagedDashboardImportError(f"{context} must be a non-empty trimmed string")
    return value


def _sha256(value: object, context: str) -> str:
    result = _text(value, context)
    if SHA256_PATTERN.fullmatch(result) is None:
        raise StagedDashboardImportError(f"{context} must be a canonical SHA-256")
    return result


def _number(value: object, context: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StagedDashboardImportError(f"{context} must be a number")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0.0):
        qualifier = "finite and positive" if positive else "finite"
        raise StagedDashboardImportError(f"{context} must be {qualifier}")
    return result


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.casefold()).strip("-._")
    if not slug:
        slug = "item"
    if len(slug) > 96:
        suffix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        slug = f"{slug[:83].rstrip('-._')}-{suffix}"
    return slug


def _record_digest(record: Mapping[str, Any]) -> str:
    unhashed = dict(record)
    unhashed.pop("record_sha256", None)
    return hashlib.sha256(canonical_json_bytes(unhashed)).hexdigest()


def _classify_record(record: Mapping[str, Any], context: str) -> str:
    timed_out = record.get("timed_out")
    if type(timed_out) is not bool:
        raise StagedDashboardImportError(f"{context}.timed_out must be boolean")
    if timed_out:
        return "timeout"
    if (
        record.get("spawn_error") is not None
        or record.get("termination_cause") in {"signal", "spawn_error"}
        or record.get("exit_code") != 0
    ):
        return "error"
    if record.get("result_token_status") != "valid":
        return "invalid"
    token = record.get("result_token")
    if token == "unknown":
        return "unknown"
    if token not in DECISIVE_RESULTS:
        return "invalid"
    wall = _number(record.get("wall_time_s"), f"{context}.wall_time_s")
    if record.get("child_cpu_time_s") is None or wall <= 0.0:
        return "invalid"
    expected = record.get("expected_status")
    if token != expected:
        raise StagedDashboardImportError(
            f"{context} contains a wrong answer: expected {expected!r}, got {token!r}"
        )
    return token


def _shard_descriptors(analysis: Mapping[str, Any]) -> list[dict[str, Any]]:
    inputs = _mapping(analysis.get("inputs"), "analysis.inputs")
    descriptors = list(_array(inputs.get("base_shards"), "analysis.inputs.base_shards"))
    for stage_index, raw_stage in enumerate(
        _array(inputs.get("stages"), "analysis.inputs.stages", nonempty=False)
    ):
        stage = _mapping(raw_stage, f"analysis.inputs.stages[{stage_index}]")
        execution = stage.get("execution_shards")
        if execution is not None:
            descriptors.extend(
                _array(
                    execution,
                    f"analysis.inputs.stages[{stage_index}].execution_shards",
                    nonempty=False,
                )
            )
    normalized: list[dict[str, Any]] = []
    seen_paths: dict[str, str] = {}
    for index, raw_descriptor in enumerate(descriptors):
        descriptor = _mapping(raw_descriptor, f"shard[{index}]")
        path = _text(descriptor.get("raw"), f"shard[{index}].raw")
        digest = _sha256(descriptor.get("raw_sha256"), f"shard[{index}].raw_sha256")
        prior = seen_paths.setdefault(path, digest)
        if prior != digest:
            raise StagedDashboardImportError(
                f"raw shard {path!r} has conflicting SHA-256 declarations"
            )
        if prior == digest and any(item["path"] == path for item in normalized):
            continue
        normalized.append({"path": path, "sha256": digest})
    if not normalized:
        raise StagedDashboardImportError("analysis names no physical raw shards")
    return normalized


def _load_records(
    descriptors: Sequence[Mapping[str, str]],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    records: dict[str, dict[str, Any]] = {}
    record_raw_hash: dict[str, str] = {}
    for descriptor in descriptors:
        path = Path(descriptor["path"])
        actual = sha256_file(path)
        if actual != descriptor["sha256"]:
            raise StagedDashboardImportError(
                f"raw shard SHA-256 mismatch for {path}: declared "
                f"{descriptor['sha256']}, actual {actual}"
            )
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            raise StagedDashboardImportError(f"cannot read raw shard {path}: {error}") from error
        if not lines:
            raise StagedDashboardImportError(f"raw shard {path} is empty")
        for line_number, line in enumerate(lines, start=1):
            context = f"{path}:{line_number}"
            if not line:
                raise StagedDashboardImportError(f"{context}: blank record")
            try:
                value = json.loads(
                    line,
                    object_pairs_hook=_unique_object,
                    parse_constant=_reject_constant,
                )
            except json.JSONDecodeError as error:
                raise StagedDashboardImportError(
                    f"{context}: invalid JSON: {error.msg}"
                ) from error
            record = _mapping(value, context)
            digest = _sha256(record.get("record_sha256"), f"{context}.record_sha256")
            actual_record_digest = _record_digest(record)
            if digest != actual_record_digest:
                raise StagedDashboardImportError(
                    f"{context}: record SHA-256 mismatch: declared {digest}, "
                    f"actual {actual_record_digest}"
                )
            if digest in records:
                raise StagedDashboardImportError(
                    f"duplicate source record SHA-256 {digest}"
                )
            records[digest] = record
            record_raw_hash[digest] = actual
    return records, record_raw_hash


def _load_parent_lock(
    analysis: Mapping[str, Any], analysis_path: Path
) -> tuple[dict[str, Any], Path]:
    inputs = _mapping(analysis.get("inputs"), "analysis.inputs")
    base = _mapping(inputs.get("base"), "analysis.inputs.base")
    parent_path = Path(_text(base.get("parent_lock"), "analysis.inputs.base.parent_lock"))
    expected = _sha256(
        _mapping(analysis.get("input_hashes"), "analysis.input_hashes").get(
            "base_lock_file_sha256"
        ),
        "analysis.input_hashes.base_lock_file_sha256",
    )
    actual = sha256_file(parent_path)
    if actual != expected:
        raise StagedDashboardImportError(
            f"parent lock SHA-256 mismatch for {parent_path}: declared {expected}, "
            f"actual {actual}; analysis={analysis_path}"
        )
    return load_json(parent_path, "parent lock"), parent_path


def _solver_labels(
    solver_ids: Sequence[str], overrides: Mapping[str, str]
) -> list[dict[str, str]]:
    unknown = sorted(set(overrides) - set(solver_ids))
    if unknown:
        raise StagedDashboardImportError(
            f"solver label overrides reference absent solvers {unknown!r}"
        )
    return [
        {
            "id": solver_id,
            "label": overrides.get(
                solver_id,
                DEFAULT_LABELS.get(solver_id, solver_id.replace("-", " ").title()),
            ),
        }
        for solver_id in solver_ids
    ]


def import_staged_campaign(
    analysis_path: Path,
    *,
    registry_id: str,
    title: str,
    updated_at: str,
    evidence_prefix: str,
    corpus_id_override: str | None,
    corpus_label: str,
    host_id: str,
    host_label: str,
    evidence_class: str = "audited-staged-locked",
    evidence_status: str = "verified",
    solver_label_overrides: Mapping[str, str] | None = None,
    include_family_panels: bool = True,
    include_expected_status_panels: bool = True,
    source_path: str | None = None,
) -> dict[str, Any]:
    """Verify and normalize one staged analysis into a dashboard registry."""

    analysis_path = analysis_path.expanduser().resolve()
    analysis_sha256 = sha256_file(analysis_path)
    analysis = load_json(analysis_path, "staged analysis")
    if analysis.get("status") not in {"promoted", "rejected"}:
        raise StagedDashboardImportError("analysis.status must be promoted or rejected")
    if type(analysis.get("promoted")) is not bool:
        raise StagedDashboardImportError("analysis.promoted must be boolean")
    if analysis["promoted"] != (analysis["status"] == "promoted"):
        raise StagedDashboardImportError("analysis promotion fields disagree")

    inputs = _mapping(analysis.get("inputs"), "analysis.inputs")
    candidate_id = _text(inputs.get("candidate_id"), "analysis.inputs.candidate_id")
    baseline_ids = [
        _text(value, f"analysis.inputs.baseline_ids[{index}]")
        for index, value in enumerate(
            _array(inputs.get("baseline_ids"), "analysis.inputs.baseline_ids")
        )
    ]
    solver_ids = [candidate_id, *baseline_ids]
    duplicates = sorted(
        solver_id for solver_id, count in Counter(solver_ids).items() if count > 1
    )
    if duplicates:
        raise StagedDashboardImportError(
            f"analysis solver IDs are not unique: {duplicates!r}"
        )
    budgets = [
        _number(value, f"analysis.inputs.budgets_s[{index}]", positive=True)
        for index, value in enumerate(
            _array(inputs.get("budgets_s"), "analysis.inputs.budgets_s")
        )
    ]
    if budgets != sorted(set(budgets)):
        raise StagedDashboardImportError(
            "analysis.inputs.budgets_s must be strictly increasing and unique"
        )

    parent_lock, _ = _load_parent_lock(analysis, analysis_path)
    repository = _mapping(parent_lock.get("repository"), "parent_lock.repository")
    revision = _text(repository.get("commit"), "parent_lock.repository.commit")
    corpus = _mapping(parent_lock.get("corpus"), "parent_lock.corpus")
    parent_corpus_id = _text(corpus.get("id"), "parent_lock.corpus.id")
    corpus_id = (
        parent_corpus_id
        if corpus_id_override is None
        else _text(corpus_id_override, "corpus_id_override")
    )
    raw_instances = _array(corpus.get("instances"), "parent_lock.corpus.instances")
    instances_by_path: dict[str, dict[str, str]] = {}
    for index, raw_instance in enumerate(raw_instances):
        instance = _mapping(raw_instance, f"parent_lock.corpus.instances[{index}]")
        relative_path = _text(
            instance.get("relative_path"),
            f"parent_lock.corpus.instances[{index}].relative_path",
        )
        if relative_path in instances_by_path:
            raise StagedDashboardImportError(
                f"parent corpus contains duplicate path {relative_path!r}"
            )
        instances_by_path[relative_path] = {
            "family": _text(
                instance.get("family"),
                f"parent_lock.corpus.instances[{index}].family",
            ),
            "expected_status": _text(
                instance.get("status"),
                f"parent_lock.corpus.instances[{index}].status",
            ),
        }
    declared_instances = inputs.get("instances")
    if type(declared_instances) is not int or declared_instances != len(instances_by_path):
        raise StagedDashboardImportError(
            "analysis.inputs.instances disagrees with the parent corpus"
        )

    records, record_raw_hash = _load_records(_shard_descriptors(analysis))
    observations: dict[tuple[str, float, str], dict[str, Any]] = {}
    provenance_rows = _array(
        inputs.get("observation_provenance"),
        "analysis.inputs.observation_provenance",
    )
    for index, raw_provenance in enumerate(provenance_rows):
        context = f"analysis.inputs.observation_provenance[{index}]"
        provenance = _mapping(raw_provenance, context)
        relative_path = _text(provenance.get("relative_path"), f"{context}.relative_path")
        if relative_path not in instances_by_path:
            raise StagedDashboardImportError(
                f"{context} references absent instance {relative_path!r}"
            )
        budget = _number(provenance.get("budget_s"), f"{context}.budget_s", positive=True)
        origin_budget = _number(
            provenance.get("origin_budget_s"),
            f"{context}.origin_budget_s",
            positive=True,
        )
        solver_id = _text(provenance.get("solver_id"), f"{context}.solver_id")
        if solver_id not in solver_ids:
            raise StagedDashboardImportError(
                f"{context} references absent solver {solver_id!r}"
            )
        source_hashes = [
            _sha256(value, f"{context}.source_record_sha256s[{source_index}]")
            for source_index, value in enumerate(
                _array(
                    provenance.get("source_record_sha256s"),
                    f"{context}.source_record_sha256s",
                )
            )
        ]
        if len(source_hashes) != len(set(source_hashes)):
            raise StagedDashboardImportError(
                f"{context}.source_record_sha256s contains duplicates"
            )
        source_records: list[dict[str, Any]] = []
        for record_hash in source_hashes:
            try:
                record = records[record_hash]
            except KeyError as error:
                raise StagedDashboardImportError(
                    f"{context} references missing source record {record_hash}"
                ) from error
            if record_raw_hash[record_hash] != provenance.get("source_raw_sha256"):
                raise StagedDashboardImportError(
                    f"{context} source raw SHA-256 does not match record {record_hash}"
                )
            source_records.append(record)
        source_lock_hash = _sha256(
            provenance.get("source_lock_sha256"), f"{context}.source_lock_sha256"
        )
        classifications: list[str] = []
        wall_times: list[float] = []
        for record_index, record in enumerate(source_records):
            record_context = f"{context}.source_record[{record_index}]"
            for field, expected in (
                ("relative_path", relative_path),
                ("solver_id", solver_id),
                ("lock_sha256", source_lock_hash),
            ):
                if record.get(field) != expected:
                    raise StagedDashboardImportError(
                        f"{record_context}.{field} does not match provenance"
                    )
            if _number(record.get("budget_s"), f"{record_context}.budget_s", positive=True) != origin_budget:
                raise StagedDashboardImportError(
                    f"{record_context}.budget_s does not match origin_budget_s"
                )
            classifications.append(_classify_record(record, record_context))
            wall_times.append(
                _number(record.get("wall_time_s"), f"{record_context}.wall_time_s")
            )
        aggregate = classifications[0] if len(set(classifications)) == 1 else "invalid"
        declared_result = _text(provenance.get("result"), f"{context}.result")
        if aggregate != declared_result:
            raise StagedDashboardImportError(
                f"{context}.result {declared_result!r} disagrees with reconstructed "
                f"result {aggregate!r}"
            )
        expected_status = instances_by_path[relative_path]["expected_status"]
        if aggregate in DECISIVE_RESULTS:
            if aggregate != expected_status:
                raise StagedDashboardImportError(f"{context} contains a wrong answer")
            status = "solved"
            time_s: float | None = float(median(wall_times))
            if time_s <= 0.0:
                raise StagedDashboardImportError(
                    f"{context} decisive median wall time must be positive"
                )
        else:
            try:
                status = NONDECISIVE_STATUS[aggregate]
            except KeyError as error:
                raise StagedDashboardImportError(
                    f"{context}.result has unsupported value {aggregate!r}"
                ) from error
            time_s = None
        key = (relative_path, budget, solver_id)
        if key in observations:
            raise StagedDashboardImportError(f"duplicate final observation {key!r}")
        observations[key] = {"solver_id": solver_id, "status": status, "time_s": time_s}

    expected_keys = {
        (relative_path, budget, solver_id)
        for relative_path in instances_by_path
        for budget in budgets
        for solver_id in solver_ids
    }
    actual_keys = set(observations)
    if actual_keys != expected_keys:
        raise StagedDashboardImportError(
            "final observation rectangle is incomplete: "
            f"missing={len(expected_keys - actual_keys)}, "
            f"unexpected={len(actual_keys - expected_keys)}"
        )

    family_ids: dict[str, str] = {}
    for family in sorted({item["family"] for item in instances_by_path.values()}):
        identifier = _slug(family)
        if identifier in family_ids.values():
            identifier = f"{identifier}-{hashlib.sha256(family.encode()).hexdigest()[:8]}"
        family_ids[family] = identifier
    source = {
        "path": source_path if source_path is not None else str(analysis_path),
        "sha256": analysis_sha256,
    }
    solver_ids_sorted = sorted(solver_ids)
    evidence: list[dict[str, Any]] = []
    for budget in budgets:
        by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
        all_instances: list[dict[str, Any]] = []
        for relative_path in sorted(instances_by_path):
            observed_instance = {
                "id": relative_path,
                "results": [
                    observations[(relative_path, budget, solver_id)]
                    for solver_id in solver_ids_sorted
                ],
            }
            all_instances.append(observed_instance)
            by_family[instances_by_path[relative_path]["family"]].append(observed_instance)
        budget_token = format(budget, ".17g").replace(".", "p")
        panels: list[tuple[str, str, list[dict[str, Any]]]] = [
            ("all", "All families", all_instances)
        ]
        if include_family_panels:
            panels.extend(
                (family_ids[family], family, by_family[family])
                for family in sorted(by_family)
            )
        for family_id, family_label, panel_instances in panels:
            status_panels = [("all", panel_instances)]
            if include_expected_status_panels:
                status_panels.extend(
                    (expected_status, selected)
                    for expected_status in ("sat", "unsat")
                    if (
                        selected := [
                            instance
                            for instance in panel_instances
                            if instances_by_path[instance["id"]]["expected_status"]
                            == expected_status
                        ]
                    )
                )
            for expected_status, status_instances in status_panels:
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
                        "source": source,
                        "instances": status_instances,
                    }
                )
    registry = {
        "schema_version": dashboard.REGISTRY_SCHEMA_VERSION,
        "registry_id": registry_id,
        "title": title,
        "updated_at": updated_at,
        "viper_solver_id": candidate_id,
        "solvers": _solver_labels(
            solver_ids, {} if solver_label_overrides is None else solver_label_overrides
        ),
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
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--updated-at", required=True)
    parser.add_argument("--evidence-prefix", required=True)
    parser.add_argument("--corpus-id")
    parser.add_argument("--corpus-label", required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--host-label", required=True)
    parser.add_argument("--evidence-class", default="audited-staged-locked")
    parser.add_argument(
        "--evidence-status",
        choices=dashboard.EVIDENCE_STATUSES,
        default="verified",
    )
    parser.add_argument("--solver-label", action="append", type=_parse_label, default=[])
    parser.add_argument("--source-path")
    parser.add_argument("--no-family-panels", action="store_true")
    parser.add_argument("--no-status-panels", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    arguments = parser.parse_args(argv)
    label_pairs = arguments.solver_label
    labels = dict(label_pairs)
    if len(labels) != len(label_pairs):
        parser.error("--solver-label contains a duplicate solver ID")
    try:
        registry = import_staged_campaign(
            arguments.analysis,
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
            solver_label_overrides=labels,
            include_family_panels=not arguments.no_family_panels,
            include_expected_status_panels=not arguments.no_status_panels,
            source_path=arguments.source_path,
        )
        payload = dashboard.pretty_json_bytes(registry)
        _atomic_write(arguments.output.expanduser().resolve(), payload)
    except (StagedDashboardImportError, dashboard.DashboardInputError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    receipt = {
        "analysis": str(arguments.analysis.expanduser().resolve()),
        "evidence": len(registry["evidence"]),
        "output": str(arguments.output.expanduser().resolve()),
        "output_sha256": hashlib.sha256(payload).hexdigest(),
        "solvers": len(registry["solvers"]),
    }
    print(json.dumps(receipt, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
