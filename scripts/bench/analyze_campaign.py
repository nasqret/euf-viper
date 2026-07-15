#!/usr/bin/env python3
"""Rigorous deterministic analysis for paired P0 campaign results.

The primary input is ``raw.jsonl`` from ``run_locked_campaign.py`` together
with its self-hashed campaign lock.  A sharded campaign may instead provide
the parent lock plus all runtime-bound shard lock/raw pairs.  The analyzer
verifies the complete locked schedule, shard derivation, every record digest,
solver and instance hashes, budgets, statuses, and repetitions before
comparing a candidate with each named comparator.

For imported evidence, ``--manifest`` selects a strict normalized CSV adapter.
That schema contains one row per (instance, budget, label), where label is
``baseline`` or ``candidate``::

    relative_path,family,expected_status,budget_s,label,manifest_sha256,
    instance_sha256,binary_sha256,result,cpu_time_s,wall_time_s

``result`` is one of sat, unsat, timeout, unknown, error, or invalid.  A
decisive result that disagrees with ``expected_status`` makes the entire input
invalid; it is never treated as an ordinary coverage loss.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import sys
from collections import Counter, defaultdict
from fractions import Fraction
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


CERT_DIR = Path(__file__).resolve().parents[1] / "cert"
if str(CERT_DIR) not in sys.path:
    sys.path.insert(0, str(CERT_DIR))

from check_production_evidence import (  # noqa: E402
    ProductionEvidenceError,
    validate_production_evidence,
)
from strict_artifacts import (  # noqa: E402
    StrictArtifactError,
    read_regular_nofollow as strict_read_regular_nofollow,
)


SCHEMA_VERSION = 1
FIELDNAMES = [
    "relative_path",
    "family",
    "expected_status",
    "budget_s",
    "label",
    "manifest_sha256",
    "instance_sha256",
    "binary_sha256",
    "result",
    "cpu_time_s",
    "wall_time_s",
]
LABELS = ("baseline", "candidate")
DECISIVE_RESULTS = {"sat", "unsat"}
NONDECISIVE_RESULTS = {"timeout", "unknown", "unsupported", "error", "invalid"}
VALID_RESULTS = DECISIVE_RESULTS | NONDECISIVE_RESULTS
HEX_DIGITS = frozenset("0123456789abcdef")

DEFAULT_SEED = 20260712
DEFAULT_BOOTSTRAP_REPLICATES = 10_000
DEFAULT_CONFIDENCE_LEVEL = 0.95
DEFAULT_MINIMUM_SPEEDUP = 1.0

BOOTSTRAP_METRICS = (
    "timeout_charged_wall",
    "par2_wall",
    "common_wall_total",
    "common_wall_geometric",
    "common_cpu_total",
    "common_cpu_geometric",
)
REQUIRED_PROMOTION_METRICS = (
    "timeout_charged_wall",
    "common_wall_total",
    "common_wall_geometric",
)
NON_REGRESSION_METRICS = (
    "timeout_charged_wall",
    "par2_wall",
    "common_wall_total",
    "common_wall_geometric",
)

LOCK_TOP_LEVEL_KEYS = {
    "schema_version",
    "campaign_id",
    "lock_sha256",
    "created_from_commit_time",
    "promotion_eligible",
    "spec",
    "repository",
    "host",
    "corpus",
    "solver_config",
    "solver_release_lock",
    "solvers",
    "budgets_s",
    "execution",
    "output",
}
LOCK_RELEASE_KEYS = {"path", "sha256"}
LOCK_SHARD_KEYS = {"index", "count", "parent_lock_sha256"}
LOCK_RUNTIME_BINDING_KEYS = {
    "parent_lock_sha256",
    "mechanism",
    "cpu_ids",
}
LOCK_CONTINUATION_KEYS = {
    "mode",
    "root_lock_sha256",
    "parent_lock_path",
    "parent_lock_file_sha256",
    "parent_lock_sha256",
    "shard_bundle_sha256",
    "source_evidence_sha256",
    "shard_lock_directory",
    "shard_results_root",
    "source_budget_s",
    "target_budget_s",
    "selection_sha256",
    "selected_instances",
    "selected_runs",
    "runner_path",
    "runner_sha256",
}
LOCK_RUN_SELECTION_KEYS = {"instance_id", "solver_id"}
LOCK_CORPUS_KEYS = {
    "id",
    "manifest_path",
    "manifest_sha256",
    "taxonomy_path",
    "taxonomy_sha256",
    "root",
    "instances",
}
LOCK_EXECUTION_KEYS = {
    "resource_model",
    "cpu_ids",
    "memory_bytes",
    "order",
    "environment",
    "timeout_grace_s",
}
LOCK_SOLVER_KEYS = {
    "id",
    "comparator_id",
    "configuration",
    "version",
    "binary",
    "sha256",
    "argv_template",
    "version_output",
    "version_output_sha256",
    "environment",
}
LOCK_EVIDENCE_KEYS = {
    "schema",
    "argv_flag",
    "accepted_decisive_statuses",
}
RUN_RECORD_KEYS = {
    "record_type",
    "schema_version",
    "lock_sha256",
    "invocation",
    "sequence",
    "key",
    "instance_id",
    "relative_path",
    "instance_sha256",
    "expected_status",
    "family",
    "solver_id",
    "solver_sha256",
    "solver_version",
    "budget_s",
    "repetition",
    "cpu_id",
    "argv",
    "descriptor_binding",
    "environment_sha256",
    "pid",
    "started_at",
    "finished_at",
    "wall_time_s",
    "child_user_time_s",
    "child_system_time_s",
    "child_cpu_time_s",
    "max_rss_bytes",
    "exit_code",
    "termination_cause",
    "termination_signal",
    "timed_out",
    "spawn_error",
    "stdout_sha256",
    "stdout_bytes",
    "stderr_sha256",
    "stderr_bytes",
    "result_token",
    "result_token_status",
    "previous_record_sha256",
    "record_sha256",
}
PRODUCTION_EVIDENCE_KEYS = {
    "path",
    "sha256",
    "bytes",
    "schema",
    "source_sha256",
    "solver_revision",
    "solver_executable_sha256",
    "solver_configuration",
    "solver_config_sha256",
    "solver_runtime_config_sha256",
    "solver_build_sha256",
    "run_nonce",
    "status",
    "backend_status",
}


class CampaignInputError(ValueError):
    """Raised when campaign evidence is incomplete or internally inconsistent."""

    def __init__(self, errors: Sequence[str]):
        self.errors = list(errors)
        if not self.errors:
            raise ValueError("CampaignInputError requires at least one error")
        super().__init__(self.errors[0])


def sha256_file(path: Path) -> str:
    try:
        _, content = strict_read_regular_nofollow(path, f"hash input {path}")
    except StrictArtifactError as error:
        raise OSError(str(error)) from error
    return hashlib.sha256(content).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in HEX_DIGITS for character in value)


def _parse_positive_float(raw: str, field: str, context: str) -> float:
    if raw != raw.strip() or not raw:
        raise ValueError(f"{context}: invalid {field} {raw!r}")
    try:
        value = float(raw)
    except ValueError as error:
        raise ValueError(f"{context}: invalid {field} {raw!r}") from error
    if not math.isfinite(value) or value <= 0.0:
        raise ValueError(f"{context}: {field} must be finite and positive")
    return value


def _parse_nonnegative_float(raw: str, field: str, context: str) -> float:
    if raw != raw.strip() or not raw:
        raise ValueError(f"{context}: invalid {field} {raw!r}")
    try:
        value = float(raw)
    except ValueError as error:
        raise ValueError(f"{context}: invalid {field} {raw!r}") from error
    if not math.isfinite(value) or value < 0.0:
        raise ValueError(f"{context}: {field} must be finite and non-negative")
    return value


def _validate_relative_path(value: str, context: str) -> None:
    parsed = PurePosixPath(value)
    if (
        not value
        or value != parsed.as_posix()
        or parsed.is_absolute()
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise ValueError(f"{context}: relative_path is not normalized: {value!r}")


def _validate_text(value: str, field: str, context: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{context}: {field} must be non-empty and trimmed")


def _parse_csv_record(record: dict[str | None, Any], context: str) -> dict[str, Any]:
    if None in record:
        raise ValueError(f"{context}: unexpected extra fields {record[None]!r}")
    missing = [field for field in FIELDNAMES if record.get(field) is None]
    if missing:
        raise ValueError(f"{context}: missing fields {missing!r}")

    values = {field: record[field] for field in FIELDNAMES}
    assert all(isinstance(value, str) for value in values.values())
    relative_path = values["relative_path"]
    family = values["family"]
    expected_status = values["expected_status"]
    label = values["label"]
    result = values["result"]
    _validate_relative_path(relative_path, context)
    _validate_text(family, "family", context)

    if expected_status not in DECISIVE_RESULTS:
        raise ValueError(
            f"{context}: expected_status must be 'sat' or 'unsat', "
            f"got {expected_status!r}"
        )
    if label not in LABELS:
        raise ValueError(f"{context}: invalid label {label!r}")
    if result not in VALID_RESULTS:
        raise ValueError(f"{context}: invalid result status {result!r}")
    if result in DECISIVE_RESULTS and result != expected_status:
        raise ValueError(
            f"{context}: wrong answer for {relative_path!r}: "
            f"expected {expected_status!r}, got {result!r}"
        )

    for field in ("manifest_sha256", "instance_sha256", "binary_sha256"):
        if not _is_sha256(values[field]):
            raise ValueError(f"{context}: {field} is not a canonical SHA-256 digest")

    budget_s = _parse_positive_float(values["budget_s"], "budget_s", context)
    cpu_time_s = _parse_nonnegative_float(
        values["cpu_time_s"], "cpu_time_s", context
    )
    wall_time_s = _parse_nonnegative_float(
        values["wall_time_s"], "wall_time_s", context
    )
    if result in DECISIVE_RESULTS:
        if wall_time_s <= 0.0:
            raise ValueError(f"{context}: decisive rows require positive wall time")
        if wall_time_s > budget_s:
            raise ValueError(
                f"{context}: decisive wall_time_s {wall_time_s} exceeds "
                f"budget_s {budget_s}"
            )

    return {
        "relative_path": relative_path,
        "family": family,
        "expected_status": expected_status,
        "budget_s": budget_s,
        "label": label,
        "manifest_sha256": values["manifest_sha256"],
        "instance_sha256": values["instance_sha256"],
        "binary_sha256": values["binary_sha256"],
        "result": result,
        "cpu_time_s": cpu_time_s,
        "wall_time_s": wall_time_s,
    }


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict[str, dict[str, str]]:
    """Load the exact JSONL manifest used to establish campaign completeness."""

    entries: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                context = f"{path}:{line_number}"
                try:
                    value = json.loads(
                        line,
                        object_pairs_hook=_unique_json_object,
                        parse_constant=lambda item: (_ for _ in ()).throw(
                            ValueError(f"non-finite JSON number {item!r}")
                        ),
                    )
                except (json.JSONDecodeError, ValueError) as error:
                    errors.append(f"{context}: invalid JSON object: {error}")
                    continue
                if not isinstance(value, dict):
                    errors.append(f"{context}: manifest row must be an object")
                    continue
                relative_path = value.get("relative_path")
                status = value.get("status")
                instance_sha256 = value.get("sha256")
                family = value.get("family")
                try:
                    if not isinstance(relative_path, str):
                        raise ValueError(f"{context}: relative_path must be a string")
                    _validate_relative_path(relative_path, context)
                    if status not in DECISIVE_RESULTS:
                        raise ValueError(
                            f"{context}: status must be 'sat' or 'unsat'"
                        )
                    if not isinstance(instance_sha256, str) or not _is_sha256(
                        instance_sha256
                    ):
                        raise ValueError(
                            f"{context}: sha256 is not a canonical SHA-256 digest"
                        )
                    if family is not None:
                        if not isinstance(family, str):
                            raise ValueError(f"{context}: family must be a string")
                        _validate_text(family, "family", context)
                except ValueError as error:
                    errors.append(str(error))
                    continue
                if relative_path in entries:
                    errors.append(
                        f"{context}: duplicate manifest relative_path {relative_path!r}"
                    )
                    continue
                entry = {
                    "expected_status": status,
                    "instance_sha256": instance_sha256,
                }
                if family is not None:
                    entry["family"] = family
                entries[relative_path] = entry
    except (OSError, UnicodeError) as error:
        raise CampaignInputError([f"{path}: cannot read manifest: {error}"]) from error

    if errors:
        raise CampaignInputError(errors)
    if not entries:
        raise CampaignInputError([f"{path}: manifest contains no instances"])
    return entries


def _canonical_instance_set_hash(
    manifest: Mapping[str, Mapping[str, str]], families: Mapping[str, str]
) -> str:
    records = [
        {
            "expected_status": manifest[path]["expected_status"],
            "family": families[path],
            "instance_sha256": manifest[path]["instance_sha256"],
            "relative_path": path,
        }
        for path in sorted(manifest)
    ]
    encoded = json.dumps(
        records, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def load_campaign(
    csv_path: Path,
    manifest_path: Path,
    *,
    binary_paths: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    """Load and validate a complete rectangular paired campaign."""

    try:
        manifest_sha256 = sha256_file(manifest_path)
        csv_sha256 = sha256_file(csv_path)
    except OSError as error:
        raise CampaignInputError([f"cannot hash campaign input: {error}"]) from error
    manifest = load_manifest(manifest_path)

    observations: dict[tuple[str, float, str], dict[str, Any]] = {}
    families: dict[str, str] = {}
    binary_hashes_seen: dict[str, set[str]] = {label: set() for label in LABELS}
    errors: list[str] = []
    try:
        with csv_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames != FIELDNAMES:
                raise CampaignInputError(
                    [
                        f"{csv_path}: incompatible CSV header: expected "
                        f"{FIELDNAMES!r}; got {reader.fieldnames!r}"
                    ]
                )
            for record in reader:
                context = f"{csv_path}: row ending at line {reader.line_num}"
                try:
                    parsed = _parse_csv_record(record, context)
                except ValueError as error:
                    errors.append(str(error))
                    continue

                relative_path = parsed["relative_path"]
                entry = manifest.get(relative_path)
                if entry is None:
                    errors.append(
                        f"{context}: relative_path {relative_path!r} is not in manifest"
                    )
                    continue
                if parsed["manifest_sha256"] != manifest_sha256:
                    errors.append(
                        f"{context}: manifest SHA-256 mismatch: declared "
                        f"{parsed['manifest_sha256']}, actual {manifest_sha256}"
                    )
                if parsed["instance_sha256"] != entry["instance_sha256"]:
                    errors.append(
                        f"{context}: instance SHA-256 mismatch for {relative_path!r}"
                    )
                if parsed["expected_status"] != entry["expected_status"]:
                    errors.append(
                        f"{context}: expected_status mismatch for {relative_path!r}"
                    )
                if "family" in entry and parsed["family"] != entry["family"]:
                    errors.append(
                        f"{context}: family mismatch for {relative_path!r}: "
                        f"{parsed['family']!r} vs {entry['family']!r}"
                    )
                prior_family = families.setdefault(relative_path, parsed["family"])
                if prior_family != parsed["family"]:
                    errors.append(
                        f"{context}: inconsistent family for {relative_path!r}: "
                        f"{prior_family!r} vs {parsed['family']!r}"
                    )

                key = (relative_path, parsed["budget_s"], parsed["label"])
                if key in observations:
                    errors.append(f"{context}: duplicate observation key {key!r}")
                    continue
                observations[key] = parsed
                binary_hashes_seen[parsed["label"]].add(parsed["binary_sha256"])
    except CampaignInputError:
        raise
    except (OSError, UnicodeError, csv.Error) as error:
        raise CampaignInputError([f"{csv_path}: cannot read CSV: {error}"]) from error

    if not observations and not errors:
        errors.append(f"{csv_path}: CSV contains no observations")

    for label in LABELS:
        seen = binary_hashes_seen[label]
        if len(seen) != 1:
            errors.append(
                f"{csv_path}: {label} must declare exactly one binary SHA-256; "
                f"got {sorted(seen)!r}"
            )

    observed_paths = {key[0] for key in observations}
    manifest_paths = set(manifest)
    missing_paths = sorted(manifest_paths - observed_paths)
    if missing_paths:
        errors.append(
            f"{csv_path}: missing manifest instances: count={len(missing_paths)}; "
            f"first={missing_paths[:10]!r}"
        )

    budgets = sorted({key[1] for key in observations})
    for relative_path in sorted(observed_paths & manifest_paths):
        by_label = {
            label: {
                budget
                for path, budget, row_label in observations
                if path == relative_path and row_label == label
            }
            for label in LABELS
        }
        if by_label["baseline"] != by_label["candidate"]:
            errors.append(
                f"{csv_path}: incomparable budgets for {relative_path!r}: "
                f"baseline={sorted(by_label['baseline'])!r}, "
                f"candidate={sorted(by_label['candidate'])!r}"
            )

    missing_keys = [
        (relative_path, budget, label)
        for relative_path in sorted(manifest)
        for budget in budgets
        for label in LABELS
        if (relative_path, budget, label) not in observations
    ]
    if missing_keys:
        errors.append(
            f"{csv_path}: incomplete paired campaign: missing_keys="
            f"{len(missing_keys)}; first={missing_keys[:10]!r}"
        )

    binary_paths = {} if binary_paths is None else dict(binary_paths)
    unexpected_labels = sorted(set(binary_paths) - set(LABELS))
    if unexpected_labels:
        errors.append(f"unexpected binary artifact labels {unexpected_labels!r}")
    artifact_verification: dict[str, dict[str, Any]] = {}
    for label in LABELS:
        path = binary_paths.get(label)
        declared = next(iter(binary_hashes_seen[label]), None)
        if path is None:
            artifact_verification[label] = {
                "declared_sha256": declared,
                "path": None,
                "verified": False,
            }
            continue
        try:
            actual = sha256_file(path)
        except OSError as error:
            errors.append(f"cannot hash {label} binary {path}: {error}")
            continue
        artifact_verification[label] = {
            "actual_sha256": actual,
            "declared_sha256": declared,
            "path": str(path),
            "verified": actual == declared,
        }
        if actual != declared:
            errors.append(
                f"{label} binary SHA-256 mismatch: declared {declared}, actual {actual}"
            )

    if errors:
        raise CampaignInputError(errors)

    binary_hashes = {
        label: next(iter(binary_hashes_seen[label])) for label in LABELS
    }
    pairs = [
        {
            "relative_path": relative_path,
            "family": families[relative_path],
            "expected_status": manifest[relative_path]["expected_status"],
            "budget_s": budget,
            "baseline": observations[(relative_path, budget, "baseline")],
            "candidate": observations[(relative_path, budget, "candidate")],
        }
        for budget in budgets
        for relative_path in sorted(manifest)
    ]
    return {
        "artifact_verification": artifact_verification,
        "binary_sha256": binary_hashes,
        "budgets": budgets,
        "csv_sha256": csv_sha256,
        "families": families,
        "instance_set_sha256": _canonical_instance_set_hash(manifest, families),
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "pairs": pairs,
    }


def _quantile(values: Sequence[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _geometric_mean(values: Sequence[float]) -> float | None:
    if not values:
        return None
    if any(not math.isfinite(value) or value <= 0.0 for value in values):
        raise ArithmeticError("geometric mean requires finite positive values")
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def _ratio(baseline: float, candidate: float) -> float | None:
    if baseline <= 0.0 or candidate <= 0.0:
        return None
    value = baseline / candidate
    if not math.isfinite(value) or value <= 0.0:
        raise ArithmeticError("speedup ratio is not finite and positive")
    return value


def _is_solved(observation: Mapping[str, Any]) -> bool:
    return observation["result"] == observation["expected_status"]


def _score(observation: Mapping[str, Any], penalty: float) -> float:
    if _is_solved(observation):
        return observation["wall_time_s"]
    return penalty * observation["budget_s"]


def _timing_aggregate(
    all_values: Sequence[float], solved_values: Sequence[float]
) -> dict[str, float | None]:
    return {
        "total_s": math.fsum(all_values),
        "solved_total_s": math.fsum(solved_values),
        "median_s": _quantile(all_values, 0.5),
        "p95_s": _quantile(all_values, 0.95),
        "solved_median_s": _quantile(solved_values, 0.5),
    }


def _arm_summary(
    pairs: Sequence[Mapping[str, Any]], label: str
) -> dict[str, Any]:
    observations = [pair[label] for pair in pairs]
    solved = [observation for observation in observations if _is_solved(observation)]
    statuses = Counter(observation["result"] for observation in observations)
    return {
        "instances": len(observations),
        "solved": len(solved),
        "unsolved": len(observations) - len(solved),
        "coverage": len(solved) / len(observations) if observations else None,
        "statuses": {
            status: statuses.get(status, 0) for status in sorted(VALID_RESULTS)
        },
        "cpu_time": _timing_aggregate(
            [observation["cpu_time_s"] for observation in observations],
            [observation["cpu_time_s"] for observation in solved],
        ),
        "wall_time": _timing_aggregate(
            [observation["wall_time_s"] for observation in observations],
            [observation["wall_time_s"] for observation in solved],
        ),
        "timeout_charged_wall_s": math.fsum(
            _score(observation, 1.0) for observation in observations
        ),
        "par2_wall_s": math.fsum(
            _score(observation, 2.0) for observation in observations
        ),
    }


def exact_mcnemar(baseline_only: int, candidate_only: int) -> dict[str, Any]:
    """Return the exact conditional two-sided McNemar test."""

    for name, value in (
        ("baseline_only", baseline_only),
        ("candidate_only", candidate_only),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    discordant = baseline_only + candidate_only
    if discordant == 0:
        probability = Fraction(1, 1)
    else:
        tail = sum(
            math.comb(discordant, index)
            for index in range(min(baseline_only, candidate_only) + 1)
        )
        probability = min(Fraction(1, 1), Fraction(2 * tail, 2**discordant))
    return {
        "alternative": "two_sided",
        "baseline_only": baseline_only,
        "candidate_only": candidate_only,
        "discordant": discordant,
        "exact_fraction": f"{probability.numerator}/{probability.denominator}",
        "method": "exact_conditional_binomial",
        "p_value": float(probability),
    }


def _speedup_metrics(pairs: Sequence[Mapping[str, Any]]) -> dict[str, float | None]:
    baseline_timeout = math.fsum(_score(pair["baseline"], 1.0) for pair in pairs)
    candidate_timeout = math.fsum(_score(pair["candidate"], 1.0) for pair in pairs)
    baseline_par2 = math.fsum(_score(pair["baseline"], 2.0) for pair in pairs)
    candidate_par2 = math.fsum(_score(pair["candidate"], 2.0) for pair in pairs)
    common = [
        pair
        for pair in pairs
        if _is_solved(pair["baseline"]) and _is_solved(pair["candidate"])
    ]
    baseline_wall = math.fsum(pair["baseline"]["wall_time_s"] for pair in common)
    candidate_wall = math.fsum(pair["candidate"]["wall_time_s"] for pair in common)
    baseline_cpu = math.fsum(pair["baseline"]["cpu_time_s"] for pair in common)
    candidate_cpu = math.fsum(pair["candidate"]["cpu_time_s"] for pair in common)
    cpu_ratios = [
        pair["baseline"]["cpu_time_s"] / pair["candidate"]["cpu_time_s"]
        for pair in common
        if pair["baseline"]["cpu_time_s"] > 0.0
        and pair["candidate"]["cpu_time_s"] > 0.0
    ]
    return {
        "timeout_charged_wall": _ratio(baseline_timeout, candidate_timeout),
        "par2_wall": _ratio(baseline_par2, candidate_par2),
        "common_wall_total": _ratio(baseline_wall, candidate_wall),
        "common_wall_geometric": _geometric_mean(
            [
                pair["baseline"]["wall_time_s"]
                / pair["candidate"]["wall_time_s"]
                for pair in common
            ]
        ),
        "common_cpu_total": _ratio(baseline_cpu, candidate_cpu),
        "common_cpu_geometric": (
            _geometric_mean(cpu_ratios)
            if len(cpu_ratios) == len(common)
            else None
        ),
    }


def summarize_pairs(pairs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    baseline = _arm_summary(pairs, "baseline")
    candidate = _arm_summary(pairs, "candidate")
    both_solved = 0
    baseline_only = 0
    candidate_only = 0
    neither_solved = 0
    common: list[Mapping[str, Any]] = []
    for pair in pairs:
        baseline_solved = _is_solved(pair["baseline"])
        candidate_solved = _is_solved(pair["candidate"])
        if baseline_solved and candidate_solved:
            both_solved += 1
            common.append(pair)
        elif baseline_solved:
            baseline_only += 1
        elif candidate_solved:
            candidate_only += 1
        else:
            neither_solved += 1

    speedups = _speedup_metrics(pairs)
    return {
        "instances": len(pairs),
        "arms": {"baseline": baseline, "candidate": candidate},
        "coverage": {
            "both_solved": both_solved,
            "baseline_only": baseline_only,
            "candidate_only": candidate_only,
            "neither_solved": neither_solved,
            "candidate_minus_baseline": candidate["solved"] - baseline["solved"],
            "mcnemar": exact_mcnemar(baseline_only, candidate_only),
        },
        "common_solved": {
            "instances": len(common),
            "cpu_time_s": {
                "baseline": math.fsum(
                    pair["baseline"]["cpu_time_s"] for pair in common
                ),
                "candidate": math.fsum(
                    pair["candidate"]["cpu_time_s"] for pair in common
                ),
                "total_speedup": speedups["common_cpu_total"],
                "geometric_speedup": speedups["common_cpu_geometric"],
            },
            "wall_time_s": {
                "baseline": math.fsum(
                    pair["baseline"]["wall_time_s"] for pair in common
                ),
                "candidate": math.fsum(
                    pair["candidate"]["wall_time_s"] for pair in common
                ),
                "total_speedup": speedups["common_wall_total"],
                "geometric_speedup": speedups["common_wall_geometric"],
            },
        },
        "speedups": speedups,
    }


def family_cluster_bootstrap(
    pairs: Sequence[Mapping[str, Any]],
    *,
    seed: int,
    replicates: int,
    confidence_level: float,
) -> dict[str, Any]:
    """Percentile bootstrap that resamples whole declared families."""

    if not pairs:
        raise ValueError("family cluster bootstrap requires at least one pair")
    if isinstance(replicates, bool) or not isinstance(replicates, int) or replicates < 1:
        raise ValueError("replicates must be a positive integer")
    if not math.isfinite(confidence_level) or not 0.0 < confidence_level < 1.0:
        raise ValueError("confidence_level must be strictly between zero and one")

    clusters: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for pair in pairs:
        clusters[pair["family"]].append(pair)
    family_names = sorted(clusters)
    estimates = _speedup_metrics(pairs)
    samples: dict[str, list[float]] = {name: [] for name in BOOTSTRAP_METRICS}
    random_source = random.Random(seed)
    cluster_count = len(family_names)
    for _ in range(replicates):
        resample: list[Mapping[str, Any]] = []
        for _cluster in family_names:
            selected = family_names[random_source.randrange(cluster_count)]
            resample.extend(clusters[selected])
        metrics = _speedup_metrics(resample)
        for name in BOOTSTRAP_METRICS:
            value = metrics[name]
            if value is not None:
                samples[name].append(value)

    tail = (1.0 - confidence_level) / 2.0
    intervals = {
        name: {
            "estimate": estimates[name],
            "ci_lower": _quantile(samples[name], tail),
            "ci_upper": _quantile(samples[name], 1.0 - tail),
            "valid_replicates": len(samples[name]),
        }
        for name in BOOTSTRAP_METRICS
    }
    return {
        "cluster_count": cluster_count,
        "cluster_sizes": {
            family: len(clusters[family]) for family in family_names
        },
        "confidence_level": confidence_level,
        "interval_method": "percentile",
        "metrics": intervals,
        "replicates": replicates,
        "resampling_unit": "declared_family",
        "seed": seed,
    }


def holm_correction(
    p_values: Mapping[str, float], *, alpha: float = 0.05
) -> dict[str, Any]:
    """Apply deterministic Holm family-wise error correction by hypothesis name."""

    if not math.isfinite(alpha) or not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be strictly between zero and one")
    validated: list[tuple[float, str]] = []
    for name, value in p_values.items():
        if not isinstance(name, str) or not name:
            raise ValueError("hypothesis names must be non-empty strings")
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError(f"invalid p-value for {name!r}: {value!r}")
        validated.append((value, name))
    ordered = sorted(validated, key=lambda item: (item[0], item[1]))
    count = len(ordered)
    running_adjusted = 0.0
    continue_rejecting = True
    results: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for index, (p_value, name) in enumerate(ordered):
        multiplier = count - index
        adjusted = min(1.0, max(running_adjusted, multiplier * p_value))
        running_adjusted = adjusted
        threshold = alpha / multiplier
        rejected = continue_rejecting and p_value <= threshold
        if not rejected:
            continue_rejecting = False
        order.append(name)
        results[name] = {
            "adjusted_p_value": adjusted,
            "holm_threshold": threshold,
            "raw_p_value": p_value,
            "rejected": rejected,
            "rank": index + 1,
        }
    return {
        "alpha": alpha,
        "hypothesis_count": count,
        "method": "Holm",
        "order": order,
        "results": results,
    }


def _family_macro(families: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    names = sorted(families)
    arm_data: dict[str, dict[str, float]] = {}
    for label in LABELS:
        arm_data[label] = {
            "mean_family_coverage": math.fsum(
                families[name]["arms"][label]["coverage"] for name in names
            )
            / len(names),
            "mean_family_timeout_charged_wall_s_per_instance": math.fsum(
                families[name]["arms"][label]["timeout_charged_wall_s"]
                / families[name]["instances"]
                for name in names
            )
            / len(names),
            "mean_family_par2_wall_s_per_instance": math.fsum(
                families[name]["arms"][label]["par2_wall_s"]
                / families[name]["instances"]
                for name in names
            )
            / len(names),
        }

    common_total = [
        families[name]["speedups"]["common_wall_total"]
        for name in names
        if families[name]["speedups"]["common_wall_total"] is not None
    ]
    common_geometric = [
        families[name]["speedups"]["common_wall_geometric"]
        for name in names
        if families[name]["speedups"]["common_wall_geometric"] is not None
    ]
    coverage_deltas = [
        (
            families[name]["arms"]["candidate"]["coverage"]
            - families[name]["arms"]["baseline"]["coverage"],
            name,
        )
        for name in names
    ]
    worst_delta, worst_family = min(coverage_deltas, key=lambda item: (item[0], item[1]))
    return {
        "families": len(names),
        "arms": arm_data,
        "speedups": {
            "timeout_charged_wall": _ratio(
                arm_data["baseline"][
                    "mean_family_timeout_charged_wall_s_per_instance"
                ],
                arm_data["candidate"][
                    "mean_family_timeout_charged_wall_s_per_instance"
                ],
            ),
            "par2_wall": _ratio(
                arm_data["baseline"]["mean_family_par2_wall_s_per_instance"],
                arm_data["candidate"]["mean_family_par2_wall_s_per_instance"],
            ),
            "common_wall_total": _geometric_mean(common_total),
            "common_wall_geometric": _geometric_mean(common_geometric),
        },
        "worst_family_coverage_delta": {
            "candidate_minus_baseline": worst_delta,
            "family": worst_family,
        },
    }


def _non_regression_failures(
    summaries: Mapping[str, Mapping[str, Any]], group_type: str
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for name in sorted(summaries):
        summary = summaries[name]
        baseline_only = summary["coverage"]["baseline_only"]
        if baseline_only:
            failures.append(
                {
                    "actual": baseline_only,
                    "group": name,
                    "group_type": group_type,
                    "metric": "baseline_only_solves",
                    "required": 0,
                }
            )
        for metric in NON_REGRESSION_METRICS:
            value = summary["speedups"][metric]
            if value is not None and value < 1.0:
                failures.append(
                    {
                        "actual": value,
                        "group": name,
                        "group_type": group_type,
                        "metric": metric,
                        "required": 1.0,
                    }
                )
    return failures


def _macro_non_regression_failures(macro: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {"actual": value, "metric": metric, "required": 1.0}
        for metric, value in sorted(macro["speedups"].items())
        if value is not None and value < 1.0
    ]


def _check(
    passed: bool,
    *,
    actual: Any,
    operator: str,
    threshold: Any,
    details: Any | None = None,
) -> dict[str, Any]:
    result = {
        "actual": actual,
        "operator": operator,
        "passed": passed,
        "threshold": threshold,
    }
    if details is not None:
        result["details"] = details
    return result


def _budget_report(
    pairs: Sequence[Mapping[str, Any]],
    *,
    seed: int,
    bootstrap_replicates: int,
    confidence_level: float,
    minimum_speedup: float,
) -> dict[str, Any]:
    aggregate = summarize_pairs(pairs)
    status_groups = {
        status: summarize_pairs(
            [pair for pair in pairs if pair["expected_status"] == status]
        )
        for status in sorted(DECISIVE_RESULTS)
        if any(pair["expected_status"] == status for pair in pairs)
    }
    family_names = sorted({pair["family"] for pair in pairs})
    family_groups = {
        family: summarize_pairs([pair for pair in pairs if pair["family"] == family])
        for family in family_names
    }
    family_macro = _family_macro(family_groups)
    bootstrap = family_cluster_bootstrap(
        pairs,
        seed=seed,
        replicates=bootstrap_replicates,
        confidence_level=confidence_level,
    )

    invalid_count = sum(
        aggregate["arms"][label]["statuses"]["invalid"] for label in LABELS
    )
    error_count = sum(
        aggregate["arms"][label]["statuses"]["error"] for label in LABELS
    )
    status_failures = _non_regression_failures(status_groups, "expected_status")
    family_failures = _non_regression_failures(family_groups, "family")
    macro_failures = _macro_non_regression_failures(family_macro)
    checks = {
        "zero_invalid_results": _check(
            invalid_count == 0, actual=invalid_count, operator="==", threshold=0
        ),
        "zero_execution_errors": _check(
            error_count == 0, actual=error_count, operator="==", threshold=0
        ),
        "zero_coverage_loss": _check(
            aggregate["coverage"]["baseline_only"] == 0,
            actual=aggregate["coverage"]["baseline_only"],
            operator="==",
            threshold=0,
        ),
        "family_non_regression": _check(
            not family_failures,
            actual=len(family_failures),
            operator="==",
            threshold=0,
            details=family_failures,
        ),
        "status_non_regression": _check(
            not status_failures,
            actual=len(status_failures),
            operator="==",
            threshold=0,
            details=status_failures,
        ),
        "family_macro_non_regression": _check(
            not macro_failures,
            actual=len(macro_failures),
            operator="==",
            threshold=0,
            details=macro_failures,
        ),
    }
    for metric in REQUIRED_PROMOTION_METRICS:
        interval = bootstrap["metrics"][metric]
        lower = interval["ci_lower"]
        checks[f"{metric}_bootstrap_lower_bound"] = _check(
            lower is not None and lower > minimum_speedup,
            actual=lower,
            operator=">",
            threshold=minimum_speedup,
        )
    promoted = all(check["passed"] for check in checks.values())
    return {
        "aggregate": aggregate,
        "bootstrap": bootstrap,
        "families": family_groups,
        "family_macro": family_macro,
        "promotion": {
            "checks": checks,
            "passed": promoted,
            "status": "promoted" if promoted else "rejected",
        },
        "statuses": status_groups,
    }


def _format_budget(value: float) -> str:
    return format(value, ".17g")


def analyze_campaign(
    csv_path: Path,
    manifest_path: Path,
    *,
    baseline_binary: Path | None = None,
    candidate_binary: Path | None = None,
    seed: int = DEFAULT_SEED,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
    minimum_speedup: float = DEFAULT_MINIMUM_SPEEDUP,
    holm_alpha: float | None = None,
) -> dict[str, Any]:
    """Analyze a strict paired campaign and return a JSON-serializable report."""

    if isinstance(bootstrap_replicates, bool) or not isinstance(
        bootstrap_replicates, int
    ) or bootstrap_replicates < 1:
        raise ValueError("bootstrap_replicates must be a positive integer")
    if not math.isfinite(confidence_level) or not 0.0 < confidence_level < 1.0:
        raise ValueError("confidence_level must be strictly between zero and one")
    if not math.isfinite(minimum_speedup) or minimum_speedup <= 0.0:
        raise ValueError("minimum_speedup must be finite and positive")
    if holm_alpha is None:
        holm_alpha = 1.0 - confidence_level
    if not math.isfinite(holm_alpha) or not 0.0 < holm_alpha < 1.0:
        raise ValueError("holm_alpha must be strictly between zero and one")

    binary_paths = {
        label: path
        for label, path in (
            ("baseline", baseline_binary),
            ("candidate", candidate_binary),
        )
        if path is not None
    }
    campaign = load_campaign(
        csv_path, manifest_path, binary_paths=binary_paths
    )
    budget_reports: dict[str, dict[str, Any]] = {}
    hypotheses: dict[str, float] = {}
    for budget in campaign["budgets"]:
        budget_pairs = [
            pair for pair in campaign["pairs"] if pair["budget_s"] == budget
        ]
        report = _budget_report(
            budget_pairs,
            seed=seed,
            bootstrap_replicates=bootstrap_replicates,
            confidence_level=confidence_level,
            minimum_speedup=minimum_speedup,
        )
        budget_name = _format_budget(budget)
        budget_reports[budget_name] = {"budget_s": budget, **report}
        hypotheses[f"budget={budget_name}:coverage:overall"] = report["aggregate"][
            "coverage"
        ]["mcnemar"]["p_value"]
        for status, summary in report["statuses"].items():
            hypotheses[f"budget={budget_name}:coverage:status={status}"] = summary[
                "coverage"
            ]["mcnemar"]["p_value"]
        for family, summary in report["families"].items():
            hypotheses[f"budget={budget_name}:coverage:family={family}"] = summary[
                "coverage"
            ]["mcnemar"]["p_value"]

    failed_budgets = [
        budget
        for budget, report in budget_reports.items()
        if not report["promotion"]["passed"]
    ]
    promoted = not failed_budgets
    artifact_verification = campaign["artifact_verification"]
    verified_labels = [
        label for label in LABELS if artifact_verification[label]["verified"]
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "promoted" if promoted else "rejected",
        "promoted": promoted,
        "inputs": {
            "campaign_csv": str(csv_path),
            "manifest": str(manifest_path),
            "instances": len(campaign["manifest"]),
            "families": len(set(campaign["families"].values())),
            "budgets_s": campaign["budgets"],
            "artifact_verification": artifact_verification,
        },
        "input_hashes": {
            "campaign_csv_sha256": campaign["csv_sha256"],
            "manifest_sha256": campaign["manifest_sha256"],
            "instance_set_sha256": campaign["instance_set_sha256"],
            "binary_sha256": campaign["binary_sha256"],
        },
        "configuration": {
            "bootstrap_replicates": bootstrap_replicates,
            "confidence_level": confidence_level,
            "holm_alpha": holm_alpha,
            "minimum_speedup": minimum_speedup,
            "required_promotion_metrics": list(REQUIRED_PROMOTION_METRICS),
            "seed": seed,
        },
        "assumptions": {
            "binary_hash_verification": (
                "computed_for_supplied_artifacts"
                if len(verified_labels) == len(LABELS)
                else "row_declarations_only_for_unsupplied_artifacts"
            ),
            "coverage_precedes_speed": True,
            "family_identity_source": "required_csv_field_checked_against_manifest_when_present",
            "holm_scope": "all_named_budget_status_family_coverage_hypotheses",
            "mcnemar": "exact_conditional_two_sided_on_discordant_solve_pairs",
            "pairing_key": ["relative_path", "budget_s"],
            "par2_penalty": 2.0,
            "promotion_requires_stratum_non_regression": True,
            "ratio_direction": "baseline_over_candidate",
            "speed_time_basis": "wall_time_s",
            "timeout_charge_penalty": 1.0,
            "wrong_answers": "rejected_as_invalid_input_before_analysis",
        },
        "budgets": budget_reports,
        "hypotheses": holm_correction(hypotheses, alpha=holm_alpha),
        "promotion": {
            "failed_budgets": failed_budgets,
            "passed": promoted,
            "status": "promoted" if promoted else "rejected",
        },
    }


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _parse_json_strict(text: str, context: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise CampaignInputError([f"{context}: invalid JSON: {error}"]) from error


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise CampaignInputError([f"value is not canonical JSON: {error}"]) from error
    return (rendered + "\n").encode("utf-8")


def _same_json(left: Any, right: Any) -> bool:
    return _canonical_json_bytes(left) == _canonical_json_bytes(right)


def _require_exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CampaignInputError([f"{context}: must be an object"])
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing keys {missing!r}")
        if unknown:
            details.append(f"unknown keys {unknown!r}")
        raise CampaignInputError([f"{context}: " + " and ".join(details)])
    return value


def _require_string_value(value: Any, context: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise CampaignInputError([f"{context}: must be a non-empty string"])
    return value


def _require_hash_value(value: Any, context: str) -> str:
    digest = _require_string_value(value, context)
    if not _is_sha256(digest):
        raise CampaignInputError([f"{context}: must be a canonical SHA-256 digest"])
    return digest


def _require_int_value(value: Any, context: str, minimum: int | None = None) -> int:
    if type(value) is not int or (minimum is not None and value < minimum):
        qualifier = "an integer" if minimum is None else f"an integer >= {minimum}"
        raise CampaignInputError([f"{context}: must be {qualifier}"])
    return value


def _require_number_value(
    value: Any, context: str, minimum: float | None = None
) -> float:
    if type(value) not in {int, float} or not math.isfinite(value):
        raise CampaignInputError([f"{context}: must be a finite number"])
    result = float(value)
    if minimum is not None and result < minimum:
        raise CampaignInputError([f"{context}: must be at least {minimum}"])
    return result


def _read_json_object(path: Path, context: str) -> dict[str, Any]:
    try:
        _, content = strict_read_regular_nofollow(path, context)
        text = content.decode("utf-8")
    except (StrictArtifactError, UnicodeError) as error:
        raise CampaignInputError([f"cannot read {context} {path}: {error}"]) from error
    value = _parse_json_strict(text, f"{context} {path}")
    if type(value) is not dict:
        raise CampaignInputError([f"{context} {path}: root must be an object"])
    return value


def _load_lock_payload(payload: dict[str, Any], lock_path: Path) -> dict[str, Any]:
    has_continuation = "continuation" in payload
    has_run_selection = "run_selection" in payload
    expected_keys = LOCK_TOP_LEVEL_KEYS | {
        key
        for key in ("shard", "runtime_binding", "continuation", "run_selection")
        if key in payload
    }
    _require_exact_keys(payload, expected_keys, "campaign lock")
    expected_schema = 2 if has_continuation else 1
    if (
        payload["schema_version"] != expected_schema
        or type(payload["schema_version"]) is not int
    ):
        raise CampaignInputError(
            [f"campaign lock: schema_version must be integer {expected_schema}"]
        )
    _require_string_value(payload["campaign_id"], "campaign lock campaign_id")
    lock_sha256 = _require_hash_value(
        payload["lock_sha256"], "campaign lock lock_sha256"
    )
    unhashed = dict(payload)
    unhashed["lock_sha256"] = ""
    actual_lock_sha256 = hashlib.sha256(_canonical_json_bytes(unhashed)).hexdigest()
    if actual_lock_sha256 != lock_sha256:
        raise CampaignInputError(
            [
                "campaign lock hash mismatch: "
                f"declared {lock_sha256}, actual {actual_lock_sha256}"
            ]
        )
    if type(payload["promotion_eligible"]) is not bool:
        raise CampaignInputError(["campaign lock promotion_eligible must be boolean"])
    if "shard" in payload:
        shard = _require_exact_keys(payload["shard"], LOCK_SHARD_KEYS, "shard")
        index = _require_int_value(shard["index"], "shard.index", 0)
        count = _require_int_value(shard["count"], "shard.count", 1)
        if index >= count:
            raise CampaignInputError(["shard.index must be less than shard.count"])
        _require_hash_value(
            shard["parent_lock_sha256"], "shard.parent_lock_sha256"
        )
    if "runtime_binding" in payload:
        binding = _require_exact_keys(
            payload["runtime_binding"],
            LOCK_RUNTIME_BINDING_KEYS,
            "runtime_binding",
        )
        _require_hash_value(
            binding["parent_lock_sha256"],
            "runtime_binding.parent_lock_sha256",
        )
        if binding["mechanism"] != "first_allowed_slurm_cpu":
            raise CampaignInputError(["runtime_binding mechanism is not recognized"])
        cpu_ids = binding["cpu_ids"]
        if type(cpu_ids) is not list or not cpu_ids:
            raise CampaignInputError(["runtime_binding.cpu_ids must be non-empty"])
        for index, cpu_id in enumerate(cpu_ids):
            _require_int_value(cpu_id, f"runtime_binding.cpu_ids[{index}]", 0)

    if has_continuation != has_run_selection:
        raise CampaignInputError(
            ["continuation and run_selection must both be present or absent"]
        )

    release_lock = _require_exact_keys(
        payload["solver_release_lock"],
        LOCK_RELEASE_KEYS,
        "solver_release_lock",
    )
    _require_string_value(release_lock["path"], "solver_release_lock.path")
    _require_hash_value(
        release_lock["sha256"], "solver_release_lock.sha256"
    )

    corpus = _require_exact_keys(
        payload["corpus"], LOCK_CORPUS_KEYS, "campaign lock corpus"
    )
    _require_hash_value(corpus["manifest_sha256"], "corpus.manifest_sha256")
    taxonomy_path = corpus["taxonomy_path"]
    taxonomy_sha256 = corpus["taxonomy_sha256"]
    if taxonomy_path is None or taxonomy_sha256 is None:
        raise CampaignInputError(
            ["campaign lock requires a frozen family taxonomy for rigorous analysis"]
        )
    _require_string_value(taxonomy_path, "corpus.taxonomy_path")
    _require_hash_value(taxonomy_sha256, "corpus.taxonomy_sha256")
    instances = corpus["instances"]
    if type(instances) is not list or not instances:
        raise CampaignInputError(["campaign lock corpus.instances must be non-empty"])
    seen_instance_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, instance in enumerate(instances):
        context = f"corpus.instances[{index}]"
        if type(instance) is not dict:
            raise CampaignInputError([f"{context}: must be an object"])
        required = {
            "id",
            "relative_path",
            "path",
            "sha256",
            "bytes",
            "status",
            "family",
            "lineage",
            "normalized_sha256",
            "split",
        }
        _require_exact_keys(instance, required, context)
        identifier = _require_string_value(instance["id"], f"{context}.id")
        relative_path = _require_string_value(
            instance["relative_path"], f"{context}.relative_path"
        )
        try:
            _validate_relative_path(relative_path, context)
        except ValueError as error:
            raise CampaignInputError([str(error)]) from error
        if identifier in seen_instance_ids:
            raise CampaignInputError([f"duplicate locked instance id {identifier!r}"])
        if relative_path in seen_paths:
            raise CampaignInputError([f"duplicate locked path {relative_path!r}"])
        seen_instance_ids.add(identifier)
        seen_paths.add(relative_path)
        _require_hash_value(instance["sha256"], f"{context}.sha256")
        _require_hash_value(
            instance["normalized_sha256"], f"{context}.normalized_sha256"
        )
        _require_string_value(instance["family"], f"{context}.family")
        _require_string_value(instance["lineage"], f"{context}.lineage")
        if instance["status"] not in DECISIVE_RESULTS:
            raise CampaignInputError([f"{context}.status must be sat or unsat"])
        if instance["split"] not in {"dev", "development", "holdout"}:
            raise CampaignInputError(
                [f"{context}.split must be dev, development, or holdout"]
            )

    solvers = payload["solvers"]
    if type(solvers) is not list or len(solvers) < 2:
        raise CampaignInputError(["campaign lock requires at least two solvers"])
    seen_solver_ids: set[str] = set()
    for index, solver in enumerate(solvers):
        context = f"solvers[{index}]"
        solver_keys = LOCK_SOLVER_KEYS | (
            {"evidence"} if type(solver) is dict and "evidence" in solver else set()
        )
        _require_exact_keys(solver, solver_keys, context)
        identifier = _require_string_value(solver["id"], f"{context}.id")
        if identifier in seen_solver_ids:
            raise CampaignInputError([f"duplicate locked solver id {identifier!r}"])
        seen_solver_ids.add(identifier)
        _require_hash_value(solver["sha256"], f"{context}.sha256")
        _require_string_value(solver["version"], f"{context}.version")
        if type(solver["environment"]) is not dict or not all(
            type(key) is str and type(value) is str
            for key, value in solver["environment"].items()
        ):
            raise CampaignInputError([f"{context}.environment must map strings"])
        if type(solver["argv_template"]) is not list or not all(
            type(value) is str for value in solver["argv_template"]
        ):
            raise CampaignInputError([f"{context}.argv_template must be strings"])
        if "evidence" in solver:
            evidence = _require_exact_keys(
                solver["evidence"], LOCK_EVIDENCE_KEYS, f"{context}.evidence"
            )
            if evidence != {
                "schema": "euf-viper.production-evidence.v4",
                "argv_flag": "--evidence-out",
                "accepted_decisive_statuses": ["sat"],
            }:
                raise CampaignInputError(
                    [f"{context}.evidence has an unsupported production contract"]
                )
        if has_continuation and any(
            "{budget_s}" in argument for argument in solver["argv_template"]
        ):
            raise CampaignInputError(
                [
                    f"{context}.argv_template is budget-dependent; "
                    "timeout-only carry-forward is invalid"
                ]
            )
    if [solver["id"] for solver in solvers] != sorted(seen_solver_ids):
        raise CampaignInputError(["campaign lock solvers must be sorted by id"])

    target_budget: float | None = None
    if has_continuation:
        continuation = _require_exact_keys(
            payload["continuation"],
            LOCK_CONTINUATION_KEYS,
            "continuation",
        )
        if continuation["mode"] != "timeout_only":
            raise CampaignInputError(["continuation.mode must be timeout_only"])
        for field in (
            "root_lock_sha256",
            "parent_lock_file_sha256",
            "parent_lock_sha256",
            "shard_bundle_sha256",
            "source_evidence_sha256",
            "selection_sha256",
            "runner_sha256",
        ):
            _require_hash_value(continuation[field], f"continuation.{field}")
        for field in (
            "parent_lock_path",
            "shard_lock_directory",
            "shard_results_root",
            "runner_path",
        ):
            value = _require_string_value(
                continuation[field], f"continuation.{field}"
            )
            if not Path(value).is_absolute():
                raise CampaignInputError(
                    [f"continuation.{field} must be an absolute path"]
                )
        source_budget = _require_number_value(
            continuation["source_budget_s"], "continuation.source_budget_s", 0.001
        )
        target_budget = _require_number_value(
            continuation["target_budget_s"], "continuation.target_budget_s", 0.001
        )
        if target_budget <= source_budget:
            raise CampaignInputError(
                ["continuation target budget must exceed source budget"]
            )
        if continuation["source_evidence_sha256"] != continuation["shard_bundle_sha256"]:
            raise CampaignInputError(
                ["continuation source evidence and shard bundle hashes disagree"]
            )
        selected_instances = _require_int_value(
            continuation["selected_instances"],
            "continuation.selected_instances",
            1,
        )
        selected_runs = _require_int_value(
            continuation["selected_runs"], "continuation.selected_runs", 1
        )
        raw_selection = payload["run_selection"]
        if type(raw_selection) is not list or not raw_selection:
            raise CampaignInputError(["run_selection must be a non-empty array"])
        instance_ordinals = {
            instance["id"]: index for index, instance in enumerate(instances)
        }
        solver_ordinals = {
            solver["id"]: index for index, solver in enumerate(solvers)
        }
        canonical_selection: list[dict[str, str]] = []
        seen_run_pairs: set[tuple[str, str]] = set()
        selected_instance_ids: set[str] = set()
        previous_ordinal: tuple[int, int] | None = None
        for index, raw_item in enumerate(raw_selection):
            context = f"run_selection[{index}]"
            item = _require_exact_keys(raw_item, LOCK_RUN_SELECTION_KEYS, context)
            instance_id = _require_string_value(
                item["instance_id"], f"{context}.instance_id"
            )
            solver_id = _require_string_value(
                item["solver_id"], f"{context}.solver_id"
            )
            if instance_id not in instance_ordinals:
                raise CampaignInputError(
                    [f"{context}: unknown instance {instance_id!r}"]
                )
            if solver_id not in solver_ordinals:
                raise CampaignInputError([f"{context}: unknown solver {solver_id!r}"])
            pair = (instance_id, solver_id)
            if pair in seen_run_pairs:
                raise CampaignInputError([f"duplicate run_selection pair {pair!r}"])
            ordinal = (instance_ordinals[instance_id], solver_ordinals[solver_id])
            if previous_ordinal is not None and ordinal <= previous_ordinal:
                raise CampaignInputError(
                    ["run_selection must follow corpus instance and solver order"]
                )
            previous_ordinal = ordinal
            seen_run_pairs.add(pair)
            selected_instance_ids.add(instance_id)
            canonical_selection.append(
                {"instance_id": instance_id, "solver_id": solver_id}
            )
        if selected_runs != len(canonical_selection):
            raise CampaignInputError(
                ["continuation.selected_runs disagrees with run_selection"]
            )
        if selected_instances != len(selected_instance_ids):
            raise CampaignInputError(
                ["continuation.selected_instances disagrees with run_selection"]
            )
        if selected_instance_ids != set(instance_ordinals):
            raise CampaignInputError(
                ["every continuation corpus instance must have a selected run"]
            )
        selection_sha256 = hashlib.sha256(
            _canonical_json_bytes(canonical_selection)
        ).hexdigest()
        if selection_sha256 != continuation["selection_sha256"]:
            raise CampaignInputError(["continuation selection SHA-256 mismatch"])

    budgets = payload["budgets_s"]
    if type(budgets) is not list or not budgets:
        raise CampaignInputError(["campaign lock budgets_s must be non-empty"])
    numeric_budgets = [
        _require_number_value(value, f"budgets_s[{index}]", 0.001)
        for index, value in enumerate(budgets)
    ]
    if any(left >= right for left, right in zip(numeric_budgets, numeric_budgets[1:])):
        raise CampaignInputError(["campaign lock budgets_s must be strictly increasing"])
    if has_continuation and numeric_budgets != [target_budget]:
        raise CampaignInputError(
            ["continuation lock budgets_s must contain only target_budget_s"]
        )

    execution = _require_exact_keys(
        payload["execution"], LOCK_EXECUTION_KEYS, "campaign lock execution"
    )
    if execution["order"] not in {"abba", "balanced_latin_square"}:
        raise CampaignInputError(["campaign lock execution.order is invalid"])
    if execution["order"] == "abba" and len(solvers) != 2:
        raise CampaignInputError(["ABBA execution requires exactly two solvers"])
    if has_continuation and execution["order"] != "balanced_latin_square":
        raise CampaignInputError(
            ["continuation execution order must be balanced_latin_square"]
        )
    cpu_ids = execution["cpu_ids"]
    if type(cpu_ids) is not list or not cpu_ids:
        raise CampaignInputError(["campaign lock execution.cpu_ids must be non-empty"])
    for index, cpu_id in enumerate(cpu_ids):
        _require_int_value(cpu_id, f"execution.cpu_ids[{index}]", 0)
    if len(set(cpu_ids)) != len(cpu_ids):
        raise CampaignInputError(["campaign lock execution.cpu_ids must be unique"])
    if (
        "runtime_binding" in payload
        and payload["runtime_binding"]["cpu_ids"] != cpu_ids
    ):
        raise CampaignInputError(
            ["runtime_binding.cpu_ids must equal execution.cpu_ids"]
        )
    if type(execution["environment"]) is not dict or not all(
        type(key) is str and type(value) is str
        for key, value in execution["environment"].items()
    ):
        raise CampaignInputError(["execution.environment must map strings"])
    return payload


def _load_lock(lock_path: Path) -> dict[str, Any]:
    return _load_lock_payload(_read_json_object(lock_path, "campaign lock"), lock_path)


def _locked_solver_order(order: str, instance_index: int, solver_count: int) -> list[int]:
    if order == "abba":
        return [0, 1, 1, 0] if instance_index % 2 == 0 else [1, 0, 0, 1]
    offset = instance_index % solver_count
    return [(offset + position) % solver_count for position in range(solver_count)]


def _expand_locked_argv(
    template: Sequence[str], binary: str, instance: str, budget: Any
) -> list[str]:
    values = {
        "binary": binary,
        "instance": instance,
        "budget_s": str(budget),
    }
    try:
        return [argument.format_map(values) for argument in template]
    except (KeyError, ValueError) as error:
        raise CampaignInputError([f"invalid locked argv template: {error}"]) from error


def _locked_schedule(lock: Mapping[str, Any]) -> list[dict[str, Any]]:
    instances = lock["corpus"]["instances"]
    solvers = lock["solvers"]
    budgets = lock["budgets_s"]
    execution = lock["execution"]
    output_directory = Path(lock["output"]["directory"])
    selected_pairs = (
        {
            (item["instance_id"], item["solver_id"])
            for item in lock["run_selection"]
        }
        if "run_selection" in lock
        else None
    )
    schedule: list[dict[str, Any]] = []
    sequence = 0
    for instance_index, instance in enumerate(instances):
        cpu_id = execution["cpu_ids"][instance_index % len(execution["cpu_ids"])]
        order = _locked_solver_order(
            execution["order"], instance_index, len(solvers)
        )
        if selected_pairs is not None:
            order = [
                solver_index
                for solver_index in order
                if (instance["id"], solvers[solver_index]["id"]) in selected_pairs
            ]
        for budget in budgets:
            repetitions = {index: 0 for index in range(len(solvers))}
            for solver_index in order:
                solver = solvers[solver_index]
                environment = dict(execution["environment"])
                environment.update(solver["environment"])
                environment_sha256 = hashlib.sha256(
                    _canonical_json_bytes(environment)
                ).hexdigest()
                repetition = repetitions[solver_index]
                argv = _expand_locked_argv(
                    solver["argv_template"],
                    solver["binary"],
                    instance["path"],
                    budget,
                )
                evidence_path = None
                if "evidence" in solver:
                    evidence_path = (
                        output_directory
                        / "production-evidence"
                        / f"run-{sequence:08d}.json"
                    )
                    argv.extend([solver["evidence"]["argv_flag"], str(evidence_path)])
                schedule.append(
                    {
                        "sequence": sequence,
                        "key": {
                            "instance_id": instance["id"],
                            "solver_id": solver["id"],
                            "budget_s": budget,
                            "repetition": repetition,
                        },
                        "instance": instance,
                        "solver": solver,
                        "budget_s": budget,
                        "repetition": repetition,
                        "cpu_id": cpu_id,
                        "environment_sha256": environment_sha256,
                        "environment": environment,
                        "argv": argv,
                        "evidence_path": evidence_path,
                        "output_directory": output_directory,
                        "repository_revision": lock["repository"].get("commit", ""),
                    }
                )
                repetitions[solver_index] += 1
                sequence += 1
    return schedule


def _run_key_token(value: Mapping[str, Any]) -> bytes:
    return _canonical_json_bytes(value)


def _record_digest(record: Mapping[str, Any]) -> str:
    unhashed = dict(record)
    unhashed.pop("record_sha256", None)
    return hashlib.sha256(_canonical_json_bytes(unhashed)).hexdigest()


def _classify_locked_record(record: Mapping[str, Any]) -> str:
    if record["timed_out"]:
        return "timeout"
    if (
        record["spawn_error"] is not None
        or record["termination_cause"] in {"signal", "spawn_error"}
        or record["exit_code"] != 0
    ):
        return "error"
    if record["result_token_status"] != "valid":
        return "invalid"
    token = record["result_token"]
    if token in {"unknown", "unsupported"}:
        return token
    assert token in DECISIVE_RESULTS
    if (
        record["child_cpu_time_s"] is None
        or record["wall_time_s"] <= 0.0
    ):
        return "invalid"
    return token


def _expected_runtime_config(environment: Mapping[str, str]) -> dict[str, str]:
    controls = {
        "EUF_VIPER_RUN_NONCE",
        "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256",
    }
    config = {
        key: value
        for key, value in environment.items()
        if key.startswith("EUF_VIPER_") and key not in controls
    }
    for name, default, resolved in (
        ("EUF_VIPER_DIRECT_ROOT_CNF", "1", "resolved.direct_root_cnf"),
        ("EUF_VIPER_DIRECT_NEGATED_ROOT", "0", "resolved.direct_negated_root"),
    ):
        setting = environment.get(name, default)
        if setting not in {"0", "1"}:
            raise CampaignInputError([f"{name} is invalid in the locked environment"])
        config[resolved] = setting
    config.update(
        {
            "resolved.production_evidence_contract": "deterministic-cnf-transcript-v1",
            "resolved.production_evidence_mode": "cnf-assignment-transcript",
            "resolved.eq_abstraction": "off",
            "resolved.finite_domain": "off",
            "resolved.full_ackermann": "off",
            "resolved.chordal_transitivity": "off",
            "resolved.refinement_mode": "model-cuts",
        }
    )
    return dict(sorted(config.items()))


def _validate_locked_production_evidence(
    value: object,
    record: Mapping[str, Any],
    expected: Mapping[str, Any],
    context: str,
) -> dict[str, Any] | None:
    solver = expected["solver"]
    contract = solver.get("evidence")
    if contract is None:
        raise CampaignInputError([f"{context}: unexpected production evidence"])
    if value is None:
        if record["result_token"] in DECISIVE_RESULTS:
            raise CampaignInputError(
                [f"{context}: decisive result is missing production evidence"]
            )
        return None
    binding = _require_exact_keys(value, PRODUCTION_EVIDENCE_KEYS, context)
    expected_path = expected["evidence_path"]
    assert isinstance(expected_path, Path)
    output_directory = expected["output_directory"]
    assert isinstance(output_directory, Path)
    expected_relative = expected_path.relative_to(output_directory).as_posix()
    if binding["path"] != expected_relative:
        raise CampaignInputError([f"{context}: evidence path differs from schedule"])
    try:
        expected_path.relative_to(output_directory)
    except ValueError as error:
        raise CampaignInputError([f"{context}: evidence artifact escapes output root"]) from error
    evidence_sha256 = _require_hash_value(binding["sha256"], f"{context}.sha256")
    evidence_bytes = _require_int_value(binding["bytes"], f"{context}.bytes", 1)
    if binding["schema"] != contract["schema"]:
        raise CampaignInputError([f"{context}: evidence schema differs from lock"])
    if binding["source_sha256"] != expected["instance"]["sha256"]:
        raise CampaignInputError([f"{context}: evidence source hash differs from lock"])
    if binding["solver_revision"] != expected["repository_revision"]:
        raise CampaignInputError([f"{context}: evidence solver revision differs from lock"])
    if binding["solver_configuration"] != solver["configuration"]:
        raise CampaignInputError([f"{context}: evidence solver configuration differs from lock"])
    expected_solver_config_hash = hashlib.sha256(
        _canonical_json_bytes(solver)
    ).hexdigest()
    if binding["solver_config_sha256"] != expected_solver_config_hash:
        raise CampaignInputError([f"{context}: evidence solver config hash mismatch"])
    _require_hash_value(
        binding["solver_runtime_config_sha256"],
        f"{context}.solver_runtime_config_sha256",
    )
    if binding["solver_executable_sha256"] != solver["sha256"]:
        raise CampaignInputError([f"{context}: evidence executable hash differs from lock"])
    _require_hash_value(binding["solver_build_sha256"], f"{context}.solver_build_sha256")
    _require_hash_value(binding["run_nonce"], f"{context}.run_nonce")
    if (binding["status"], binding["backend_status"]) not in {
        ("sat", "sat"),
        ("unsupported", "sat"),
        ("unsupported", "unsat"),
        ("unsupported", "unsupported"),
    }:
        raise CampaignInputError([f"{context}: incoherent evidence statuses"])
    if record["result_token"] in DECISIVE_RESULTS and (
        record["result_token"] not in contract["accepted_decisive_statuses"]
        or binding["status"] != record["result_token"]
        or binding["backend_status"] != record["result_token"]
    ):
        raise CampaignInputError([f"{context}: evidence does not certify stdout"])

    source_path = Path(expected["instance"]["path"])
    expected_runtime = _expected_runtime_config(expected["environment"])
    try:
        checked = validate_production_evidence(
            expected_path,
            source_path,
            expected_source_sha256=expected["instance"]["sha256"],
            expected_revision=expected["repository_revision"],
            expected_status=(record["result_token"] if record["result_token"] == "sat" else None),
            expected_executable_sha256=solver["sha256"],
            expected_runtime_config=expected_runtime,
            expected_evidence_sha256=evidence_sha256,
            expected_run_nonce=binding["run_nonce"],
        )
    except (OSError, ProductionEvidenceError) as error:
        raise CampaignInputError(
            [f"{context}: independent production-evidence check failed: {error}"]
        ) from error
    checked_bindings = {
        "schema": binding["schema"],
        "status": binding["status"],
        "backend_status": binding["backend_status"],
        "run_nonce": binding["run_nonce"],
        "evidence_sha256": evidence_sha256,
        "evidence_bytes": evidence_bytes,
        "source_sha256": binding["source_sha256"],
        "solver_revision": binding["solver_revision"],
        "solver_executable_sha256": binding["solver_executable_sha256"],
        "solver_config_sha256": binding["solver_runtime_config_sha256"],
        "solver_build_sha256": binding["solver_build_sha256"],
    }
    for field, expected_value in checked_bindings.items():
        if checked.get(field) != expected_value:
            raise CampaignInputError(
                [f"{context}: checker binding mismatch for {field}"]
            )
    return dict(binding)


def _validate_locked_record(
    record: dict[str, Any],
    expected: Mapping[str, Any],
    lock_sha256: str,
    context: str,
) -> str:
    expected_record_keys = RUN_RECORD_KEYS | (
        {"production_evidence"} if "evidence" in expected["solver"] else set()
    )
    _require_exact_keys(record, expected_record_keys, context)
    if (
        record["record_type"] != "run"
        or type(record["schema_version"]) is not int
        or record["schema_version"] != 1
    ):
        raise CampaignInputError([f"{context}: invalid run record type or schema"])
    if record["lock_sha256"] != lock_sha256:
        raise CampaignInputError([f"{context}: lock SHA-256 mismatch"])
    _require_hash_value(record["record_sha256"], f"{context}.record_sha256")
    actual_record_sha256 = _record_digest(record)
    if record["record_sha256"] != actual_record_sha256:
        raise CampaignInputError(
            [
                f"{context}: record SHA-256 mismatch: declared "
                f"{record['record_sha256']}, actual {actual_record_sha256}"
            ]
        )
    _require_hash_value(
        record["previous_record_sha256"], f"{context}.previous_record_sha256"
    )
    _require_int_value(record["invocation"], f"{context}.invocation", 0)
    _require_int_value(record["sequence"], f"{context}.sequence", 0)
    _require_int_value(record["repetition"], f"{context}.repetition", 0)
    if not _same_json(record["key"], expected["key"]):
        raise CampaignInputError([f"{context}: locked run key mismatch"])

    instance = expected["instance"]
    solver = expected["solver"]
    expected_static = {
        "sequence": expected["sequence"],
        "instance_id": instance["id"],
        "relative_path": instance["relative_path"],
        "instance_sha256": instance["sha256"],
        "expected_status": instance["status"],
        "family": instance["family"],
        "solver_id": solver["id"],
        "solver_sha256": solver["sha256"],
        "solver_version": solver["version"],
        "budget_s": expected["budget_s"],
        "repetition": expected["repetition"],
        "cpu_id": expected["cpu_id"],
        "argv": expected["argv"],
        "environment_sha256": expected["environment_sha256"],
    }
    for field, value in expected_static.items():
        if not _same_json(record[field], value):
            raise CampaignInputError([f"{context}: locked field {field!r} mismatch"])

    descriptor_binding = _require_exact_keys(
        record["descriptor_binding"],
        {"mechanism", "solver_sha256", "source_sha256"},
        f"{context}.descriptor_binding",
    )
    if descriptor_binding["mechanism"] not in {
        "linux_procfd",
        "platform_pathname",
    }:
        raise CampaignInputError(
            [f"{context}.descriptor_binding: unsupported execution mechanism"]
        )
    _require_hash_value(
        descriptor_binding["solver_sha256"],
        f"{context}.descriptor_binding.solver_sha256",
    )
    _require_hash_value(
        descriptor_binding["source_sha256"],
        f"{context}.descriptor_binding.source_sha256",
    )
    if (
        descriptor_binding["solver_sha256"] != solver["sha256"]
        or descriptor_binding["source_sha256"] != instance["sha256"]
    ):
        raise CampaignInputError(
            [f"{context}.descriptor_binding: source or solver hash mismatch"]
        )
    if "evidence" in solver and descriptor_binding["mechanism"] != "linux_procfd":
        raise CampaignInputError(
            [f"{context}.descriptor_binding: production execution was not descriptor-bound"]
        )

    for field in ("started_at", "finished_at"):
        _require_string_value(record[field], f"{context}.{field}")
    _require_number_value(record["wall_time_s"], f"{context}.wall_time_s", 0.0)
    for field in (
        "child_user_time_s",
        "child_system_time_s",
        "child_cpu_time_s",
    ):
        if record[field] is not None:
            _require_number_value(record[field], f"{context}.{field}", 0.0)
    if record["max_rss_bytes"] is not None:
        _require_int_value(record["max_rss_bytes"], f"{context}.max_rss_bytes", 0)
    for field in ("pid", "exit_code", "termination_signal"):
        if record[field] is not None and type(record[field]) is not int:
            raise CampaignInputError([f"{context}.{field} must be integer or null"])
    if record["termination_cause"] not in {
        "exit",
        "signal",
        "timeout",
        "spawn_error",
    }:
        raise CampaignInputError([f"{context}: invalid termination_cause"])
    if type(record["timed_out"]) is not bool:
        raise CampaignInputError([f"{context}.timed_out must be boolean"])
    if record["timed_out"] != (record["termination_cause"] == "timeout"):
        raise CampaignInputError([f"{context}: timeout fields disagree"])
    if (record["spawn_error"] is not None) != (
        record["termination_cause"] == "spawn_error"
    ):
        raise CampaignInputError([f"{context}: spawn_error fields disagree"])
    if record["spawn_error"] is not None:
        _require_string_value(record["spawn_error"], f"{context}.spawn_error")
    for field in ("stdout_sha256", "stderr_sha256", "environment_sha256"):
        _require_hash_value(record[field], f"{context}.{field}")
    for field in ("stdout_bytes", "stderr_bytes"):
        _require_int_value(record[field], f"{context}.{field}", 0)
    if record["result_token"] is not None and record["result_token"] not in {
        "sat",
        "unsat",
        "unknown",
        "unsupported",
    }:
        raise CampaignInputError([f"{context}: invalid result token"])
    if record["result_token_status"] not in {"valid", "missing", "malformed"}:
        raise CampaignInputError([f"{context}: invalid result token status"])
    if (record["result_token"] is None) == (
        record["result_token_status"] == "valid"
    ):
        raise CampaignInputError([f"{context}: result token fields disagree"])
    if (
        record["result_token"] in DECISIVE_RESULTS
        and record["result_token"] != record["expected_status"]
    ):
        raise CampaignInputError(
            [
                f"{context}: wrong answer: expected {record['expected_status']!r}, "
                f"got {record['result_token']!r}"
            ]
        )
    if "evidence" in solver:
        _validate_locked_production_evidence(
            record["production_evidence"],
            record,
            expected,
            f"{context}.production_evidence",
        )
    return _classify_locked_record(record)


def _load_locked_runs(
    raw_bytes: bytes,
    raw_path: Path,
    lock: Mapping[str, Any],
    schedule: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    try:
        lines = raw_bytes.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise CampaignInputError([f"cannot read locked raw results {raw_path}: {error}"]) from error
    if not lines:
        raise CampaignInputError([f"{raw_path}: contains no run records"])
    expected_by_key = {_run_key_token(item["key"]): item for item in schedule}
    records_by_key: dict[bytes, dict[str, Any]] = {}
    classifications: dict[bytes, str] = {}
    errors: list[str] = []
    previous_valid_record: dict[str, Any] | None = None
    for line_number, line in enumerate(lines, start=1):
        context = f"{raw_path}:{line_number}"
        if not line.strip():
            errors.append(f"{context}: blank records are forbidden")
            continue
        try:
            value = _parse_json_strict(line, context)
            if type(value) is not dict:
                raise CampaignInputError([f"{context}: run record must be an object"])
            key = value.get("key")
            if type(key) is not dict:
                raise CampaignInputError([f"{context}: run key must be an object"])
            token = _run_key_token(key)
            if token in records_by_key:
                raise CampaignInputError([f"{context}: duplicate run key {key!r}"])
            expected = expected_by_key.get(token)
            if expected is None:
                raise CampaignInputError([f"{context}: run key is not in locked schedule"])
            classification = _validate_locked_record(
                value, expected, lock["lock_sha256"], context
            )
            if value["sequence"] != line_number - 1:
                raise CampaignInputError(
                    [
                        f"{context}: raw record order mismatch: sequence "
                        f"{value['sequence']}, expected {line_number - 1}"
                    ]
                )
            if (
                previous_valid_record is not None
                and value["invocation"] == previous_valid_record["invocation"]
                and value["previous_record_sha256"]
                != previous_valid_record["record_sha256"]
            ):
                raise CampaignInputError(
                    [f"{context}: broken record hash chain within invocation"]
                )
            records_by_key[token] = value
            classifications[token] = classification
            previous_valid_record = value
        except CampaignInputError as error:
            errors.extend(error.errors)

    missing = [
        item["key"]
        for item in schedule
        if _run_key_token(item["key"]) not in records_by_key
    ]
    if missing:
        errors.append(
            f"{raw_path}: incomplete locked campaign: missing_keys={len(missing)}; "
            f"first={missing[:10]!r}"
        )
    if len(records_by_key) != len(schedule):
        errors.append(
            f"{raw_path}: run count mismatch: actual={len(records_by_key)}, "
            f"expected={len(schedule)}"
        )
    if errors:
        raise CampaignInputError(errors)

    ordered: list[dict[str, Any]] = []
    for item in schedule:
        token = _run_key_token(item["key"])
        record = dict(records_by_key[token])
        record["analysis_result"] = classifications[token]
        ordered.append(record)
    return ordered


def _aggregate_locked_observation(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not records:
        raise ValueError("cannot aggregate an empty locked observation")
    classifications = [record["analysis_result"] for record in records]
    result = classifications[0] if len(set(classifications)) == 1 else "invalid"
    expected = records[0]["expected_status"]
    if result in DECISIVE_RESULTS and result != expected:
        raise AssertionError("wrong answers must be rejected before aggregation")
    cpu_values = [
        float(record["child_cpu_time_s"])
        for record in records
        if record["child_cpu_time_s"] is not None
    ]
    if result in DECISIVE_RESULTS and len(cpu_values) != len(records):
        result = "invalid"
    cpu_time_s = _quantile(cpu_values, 0.5) if cpu_values else 0.0
    wall_time_s = _quantile(
        [float(record["wall_time_s"]) for record in records], 0.5
    )
    assert cpu_time_s is not None and wall_time_s is not None
    observation = {
        "relative_path": records[0]["relative_path"],
        "family": records[0]["family"],
        "expected_status": expected,
        "budget_s": float(records[0]["budget_s"]),
        "binary_sha256": records[0]["solver_sha256"],
        "result": result,
        "cpu_time_s": cpu_time_s,
        "wall_time_s": wall_time_s,
        "repetitions": len(records),
        "origin_budget_s": float(records[0]["budget_s"]),
        "carried_forward": False,
        "source_lock_sha256": records[0]["lock_sha256"],
        "source_record_sha256": [record["record_sha256"] for record in records],
    }
    if all("production_evidence" in record for record in records):
        observation["production_evidence"] = [
            record["production_evidence"] for record in records
        ]
    return observation


def load_locked_campaign(lock_path: Path, raw_path: Path) -> dict[str, Any]:
    """Validate a runner lock/raw pair and aggregate locked repetitions."""

    try:
        lock_path, lock_bytes = strict_read_regular_nofollow(lock_path, "campaign lock")
        raw_path, raw_bytes = strict_read_regular_nofollow(raw_path, "locked raw results")
        lock_file_sha256 = hashlib.sha256(lock_bytes).hexdigest()
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        lock_value = _parse_json_strict(
            lock_bytes.decode("utf-8"), f"campaign lock {lock_path}"
        )
    except (StrictArtifactError, UnicodeError) as error:
        raise CampaignInputError([f"cannot hash locked campaign input: {error}"]) from error
    if type(lock_value) is not dict:
        raise CampaignInputError([f"campaign lock {lock_path}: root must be an object"])
    lock = _load_lock_payload(lock_value, lock_path)
    schedule = _locked_schedule(lock)
    runs = _load_locked_runs(raw_bytes, raw_path, lock, schedule)
    grouped: dict[tuple[str, float, str], list[dict[str, Any]]] = defaultdict(list)
    for record in runs:
        grouped[
            (
                record["relative_path"],
                float(record["budget_s"]),
                record["solver_id"],
            )
        ].append(record)
    observations = {
        key: _aggregate_locked_observation(
            sorted(records, key=lambda record: record["repetition"])
        )
        for key, records in grouped.items()
    }
    for observation in observations.values():
        observation["source_raw_sha256"] = raw_sha256
    return {
        "lock": lock,
        "lock_file_sha256": lock_file_sha256,
        "observations": observations,
        "raw_records": len(runs),
        "raw_sha256": raw_sha256,
    }


def _lock_sha256(payload: Mapping[str, Any]) -> str:
    unhashed = dict(payload)
    unhashed["lock_sha256"] = ""
    return hashlib.sha256(_canonical_json_bytes(unhashed)).hexdigest()


def _expected_prepared_shard(
    parent: Mapping[str, Any], index: int, count: int
) -> dict[str, Any]:
    instances = parent["corpus"]["instances"]
    selected = [
        instance
        for position, instance in enumerate(instances)
        if position % count == index
    ]
    if not selected:
        raise CampaignInputError([f"shard {index} is empty"])
    selected_ids = {instance["id"] for instance in selected}
    selected_runs = None
    if "run_selection" in parent:
        selected_runs = [
            item
            for item in parent["run_selection"]
            if item["instance_id"] in selected_ids
        ]
        if not selected_runs:
            raise CampaignInputError([f"shard {index} has no selected runs"])
    shard = {
        **parent,
        "lock_sha256": "",
        "promotion_eligible": parent["promotion_eligible"],
        "corpus": {**parent["corpus"], "instances": selected},
        "output": {
            **parent["output"],
            "directory": str(
                Path(parent["output"]["directory"]) / f"shard-{index:04d}"
            ),
        },
        "shard": {
            "index": index,
            "count": count,
            "parent_lock_sha256": parent["lock_sha256"],
        },
    }
    if selected_runs is not None:
        shard["run_selection"] = selected_runs
        shard["continuation"] = {
            **parent["continuation"],
            "selection_sha256": hashlib.sha256(
                _canonical_json_bytes(selected_runs)
            ).hexdigest(),
            "selected_instances": len(selected),
            "selected_runs": len(selected_runs),
        }
    shard["lock_sha256"] = _lock_sha256(shard)
    return shard


def _recover_prepared_shard(bound: Mapping[str, Any], context: str) -> dict[str, Any]:
    if "shard" not in bound or "runtime_binding" not in bound:
        raise CampaignInputError(
            [f"{context}: shard and runtime_binding metadata are required"]
        )
    runtime_parent = bound["runtime_binding"]["parent_lock_sha256"]
    prepared = dict(bound)
    prepared.pop("runtime_binding")
    prepared["execution"] = {**prepared["execution"], "cpu_ids": [0]}
    prepared["lock_sha256"] = ""
    actual = _lock_sha256(prepared)
    if actual != runtime_parent:
        raise CampaignInputError(
            [
                f"{context}: runtime binding parent hash mismatch: "
                f"declared {runtime_parent}, reconstructed {actual}"
            ]
        )
    prepared["lock_sha256"] = actual
    return prepared


def load_sharded_locked_campaign(
    parent_lock_path: Path,
    shard_pairs: Sequence[tuple[Path, Path]],
) -> dict[str, Any]:
    """Validate an exact shard partition and combine its observations."""

    if not shard_pairs:
        raise CampaignInputError(["sharded campaign contains no shard pairs"])
    parent = _load_lock(parent_lock_path)
    if "shard" in parent or "runtime_binding" in parent:
        raise CampaignInputError(["parent lock cannot itself be a shard or bound lock"])
    parent_file_sha256 = sha256_file(parent_lock_path)

    observations: dict[tuple[str, float, str], dict[str, Any]] = {}
    provenance: list[dict[str, Any]] = []
    seen_indices: set[int] = set()
    declared_count: int | None = None
    raw_records = 0
    for lock_path, raw_path in shard_pairs:
        shard_campaign = load_locked_campaign(lock_path, raw_path)
        bound = shard_campaign["lock"]
        context = f"shard lock {lock_path}"
        if "shard" not in bound or "runtime_binding" not in bound:
            raise CampaignInputError(
                [f"{context}: expected a runtime-bound shard lock"]
            )
        index = bound["shard"]["index"]
        count = bound["shard"]["count"]
        if declared_count is None:
            declared_count = count
        elif count != declared_count:
            raise CampaignInputError(
                [f"{context}: shard count {count} disagrees with {declared_count}"]
            )
        if index in seen_indices:
            raise CampaignInputError([f"duplicate shard index {index}"])
        seen_indices.add(index)

        expected = _expected_prepared_shard(parent, index, count)
        prepared = _recover_prepared_shard(bound, context)
        if not _same_json(prepared, expected):
            raise CampaignInputError(
                [f"{context}: shard is not the exact derivation of the parent lock"]
            )

        for key, observation in shard_campaign["observations"].items():
            if key in observations:
                raise CampaignInputError(
                    [f"{context}: duplicate global observation key {key!r}"]
                )
            observations[key] = observation
        raw_records += shard_campaign["raw_records"]
        provenance.append(
            {
                "index": index,
                "lock": str(lock_path),
                "lock_file_sha256": shard_campaign["lock_file_sha256"],
                "lock_sha256": bound["lock_sha256"],
                "raw": str(raw_path),
                "raw_sha256": shard_campaign["raw_sha256"],
                "raw_records": shard_campaign["raw_records"],
                "cpu_ids": bound["execution"]["cpu_ids"],
            }
        )

    assert declared_count is not None
    expected_indices = set(range(declared_count))
    if seen_indices != expected_indices:
        missing = sorted(expected_indices - seen_indices)
        extra = sorted(seen_indices - expected_indices)
        raise CampaignInputError(
            [f"shard partition is incomplete: missing={missing}, extra={extra}"]
        )

    expected_observations = (
        len(parent["run_selection"]) * len(parent["budgets_s"])
        if "run_selection" in parent
        else len(parent["corpus"]["instances"])
        * len(parent["solvers"])
        * len(parent["budgets_s"])
    )
    if len(observations) != expected_observations:
        raise CampaignInputError(
            [
                "global observation count mismatch: "
                f"actual={len(observations)}, expected={expected_observations}"
            ]
        )
    provenance.sort(key=lambda item: item["index"])
    content_manifest = [
        {
            "index": item["index"],
            "lock_file_sha256": item["lock_file_sha256"],
            "lock_sha256": item["lock_sha256"],
            "raw_sha256": item["raw_sha256"],
            "raw_records": item["raw_records"],
            "cpu_ids": item["cpu_ids"],
        }
        for item in provenance
    ]
    bundle_sha256 = hashlib.sha256(
        _canonical_json_bytes(
            {
                "parent_lock_sha256": parent["lock_sha256"],
                "shards": content_manifest,
            }
        )
    ).hexdigest()
    return {
        "lock": parent,
        "lock_file_sha256": parent_file_sha256,
        "observations": observations,
        "raw_records": raw_records,
        "shards": provenance,
        "shard_bundle_sha256": bundle_sha256,
    }


def _comparison_pairs(
    campaign: Mapping[str, Any], candidate_id: str, baseline_id: str, budget: float
) -> list[dict[str, Any]]:
    pairs = []
    for instance in campaign["lock"]["corpus"]["instances"]:
        relative_path = instance["relative_path"]
        baseline = campaign["observations"][(relative_path, budget, baseline_id)]
        candidate = campaign["observations"][(relative_path, budget, candidate_id)]
        pairs.append(
            {
                "relative_path": relative_path,
                "family": instance["family"],
                "expected_status": instance["status"],
                "budget_s": budget,
                "baseline": baseline,
                "candidate": candidate,
            }
        )
    return pairs


def _add_coverage_hypotheses(
    target: dict[str, float], prefix: str, report: Mapping[str, Any]
) -> None:
    target[f"{prefix}:coverage:overall"] = report["aggregate"]["coverage"][
        "mcnemar"
    ]["p_value"]
    for status, summary in report["statuses"].items():
        target[f"{prefix}:coverage:status={status}"] = summary["coverage"][
            "mcnemar"
        ]["p_value"]
    for family, summary in report["families"].items():
        target[f"{prefix}:coverage:family={family}"] = summary["coverage"][
            "mcnemar"
        ]["p_value"]


def _analyze_loaded_locked_campaign(
    campaign: Mapping[str, Any],
    source_inputs: Mapping[str, Any],
    source_hashes: Mapping[str, Any],
    *,
    candidate_id: str = "euf-viper",
    baseline_ids: Sequence[str] | None = None,
    seed: int = DEFAULT_SEED,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
    minimum_speedup: float = DEFAULT_MINIMUM_SPEEDUP,
    holm_alpha: float | None = None,
) -> dict[str, Any]:
    """Analyze already validated locked observations."""

    if "run_selection" in campaign["lock"]:
        raise CampaignInputError(
            [
                "sparse continuation evidence must be assembled with its parent "
                "before comparative analysis"
            ]
        )

    if isinstance(bootstrap_replicates, bool) or not isinstance(
        bootstrap_replicates, int
    ) or bootstrap_replicates < 1:
        raise ValueError("bootstrap_replicates must be a positive integer")
    if not math.isfinite(confidence_level) or not 0.0 < confidence_level < 1.0:
        raise ValueError("confidence_level must be strictly between zero and one")
    if not math.isfinite(minimum_speedup) or minimum_speedup <= 0.0:
        raise ValueError("minimum_speedup must be finite and positive")
    if holm_alpha is None:
        holm_alpha = 1.0 - confidence_level
    if not math.isfinite(holm_alpha) or not 0.0 < holm_alpha < 1.0:
        raise ValueError("holm_alpha must be strictly between zero and one")

    lock = campaign["lock"]
    solvers = {solver["id"]: solver for solver in lock["solvers"]}
    if candidate_id not in solvers:
        raise CampaignInputError([f"candidate solver {candidate_id!r} is not in lock"])
    if baseline_ids is None:
        selected_baselines = sorted(set(solvers) - {candidate_id})
    else:
        selected_baselines = list(baseline_ids)
    if not selected_baselines:
        raise CampaignInputError(["at least one baseline solver is required"])
    if len(set(selected_baselines)) != len(selected_baselines):
        raise CampaignInputError(["baseline solver ids must be unique"])
    for baseline_id in selected_baselines:
        if baseline_id == candidate_id:
            raise CampaignInputError(["candidate cannot also be a baseline"])
        if baseline_id not in solvers:
            raise CampaignInputError([f"baseline solver {baseline_id!r} is not in lock"])

    hypotheses: dict[str, float] = {}
    comparisons: dict[str, dict[str, Any]] = {}
    budgets = [float(value) for value in lock["budgets_s"]]
    for baseline_id in selected_baselines:
        budget_reports: dict[str, dict[str, Any]] = {}
        for budget in budgets:
            pairs = _comparison_pairs(campaign, candidate_id, baseline_id, budget)
            report = _budget_report(
                pairs,
                seed=seed,
                bootstrap_replicates=bootstrap_replicates,
                confidence_level=confidence_level,
                minimum_speedup=minimum_speedup,
            )
            budget_name = _format_budget(budget)
            budget_reports[budget_name] = {"budget_s": budget, **report}
            _add_coverage_hypotheses(
                hypotheses,
                f"baseline={baseline_id}:budget={budget_name}",
                report,
            )
        failed_budgets = [
            name
            for name, report in budget_reports.items()
            if not report["promotion"]["passed"]
        ]
        comparisons[baseline_id] = {
            "baseline_id": baseline_id,
            "candidate_id": candidate_id,
            "budgets": budget_reports,
            "promotion": {
                "failed_budgets": failed_budgets,
                "passed": not failed_budgets,
                "status": "promoted" if not failed_budgets else "rejected",
            },
        }

    failed_comparisons = [
        name
        for name, comparison in comparisons.items()
        if not comparison["promotion"]["passed"]
    ]
    promotion_eligible = lock["promotion_eligible"]
    promoted = promotion_eligible and not failed_comparisons
    solver_hashes = {
        solver_id: solvers[solver_id]["sha256"]
        for solver_id in [candidate_id, *selected_baselines]
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "promoted" if promoted else "rejected",
        "promoted": promoted,
        "inputs": {
            **source_inputs,
            "campaign_id": lock["campaign_id"],
            "instances": len(lock["corpus"]["instances"]),
            "families": len(
                {instance["family"] for instance in lock["corpus"]["instances"]}
            ),
            "budgets_s": budgets,
            "raw_records": campaign["raw_records"],
            "candidate_id": candidate_id,
            "baseline_ids": selected_baselines,
        },
        "input_hashes": {
            **source_hashes,
            "lock_sha256": lock["lock_sha256"],
            "manifest_sha256": lock["corpus"]["manifest_sha256"],
            "taxonomy_sha256": lock["corpus"]["taxonomy_sha256"],
            "solver_binary_sha256": solver_hashes,
        },
        "configuration": {
            "bootstrap_replicates": bootstrap_replicates,
            "confidence_level": confidence_level,
            "holm_alpha": holm_alpha,
            "minimum_speedup": minimum_speedup,
            "required_promotion_metrics": list(REQUIRED_PROMOTION_METRICS),
            "seed": seed,
        },
        "assumptions": {
            "coverage_precedes_speed": True,
            "family_identity_source": "hash_bound_campaign_lock",
            "holm_scope": "all_named_comparator_budget_status_family_coverage_hypotheses",
            "mcnemar": "exact_conditional_two_sided_on_discordant_solve_pairs",
            "pairing_key": ["instance_id", "budget_s", "solver_id"],
            "par2_penalty": 2.0,
            "promotion_requires_stratum_non_regression": True,
            "ratio_direction": "baseline_comparator_over_candidate",
            "repetition_aggregation": "per_instance_median_after_status_consistency_check",
            "speed_time_basis": "wall_time_s",
            "timeout_charge_penalty": 1.0,
            "wrong_answers": "rejected_as_invalid_input_before_analysis",
        },
        "comparisons": comparisons,
        "hypotheses": holm_correction(hypotheses, alpha=holm_alpha),
        "promotion": {
            "failed_comparisons": failed_comparisons,
            "lock_promotion_eligible": promotion_eligible,
            "passed": promoted,
            "status": "promoted" if promoted else "rejected",
        },
    }


def analyze_locked_campaign(
    lock_path: Path,
    raw_path: Path,
    **options: Any,
) -> dict[str, Any]:
    """Analyze one complete unsharded or individual-shard campaign."""

    campaign = load_locked_campaign(lock_path, raw_path)
    return _analyze_loaded_locked_campaign(
        campaign,
        {"lock": str(lock_path), "raw": str(raw_path)},
        {
            "lock_file_sha256": campaign["lock_file_sha256"],
            "raw_sha256": campaign["raw_sha256"],
        },
        **options,
    )


def analyze_sharded_locked_campaign(
    parent_lock_path: Path,
    shard_pairs: Sequence[tuple[Path, Path]],
    **options: Any,
) -> dict[str, Any]:
    """Analyze a globally complete, provenance-checked sharded campaign."""

    campaign = load_sharded_locked_campaign(parent_lock_path, shard_pairs)
    return _analyze_loaded_locked_campaign(
        campaign,
        {
            "parent_lock": str(parent_lock_path),
            "shards": campaign["shards"],
        },
        {
            "lock_file_sha256": campaign["lock_file_sha256"],
            "shard_bundle_sha256": campaign["shard_bundle_sha256"],
            "shard_lock_file_sha256": {
                str(item["index"]): item["lock_file_sha256"]
                for item in campaign["shards"]
            },
            "shard_raw_sha256": {
                str(item["index"]): item["raw_sha256"]
                for item in campaign["shards"]
            },
        },
        **options,
    )


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def _positive_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(value) or value <= 0.0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return value


def _probability(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(value) or not 0.0 < value < 1.0:
        raise argparse.ArgumentTypeError("must be strictly between zero and one")
    return value


def _json_text(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True
    ) + "\n"


def _emit_json(payload: Mapping[str, Any], output: Path | None) -> None:
    text = _json_text(payload)
    if output is None:
        sys.stdout.write(text)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


def _safe_hash(path: Path) -> str | None:
    try:
        return sha256_file(path)
    except OSError:
        return None


def discover_shard_pairs(
    lock_directory: Path, results_directory: Path
) -> list[tuple[Path, Path]]:
    """Discover the strict bound-NNNN/raw shard layout used by WMI."""

    try:
        lock_paths = sorted(lock_directory.glob("bound-*.json"))
    except OSError as error:
        raise CampaignInputError(
            [f"cannot enumerate shard lock directory {lock_directory}: {error}"]
        ) from error
    if not lock_paths:
        raise CampaignInputError(
            [f"shard lock directory contains no bound locks: {lock_directory}"]
        )
    pairs: list[tuple[Path, Path]] = []
    seen_names: set[str] = set()
    for lock_path in lock_paths:
        suffix = lock_path.stem.removeprefix("bound-")
        if len(suffix) != 4 or not suffix.isascii() or not suffix.isdigit():
            raise CampaignInputError(
                [f"invalid bound shard lock filename: {lock_path.name}"]
            )
        if suffix in seen_names:
            raise CampaignInputError([f"duplicate shard lock suffix {suffix}"])
        seen_names.add(suffix)
        raw_path = results_directory / f"shard-{suffix}" / "raw.jsonl"
        if not raw_path.is_file():
            raise CampaignInputError([f"missing shard raw results: {raw_path}"])
        pairs.append((lock_path, raw_path))
    return pairs


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze locked raw JSONL or normalized paired CSV evidence and "
            "adjudicate P0 promotion."
        )
    )
    parser.add_argument(
        "results",
        type=Path,
        nargs="?",
        help="raw JSONL or normalized paired CSV (omitted for sharded input)",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--lock", type=Path, help="self-hashed runner campaign lock")
    source.add_argument("--manifest", type=Path, help="exact manifest for CSV import")
    source.add_argument(
        "--parent-lock", type=Path, help="self-hashed parent lock for shard analysis"
    )
    parser.add_argument(
        "--shard-lock-dir", type=Path, help="directory containing bound-NNNN.json"
    )
    parser.add_argument(
        "--shard-results-root",
        type=Path,
        help="directory containing shard-NNNN/raw.jsonl",
    )
    parser.add_argument("--candidate", default="euf-viper", help="locked candidate solver id")
    parser.add_argument(
        "--baseline", action="append", default=[], help="locked comparator solver id"
    )
    parser.add_argument("--baseline-binary", type=Path)
    parser.add_argument("--candidate-binary", type=Path)
    parser.add_argument("--out", type=Path, help="JSON output (stdout when omitted)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--bootstrap-replicates",
        type=_positive_int,
        default=DEFAULT_BOOTSTRAP_REPLICATES,
    )
    parser.add_argument(
        "--confidence-level", type=_probability, default=DEFAULT_CONFIDENCE_LEVEL
    )
    parser.add_argument(
        "--minimum-speedup", type=_positive_float, default=DEFAULT_MINIMUM_SPEEDUP
    )
    parser.add_argument("--holm-alpha", type=_probability)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if (args.lock is not None or args.parent_lock is not None) and (
        args.baseline_binary is not None or args.candidate_binary is not None
    ):
        parser.error("binary artifact options apply only to normalized CSV input")
    if args.manifest is not None and (args.baseline or args.candidate != "euf-viper"):
        parser.error("solver id options apply only to locked raw input")
    if args.parent_lock is None:
        if args.results is None:
            parser.error("results is required for --lock and --manifest")
        if args.shard_lock_dir is not None or args.shard_results_root is not None:
            parser.error("shard directory options require --parent-lock")
    else:
        if args.results is not None:
            parser.error("results must be omitted with --parent-lock")
        if args.shard_lock_dir is None or args.shard_results_root is None:
            parser.error(
                "--parent-lock requires --shard-lock-dir and --shard-results-root"
            )
    try:
        if args.parent_lock is not None:
            assert args.shard_lock_dir is not None
            assert args.shard_results_root is not None
            shard_pairs = discover_shard_pairs(
                args.shard_lock_dir, args.shard_results_root
            )
            payload = analyze_sharded_locked_campaign(
                args.parent_lock,
                shard_pairs,
                candidate_id=args.candidate,
                baseline_ids=args.baseline or None,
                seed=args.seed,
                bootstrap_replicates=args.bootstrap_replicates,
                confidence_level=args.confidence_level,
                minimum_speedup=args.minimum_speedup,
                holm_alpha=args.holm_alpha,
            )
        elif args.lock is not None:
            assert args.results is not None
            payload = analyze_locked_campaign(
                args.lock,
                args.results,
                candidate_id=args.candidate,
                baseline_ids=args.baseline or None,
                seed=args.seed,
                bootstrap_replicates=args.bootstrap_replicates,
                confidence_level=args.confidence_level,
                minimum_speedup=args.minimum_speedup,
                holm_alpha=args.holm_alpha,
            )
        else:
            assert args.manifest is not None
            assert args.results is not None
            payload = analyze_campaign(
                args.results,
                args.manifest,
                baseline_binary=args.baseline_binary,
                candidate_binary=args.candidate_binary,
                seed=args.seed,
                bootstrap_replicates=args.bootstrap_replicates,
                confidence_level=args.confidence_level,
                minimum_speedup=args.minimum_speedup,
                holm_alpha=args.holm_alpha,
            )
    except CampaignInputError as error:
        companion = (
            args.parent_lock
            if args.parent_lock is not None
            else args.lock
            if args.lock is not None
            else args.manifest
        )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "invalid_input",
            "promoted": False,
            "errors": error.errors,
            "input_hashes": {
                "results_sha256": (
                    _safe_hash(args.results) if args.results is not None else None
                ),
                "lock_or_manifest_sha256": (
                    _safe_hash(companion) if companion is not None else None
                ),
            },
        }
        _emit_json(payload, args.out)
        return 2
    _emit_json(payload, args.out)
    return 0 if payload["promoted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
