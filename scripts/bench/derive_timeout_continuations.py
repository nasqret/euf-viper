#!/usr/bin/env python3
"""Derive a strict timeout-only continuation from a sharded campaign.

The source campaign is accepted only after ``analyze_campaign.py`` validates
the parent lock, every runtime-bound shard lock, every raw record, and the
complete global shard partition.  The derived schema-v2 lock keeps all source
solvers, narrows the corpus to the union of timed-out instances, and records
the exact timed-out (instance, solver) arms in ``run_selection``.  The
schema-v1 index is a locator and lineage record; it is never standalone
promotion evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import analyze_campaign as campaign_analyzer  # noqa: E402
from validate_campaign_spec import CampaignSpecError, validate_spec  # noqa: E402


INDEX_SCHEMA_VERSION = 1
CONTINUATION_LOCK_SCHEMA_VERSION = 2
LOCK_FILENAME = "continuation-parent.json"
INDEX_FILENAME = "index.json"
RUN_SELECTION_KEYS = {"instance_id", "solver_id"}
CONTINUATION_KEYS = {
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
INDEX_KEYS = {
    "schema_version",
    "status",
    "source",
    "target_budget_s",
    "selected_instances",
    "selected_runs",
    "selection_sha256",
    "continuation_lock",
    "output_directory",
}
INDEX_SOURCE_KEYS = {
    "parent_lock",
    "shard_lock_directory",
    "shard_results_root",
    "parent_lock_file_sha256",
    "parent_lock_sha256",
    "shard_bundle_sha256",
    "root_lock_sha256",
    "source_evidence_sha256",
    "budget_s",
}
INDEX_LOCK_KEYS = {"path", "lock_sha256", "file_sha256"}
ACCEPTED_SOURCE_RESULTS = {"sat", "unsat", "timeout"}


class ContinuationError(ValueError):
    """Raised when source evidence or an output invariant is not exact."""


# A descriptive alias for callers that name the operation rather than artifact.
DerivationError = ContinuationError


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical JSON representation used by campaign artifacts."""

    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise ContinuationError(f"value is not canonical JSON: {error}") from error
    return (rendered + "\n").encode("utf-8")


def lock_hash(lock: Mapping[str, Any]) -> str:
    """Compute a campaign lock self-hash with ``lock_sha256`` blanked."""

    unsigned = dict(lock)
    unsigned["lock_sha256"] = ""
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def selection_hash(run_selection: Sequence[Mapping[str, str]]) -> str:
    """Hash the ordered exact-arm selection as canonical JSON."""

    return hashlib.sha256(canonical_bytes(list(run_selection))).hexdigest()


def _normalize_target_budget(value: Any) -> int | float:
    if type(value) not in {int, float} or value <= 0:
        raise ContinuationError("target budget must be a finite positive number")
    try:
        numeric = float(value)
    except OverflowError as error:
        raise ContinuationError(
            "target budget must be a finite positive number"
        ) from error
    if not math.isfinite(numeric):
        raise ContinuationError("target budget must be a finite positive number")
    if numeric.is_integer():
        return int(numeric)
    return numeric


def _resolved(path: Path) -> Path:
    try:
        return path.expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise ContinuationError(f"cannot resolve path {path}: {error}") from error


def _validated_source_campaign(
    parent_lock_path: Path,
    shard_lock_directory: Path,
    shard_results_root: Path,
) -> dict[str, Any]:
    try:
        shard_pairs = campaign_analyzer.discover_shard_pairs(
            shard_lock_directory, shard_results_root
        )
        return campaign_analyzer.load_sharded_locked_campaign(
            parent_lock_path, shard_pairs
        )
    except campaign_analyzer.CampaignInputError as error:
        raise ContinuationError(
            "invalid source campaign: " + "; ".join(error.errors)
        ) from error
    except OSError as error:
        raise ContinuationError(f"cannot load source campaign: {error}") from error


def _select_timeout_runs(
    campaign: Mapping[str, Any], source_budget_s: int | float
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    parent = campaign["lock"]
    observations = campaign["observations"]
    if "run_selection" in parent:
        selected_source_pairs = {
            (item["instance_id"], item["solver_id"])
            for item in parent["run_selection"]
        }
    else:
        selected_source_pairs = {
            (instance["id"], solver["id"])
            for instance in parent["corpus"]["instances"]
            for solver in parent["solvers"]
        }
    selected_instances: list[dict[str, Any]] = []
    run_selection: list[dict[str, str]] = []

    for instance in parent["corpus"]["instances"]:
        instance_pairs: list[dict[str, str]] = []
        for solver in parent["solvers"]:
            solver_id = solver["id"]
            if (instance["id"], solver_id) not in selected_source_pairs:
                continue
            key = (
                instance["relative_path"],
                float(source_budget_s),
                solver_id,
            )
            try:
                observation = observations[key]
            except KeyError as error:  # Defensive: the analyzer checks completeness.
                raise ContinuationError(
                    "validated source campaign lacks observation " f"{key!r}"
                ) from error
            result = observation.get("result")
            if result not in ACCEPTED_SOURCE_RESULTS:
                raise ContinuationError(
                    "source campaign contains a non-runnable classification: "
                    f"instance={instance['id']!r}, solver={solver_id!r}, "
                    f"result={result!r}"
                )
            if result in {"sat", "unsat"} and result != instance["status"]:
                raise ContinuationError(
                    "source campaign contains a wrong answer after validation: "
                    f"instance={instance['id']!r}, solver={solver_id!r}"
                )
            if result == "timeout":
                pair = {"instance_id": instance["id"], "solver_id": solver_id}
                if set(pair) != RUN_SELECTION_KEYS:  # Keeps the schema explicit.
                    raise AssertionError("internal run_selection schema drift")
                instance_pairs.append(pair)
        if instance_pairs:
            selected_instances.append(copy.deepcopy(instance))
            run_selection.extend(instance_pairs)

    return selected_instances, run_selection


def _continuation_provenance(
    campaign: Mapping[str, Any],
    *,
    parent_lock_path: Path,
    shard_lock_directory: Path,
    shard_results_root: Path,
    source_budget_s: int | float,
    target_budget_s: int | float,
    run_selection: Sequence[Mapping[str, str]],
    selected_instances: int,
) -> dict[str, Any]:
    parent = campaign["lock"]
    root_lock_sha256 = (
        parent["continuation"]["root_lock_sha256"]
        if "continuation" in parent
        else parent["lock_sha256"]
    )
    runner_path = (SCRIPT_DIR / "run_locked_campaign.py").resolve()
    provenance = {
        "mode": "timeout_only",
        "root_lock_sha256": root_lock_sha256,
        "parent_lock_path": str(parent_lock_path),
        "parent_lock_file_sha256": campaign["lock_file_sha256"],
        "parent_lock_sha256": campaign["lock"]["lock_sha256"],
        "shard_bundle_sha256": campaign["shard_bundle_sha256"],
        "source_evidence_sha256": campaign["shard_bundle_sha256"],
        "shard_lock_directory": str(shard_lock_directory),
        "shard_results_root": str(shard_results_root),
        "source_budget_s": source_budget_s,
        "target_budget_s": target_budget_s,
        "selection_sha256": selection_hash(run_selection),
        "selected_instances": selected_instances,
        "selected_runs": len(run_selection),
        "runner_path": str(runner_path),
        "runner_sha256": campaign_analyzer.sha256_file(runner_path),
    }
    if set(provenance) != CONTINUATION_KEYS:
        raise AssertionError("internal continuation provenance schema drift")
    return provenance


def _declared_budget_ladder(parent: Mapping[str, Any]) -> list[int | float]:
    spec_record = parent.get("spec")
    if not isinstance(spec_record, dict):
        raise ContinuationError("source parent lock lacks a campaign specification")
    spec_path = Path(str(spec_record.get("path", "")))
    expected_hash = spec_record.get("sha256")
    try:
        if campaign_analyzer.sha256_file(spec_path) != expected_hash:
            raise ContinuationError("campaign specification SHA-256 drift")
        spec = campaign_analyzer._parse_json_strict(
            spec_path.read_text(encoding="utf-8"),
            f"campaign specification {spec_path}",
        )
        validate_spec(spec)
    except (
        OSError,
        UnicodeError,
        CampaignSpecError,
        campaign_analyzer.CampaignInputError,
    ) as error:
        raise ContinuationError(
            f"cannot read campaign specification {spec_path}: {error}"
        ) from error
    budgets = spec.get("budgets_s") if isinstance(spec, dict) else None
    if (
        not isinstance(budgets, list)
        or not budgets
        or any(type(value) not in {int, float} for value in budgets)
        or any(not math.isfinite(float(value)) or float(value) <= 0 for value in budgets)
        or any(float(left) >= float(right) for left, right in zip(budgets, budgets[1:]))
    ):
        raise ContinuationError("campaign specification has an invalid budget ladder")
    return [_normalize_target_budget(value) for value in budgets]


def make_continuation_lock(
    campaign: Mapping[str, Any],
    *,
    parent_lock_path: Path,
    shard_lock_directory: Path,
    shard_results_root: Path,
    target_budget_s: int | float,
    output_directory: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any], list[dict[str, str]]]:
    """Build the derived lock and provenance without writing output files."""

    parent = campaign["lock"]
    budgets = parent.get("budgets_s")
    if type(budgets) is not list or len(budgets) != 1:
        raise ContinuationError("source parent lock must contain exactly one budget")
    source_budget_s = budgets[0]
    target_budget_s = _normalize_target_budget(target_budget_s)
    if float(target_budget_s) <= float(source_budget_s):
        raise ContinuationError(
            "target budget must be strictly greater than source budget"
        )
    ladder = _declared_budget_ladder(parent)
    try:
        source_index = [float(value) for value in ladder].index(float(source_budget_s))
    except ValueError as error:
        raise ContinuationError("source budget is not in the declared ladder") from error
    if source_index + 1 >= len(ladder) or float(ladder[source_index + 1]) != float(
        target_budget_s
    ):
        raise ContinuationError(
            "target budget must be the next declared budget after source"
        )
    for solver in parent["solvers"]:
        if any("{budget_s}" in argument for argument in solver["argv_template"]):
            raise ContinuationError(
                f"solver {solver['id']!r} has budget-dependent argv; "
                "timeout-only carry-forward is invalid"
            )

    selected_instances, run_selection = _select_timeout_runs(
        campaign, source_budget_s
    )
    provenance = _continuation_provenance(
        campaign,
        parent_lock_path=parent_lock_path,
        shard_lock_directory=shard_lock_directory,
        shard_results_root=shard_results_root,
        source_budget_s=source_budget_s,
        target_budget_s=target_budget_s,
        run_selection=run_selection,
        selected_instances=len(selected_instances),
    )
    if not run_selection:
        return None, provenance, run_selection

    lock = copy.deepcopy(parent)
    lock["schema_version"] = CONTINUATION_LOCK_SCHEMA_VERSION
    lock["lock_sha256"] = ""
    lock["promotion_eligible"] = False
    lock["corpus"]["instances"] = selected_instances
    lock["solvers"] = copy.deepcopy(parent["solvers"])
    lock["budgets_s"] = [target_budget_s]
    lock["execution"]["order"] = "balanced_latin_square"
    lock["output"]["directory"] = str(output_directory)
    lock["run_selection"] = run_selection
    lock["continuation"] = provenance
    lock["lock_sha256"] = lock_hash(lock)
    return lock, provenance, run_selection


def _read_existing(path: Path) -> bytes | None:
    try:
        if not path.exists():
            return None
        if not path.is_file():
            raise ContinuationError(f"output drift: expected a regular file at {path}")
        return path.read_bytes()
    except OSError as error:
        raise ContinuationError(f"cannot inspect output {path}: {error}") from error


def _reject_drift(path: Path, expected: bytes) -> bool:
    existing = _read_existing(path)
    if existing is None:
        return False
    if existing != expected:
        raise ContinuationError(f"output drift at {path}")
    return True


def _atomic_write(path: Path, payload: bytes) -> None:
    """Write one already-checked artifact by atomic replacement."""

    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except OSError as error:
        raise ContinuationError(f"cannot atomically write {path}: {error}") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _index_payload(
    *,
    provenance: Mapping[str, Any],
    lock: Mapping[str, Any] | None,
    lock_path: Path,
    output_directory: Path,
) -> dict[str, Any]:
    lock_record: dict[str, str] | None = None
    if lock is not None:
        lock_bytes = canonical_bytes(lock)
        lock_record = {
            "path": str(lock_path),
            "file_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "lock_sha256": str(lock["lock_sha256"]),
        }
        if set(lock_record) != INDEX_LOCK_KEYS:
            raise AssertionError("internal continuation lock index schema drift")
    source = {
        "parent_lock": provenance["parent_lock_path"],
        "shard_lock_directory": provenance["shard_lock_directory"],
        "shard_results_root": provenance["shard_results_root"],
        "parent_lock_file_sha256": provenance["parent_lock_file_sha256"],
        "parent_lock_sha256": provenance["parent_lock_sha256"],
        "shard_bundle_sha256": provenance["shard_bundle_sha256"],
        "root_lock_sha256": provenance["root_lock_sha256"],
        "source_evidence_sha256": provenance["source_evidence_sha256"],
        "budget_s": provenance["source_budget_s"],
    }
    if set(source) != INDEX_SOURCE_KEYS:
        raise AssertionError("internal source index schema drift")
    index = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "status": "ready" if lock is not None else "no_timeouts",
        "source": source,
        "target_budget_s": provenance["target_budget_s"],
        "selected_instances": provenance["selected_instances"],
        "selected_runs": provenance["selected_runs"],
        "selection_sha256": provenance["selection_sha256"],
        "continuation_lock": lock_record,
        "output_directory": str(output_directory),
    }
    if set(index) != INDEX_KEYS:
        raise AssertionError("internal continuation index schema drift")
    return index


def derive_continuation(
    parent_lock_path: Path,
    shard_lock_directory: Path,
    shard_results_root: Path,
    target_budget_s: int | float,
    output_directory: Path,
) -> dict[str, Any]:
    """Validate source shards, derive artifacts, and return the written index."""

    parent_lock_path = _resolved(Path(parent_lock_path))
    shard_lock_directory = _resolved(Path(shard_lock_directory))
    shard_results_root = _resolved(Path(shard_results_root))
    output_directory = _resolved(Path(output_directory))
    campaign = _validated_source_campaign(
        parent_lock_path, shard_lock_directory, shard_results_root
    )
    lock, provenance, run_selection = make_continuation_lock(
        campaign,
        parent_lock_path=parent_lock_path,
        shard_lock_directory=shard_lock_directory,
        shard_results_root=shard_results_root,
        target_budget_s=target_budget_s,
        output_directory=output_directory,
    )

    lock_path = output_directory / LOCK_FILENAME
    index_path = output_directory / INDEX_FILENAME
    if lock is None:
        if _read_existing(lock_path) is not None:
            raise ContinuationError(
                f"output drift: zero-timeout derivation found {lock_path}"
            )
        lock_bytes = None
    else:
        lock_bytes = canonical_bytes(lock)
    index = _index_payload(
        provenance=provenance,
        lock=lock,
        lock_path=lock_path,
        output_directory=output_directory,
    )
    index_bytes = canonical_bytes(index)

    lock_exists = False
    if lock_bytes is not None:
        lock_exists = _reject_drift(lock_path, lock_bytes)
    index_exists = _reject_drift(index_path, index_bytes)
    if lock_bytes is not None and not lock_exists:
        _atomic_write(lock_path, lock_bytes)
    if not index_exists:
        _atomic_write(index_path, index_bytes)
    return index


# Keep both discoverable names for callers following the script filename.
derive_timeout_continuation = derive_continuation
derive_timeout_continuations = derive_continuation


def _budget_argument(raw: str) -> int | float:
    try:
        return _normalize_target_budget(float(raw))
    except (ValueError, ContinuationError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("parent", type=Path, nargs="?", help="source parent lock")
    parser.add_argument("--parent-lock", dest="parent_option", type=Path)
    parser.add_argument(
        "--shard-lock-dir",
        "--bound-lock-dir",
        "--bound-lock-directory",
        dest="shard_lock_directory",
        type=Path,
        required=True,
    )
    parser.add_argument("--shard-results-root", type=Path, required=True)
    parser.add_argument(
        "--target-budget",
        "--target-budget-s",
        dest="target_budget_s",
        type=_budget_argument,
        required=True,
    )
    parser.add_argument(
        "--output-dir",
        "--out-dir",
        "--output-directory",
        dest="output_directory",
        type=Path,
        required=True,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if (args.parent is None) == (args.parent_option is None):
        parser.error("provide exactly one of parent or --parent-lock")
    parent_lock_path = args.parent if args.parent is not None else args.parent_option
    assert parent_lock_path is not None
    try:
        index = derive_continuation(
            parent_lock_path,
            args.shard_lock_directory,
            args.shard_results_root,
            args.target_budget_s,
            args.output_directory,
        )
    except ContinuationError as error:
        parser.exit(2, f"continuation derivation failed: {error}\n")
    sys.stdout.write(json.dumps(index, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
