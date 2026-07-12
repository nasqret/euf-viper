#!/usr/bin/env python3
"""Assemble and analyze exact timeout-only locked campaign stages.

Raw records are never rewritten.  Each source and continuation shard is first
validated by ``analyze_campaign.py``.  A later stage may replace exactly the
rows classified as timeout at the preceding budget; every other observation
is carried forward with its original measured solve time.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import analyze_campaign as analyzer  # noqa: E402
import derive_timeout_continuations as derivation  # noqa: E402


class StagedCampaignError(ValueError):
    """Raised when staged evidence is incomplete or not an exact continuation."""


def canonical_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise StagedCampaignError(f"value is not canonical JSON: {error}") from error
    return (rendered + "\n").encode("ascii")


def _resolved(path: Path) -> Path:
    try:
        return path.expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise StagedCampaignError(f"cannot resolve path {path}: {error}") from error


def _load_sharded(
    parent_lock: Path, shard_lock_directory: Path, shard_results_root: Path
) -> dict[str, Any]:
    parent_lock = _resolved(parent_lock)
    shard_lock_directory = _resolved(shard_lock_directory)
    shard_results_root = _resolved(shard_results_root)
    try:
        pairs = analyzer.discover_shard_pairs(
            shard_lock_directory, shard_results_root
        )
        campaign = analyzer.load_sharded_locked_campaign(parent_lock, pairs)
    except analyzer.CampaignInputError as error:
        raise StagedCampaignError("; ".join(error.errors)) from error
    campaign["evidence_paths"] = {
        "parent_lock": str(parent_lock),
        "shard_lock_directory": str(shard_lock_directory),
        "shard_results_root": str(shard_results_root),
    }
    return campaign


def _read_index(path: Path) -> tuple[dict[str, Any], str]:
    path = _resolved(path)
    try:
        data = analyzer._read_json_object(path, "continuation index")
    except analyzer.CampaignInputError as error:
        raise StagedCampaignError("; ".join(error.errors)) from error
    if set(data) != derivation.INDEX_KEYS:
        raise StagedCampaignError("continuation index has an incompatible schema")
    if data.get("schema_version") != 1:
        raise StagedCampaignError("continuation index schema_version must be 1")
    if data.get("status") not in {"ready", "no_timeouts"}:
        raise StagedCampaignError("continuation index status is invalid")
    source = data.get("source")
    if not isinstance(source, dict) or set(source) != derivation.INDEX_SOURCE_KEYS:
        raise StagedCampaignError("continuation index source schema is invalid")
    lock_record = data.get("continuation_lock")
    if lock_record is not None and (
        not isinstance(lock_record, dict)
        or set(lock_record) != derivation.INDEX_LOCK_KEYS
    ):
        raise StagedCampaignError("continuation index lock schema is invalid")
    return data, analyzer.sha256_file(path)


def _single_budget(campaign: Mapping[str, Any], context: str) -> float:
    budgets = campaign["lock"].get("budgets_s")
    if not isinstance(budgets, list) or len(budgets) != 1:
        raise StagedCampaignError(f"{context} must contain exactly one budget")
    value = budgets[0]
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise StagedCampaignError(f"{context} budget is invalid")
    return float(value)


def _selection_from_timeouts(
    campaign: Mapping[str, Any], budget: float
) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    observations = campaign["observations"]
    source_selection = (
        {
            (item["instance_id"], item["solver_id"])
            for item in campaign["lock"]["run_selection"]
        }
        if "run_selection" in campaign["lock"]
        else None
    )
    for instance in campaign["lock"]["corpus"]["instances"]:
        for solver in campaign["lock"]["solvers"]:
            if (
                source_selection is not None
                and (instance["id"], solver["id"]) not in source_selection
            ):
                continue
            key = (instance["relative_path"], budget, solver["id"])
            try:
                observation = observations[key]
            except KeyError as error:
                raise StagedCampaignError(
                    f"source campaign lacks observation {key!r}"
                ) from error
            result = observation["result"]
            if result not in {"sat", "unsat", "timeout"}:
                raise StagedCampaignError(
                    "source stage contains a non-runnable result: "
                    f"{instance['id']!r}/{solver['id']!r}={result!r}"
                )
            if result == "timeout":
                selected.append(
                    {"instance_id": instance["id"], "solver_id": solver["id"]}
                )
    return selected


def _verify_index_source(
    index: Mapping[str, Any], source_campaign: Mapping[str, Any], source_budget: float
) -> None:
    source = index["source"]
    paths = source_campaign["evidence_paths"]
    root_lock_sha256 = (
        source_campaign["lock"]["continuation"]["root_lock_sha256"]
        if "continuation" in source_campaign["lock"]
        else source_campaign["lock"]["lock_sha256"]
    )
    expected = {
        "parent_lock": paths["parent_lock"],
        "shard_lock_directory": paths["shard_lock_directory"],
        "shard_results_root": paths["shard_results_root"],
        "parent_lock_file_sha256": source_campaign["lock_file_sha256"],
        "parent_lock_sha256": source_campaign["lock"]["lock_sha256"],
        "shard_bundle_sha256": source_campaign["shard_bundle_sha256"],
        "root_lock_sha256": root_lock_sha256,
        "source_evidence_sha256": source_campaign["shard_bundle_sha256"],
        "budget_s": source_budget,
    }
    for field, expected_value in expected.items():
        actual = source.get(field)
        if field == "budget_s":
            if type(actual) not in {int, float} or float(actual) != float(expected_value):
                raise StagedCampaignError("continuation source budget mismatch")
        elif actual != expected_value:
            raise StagedCampaignError(
                f"continuation source {field} mismatch: {actual!r} != {expected_value!r}"
            )


def _verify_derived_parent(
    source_campaign: Mapping[str, Any],
    index: Mapping[str, Any],
    expected_selection: Sequence[Mapping[str, str]],
) -> tuple[Path, dict[str, Any]]:
    lock_record = index["continuation_lock"]
    if not isinstance(lock_record, dict):
        raise StagedCampaignError("ready continuation index has no lock")
    lock_path = _resolved(Path(lock_record["path"]))
    try:
        file_hash = analyzer.sha256_file(lock_path)
        lock = analyzer._load_lock(lock_path)
    except (OSError, analyzer.CampaignInputError) as error:
        details = error.errors if isinstance(error, analyzer.CampaignInputError) else [str(error)]
        raise StagedCampaignError("; ".join(details)) from error
    if file_hash != lock_record["file_sha256"]:
        raise StagedCampaignError("continuation lock file SHA-256 mismatch")
    if lock["lock_sha256"] != lock_record["lock_sha256"]:
        raise StagedCampaignError("continuation lock self-hash index mismatch")

    expected_selection = [dict(item) for item in expected_selection]
    expected_hash = derivation.selection_hash(expected_selection)
    if lock["run_selection"] != expected_selection:
        raise StagedCampaignError("continuation does not select exactly prior timeouts")
    if index["selection_sha256"] != expected_hash:
        raise StagedCampaignError("continuation index selection SHA-256 mismatch")
    if lock["continuation"]["selection_sha256"] != expected_hash:
        raise StagedCampaignError("continuation lock selection SHA-256 mismatch")
    if index["selected_runs"] != len(expected_selection):
        raise StagedCampaignError("continuation selected_runs mismatch")

    source_lock = source_campaign["lock"]
    immutable_fields = (
        "campaign_id",
        "created_from_commit_time",
        "spec",
        "repository",
        "host",
        "solver_config",
        "solver_release_lock",
        "solvers",
    )
    for field in immutable_fields:
        if lock[field] != source_lock[field]:
            raise StagedCampaignError(f"continuation drifted locked field {field!r}")
    if lock["schema_version"] != 2 or lock["promotion_eligible"] is not False:
        raise StagedCampaignError(
            "continuation lock must use schema v2 and be independently ineligible"
        )
    source_corpus = dict(source_lock["corpus"])
    source_instances = source_corpus.pop("instances")
    derived_corpus = dict(lock["corpus"])
    derived_instances = derived_corpus.pop("instances")
    if derived_corpus != source_corpus:
        raise StagedCampaignError("continuation drifted corpus metadata")
    selected_instance_ids = {item["instance_id"] for item in expected_selection}
    expected_instances = [
        instance
        for instance in source_instances
        if instance["id"] in selected_instance_ids
    ]
    if derived_instances != expected_instances:
        raise StagedCampaignError("continuation instance union is not exact")

    expected_execution = copy.deepcopy(source_lock["execution"])
    expected_execution["order"] = "balanced_latin_square"
    if lock["execution"] != expected_execution:
        raise StagedCampaignError("continuation drifted execution controls")
    if lock["budgets_s"] != [index["target_budget_s"]]:
        raise StagedCampaignError("continuation target budget mismatch")
    if lock["output"]["directory"] != index["output_directory"]:
        raise StagedCampaignError("continuation output directory mismatch")

    expected_provenance = {
        "mode": "timeout_only",
        "root_lock_sha256": index["source"]["root_lock_sha256"],
        "parent_lock_path": index["source"]["parent_lock"],
        "parent_lock_file_sha256": index["source"]["parent_lock_file_sha256"],
        "parent_lock_sha256": index["source"]["parent_lock_sha256"],
        "shard_bundle_sha256": index["source"]["shard_bundle_sha256"],
        "source_evidence_sha256": index["source"]["source_evidence_sha256"],
        "shard_lock_directory": index["source"]["shard_lock_directory"],
        "shard_results_root": index["source"]["shard_results_root"],
        "source_budget_s": index["source"]["budget_s"],
        "target_budget_s": index["target_budget_s"],
        "selection_sha256": index["selection_sha256"],
        "selected_instances": index["selected_instances"],
        "selected_runs": index["selected_runs"],
        "runner_path": lock["continuation"]["runner_path"],
        "runner_sha256": lock["continuation"]["runner_sha256"],
    }
    if lock["continuation"] != expected_provenance:
        raise StagedCampaignError("continuation provenance differs from its index")
    runner_path = _resolved(Path(lock["continuation"]["runner_path"]))
    if analyzer.sha256_file(runner_path) != lock["continuation"]["runner_sha256"]:
        raise StagedCampaignError("continuation runner SHA-256 drift")
    return lock_path, lock


def _carry_observation(observation: Mapping[str, Any], budget: float) -> dict[str, Any]:
    carried = dict(observation)
    carried["budget_s"] = budget
    carried["carried_forward"] = True
    return carried


def analyze_staged_campaign(
    base_parent_lock: Path,
    base_shard_lock_directory: Path,
    base_shard_results_root: Path,
    stages: Sequence[tuple[Path, Path | None, Path | None]],
    *,
    candidate_id: str = "euf-viper",
    baseline_ids: Sequence[str] | None = None,
    seed: int = analyzer.DEFAULT_SEED,
    bootstrap_replicates: int = analyzer.DEFAULT_BOOTSTRAP_REPLICATES,
    confidence_level: float = analyzer.DEFAULT_CONFIDENCE_LEVEL,
    minimum_speedup: float = analyzer.DEFAULT_MINIMUM_SPEEDUP,
    holm_alpha: float | None = None,
) -> dict[str, Any]:
    """Validate, assemble, and analyze one base plus timeout continuations."""

    base = _load_sharded(
        base_parent_lock, base_shard_lock_directory, base_shard_results_root
    )
    if "continuation" in base["lock"]:
        raise StagedCampaignError("base campaign cannot itself be a continuation")
    for solver in base["lock"]["solvers"]:
        if any("{budget_s}" in argument for argument in solver["argv_template"]):
            raise StagedCampaignError(
                f"solver {solver['id']!r} has budget-dependent argv; "
                "staged carry-forward is invalid"
            )
    base_budget = _single_budget(base, "base campaign")
    declared_budgets = [
        float(value) for value in derivation._declared_budget_ladder(base["lock"])
    ]
    if not declared_budgets or base_budget != declared_budgets[0]:
        raise StagedCampaignError("base campaign is not the first declared budget")
    observations = dict(base["observations"])
    budgets = [base_budget]
    raw_records = base["raw_records"]
    source_campaign = base
    stage_provenance: list[dict[str, Any]] = []

    for stage_number, (index_path, lock_directory, results_root) in enumerate(
        stages, start=1
    ):
        index_path = _resolved(index_path)
        index, index_sha256 = _read_index(index_path)
        source_budget = _single_budget(source_campaign, "source stage")
        _verify_index_source(index, source_campaign, source_budget)
        target_budget = index["target_budget_s"]
        if type(target_budget) not in {int, float} or not math.isfinite(
            float(target_budget)
        ):
            raise StagedCampaignError("continuation target budget is invalid")
        target_budget = float(target_budget)
        if target_budget <= budgets[-1]:
            raise StagedCampaignError("continuation budgets must strictly increase")
        if len(budgets) >= len(declared_budgets) or target_budget != declared_budgets[
            len(budgets)
        ]:
            raise StagedCampaignError(
                "continuation target is not the next declared campaign budget"
            )
        expected_selection = _selection_from_timeouts(source_campaign, source_budget)
        expected_hash = derivation.selection_hash(expected_selection)

        if not expected_selection:
            if index["status"] != "no_timeouts" or index["continuation_lock"] is not None:
                raise StagedCampaignError("zero-timeout stage emitted a runnable lock")
            if index["selected_instances"] != 0 or index["selected_runs"] != 0:
                raise StagedCampaignError("zero-timeout stage has nonzero selection")
            if index["selection_sha256"] != expected_hash:
                raise StagedCampaignError("zero-timeout selection hash mismatch")
            if stage_number != len(stages):
                raise StagedCampaignError("no-timeout stage must be the final stage")
            stage_campaign = None
        else:
            if index["status"] != "ready":
                raise StagedCampaignError("timeout rows require a ready continuation")
            if lock_directory is None or results_root is None:
                raise StagedCampaignError("ready continuation lacks shard evidence paths")
            continuation_lock_path, _ = _verify_derived_parent(
                source_campaign, index, expected_selection
            )
            stage_campaign = _load_sharded(
                continuation_lock_path, lock_directory, results_root
            )
            if stage_campaign["lock"]["lock_sha256"] != index["continuation_lock"][
                "lock_sha256"
            ]:
                raise StagedCampaignError("executed continuation lock differs from index")
            raw_records += stage_campaign["raw_records"]

        selected_pairs = {
            (item["instance_id"], item["solver_id"])
            for item in expected_selection
        }
        for instance in base["lock"]["corpus"]["instances"]:
            relative_path = instance["relative_path"]
            for solver in base["lock"]["solvers"]:
                solver_id = solver["id"]
                previous = observations[(relative_path, budgets[-1], solver_id)]
                if (instance["id"], solver_id) in selected_pairs:
                    assert stage_campaign is not None
                    try:
                        current = stage_campaign["observations"][(
                            relative_path,
                            target_budget,
                            solver_id,
                        )]
                    except KeyError as error:
                        raise StagedCampaignError(
                            "continuation execution lacks a selected observation"
                        ) from error
                    observations[(relative_path, target_budget, solver_id)] = current
                else:
                    observations[(relative_path, target_budget, solver_id)] = (
                        _carry_observation(previous, target_budget)
                    )

        stage_record = {
            "number": stage_number,
            "index": str(index_path),
            "index_sha256": index_sha256,
            "status": index["status"],
            "source_budget_s": source_budget,
            "target_budget_s": target_budget,
            "selected_instances": index["selected_instances"],
            "selected_runs": index["selected_runs"],
            "selection_sha256": index["selection_sha256"],
            "continuation_lock": index["continuation_lock"],
            "source_evidence": copy.deepcopy(index["source"]),
            "execution_evidence": (
                copy.deepcopy(stage_campaign["evidence_paths"])
                if stage_campaign is not None
                else None
            ),
            "execution_shards": (
                copy.deepcopy(stage_campaign["shards"])
                if stage_campaign is not None
                else []
            ),
            "shard_bundle_sha256": (
                stage_campaign["shard_bundle_sha256"]
                if stage_campaign is not None
                else None
            ),
        }
        stage_provenance.append(stage_record)
        budgets.append(target_budget)
        if stage_campaign is not None:
            source_campaign = stage_campaign

    while len(budgets) < len(declared_budgets):
        source_budget = budgets[-1]
        unresolved = [
            key
            for key, observation in observations.items()
            if key[1] == source_budget
            and observation["result"] not in {"sat", "unsat"}
        ]
        if unresolved:
            break
        target_budget = declared_budgets[len(budgets)]
        for instance in base["lock"]["corpus"]["instances"]:
            for solver in base["lock"]["solvers"]:
                key = (instance["relative_path"], source_budget, solver["id"])
                observations[(instance["relative_path"], target_budget, solver["id"])] = (
                    _carry_observation(observations[key], target_budget)
                )
        stage_provenance.append(
            {
                "number": len(stage_provenance) + 1,
                "status": "implicit_no_timeouts",
                "source_budget_s": source_budget,
                "target_budget_s": target_budget,
                "selected_instances": 0,
                "selected_runs": 0,
                "source_evidence": copy.deepcopy(
                    source_campaign["evidence_paths"]
                ),
                "source_shard_bundle_sha256": source_campaign[
                    "shard_bundle_sha256"
                ],
            }
        )
        budgets.append(target_budget)

    virtual_lock = copy.deepcopy(base["lock"])
    virtual_lock["budgets_s"] = budgets
    complete_ladder = budgets == declared_budgets
    virtual_lock["promotion_eligible"] = bool(
        base["lock"]["promotion_eligible"] and complete_ladder
    )
    virtual_lock["lock_sha256"] = analyzer._lock_sha256(virtual_lock)
    virtual_campaign = {
        "lock": virtual_lock,
        "lock_file_sha256": base["lock_file_sha256"],
        "observations": observations,
        "raw_records": raw_records,
    }
    result = analyzer._analyze_loaded_locked_campaign(
        virtual_campaign,
        {
            "base": base["evidence_paths"],
            "stages": stage_provenance,
        },
        {
            "base_lock_file_sha256": base["lock_file_sha256"],
            "base_lock_sha256": base["lock"]["lock_sha256"],
            "base_shard_bundle_sha256": base["shard_bundle_sha256"],
            "staged_evidence_sha256": hashlib.sha256(
                canonical_bytes(stage_provenance)
            ).hexdigest(),
        },
        candidate_id=candidate_id,
        baseline_ids=baseline_ids,
        seed=seed,
        bootstrap_replicates=bootstrap_replicates,
        confidence_level=confidence_level,
        minimum_speedup=minimum_speedup,
        holm_alpha=holm_alpha,
    )
    result["assumptions"]["staged_timeout_policy"] = (
        "only immediately preceding timeout rows are rerun; solved rows retain "
        "their original measurements"
    )
    result["assumptions"]["complete_declared_budget_ladder"] = complete_ladder
    result["inputs"]["physical_raw_records"] = raw_records
    result["inputs"]["base_shards"] = copy.deepcopy(base["shards"])
    result["inputs"]["stages"] = stage_provenance
    result["inputs"]["carried_forward_observations"] = sum(
        observation.get("carried_forward") is True
        for observation in observations.values()
    )
    origin_counts: dict[str, int] = {}
    for observation in observations.values():
        key = format(float(observation["origin_budget_s"]), ".17g")
        origin_counts[key] = origin_counts.get(key, 0) + 1
    result["inputs"]["origin_budget_counts"] = dict(sorted(origin_counts.items()))
    observation_provenance = [
        {
            "relative_path": relative_path,
            "budget_s": budget,
            "solver_id": solver_id,
            "result": observation["result"],
            "origin_budget_s": observation["origin_budget_s"],
            "carried_forward": observation["carried_forward"],
            "source_lock_sha256": observation["source_lock_sha256"],
            "source_raw_sha256": observation["source_raw_sha256"],
            "source_record_sha256s": observation["source_record_sha256"],
        }
        for (relative_path, budget, solver_id), observation in sorted(
            observations.items()
        )
    ]
    result["inputs"]["observation_provenance"] = observation_provenance
    result["input_hashes"]["observation_provenance_sha256"] = hashlib.sha256(
        canonical_bytes(observation_provenance)
    ).hexdigest()
    return result


def _positive_int(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-parent-lock", type=Path, required=True)
    parser.add_argument("--base-shard-lock-dir", type=Path, required=True)
    parser.add_argument("--base-shard-results-root", type=Path, required=True)
    parser.add_argument(
        "--stage",
        action="append",
        nargs=3,
        metavar=("INDEX", "BOUND_LOCK_DIR", "RESULTS_ROOT"),
        default=[],
        help="use '-' for both evidence paths only when INDEX records no_timeouts",
    )
    parser.add_argument("--candidate", default="euf-viper")
    parser.add_argument("--baseline", action="append", default=[])
    parser.add_argument("--out", type=Path)
    parser.add_argument("--seed", type=int, default=analyzer.DEFAULT_SEED)
    parser.add_argument(
        "--bootstrap-replicates",
        type=_positive_int,
        default=analyzer.DEFAULT_BOOTSTRAP_REPLICATES,
    )
    parser.add_argument(
        "--confidence-level", type=float, default=analyzer.DEFAULT_CONFIDENCE_LEVEL
    )
    parser.add_argument(
        "--minimum-speedup", type=float, default=analyzer.DEFAULT_MINIMUM_SPEEDUP
    )
    parser.add_argument("--holm-alpha", type=float)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    stages: list[tuple[Path, Path | None, Path | None]] = []
    for index, lock_directory, results_root in args.stage:
        if (lock_directory == "-") != (results_root == "-"):
            parser.error("stage evidence paths must both be '-' or both be paths")
        stages.append(
            (
                Path(index),
                None if lock_directory == "-" else Path(lock_directory),
                None if results_root == "-" else Path(results_root),
            )
        )
    try:
        result = analyze_staged_campaign(
            args.base_parent_lock,
            args.base_shard_lock_dir,
            args.base_shard_results_root,
            stages,
            candidate_id=args.candidate,
            baseline_ids=args.baseline or None,
            seed=args.seed,
            bootstrap_replicates=args.bootstrap_replicates,
            confidence_level=args.confidence_level,
            minimum_speedup=args.minimum_speedup,
            holm_alpha=args.holm_alpha,
        )
    except (StagedCampaignError, analyzer.CampaignInputError, ValueError) as error:
        parser.exit(2, f"staged analysis failed: {error}\n")
    analyzer._emit_json(result, args.out)
    return 0 if result["promoted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
