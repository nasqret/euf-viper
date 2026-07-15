#!/usr/bin/env python3
"""Audit a complete T7 ABBA journal and apply the preregistered gates."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "campaigns" / "t7-sat-impact-2026-07.json"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MANIFEST = _load(
    "t7_analyze_manifest",
    ROOT / "scripts" / "bench" / "build_t7_sat_impact_manifest.py",
)
T2 = MANIFEST.T2


JOURNAL_SCHEMA = "t7-sat-impact-journal-v1"
AUDIT_SCHEMA = "t7-sat-impact-audit-v1"
ARMS = ("off", "on")
REPEATS = 4


class AnalyzeError(RuntimeError):
    """Raised when journal evidence is malformed or incomplete."""


def load_journal(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise AnalyzeError(f"cannot read journal {path}: {error}") from error
    if not raw or not raw.endswith(b"\n"):
        raise AnalyzeError("journal must be non-empty JSONL with a final newline")
    previous: str | None = None
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise AnalyzeError(f"journal line {line_number} is blank")
        try:
            record = json.loads(line, object_pairs_hook=T2._reject_duplicate_keys)
        except (json.JSONDecodeError, T2.ManifestError) as error:
            raise AnalyzeError(f"journal line {line_number} is invalid: {error}") from error
        if type(record) is not dict or record.get("schema") != JOURNAL_SCHEMA:
            raise AnalyzeError(f"journal line {line_number} has an invalid schema")
        if record.get("previous_record_sha256") != previous:
            raise AnalyzeError(f"journal line {line_number} breaks the record chain")
        expected = record.get("record_sha256")
        payload = dict(record)
        payload.pop("record_sha256", None)
        actual = T2.sha256_bytes(T2.canonical_bytes(payload))
        if expected != actual:
            raise AnalyzeError(f"journal line {line_number} record hash mismatch")
        previous = actual
        records.append(record)
    if records[0].get("kind") != "plan" or any(
        record.get("kind") != "observation" for record in records[1:]
    ):
        raise AnalyzeError("journal must contain one plan followed by observations")
    return records[0], records[1:], previous or ""


def _nonnegative(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise AnalyzeError(f"{context} must be a non-negative integer")
    return value


def percentile95(values: Iterable[float]) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def geometric_mean(values: Iterable[float]) -> float:
    values = list(values)
    if not values or any(value <= 0 or not math.isfinite(value) for value in values):
        return 0.0
    return math.exp(sum(math.log(value) for value in values) / len(values))


def _summary(observation: dict[str, Any]) -> dict[str, Any]:
    summary = observation.get("t7_summary")
    if type(summary) is not dict:
        raise AnalyzeError(
            f"observation {observation.get('sequence')} lacks T7 summary telemetry"
        )
    for key in (
        "build_ns",
        "score_ns",
        "replay_ns",
        "disagreements",
        "replay_failures",
        "fallbacks",
        "validations",
        "propagations",
    ):
        _nonnegative(summary.get(key), f"T7 summary {key}")
    return summary


def analyze(plan: dict[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any]:
    stage = plan.get("stage")
    if stage not in {"canary", "full"}:
        raise AnalyzeError("plan stage must be canary or full")
    expected_sources = 4 if stage == "canary" else 24
    expected_observations = expected_sources * len(ARMS) * REPEATS
    if (
        plan.get("sources") != expected_sources
        or plan.get("repeats") != REPEATS
        or plan.get("ordering") != "ABBA"
        or plan.get("proofs_required") is not True
        or plan.get("expected_observations") != expected_observations
        or len(observations) != expected_observations
    ):
        raise AnalyzeError(
            "plan or journal violates the fixed proved 2-arm/4-repeat contract"
        )

    by_pair: dict[tuple[int, int], dict[str, dict[str, Any]]] = {}
    seen_observations: set[tuple[int, int, str]] = set()
    source_populations: dict[int, str] = {}
    for sequence, observation in enumerate(observations):
        if observation.get("sequence") != sequence:
            raise AnalyzeError("observation sequences are not contiguous")
        arm = observation.get("arm")
        repeat = observation.get("repeat")
        index = observation.get("manifest_index")
        if arm not in ARMS or type(repeat) is not int or not 0 <= repeat < REPEATS:
            raise AnalyzeError(f"observation {sequence} has invalid arm/repeat")
        order_slot = observation.get("order_slot")
        expected_order = ARMS if repeat % 2 == 0 else tuple(reversed(ARMS))
        if (
            type(order_slot) is not int
            or order_slot not in {0, 1}
            or arm != expected_order[order_slot]
        ):
            raise AnalyzeError(f"observation {sequence} violates ABBA arm ordering")
        if type(index) is not int or index < 0:
            raise AnalyzeError(f"observation {sequence} has invalid manifest index")
        population = observation.get("population")
        if population not in {"M3", "T9", "A12"}:
            raise AnalyzeError(f"observation {sequence} has invalid population")
        previous_population = source_populations.setdefault(index, population)
        if previous_population != population:
            raise AnalyzeError(f"manifest index {index} changes population")
        if observation.get("outcome") not in {"correct", "wrong", "error", "missing"}:
            raise AnalyzeError(f"observation {sequence} has invalid outcome")
        identity = (index, repeat, arm)
        if identity in seen_observations:
            raise AnalyzeError(f"duplicate observation identity {identity}")
        seen_observations.add(identity)
        by_pair.setdefault((index, repeat), {})[arm] = observation
    if any(set(pair) != set(ARMS) for pair in by_pair.values()):
        raise AnalyzeError("one or more ABBA pairs lack an arm")
    if len({index for index, _ in by_pair}) != expected_sources:
        raise AnalyzeError("journal source coverage differs from its stage contract")
    expected_populations = (
        Counter({"M3": 3, "A12": 1})
        if stage == "canary"
        else Counter({"M3": 3, "T9": 9, "A12": 12})
    )
    if Counter(source_populations.values()) != expected_populations:
        raise AnalyzeError("journal population coverage differs from its stage contract")

    forbidden = Counter(
        {
            "wrong": sum(row.get("outcome") == "wrong" for row in observations),
            "error": sum(row.get("outcome") == "error" for row in observations),
            "missing": sum(
                row.get("outcome") == "missing"
                or type(row.get("t7_summary")) is not dict
                or row.get("transcript_sha256") is None
                for row in observations
            ),
            "replay_failure": 0,
            "certificate_failure": 0,
            "fallback": 0,
            "off_only_solve": 0,
        }
    )
    selector_ns = {arm: 0 for arm in ARMS}
    wall_ns = {arm: 0 for arm in ARMS}
    disagreements = 0
    for observation in observations:
        certificate = observation.get("certificate_status")
        expected_certificate = (
            "sat-model" if observation.get("result") == "sat" else "verified"
        )
        if (
            observation.get("validation_error") is not None
            or certificate != expected_certificate
        ):
            forbidden["certificate_failure"] += 1
        arm = observation["arm"]
        observation_wall_ns = _nonnegative(
            observation.get("wall_time_ns"), "wall_time_ns"
        )
        if observation_wall_ns == 0:
            raise AnalyzeError("wall_time_ns must be positive")
        wall_ns[arm] += observation_wall_ns
        if type(observation.get("t7_summary")) is not dict:
            continue
        summary = _summary(observation)
        forbidden["replay_failure"] += summary["replay_failures"]
        forbidden["fallback"] += summary["fallbacks"]
        selector_ns[arm] += summary["build_ns"] + summary["score_ns"] + summary["replay_ns"]
        disagreements += summary["disagreements"]

    paired_correct_t9 = True
    t9_ratios: list[float] = []
    a12_ratios: list[float] = []
    m3_totals = {
        arm: {"validations": 0, "propagations": 0} for arm in ARMS
    }
    coverage = {arm: Counter() for arm in ARMS}
    for pair in by_pair.values():
        off = pair["off"]
        on = pair["on"]
        off_correct = off.get("outcome") == "correct"
        on_correct = on.get("outcome") == "correct"
        population = off.get("population")
        if population != on.get("population"):
            raise AnalyzeError("paired observations disagree on population")
        coverage["off"][population] += int(off_correct)
        coverage["on"][population] += int(on_correct)
        if off_correct and not on_correct:
            forbidden["off_only_solve"] += 1
        if population == "T9":
            paired_correct_t9 &= off_correct and on_correct
            if off_correct and on_correct:
                t9_ratios.append(off["wall_time_ns"] / on["wall_time_ns"])
        elif population == "M3":
            if (
                off_correct
                and on_correct
                and type(off.get("t7_summary")) is dict
                and type(on.get("t7_summary")) is dict
            ):
                for arm, observation in pair.items():
                    summary = _summary(observation)
                    m3_totals[arm]["validations"] += summary["validations"]
                    m3_totals[arm]["propagations"] += summary["propagations"]
        elif population == "A12":
            if off_correct and on_correct:
                a12_ratios.append(on["wall_time_ns"] / off["wall_time_ns"])
        else:
            raise AnalyzeError(f"unknown population {population!r}")

    m3_reductions: dict[str, float] = {}
    for metric in ("validations", "propagations"):
        off_total = m3_totals["off"][metric]
        on_total = m3_totals["on"][metric]
        m3_reductions[metric] = (
            1.0 - on_total / off_total if off_total > 0 else -1.0
        )
    selector_fractions = {
        arm: selector_ns[arm] / wall_ns[arm] if wall_ns[arm] else math.inf
        for arm in ARMS
    }
    selector_total_fraction = sum(selector_ns.values()) / sum(wall_ns.values())
    t9_geometric_speed = geometric_mean(t9_ratios)
    a12_p95 = percentile95(a12_ratios)
    coverage_loss = {
        population: coverage["on"][population] < coverage["off"][population]
        for population in ("M3", "T9", "A12")
    }
    gates: dict[str, bool | None] = {
        "zero_forbidden": not any(forbidden.values()),
        "m3_reduction": any(
            m3_totals["off"][metric] > 0
            and 5 * m3_totals["on"][metric] <= 4 * m3_totals["off"][metric]
            for metric in ("validations", "propagations")
        ),
        "paired_correct_t9": paired_correct_t9 if stage == "full" else None,
        "t9_geometric_speed": t9_geometric_speed >= 1.10 if stage == "full" else None,
        "selector_fraction": selector_total_fraction < 0.05,
        "nonzero_disagreements": disagreements > 0,
        "a12_p95": a12_p95 is not None and a12_p95 <= 1.10,
        "a12_no_coverage_loss": not coverage_loss["A12"],
        "global_no_coverage_loss": not any(coverage_loss.values()),
    }
    required = [value for value in gates.values() if value is not None]
    return {
        "a12_p95_on_over_off": a12_p95,
        "coverage": {arm: dict(coverage[arm]) for arm in ARMS},
        "coverage_loss": coverage_loss,
        "disagreements": disagreements,
        "forbidden": dict(forbidden),
        "gates": gates,
        "m3_reductions": m3_reductions,
        "m3_totals": m3_totals,
        "observations": len(observations),
        "schema_version": AUDIT_SCHEMA,
        "selector_fractions": selector_fractions,
        "selector_total_fraction": selector_total_fraction,
        "stage": stage,
        "status": "pass" if all(required) else "stop",
        "t9_geometric_speed": t9_geometric_speed,
        "t9_pairs": len(t9_ratios),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("--out already exists")
    try:
        plan, observations, chain_head = load_journal(args.journal)
        audit = analyze(plan, observations)
        audit.update(
            {
                "contract_sha256": T2.sha256_file(CONTRACT),
                "journal": str(args.journal.resolve()),
                "journal_chain_head": chain_head,
                "journal_sha256": T2.sha256_file(args.journal),
                "summary_sha256": "",
            }
        )
        audit["summary_sha256"] = T2.sha256_bytes(T2.canonical_bytes(audit))
        T2.atomic_write(args.out, T2.canonical_bytes(audit))
    except (OSError, AnalyzeError, T2.ManifestError) as error:
        print(f"T7 analysis failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(audit, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0 if audit["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
