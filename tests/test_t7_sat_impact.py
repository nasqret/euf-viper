from __future__ import annotations

import copy
import hashlib
import importlib.util
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str) -> Any:
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUILDER = load_module(
    "test_t7_manifest_builder",
    "scripts/bench/build_t7_sat_impact_manifest.py",
)
ANALYZER = load_module(
    "test_t7_analyzer",
    "scripts/bench/analyze_t7_sat_impact.py",
)
VALIDATOR = load_module(
    "test_t7_transcript_validator",
    "scripts/cert/validate_t7_transcript.py",
)
COMPARE = load_module(
    "test_t7_compare",
    "scripts/bench/compare_t7_sat_impact.py",
)
OPPORTUNITY = load_module(
    "test_t7_opportunity",
    "scripts/bench/t7_shadow_opportunity_gate.py",
)
T2 = BUILDER.T2


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def source_row(root: Path, identifier: int, relative_path: str, status: str) -> dict[str, Any]:
    source = root / "corpus" / relative_path
    source.parent.mkdir(parents=True, exist_ok=True)
    payload = f"; {relative_path}\n(set-logic QF_UF)\n(check-sat)\n".encode()
    source.write_bytes(payload)
    return {
        "bytes": len(payload),
        "id": identifier,
        "logic": "QF_UF",
        "path": str(source),
        "relative_path": relative_path,
        "sha256": digest(payload),
        "status": status,
    }


class T7ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="t7 manifest ")
        self.root = Path(self.temporary.name)
        self.rows: list[dict[str, Any]] = []
        identifier = 0
        for relative_path, status in T2.TARGETS:
            self.rows.append(source_row(self.root, identifier, relative_path, status))
            identifier += 1
        for status in ("sat", "unsat"):
            for index in range(8):
                self.rows.append(
                    source_row(
                        self.root,
                        identifier,
                        f"QF_UF/t7-{status}/case-{index}.smt2",
                        status,
                    )
                )
                identifier += 1

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self, path: Path, rows: list[dict[str, Any]]) -> None:
        path.write_bytes(b"".join(T2.canonical_bytes(row) for row in rows))

    def test_fresh_manifest_is_deterministic_hash_bound_and_exactly_partitioned(self) -> None:
        first_source = self.root / "first-source.jsonl"
        second_source = self.root / "second-source.jsonl"
        self.write_manifest(first_source, list(reversed(self.rows)))
        self.write_manifest(second_source, self.rows[::2] + self.rows[1::2])
        first = BUILDER.build_rows(T2.load_manifest(first_source))
        second = BUILDER.build_rows(T2.load_manifest(second_source))
        self.assertEqual(first, second)
        self.assertEqual(len(first), 24)
        self.assertEqual(
            {population: sum(row["t7_population"] == population for row in first)
             for population in ("M3", "T9", "A12")},
            {"M3": 3, "T9": 9, "A12": 12},
        )
        self.assertEqual(
            tuple(row["relative_path"] for row in first if row["t7_population"] == "M3"),
            BUILDER.M3_PATHS,
        )
        self.assertTrue(all(row["schema_version"] == BUILDER.SCHEMA for row in first))
        self.assertTrue(all(row["source_row_sha256"] for row in first))
        for index, row in enumerate(first):
            BUILDER.validate_output_row(row, index)
        self.assertTrue(
            all(
                row["t7_selection_rank"] is None
                for row in first
                if row["t7_population"] != "A12"
            )
        )
        output = self.root / "t7.jsonl"
        output_bytes = T2.encode_jsonl(first)
        summary = BUILDER.build_summary(
            source_manifest=first_source,
            output_manifest=output,
            rows=first,
            output_bytes=output_bytes,
            source_verification=True,
        )
        expected = summary["summary_sha256"]
        summary["summary_sha256"] = ""
        self.assertEqual(expected, digest(T2.canonical_bytes(summary)))
        self.assertFalse(summary["missing_old_manifest_reused"])
        self.assertEqual(
            summary["construction"],
            "fresh-selection-from-exact-plan-atlas-t2-sources",
        )
        output.write_bytes(output_bytes)
        self.assertEqual(len(COMPARE.load_rows(output, "canary")), 4)
        self.assertEqual(len(COMPARE.load_rows(output, "full")), 24)
        mutated = copy.deepcopy(first)
        mutated[0]["source_row_sha256"] = "0" * 64
        tampered = self.root / "tampered-t7.jsonl"
        tampered.write_bytes(T2.encode_jsonl(mutated))
        with self.assertRaises(COMPARE.CompareError):
            COMPARE.load_rows(tampered, "full")
        contract = COMPARE.load_contract()
        self.assertEqual(contract["stages"]["canary"]["expected_observations"], 32)
        self.assertEqual(contract["stages"]["full"]["expected_observations"], 192)

    def test_missing_exact_target_and_source_tampering_fail_closed(self) -> None:
        manifest = self.root / "source.jsonl"
        self.write_manifest(manifest, self.rows[1:])
        with self.assertRaises(T2.ManifestError):
            BUILDER.build_rows(T2.load_manifest(manifest))

        self.write_manifest(self.root / "complete.jsonl", self.rows)
        Path(self.rows[0]["path"]).write_text("tampered", encoding="utf-8")
        with self.assertRaises(T2.ManifestError):
            T2.verify_source(self.rows[0], self.root / "complete.jsonl", None)


def synthetic_observations(stage: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    populations = ["M3"] * 3 + (["A12"] if stage == "canary" else ["T9"] * 9 + ["A12"] * 12)
    observations: list[dict[str, Any]] = []
    sequence = 0
    for index, population in enumerate(populations):
        for repeat in range(4):
            order = ("off", "on") if repeat % 2 == 0 else ("on", "off")
            for arm in order:
                if population == "M3":
                    wall = 1_000 if arm == "off" else 800
                    validations = 10 if arm == "off" else 8
                    propagations = 100 if arm == "off" else 80
                elif population == "T9":
                    wall = 1_200 if arm == "off" else 1_000
                    validations = 1
                    propagations = 10
                else:
                    wall = 1_000 if arm == "off" else 1_090
                    validations = 1
                    propagations = 10
                observations.append(
                    {
                        "arm": arm,
                        "certificate_status": "sat-model",
                        "expected_status": "sat",
                        "manifest_index": index,
                        "outcome": "correct",
                        "order_slot": order.index(arm),
                        "population": population,
                        "repeat": repeat,
                        "result": "sat",
                        "sequence": sequence,
                        "t7_summary": {
                            "build_ns": 10,
                            "disagreements": 1,
                            "fallbacks": 0,
                            "propagations": propagations,
                            "replay_failures": 0,
                            "replay_ns": 10,
                            "score_ns": 10,
                            "validations": validations,
                        },
                        "transcript_sha256": "a" * 64,
                        "validation_error": None,
                        "wall_time_ns": wall,
                    }
                )
                sequence += 1
    plan = {
        "expected_observations": len(observations),
        "ordering": "ABBA",
        "proofs_required": True,
        "repeats": 4,
        "sources": len(populations),
        "stage": stage,
    }
    return plan, observations


class T7AnalyzerTests(unittest.TestCase):
    def test_canary_and_full_contracts_apply_exact_nonvacuous_gates(self) -> None:
        canary = ANALYZER.analyze(*synthetic_observations("canary"))
        self.assertEqual(canary["status"], "pass")
        self.assertIsNone(canary["gates"]["t9_geometric_speed"])
        self.assertAlmostEqual(canary["m3_reductions"]["validations"], 0.2)

        full = ANALYZER.analyze(*synthetic_observations("full"))
        self.assertEqual(full["status"], "pass")
        self.assertGreaterEqual(full["t9_geometric_speed"], 1.10)
        self.assertLessEqual(full["a12_p95_on_over_off"], 1.10)
        self.assertLess(full["selector_total_fraction"], 0.05)

    def test_wrong_missing_certificate_fallback_and_off_only_are_fatal(self) -> None:
        plan, observations = synthetic_observations("full")
        mutated = copy.deepcopy(observations)
        on = next(row for row in mutated if row["arm"] == "on")
        on["outcome"] = "error"
        on["certificate_status"] = "failed"
        on["validation_error"] = "mutated"
        on["t7_summary"]["fallbacks"] = 1
        audit = ANALYZER.analyze(plan, mutated)
        self.assertEqual(audit["status"], "stop")
        self.assertGreater(audit["forbidden"]["error"], 0)
        self.assertGreater(audit["forbidden"]["certificate_failure"], 0)
        self.assertGreater(audit["forbidden"]["fallback"], 0)
        self.assertGreater(audit["forbidden"]["off_only_solve"], 0)

    def test_incomplete_pair_and_insufficient_m3_reduction_cannot_pass(self) -> None:
        plan, observations = synthetic_observations("canary")
        with self.assertRaises(ANALYZER.AnalyzeError):
            ANALYZER.analyze(plan, observations[:-1])
        for row in observations:
            if row["population"] == "M3" and row["arm"] == "on":
                row["t7_summary"]["validations"] = 9
                row["t7_summary"]["propagations"] = 90
        audit = ANALYZER.analyze(plan, observations)
        self.assertEqual(audit["status"], "stop")
        self.assertFalse(audit["gates"]["m3_reduction"])

    def test_missing_telemetry_is_a_counted_stop_not_a_nonfinite_audit(self) -> None:
        plan, observations = synthetic_observations("full")
        for row in observations:
            if row["population"] == "A12":
                row["outcome"] = "error"
                row["t7_summary"] = None
                row["transcript_sha256"] = None
        audit = ANALYZER.analyze(plan, observations)
        self.assertEqual(audit["status"], "stop")
        self.assertGreater(audit["forbidden"]["missing"], 0)
        self.assertIsNone(audit["a12_p95_on_over_off"])
        T2.canonical_bytes(audit)

    def test_chain_hashed_analyzer_journal_rejects_rehashed_content_drift(self) -> None:
        plan, observations = synthetic_observations("canary")
        with tempfile.TemporaryDirectory(prefix="t7 journal ") as temporary:
            journal = Path(temporary) / "canary.jsonl"
            with COMPARE.JournalWriter(journal) as writer:
                writer.append(
                    {
                        **plan,
                        "kind": "plan",
                        "schema": ANALYZER.JOURNAL_SCHEMA,
                    }
                )
                for observation in observations:
                    writer.append(
                        {
                            **observation,
                            "kind": "observation",
                            "schema": ANALYZER.JOURNAL_SCHEMA,
                        }
                    )
            loaded_plan, loaded_observations, _ = ANALYZER.load_journal(journal)
            self.assertEqual(
                ANALYZER.analyze(loaded_plan, loaded_observations)["status"], "pass"
            )
            raw = bytearray(journal.read_bytes())
            marker = raw.find(b'"wall_time_ns":1000')
            self.assertGreaterEqual(marker, 0)
            raw[marker + len(b'"wall_time_ns":')] = ord("9")
            drifted = journal.with_name("drifted.jsonl")
            drifted.write_bytes(raw)
            with self.assertRaises(ANALYZER.AnalyzeError):
                ANALYZER.load_journal(drifted)

    def test_shadow_qualification_requires_two_distinct_minimum_width_candidates(self) -> None:
        records = [
            {"kind": "header"},
            {
                "candidates": [
                    {"clause": [-3, -1], "replay_valid": True},
                    {"clause": [-4, -2], "replay_valid": True},
                    {"clause": [-5, -4, -1], "replay_valid": True},
                ],
                "disagreement": True,
                "event": 0,
                "minimum_width": 2,
            },
            {"kind": "summary"},
        ]
        self.assertEqual(OPPORTUNITY.qualifying_conflicts(records), [0])
        records[1]["candidates"][1]["replay_valid"] = False
        self.assertEqual(OPPORTUNITY.qualifying_conflicts(records), [])


UNSAT_SOURCE = """
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(declare-fun f (U) U)
(assert (= a b))
(assert (distinct (f a) (f b)))
(check-sat)
"""


def chain_records(records: list[dict[str, Any]]) -> bytes:
    previous = bytes(32)
    previous_hex = "0" * 64
    output = bytearray()
    for sequence, original in enumerate(records):
        record = copy.deepcopy(original)
        record["sequence"] = sequence
        record["previous_sha256"] = previous_hex
        digest_bytes = hashlib.sha256(previous + VALIDATOR.canonical_bytes(record)).digest()
        record["record_sha256"] = digest_bytes.hex()
        output.extend(VALIDATOR.canonical_bytes(record))
        previous = digest_bytes
        previous_hex = digest_bytes.hex()
    return bytes(output)


def valid_transcript_records() -> tuple[Any, list[dict[str, Any]]]:
    problem = VALIDATOR.parse_and_encode(UNSAT_SOURCE, direct_root_cnf=True)
    first = problem.atom_for_variable(1)
    second = problem.atom_for_variable(2)
    facts = [
        {
            "decision_level": 0,
            "kind": "disequality",
            "left": problem.true_term,
            "literal": None,
            "ordinal": 0,
            "right": problem.false_term,
        },
        {
            "decision_level": 0,
            "kind": "equality",
            "left": first.left,
            "literal": 1,
            "ordinal": 1,
            "right": first.right,
        },
        {
            "decision_level": 0,
            "kind": "disequality",
            "left": second.left,
            "literal": -2,
            "ordinal": 2,
            "right": second.right,
        },
    ]
    candidate = {
        "antecedents": [-2, 1],
        "clause": [-1, 2],
        "forests": sorted(VALIDATOR.FORESTS),
        "metrics": {
            "current_level_literals": 2,
            "historical_reuse": 0,
            "lbd": 1,
            "second_highest_level": 0,
        },
        "replay_valid": True,
    }
    event = {
        "active_facts": facts,
        "build_ns": 11,
        "candidate_duplicates": 3,
        "candidates": [candidate],
        "decision_level": 0,
        "disagreement": False,
        "disposition": "emitted",
        "event": 0,
        "kind": "conflict",
        "minimum_width": 2,
        "off_index": 0,
        "on_index": 0,
        "replay_ns": 13,
        "schema": VALIDATOR.SCHEMA,
        "score_ns": 17,
        "selected_index": 0,
        "trail_sha256": digest(VALIDATOR.canonical_bytes(facts)),
    }
    header = {
        "backend": "cadical-rollback",
        "base_clauses": len(problem.clauses),
        "base_cnf_sha256": VALIDATOR.base_cnf_hash(problem),
        "base_variables": problem.variable_count,
        "direct_negated_root": False,
        "direct_root_cnf": True,
        "kind": "header",
        "mode": "off",
        "schema": VALIDATOR.SCHEMA,
    }
    summary = {
        "backtracks": 0,
        "build_ns": 11,
        "candidate_duplicates": 3,
        "decisions": 0,
        "disagreements": 0,
        "fallbacks": 0,
        "final_model": None,
        "kind": "summary",
        "mode": "off",
        "model_checks": 0,
        "persistent_duplicates": 0,
        "propagations": 2,
        "replay_failures": 0,
        "replay_ns": 13,
        "result": "unsat",
        "sat_conflicts": 0,
        "schema": VALIDATOR.SCHEMA,
        "score_ns": 17,
        "selected_suffix": [[-1, 2]],
        "selected_suffix_sha256": digest(VALIDATOR.canonical_bytes([[-1, 2]])),
        "theory_conflicts": 1,
        "validations": 0,
    }
    return problem, [header, event, summary]


class T7TranscriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="t7 transcript ")
        self.root = Path(self.temporary.name)
        self.source = self.root / "case.smt2"
        self.source.write_text(UNSAT_SOURCE, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, records: list[dict[str, Any]], name: str = "run.jsonl") -> Path:
        path = self.root / name
        path.write_bytes(chain_records(records))
        return path

    def test_independent_checker_accepts_valid_chain_and_direct_root_cnf(self) -> None:
        problem, records = valid_transcript_records()
        self.assertEqual(problem.clauses, ((1,), (-2,)))
        report = VALIDATOR.validate_transcript(self.source, self.write(records))
        self.assertEqual(report["result"], "unsat")
        self.assertEqual(report["candidate_clauses"], 1)
        self.assertEqual(report["certificate_status"], "not-requested")

    def test_rehashed_clause_metric_and_forest_mutations_are_rejected(self) -> None:
        problem, records = valid_transcript_records()
        mutations = []
        clause = copy.deepcopy(records)
        clause[1]["candidates"][0]["clause"] = [-1, 3]
        mutations.append(clause)
        metric = copy.deepcopy(records)
        metric[1]["candidates"][0]["metrics"]["lbd"] = 2
        mutations.append(metric)
        forest = copy.deepcopy(records)
        forest[1]["candidates"][0]["forests"] = ["trail"] * 4
        mutations.append(forest)
        active_fact = copy.deepcopy(records)
        active_fact[1]["active_facts"][1]["left"] = problem.false_term
        active_fact[1]["trail_sha256"] = digest(
            VALIDATOR.canonical_bytes(active_fact[1]["active_facts"])
        )
        mutations.append(active_fact)
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(VALIDATOR.T7TranscriptError):
                    VALIDATOR.validate_transcript(
                        self.source, self.write(mutation, f"mutation-{index}.jsonl")
                    )

    def test_sat_model_is_checked_against_base_cnf_euf_and_suffix(self) -> None:
        source = self.root / "sat.smt2"
        source.write_text(
            """
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(assert (= a b))
(check-sat)
""",
            encoding="utf-8",
        )
        problem = VALIDATOR.parse_and_encode(
            source.read_text(encoding="utf-8"), direct_root_cnf=True
        )
        assignment = None
        for values in itertools.product((False, True), repeat=problem.variable_count):
            candidate = [
                variable if value else -variable
                for variable, value in enumerate(values, start=1)
            ]
            try:
                VALIDATOR.validate_total_assignment(problem, candidate)
            except VALIDATOR.IndependentQfufError:
                continue
            assignment = candidate
            break
        self.assertIsNotNone(assignment)
        header = {
            "backend": "cadical-rollback",
            "base_clauses": len(problem.clauses),
            "base_cnf_sha256": VALIDATOR.base_cnf_hash(problem),
            "base_variables": problem.variable_count,
            "direct_negated_root": False,
            "direct_root_cnf": True,
            "kind": "header",
            "mode": "on",
            "schema": VALIDATOR.SCHEMA,
        }
        summary = {
            "backtracks": 0,
            "build_ns": 0,
            "candidate_duplicates": 0,
            "decisions": 0,
            "disagreements": 0,
            "fallbacks": 0,
            "final_model": assignment,
            "kind": "summary",
            "mode": "on",
            "model_checks": 0,
            "persistent_duplicates": 0,
            "propagations": 0,
            "replay_failures": 0,
            "replay_ns": 0,
            "result": "sat",
            "sat_conflicts": 0,
            "schema": VALIDATOR.SCHEMA,
            "score_ns": 0,
            "selected_suffix": [],
            "selected_suffix_sha256": digest(VALIDATOR.canonical_bytes([])),
            "theory_conflicts": 0,
            "validations": 1,
        }
        transcript = self.write([header, summary], "sat.jsonl")
        report = VALIDATOR.validate_transcript(source, transcript)
        self.assertEqual(report["certificate_status"], "sat-model")

        mutated = copy.deepcopy(summary)
        unit = next(clause[0] for clause in problem.clauses if len(clause) == 1)
        mutated["final_model"][abs(unit) - 1] = -unit
        with self.assertRaisesRegex(VALIDATOR.T7TranscriptError, "base CNF"):
            VALIDATOR.validate_transcript(
                source, self.write([header, mutated], "sat-mutated.jsonl")
            )

    def test_broken_chain_and_missing_requested_drat_fail_closed(self) -> None:
        _, records = valid_transcript_records()
        valid = self.write(records)
        raw = bytearray(valid.read_bytes())
        raw[-3] = ord("0") if raw[-3] != ord("0") else ord("1")
        broken = self.root / "broken.jsonl"
        broken.write_bytes(raw)
        with self.assertRaises(VALIDATOR.T7TranscriptError):
            VALIDATOR.load_chain(broken)
        with self.assertRaisesRegex(
            VALIDATOR.T7TranscriptError, "requested UNSAT proof evidence is absent"
        ):
            VALIDATOR.validate_transcript(
                self.source,
                valid,
                proof_cache=self.root / "proof-cache",
                require_unsat_proof=True,
            )


if __name__ == "__main__":
    unittest.main()
