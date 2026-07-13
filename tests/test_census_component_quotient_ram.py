from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "census_component_quotient_ram.py"
SPEC = importlib.util.spec_from_file_location("census_component_quotient_ram", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CENSUS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CENSUS
SPEC.loader.exec_module(CENSUS)


def query(body: str) -> str:
    return f"(set-logic QF_UF)\n{body.strip()}\n(check-sat)\n"


def bits(circuit: object, width: int) -> tuple[int, ...]:
    return tuple(circuit.input() for _ in range(width))


def input_assignment(bit_variables: tuple[int, ...], value: int) -> dict[int, bool]:
    return {
        variable: bool((value >> index) & 1)
        for index, variable in enumerate(bit_variables)
    }


def literal_value(literal: int, assignment: dict[int, bool]) -> bool:
    value = assignment[abs(literal)]
    return value if literal > 0 else not value


def decoded(bit_literals: tuple[int, ...], assignment: dict[int, bool]) -> int:
    return sum(
        int(literal_value(literal, assignment)) << index
        for index, literal in enumerate(bit_literals)
    )


class CircuitTemplateTests(unittest.TestCase):
    def test_gate_templates_are_exhaustive_and_count_exact(self) -> None:
        gates = (
            ("and2", CENSUS.AND2, lambda a, b: a and b),
            ("or2", CENSUS.OR2, lambda a, b: a or b),
            ("xor2", CENSUS.XOR2, lambda a, b: a != b),
            ("xnor2", CENSUS.XNOR2, lambda a, b: a == b),
        )
        for method_name, expected_counts, expected_value in gates:
            for left_value, right_value in itertools.product((False, True), repeat=2):
                circuit = CENSUS.CnfCircuit()
                left = circuit.input()
                right = circuit.input()
                output = getattr(circuit, method_name)(left, right)
                assignment = circuit.evaluate(
                    {left: left_value, right: right_value}
                )
                self.assertEqual(assignment[output], expected_value(left_value, right_value))
                self.assertTrue(circuit.clauses_hold(assignment))
                mutated = dict(assignment)
                mutated[output] = not mutated[output]
                self.assertFalse(circuit.clauses_hold(mutated))
                self.assertEqual(circuit.counts(), expected_counts)

    def test_mux_template_is_exhaustive_and_count_exact(self) -> None:
        for selector_value, true_value, false_value in itertools.product(
            (False, True), repeat=3
        ):
            circuit = CENSUS.CnfCircuit()
            selector = circuit.input()
            when_true = circuit.input()
            when_false = circuit.input()
            output = circuit.mux2(selector, when_true, when_false)
            assignment = circuit.evaluate(
                {
                    selector: selector_value,
                    when_true: true_value,
                    when_false: false_value,
                }
            )
            self.assertEqual(
                assignment[output], true_value if selector_value else false_value
            )
            self.assertTrue(circuit.clauses_hold(assignment))
            mutated = dict(assignment)
            mutated[output] = not mutated[output]
            self.assertFalse(circuit.clauses_hold(mutated))
            self.assertEqual(circuit.counts(), CENSUS.MUX2)

    def test_increment_templates_are_exhaustive_through_width_five(self) -> None:
        for width in range(1, 6):
            for value in range(1 << width):
                circuit = CENSUS.CnfCircuit()
                input_bits = bits(circuit, width)
                output_bits = CENSUS.build_increment_circuit(circuit, input_bits)
                assignment = circuit.evaluate(input_assignment(input_bits, value))
                self.assertTrue(circuit.clauses_hold(assignment))
                self.assertEqual(decoded(output_bits, assignment), (value + 1) % (1 << width))
                self.assertEqual(circuit.counts(), CENSUS.increment_counts(width))

    def test_unsigned_comparator_is_exhaustive_through_width_four(self) -> None:
        for width in range(1, 5):
            for left_value, right_value in itertools.product(range(1 << width), repeat=2):
                circuit = CENSUS.CnfCircuit()
                left = bits(circuit, width)
                right = bits(circuit, width)
                output = CENSUS.build_unsigned_greater_circuit(circuit, left, right)
                inputs = input_assignment(left, left_value)
                inputs.update(input_assignment(right, right_value))
                assignment = circuit.evaluate(inputs)
                self.assertTrue(circuit.clauses_hold(assignment))
                self.assertEqual(assignment[output], left_value > right_value)
                self.assertEqual(circuit.counts(), CENSUS.unsigned_greater_counts(width))

    def test_equality_link_is_exhaustive_through_width_three(self) -> None:
        for width in range(1, 4):
            for left_value, right_value, equality_value in itertools.product(
                range(1 << width), range(1 << width), (False, True)
            ):
                circuit = CENSUS.CnfCircuit()
                equality = circuit.input()
                left = bits(circuit, width)
                right = bits(circuit, width)
                CENSUS.build_equality_link_circuit(circuit, equality, left, right)
                inputs = {equality: equality_value}
                inputs.update(input_assignment(left, left_value))
                inputs.update(input_assignment(right, right_value))
                assignment = circuit.evaluate(inputs)
                self.assertEqual(
                    circuit.clauses_hold(assignment),
                    equality_value == (left_value == right_value),
                )
                self.assertEqual(circuit.counts(), CENSUS.equality_link_counts(width))

    def test_restricted_growth_sizes_through_eight_and_small_semantics(self) -> None:
        for term_count in range(1, 9):
            width = CENSUS.component_width(term_count)
            circuit = CENSUS.CnfCircuit()
            codes = tuple(bits(circuit, width) for _ in range(term_count))
            CENSUS.build_restricted_growth_circuit(circuit, codes)
            expected = CENSUS.restricted_growth_counts(term_count, width)
            self.assertEqual(circuit.counts(), expected)

        for term_count in range(1, 5):
            width = CENSUS.component_width(term_count)
            for values in itertools.product(range(1 << width), repeat=term_count):
                circuit = CENSUS.CnfCircuit()
                codes = tuple(bits(circuit, width) for _ in range(term_count))
                CENSUS.build_restricted_growth_circuit(circuit, codes)
                inputs: dict[int, bool] = {}
                for code, value in zip(codes, values):
                    inputs.update(input_assignment(code, value))
                assignment = circuit.evaluate(inputs)
                actual = circuit.clauses_hold(assignment)
                prefix_max = 0
                expected = values[0] == 0
                for value in values[1:]:
                    expected &= value <= prefix_max + 1
                    prefix_max = max(prefix_max, value)
                self.assertEqual(actual, expected, values)


class SortingNetworkTests(unittest.TestCase):
    def test_bitonic_network_sorts_every_binary_key_sequence_through_eight(self) -> None:
        for record_count in (1, 2, 4, 8):
            self.assertEqual(
                len(CENSUS.bitonic_network(record_count)),
                CENSUS.bitonic_comparator_count(record_count),
            )
            for keys in itertools.product((0, 1), repeat=record_count):
                records = [(key, index) for index, key in enumerate(keys)]
                output = CENSUS.simulate_bitonic_sort(records)
                self.assertEqual([key for key, _ in output], sorted(keys))
                self.assertEqual(
                    sorted(payload for _, payload in output), list(range(record_count))
                )

    def test_padding_flag_places_real_records_before_sentinels(self) -> None:
        records = [
            ((0, 3), "real-3"),
            ((0, 1), "real-1"),
            ((0, 2), "real-2"),
            ((1, 0), "padding"),
        ]
        output = CENSUS.simulate_bitonic_sort(records)
        self.assertEqual(
            [payload for _, payload in output],
            ["real-1", "real-2", "real-3", "padding"],
        )


class ProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.caps = CENSUS.load_campaign_lock().caps

    def project(self, body: str) -> dict[str, object]:
        problem = CENSUS.qfuf.parse_and_encode(query(body))
        return CENSUS.project_problem(problem, self.caps)

    def test_k3_has_exact_three_transitivity_clauses(self) -> None:
        projection = self.project(
            """
            (declare-sort U 0)
            (declare-const a U) (declare-const b U) (declare-const c U)
            (assert (or (= a b) (= a c) (= b c)))
            """
        )
        shape = projection["shape"]
        transitivity = projection["counts"]["eager"]["categories"]["transitivity"]
        self.assertEqual(shape["completed_equality_triangles"], 1)
        self.assertEqual(transitivity["clauses"], 3)
        self.assertEqual(transitivity["literal_slots"], 9)
        self.assertEqual(transitivity["watch_entries"], 6)

    def test_unary_three_record_ackermann_count_is_exact(self) -> None:
        projection = self.project(
            """
            (declare-sort U 0)
            (declare-fun f (U) U)
            (declare-const a U) (declare-const b U) (declare-const c U)
            (assert (distinct (f a) (f b) (f c)))
            """
        )
        symbol = projection["symbols"][0]
        self.assertEqual(symbol["ackermann_pairs"], 3)
        self.assertEqual(symbol["arguments"][0]["differing_application_pairs"], 3)
        self.assertEqual(symbol["eager_ackermann"], {"clauses": 3, "literal_slots": 6})

    def test_boolean_result_uses_two_functionality_clauses_per_pair(self) -> None:
        projection = self.project(
            """
            (declare-sort U 0)
            (declare-fun p (U) Bool)
            (declare-const a U) (declare-const b U) (declare-const c U)
            (assert (or (p a) (not (p b)) (p c)))
            """
        )
        symbol = projection["symbols"][0]
        self.assertEqual(symbol["result"]["channel"], "boolean")
        self.assertEqual(symbol["eager_ackermann"], {"clauses": 6, "literal_slots": 18})
        self.assertTrue(projection["decoder"]["complete"])

    def test_mixed_sorts_never_share_component_namespaces(self) -> None:
        projection = self.project(
            """
            (declare-sort U 0) (declare-sort V 0)
            (declare-fun f (U) U) (declare-fun g (V) V)
            (declare-const ua U) (declare-const ub U)
            (declare-const va V) (declare-const vb V)
            (assert (distinct (f ua) (f ub)))
            (assert (distinct (g va) (g vb)))
            """
        )
        components = projection["components"]
        self.assertEqual({row["sort"]["name"] for row in components}, {"U", "V"})
        for symbol in projection["symbols"]:
            expected_sort = symbol["signature"]["argument_sorts"][0]
            self.assertEqual(symbol["arguments"][0]["sort"], expected_sort)
            self.assertEqual(symbol["signature"]["result_sort"], expected_sort)

    def test_decoder_telemetry_is_structural_and_complete(self) -> None:
        projection = self.project(
            """
            (declare-sort U 0)
            (declare-fun f (U U) U)
            (declare-const a U) (declare-const b U)
            (assert (distinct (f a b) (f b a)))
            """
        )
        decoder = projection["decoder"]
        self.assertTrue(decoder["complete"])
        self.assertEqual(decoder["domain_value"], "typed_tuple_sort_id_component_id_class_code")
        self.assertEqual(decoder["counts"]["argument_code_lookups"], 4)
        self.assertEqual(decoder["counts"]["records_checked"], 2)
        self.assertNotIn("time", json.dumps(decoder).lower())

    def test_preregistered_caps_fail_with_named_observed_counts(self) -> None:
        problem = CENSUS.qfuf.parse_and_encode(
            query("(declare-sort U 0) (declare-const a U) (assert (= a a))")
        )
        values = CENSUS.asdict(self.caps)
        values["max_terms"] = 1
        with self.assertRaises(CENSUS.ProjectionCap) as raised:
            CENSUS.project_problem(problem, CENSUS.Caps(**values))
        self.assertEqual(raised.exception.code, "terms")
        self.assertEqual(raised.exception.limit, 1)
        self.assertEqual(raised.exception.observed, len(problem.terms))

    def test_symbol_cap_covers_internal_nullary_unused_and_macro_functions(self) -> None:
        problem = CENSUS.qfuf.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-fun unused (U) U)
                (declare-const unused_constant U)
                (define-fun identity ((x U)) U x)
                (assert true)
                """
            )
        )
        values = CENSUS.asdict(self.caps)
        values["max_symbols"] = len(problem.functions) - 1
        with self.assertRaises(CENSUS.ProjectionCap) as raised:
            CENSUS.project_problem(problem, CENSUS.Caps(**values))
        self.assertEqual(raised.exception.code, "symbols")
        self.assertEqual(raised.exception.observed, len(problem.functions))

        values["max_symbols"] = len(problem.functions)
        projection = CENSUS.project_problem(problem, CENSUS.Caps(**values))
        self.assertEqual(
            projection["shape"]["function_declarations"], len(problem.functions)
        )


class DecoderOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.caps = CENSUS.load_campaign_lock().caps
        cls.receipt = CENSUS.run_bounded_decoder_oracle()

    def test_registered_oracle_is_exhaustive_and_feature_complete(self) -> None:
        receipt = self.receipt
        self.assertTrue(receipt.executed)
        self.assertTrue(receipt.passed)
        self.assertEqual(receipt.fixture_names, CENSUS.DECODER_ORACLE_FIXTURES)
        self.assertEqual(receipt.assignments_examined, 316)
        self.assertEqual(receipt.assignments_accepted, 179)
        self.assertEqual(receipt.assignments_rejected, 137)
        self.assertEqual(receipt.euf_satisfaction_checks, 2998)
        self.assertEqual(receipt.padded_assignments, 170)
        self.assertEqual(receipt.repeated_key_assignments, 55)
        self.assertEqual(receipt.arbitrary_default_probes, 1608)
        self.assertEqual(receipt.non_nullary_default_probes, 1608)
        self.assertEqual(
            set(receipt.exercised_features),
            set(CENSUS.DECODER_ORACLE_REQUIRED_FEATURES),
        )
        self.assertEqual(receipt.sha256, CENSUS.DECODER_ORACLE_FROZEN_SHA256)
        self.assertEqual(
            CENSUS._decoder_oracle_counts(receipt),
            CENSUS.DECODER_ORACLE_FROZEN_COUNTS,
        )

    def test_projection_fails_closed_when_oracle_did_not_run_or_failed(self) -> None:
        problem = CENSUS.qfuf.parse_and_encode(query("(assert true)"))
        not_run = replace(self.receipt, executed=False, passed=False)
        failed = replace(self.receipt, passed=False)
        with self.assertRaisesRegex(CENSUS.ProjectionInvariant, "was not run"):
            CENSUS.project_problem(problem, self.caps, not_run)
        with self.assertRaisesRegex(CENSUS.ProjectionInvariant, "did not pass"):
            CENSUS.project_problem(problem, self.caps, failed)

    def test_fabricated_and_feature_contradictory_receipts_are_rejected(self) -> None:
        fabricated = replace(
            self.receipt,
            assignments_examined=318,
            assignments_accepted=181,
        )
        contradictory = replace(self.receipt, padded_assignments=0)
        with self.assertRaisesRegex(CENSUS.ProjectionInvariant, "counter drift"):
            CENSUS._require_decoder_oracle(fabricated)
        with self.assertRaisesRegex(
            CENSUS.ProjectionInvariant, "feature/counter contradiction"
        ):
            CENSUS._require_decoder_oracle(contradictory)

    def test_decoder_reconstructs_typed_model_and_rejects_false_atom_claim(self) -> None:
        source = dict(CENSUS._decoder_oracle_sources())[
            "boolean_multisort_padding_defaults"
        ]
        problem = CENSUS.qfuf.parse_and_encode(source)
        groups = CENSUS._application_groups(problem)
        components, _ = CENSUS.build_components(problem, groups, self.caps)
        component_codes = {
            term_id: 0 for component in components for term_id in component.terms
        }
        boolean_values = {
            term.id: False
            for term in problem.terms
            if term.sort == CENSUS.qfuf.BOOL_SORT
        }
        boolean_values[problem.true_term] = True
        term_values = CENSUS._decoder_term_values(
            problem, components, component_codes, boolean_values
        )
        atom_values = CENSUS._semantic_atom_values(problem, term_values)
        validation = CENSUS.reconstruct_decoder_model(
            problem,
            components,
            groups,
            component_codes,
            boolean_values,
            atom_values,
        )
        self.assertGreater(validation.repeated_key_pairs, 0)
        self.assertEqual(validation.padding_records, 1)
        self.assertGreater(validation.non_nullary_default_probes, 0)
        empty_sort = next(sort.id for sort in problem.sorts if sort.name == "W")
        self.assertEqual(validation.model.sort_defaults[empty_sort], (empty_sort, -1, 0))

        corrupted_atoms = dict(atom_values)
        first_atom = min(corrupted_atoms)
        corrupted_atoms[first_atom] = not corrupted_atoms[first_atom]
        with self.assertRaisesRegex(
            CENSUS.ProjectionInvariant, "does not satisfy the projected atom"
        ):
            CENSUS.reconstruct_decoder_model(
                problem,
                components,
                groups,
                component_codes,
                boolean_values,
                corrupted_atoms,
            )

    def test_decoder_rejects_collapsed_boolean_carrier(self) -> None:
        problem = CENSUS.qfuf.parse_and_encode(query("(assert true)"))
        groups = CENSUS._application_groups(problem)
        components, _ = CENSUS.build_components(problem, groups, self.caps)
        boolean_values = {
            term.id: False
            for term in problem.terms
            if term.sort == CENSUS.qfuf.BOOL_SORT
        }
        with self.assertRaisesRegex(
            CENSUS.DecoderAssignmentRejected, "does not distinguish"
        ):
            CENSUS._decoder_term_values(problem, components, {}, boolean_values)


class CountsInvariantTests(unittest.TestCase):
    def test_unit_binary_and_long_clause_layout_is_feasible(self) -> None:
        self.assertEqual(
            CENSUS.Counts(
                clauses=3,
                literal_slots=7,
                unit_clauses=1,
                watch_entries=4,
            ).clauses,
            3,
        )

    def test_all_count_semantic_contradictions_are_rejected(self) -> None:
        malformed = (
            {"variables": -1},
            {"variables": True},
            {"clauses": 1, "literal_slots": 2, "unit_clauses": 2},
            {"clauses": 2, "literal_slots": 2, "unit_clauses": 1},
            {"clauses": 1, "literal_slots": 2, "unit_clauses": 1},
            {"clauses": 1, "literal_slots": 2, "watch_entries": 1},
        )
        for fields in malformed:
            with self.subTest(fields=fields), self.assertRaises(CENSUS.CensusError):
                CENSUS.Counts(**fields)


def synthetic_record(
    *,
    eager: int,
    candidate: int,
    variables: tuple[int, int] = (100, 100),
    eager_overrides: dict[str, int] | None = None,
    candidate_overrides: dict[str, int] | None = None,
) -> dict[str, object]:
    def total(
        value: int, variable_value: int, overrides: dict[str, int] | None
    ) -> dict[str, int]:
        counts = {
            "variables": variable_value,
            "clauses": value,
            "literal_slots": 2 * value,
            "unit_clauses": 0,
            "watch_entries": 2 * value,
        }
        counts.update(overrides or {})
        return counts

    return {
        "counts": {
            "eager": {"total": total(eager, variables[0], eager_overrides)},
            "component_quotient_ram": {
                "total": total(candidate, variables[1], candidate_overrides)
            },
        }
    }


class GateBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock = CENSUS.load_campaign_lock()

    def test_exact_twenty_five_percent_reduction_passes(self) -> None:
        record = synthetic_record(eager=100, candidate=75)
        gate = CENSUS._opportunity_metric_gate([record], "clauses", self.lock)
        self.assertTrue(gate["pass"])
        self.assertEqual(gate["weighted_ratio_ppm"], 750000)

    def test_one_count_above_reduction_boundary_fails(self) -> None:
        record = synthetic_record(eager=100, candidate=76)
        gate = CENSUS._opportunity_metric_gate([record], "clauses", self.lock)
        self.assertFalse(gate["pass"])

    def test_exact_variable_ratio_boundary_passes_and_next_count_fails(self) -> None:
        passing = synthetic_record(eager=100, candidate=75, variables=(100, 125))
        failing = synthetic_record(eager=100, candidate=75, variables=(100, 126))
        self.assertTrue(CENSUS._variable_gate([passing], self.lock)["pass"])
        self.assertFalse(CENSUS._variable_gate([failing], self.lock)["pass"])

    def test_watch_only_win_cannot_hide_333x_literal_and_clause_regression(self) -> None:
        adversarial = synthetic_record(
            eager=1000,
            candidate=1500,
            eager_overrides={
                "clauses": 1000,
                "literal_slots": 3000,
                "unit_clauses": 0,
                "watch_entries": 2000,
            },
            candidate_overrides={
                "clauses": 1500,
                "literal_slots": 999000,
                "unit_clauses": 1000,
                "watch_entries": 1000,
            },
        )
        gate = CENSUS._family_opportunity_gate([adversarial], self.lock)
        self.assertTrue(gate["reductions"]["watch_entries"]["pass"])
        self.assertTrue(gate["primary_reduction_pass"])
        self.assertEqual(
            gate["ram_no_regression"]["literal_slots"]["weighted_ratio_ppm"],
            333_000_000,
        )
        self.assertFalse(gate["ram_no_regression"]["literal_slots"]["pass"])
        self.assertFalse(gate["ram_no_regression"]["clauses"]["pass"])
        self.assertFalse(gate["ram_no_regression_pass"])
        self.assertFalse(gate["pass"])

    def test_watch_only_win_remains_allowed_without_ram_regression(self) -> None:
        controlled = synthetic_record(
            eager=100,
            candidate=100,
            eager_overrides={
                "clauses": 100,
                "literal_slots": 300,
                "unit_clauses": 0,
                "watch_entries": 200,
            },
            candidate_overrides={
                "clauses": 100,
                "literal_slots": 225,
                "unit_clauses": 25,
                "watch_entries": 150,
            },
        )
        gate = CENSUS._family_opportunity_gate([controlled], self.lock)
        self.assertFalse(gate["reductions"]["clauses"]["pass"])
        self.assertTrue(gate["reductions"]["watch_entries"]["pass"])
        self.assertTrue(gate["ram_no_regression"]["clauses"]["pass"])
        self.assertTrue(gate["ram_no_regression"]["literal_slots"]["pass"])
        self.assertTrue(gate["pass"])


class HashChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock = CENSUS.load_campaign_lock()
        cls.oracle = CENSUS.run_bounded_decoder_oracle()

    def records(self) -> list[dict[str, object]]:
        source_bytes = query("(assert true)").encode("ascii")
        parser_sha256 = CENSUS.sha256_path(CENSUS.PARSER_PATH)
        analyzed = []
        for line_number, name in enumerate(("a", "b", "c"), 1):
            source = CENSUS.ManifestSource(
                record_id=line_number,
                line_number=line_number,
                relative_path=f"QF_UF/test/{name}.smt2",
                source_path=Path(name),
                source_bytes=source_bytes,
                source_sha256=hashlib.sha256(source_bytes).hexdigest(),
                source_family="QF_UF/test",
                generator_lineage=name,
                taxonomy_rule="test",
            )
            analyzed.append(
                CENSUS.analyze_source(
                    source,
                    self.lock,
                    "a" * 64,
                    parser_sha256,
                    self.oracle,
                )
            )
        return CENSUS.chain_records(analyzed)

    @staticmethod
    def encode(records: list[dict[str, object]]) -> bytes:
        return b"".join(CENSUS.canonical_json_bytes(record) for record in records)

    @staticmethod
    def rechain(records: list[dict[str, object]]) -> list[dict[str, object]]:
        return CENSUS.chain_records(records)

    def test_chain_accepts_intact_stream(self) -> None:
        records = self.records()
        self.assertEqual(
            CENSUS.verify_record_stream(self.encode(records), 3, self.lock), records
        )

    def test_deletion_reordering_and_tampering_fail(self) -> None:
        records = self.records()
        with self.assertRaisesRegex(CENSUS.CensusError, "cardinality"):
            CENSUS.verify_record_stream(self.encode(records[:-1]), 3, self.lock)
        reordered = [records[1], records[0], records[2]]
        with self.assertRaisesRegex(CENSUS.CensusError, "sequence|hash chain"):
            CENSUS.verify_record_stream(self.encode(reordered), 3, self.lock)
        tampered = [dict(record) for record in records]
        tampered[1]["record_sha256"] = "b" * 64
        with self.assertRaisesRegex(CENSUS.CensusError, "hash drift"):
            CENSUS.verify_record_stream(self.encode(tampered), 3, self.lock)

    def test_missing_provenance_and_fabricated_oracle_fail_after_rehash(self) -> None:
        missing = deepcopy(self.records())
        del missing[1]["taxonomy_builder_sha256"]
        missing = self.rechain(missing)
        with self.assertRaisesRegex(CENSUS.CensusError, "keys differ"):
            CENSUS.verify_record_stream(self.encode(missing), 3, self.lock)

        fabricated = deepcopy(self.records())
        fabricated[1]["decoder"]["oracle"]["sha256"] = "b" * 64
        fabricated = self.rechain(fabricated)
        with self.assertRaisesRegex(CENSUS.CensusError, "frozen oracle"):
            CENSUS.verify_record_stream(self.encode(fabricated), 3, self.lock)

    def test_projected_status_cannot_hide_a_rehashed_cap_event(self) -> None:
        records = deepcopy(self.records())
        records[0]["cap_events"] = [
            {
                "code": "terms",
                "limit": self.lock.caps.max_terms,
                "observed": self.lock.caps.max_terms + 1,
            }
        ]
        records = self.rechain(records)
        with self.assertRaisesRegex(CENSUS.CensusError, "contradicts reason/cap"):
            CENSUS.verify_record_stream(self.encode(records), 3, self.lock)

    def test_unknown_status_requires_a_real_locked_cap_violation(self) -> None:
        record = deepcopy(self.records()[0])
        record.update(
            {
                "status": "unknown_projection",
                "reason": "terms",
                "cap_events": [
                    {
                        "code": "terms",
                        "limit": self.lock.caps.max_terms,
                        "observed": self.lock.caps.max_terms + 1,
                    }
                ],
                "shape": {},
                "components": [],
                "symbols": [],
                "counts": {"eager": {}, "component_quotient_ram": {}},
                "decoder": {"complete": False, "reason": "terms"},
                "selector": {
                    "eligible": False,
                    "minimum_total_applications": self.lock.minimum_total_applications,
                    "minimum_max_symbol_applications": self.lock.minimum_max_symbol_applications,
                },
                "ratios_ppm": {},
            }
        )
        records = self.rechain([record])
        self.assertEqual(
            CENSUS.verify_record_stream(self.encode(records), 1, self.lock), records
        )
        records[0]["cap_events"][0]["observed"] = self.lock.caps.max_terms
        records = self.rechain(records)
        with self.assertRaisesRegex(CENSUS.CensusError, "does not prove"):
            CENSUS.verify_record_stream(self.encode(records), 1, self.lock)

    def test_every_row_rejects_malformed_rehashed_counts(self) -> None:
        malformed_counts = (
            {
                "variables": -1,
                "clauses": 0,
                "literal_slots": 0,
                "unit_clauses": 0,
                "watch_entries": 0,
            },
            {
                "variables": 0,
                "clauses": 1,
                "literal_slots": 2,
                "unit_clauses": 2,
                "watch_entries": 0,
            },
            {
                "variables": 0,
                "clauses": 2,
                "literal_slots": 2,
                "unit_clauses": 1,
                "watch_entries": 2,
            },
            {
                "variables": 0,
                "clauses": 1,
                "literal_slots": 2,
                "unit_clauses": 1,
                "watch_entries": 0,
            },
            {
                "variables": 0,
                "clauses": 1,
                "literal_slots": 2,
                "unit_clauses": 0,
                "watch_entries": 1,
            },
        )
        for row_index in range(3):
            for malformed in malformed_counts:
                with self.subTest(row=row_index, malformed=malformed):
                    records = deepcopy(self.records())
                    eager = records[row_index]["counts"]["eager"]
                    eager["categories"]["transitivity"] = dict(malformed)
                    eager["total"] = dict(malformed)
                    records = self.rechain(records)
                    with self.assertRaises(CENSUS.CensusError):
                        CENSUS.verify_record_stream(
                            self.encode(records), 3, self.lock
                        )


class CensusFixture:
    def __init__(
        self,
        root: Path,
        *,
        minimum_total_applications: int = 64,
        minimum_max_symbol_applications: int = 32,
    ) -> None:
        self.root = root
        self.rows: list[dict[str, object]] = []
        self.minimum_total_applications = minimum_total_applications
        self.minimum_max_symbol_applications = minimum_max_symbol_applications

    def add(self, relative_path: str, source: str, record_id: int) -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = source.encode("utf-8")
        path.write_bytes(raw)
        self.rows.append(
            {
                "id": record_id,
                "path": relative_path,
                "relative_path": relative_path,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    def manifest(self, rows: list[dict[str, object]] | None = None) -> Path:
        path = self.root / "manifest.jsonl"
        path.write_text(
            "".join(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                for row in (self.rows if rows is None else rows)
            ),
            encoding="utf-8",
        )
        return path

    def lock(self) -> Path:
        value = json.loads(CENSUS.DEFAULT_LOCK_PATH.read_text(encoding="ascii"))
        value["corpus"]["expected_sources"] = 2
        portable_rows = sorted(self.rows, key=lambda row: row["relative_path"])
        portable_bytes = b"".join(
            CENSUS.canonical_json_bytes(
                {
                    "relative_path": row["relative_path"],
                    "bytes": row["bytes"],
                    "sha256": row["sha256"],
                }
            )
            for row in portable_rows
        )
        value["corpus"]["portable_source_set_sha256"] = hashlib.sha256(
            portable_bytes
        ).hexdigest()
        value["corpus"]["families"]["qg"]["expected_population"] = 1
        value["corpus"]["families"]["goel"]["expected_population"] = 1
        value["gates"]["validity"]["required_sources"] = 2
        value["selector"][
            "minimum_total_applications"
        ] = self.minimum_total_applications
        value["selector"][
            "minimum_max_symbol_applications"
        ] = self.minimum_max_symbol_applications
        path = self.root / "lock.json"
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")
        return path

    def run(self, suffix: str) -> tuple[bytes, bytes, bytes, dict[str, object]]:
        records = self.root / f"records-{suffix}.jsonl"
        aggregate = self.root / f"aggregate-{suffix}.json"
        targets = self.root / f"targets-{suffix}.jsonl"
        _, summary, _ = CENSUS.run_census(
            self.manifest(),
            records,
            aggregate,
            targets,
            repository_root=self.root,
            lock_path=self.lock(),
        )
        return records.read_bytes(), aggregate.read_bytes(), targets.read_bytes(), summary

    def paths(self, suffix: str) -> dict[str, Path]:
        return {
            "manifest": self.root / "manifest.jsonl",
            "lock": self.root / "lock.json",
            "records": self.root / f"records-{suffix}.jsonl",
            "aggregate": self.root / f"aggregate-{suffix}.json",
            "targets": self.root / f"targets-{suffix}.jsonl",
        }


class BundleVerificationTests(unittest.TestCase):
    @staticmethod
    def fixture(root: Path, *, eligible: bool = False) -> CensusFixture:
        fixture = CensusFixture(
            root,
            minimum_total_applications=1 if eligible else 64,
            minimum_max_symbol_applications=1 if eligible else 32,
        )
        body = (
            """
            (declare-sort U 0)
            (declare-fun f (U) U)
            (declare-const a U)
            (declare-const b U)
            (assert (= (f a) (f b)))
            """
            if eligible
            else "(assert true)"
        )
        fixture.add(
            "QF_UF/2018-Goel-hwbench/QF_UF_demo_ab_br_max.smt2",
            query(body),
            2,
        )
        fixture.add(
            "QF_UF/QG-classification/qg1/demo1.smt2",
            query(body),
            1,
        )
        return fixture

    @staticmethod
    def verify(fixture: CensusFixture, suffix: str) -> dict[str, object]:
        paths = fixture.paths(suffix)
        return CENSUS.verify_census_bundle(
            paths["manifest"],
            paths["records"],
            paths["aggregate"],
            paths["targets"],
            repository_root=fixture.root,
            lock_path=paths["lock"],
        )

    @staticmethod
    def read_records(path: Path) -> list[dict[str, object]]:
        return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]

    @staticmethod
    def write_records(path: Path, records: list[dict[str, object]]) -> bytes:
        payload = b"".join(CENSUS.canonical_json_bytes(record) for record in records)
        path.write_bytes(payload)
        return payload

    @staticmethod
    def write_json(path: Path, value: dict[str, object]) -> None:
        path.write_bytes(CENSUS.canonical_json_bytes(value))

    def test_valid_bundle_receipt_binds_all_recomputed_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            fixture.run("valid")
            receipt = self.verify(fixture, "valid")
        self.assertTrue(receipt["verified"])
        self.assertTrue(receipt["validity_pass"])
        self.assertEqual(receipt["sources"], 2)
        self.assertEqual(
            receipt["decoder_oracle_sha256"],
            CENSUS.DECODER_ORACLE_FROZEN_SHA256,
        )
        self.assertEqual(
            set(receipt["hashes"]),
            {
                "lock_sha256",
                "input_manifest_sha256",
                "portable_source_set_sha256",
                "analyzer_sha256",
                "parser_sha256",
                "taxonomy_builder_sha256",
                "records_jsonl_sha256",
                "terminal_record_sha256",
                "derived_target_manifest_sha256",
                "aggregate_json_sha256",
                "recomputed_gates_sha256",
            },
        )

    def test_standalone_verifier_cli_emits_the_strict_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            fixture.run("cli")
            paths = fixture.paths("cli")
            receipt_path = fixture.root / "verification.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(
                        ROOT
                        / "scripts"
                        / "bench"
                        / "verify_component_quotient_ram_bundle.py"
                    ),
                    str(paths["manifest"]),
                    "--repository-root",
                    str(fixture.root),
                    "--lock",
                    str(paths["lock"]),
                    "--records",
                    str(paths["records"]),
                    "--aggregate",
                    str(paths["aggregate"]),
                    "--targets",
                    str(paths["targets"]),
                    "--receipt-out",
                    str(receipt_path),
                    "--require-validity",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("verified=true", completed.stdout)
            receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        self.assertTrue(receipt["verified"])
        self.assertTrue(receipt["validity_pass"])

    def test_reconstructed_invalid_bundle_is_verified_but_not_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add(
                "QF_UF/2018-Goel-hwbench/QF_UF_demo_ab_br_max.smt2",
                query("(assert true)"),
                2,
            )
            fixture.add(
                "QF_UF/QG-classification/qg1/demo1.smt2",
                query("(assert"),
                1,
            )
            fixture.run("invalid")
            receipt = self.verify(fixture, "invalid")
        self.assertTrue(receipt["verified"])
        self.assertFalse(receipt["validity_pass"])

    def test_rehashed_non_target_record_mutation_is_reconstructed_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            fixture.run("non-target")
            paths = fixture.paths("non-target")
            records = self.read_records(paths["records"])
            self.assertFalse(records[0]["selector"]["eligible"])
            records[0]["shape"]["sorts"] += 1
            decoder_counts = records[0]["decoder"]["counts"]
            decoder_counts["sort_defaults_materialized"] += 1
            decoder_counts["total_operations"] += 1
            records = CENSUS.chain_records(records)
            records_bytes = self.write_records(paths["records"], records)
            aggregate = json.loads(paths["aggregate"].read_text(encoding="ascii"))
            aggregate["hashes"]["records_jsonl_sha256"] = hashlib.sha256(
                records_bytes
            ).hexdigest()
            aggregate["hashes"]["terminal_record_sha256"] = records[-1][
                "record_sha256"
            ]
            self.write_json(paths["aggregate"], aggregate)
            lock = CENSUS.load_campaign_lock(paths["lock"])
            self.assertEqual(
                CENSUS.verify_record_stream(records_bytes, 2, lock), records
            )
            with self.assertRaisesRegex(CENSUS.CensusError, "fresh source"):
                self.verify(fixture, "non-target")

    def test_target_and_non_record_mutations_are_recomputed_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary), eligible=True)
            fixture.run("target")
            paths = fixture.paths("target")
            targets = self.read_records(paths["targets"])
            self.assertEqual(len(targets), 2)
            targets[0]["shape"]["applications"] += 1
            targets_bytes = self.write_records(paths["targets"], targets)
            aggregate = json.loads(paths["aggregate"].read_text(encoding="ascii"))
            aggregate["hashes"]["derived_target_manifest_sha256"] = hashlib.sha256(
                targets_bytes
            ).hexdigest()
            self.write_json(paths["aggregate"], aggregate)
            with self.assertRaisesRegex(CENSUS.CensusError, "target manifest differs"):
                self.verify(fixture, "target")

            fixture.run("aggregate")
            paths = fixture.paths("aggregate")
            aggregate = json.loads(paths["aggregate"].read_text(encoding="ascii"))
            aggregate["gates"]["validity"]["checks"]["source_cardinality"] = False
            aggregate["gates"]["validity"]["pass"] = True
            self.write_json(paths["aggregate"], aggregate)
            with self.assertRaisesRegex(CENSUS.CensusError, "full recomputation"):
                self.verify(fixture, "aggregate")

    def test_coherent_fabricated_oracle_and_source_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            fixture.run("oracle")
            paths = fixture.paths("oracle")
            aggregate = json.loads(paths["aggregate"].read_text(encoding="ascii"))
            oracle = aggregate["decoder_oracle"]
            oracle["counts"]["assignments_examined"] += 1
            oracle["counts"]["assignments_accepted"] += 1
            evidence = dict(oracle)
            evidence.pop("sha256")
            oracle["sha256"] = hashlib.sha256(
                CENSUS.canonical_json_bytes(evidence)
            ).hexdigest()
            self.write_json(paths["aggregate"], aggregate)
            with self.assertRaisesRegex(CENSUS.CensusError, "full recomputation"):
                self.verify(fixture, "oracle")

            fixture.run("source")
            source = fixture.root / str(fixture.rows[0]["relative_path"])
            source.write_text(query("(assert false)"), encoding="ascii")
            with self.assertRaisesRegex(CENSUS.CensusError, "sha256 mismatch"):
                self.verify(fixture, "source")


class ProvenanceAndDeterminismTests(unittest.TestCase):
    def test_manifest_hash_mismatch_and_path_traversal_fail_before_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add("QF_UF/QG-classification/qg1/demo1.smt2", query("(assert true)"), 1)
            row = dict(fixture.rows[0])
            row["sha256"] = "0" * 64
            with self.assertRaisesRegex(CENSUS.CensusError, "sha256 mismatch"):
                CENSUS.load_manifest(fixture.manifest([row]), root, 1)
            traversal = dict(fixture.rows[0])
            traversal["relative_path"] = "../escape.smt2"
            with self.assertRaisesRegex(CENSUS.CensusError, "safe relative path"):
                CENSUS.load_manifest(fixture.manifest([traversal]), root, 1)

    def test_manifest_requires_the_locked_exact_cardinality(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add(
                "QF_UF/QG-classification/qg1/demo1.smt2",
                query("(assert true)"),
                1,
            )
            with self.assertRaisesRegex(CENSUS.CensusError, "cardinality mismatch"):
                CENSUS.load_manifest(fixture.manifest(), root, 7503)

    def test_census_rejects_a_different_source_set_with_the_same_cardinality(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add(
                "QF_UF/2018-Goel-hwbench/QF_UF_demo_ab_br_max.smt2",
                query("(assert true)"),
                2,
            )
            fixture.add(
                "QF_UF/QG-classification/qg1/demo1.smt2",
                query("(assert true)"),
                1,
            )
            lock = fixture.lock()
            value = json.loads(lock.read_text(encoding="ascii"))
            value["corpus"]["portable_source_set_sha256"] = "0" * 64
            lock.write_text(json.dumps(value), encoding="ascii")
            with self.assertRaisesRegex(
                CENSUS.CensusError, "portable source-set SHA-256 mismatch"
            ):
                CENSUS.run_census(
                    fixture.manifest(),
                    root / "records.jsonl",
                    root / "aggregate.json",
                    root / "targets.jsonl",
                    repository_root=root,
                    lock_path=lock,
                )

    def test_outputs_are_byte_deterministic_and_portably_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add(
                "QF_UF/2018-Goel-hwbench/QF_UF_demo_ab_br_max.smt2",
                query("(assert true)"),
                2,
            )
            fixture.add(
                "QF_UF/QG-classification/qg1/demo1.smt2",
                query("(assert true)"),
                1,
            )
            first = fixture.run("first")
            second = fixture.run("second")
        self.assertEqual(first[:3], second[:3])
        self.assertTrue(first[3]["gates"]["validity"]["pass"])
        self.assertEqual(
            first[3]["hashes"]["records_jsonl_sha256"],
            hashlib.sha256(first[0]).hexdigest(),
        )
        self.assertRegex(
            first[3]["hashes"]["portable_source_set_sha256"], r"^[0-9a-f]{64}$"
        )

    def test_weakened_validity_lock_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            value = json.loads(CENSUS.DEFAULT_LOCK_PATH.read_text(encoding="ascii"))
            value["gates"]["validity"]["allowed_parse_errors"] = 1
            path.write_text(json.dumps(value), encoding="ascii")
            with self.assertRaisesRegex(CENSUS.CensusError, "exact complete coverage"):
                CENSUS.load_campaign_lock(path)

    def test_weakened_ram_control_and_decoder_oracle_lock_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = json.loads(CENSUS.DEFAULT_LOCK_PATH.read_text(encoding="ascii"))
            value["gates"]["ram_control"]["maximum_ratio"] = {
                "numerator": 2,
                "denominator": 1,
            }
            path = root / "weak-ram.json"
            path.write_text(json.dumps(value), encoding="ascii")
            with self.assertRaisesRegex(CENSUS.CensusError, "forbid weighted"):
                CENSUS.load_campaign_lock(path)

            value = json.loads(CENSUS.DEFAULT_LOCK_PATH.read_text(encoding="ascii"))
            value["projection"]["component_quotient_ram"]["decoder_oracle"][
                "maximum_component_terms"
            ] = 3
            path = root / "weak-oracle.json"
            path.write_text(json.dumps(value), encoding="ascii")
            with self.assertRaisesRegex(CENSUS.CensusError, "oracle contract drift"):
                CENSUS.load_campaign_lock(path)

            for field, value in (
                ("receipt_sha256", "0" * 64),
                ("counts.assignments_examined", 317),
            ):
                value_dict = json.loads(
                    CENSUS.DEFAULT_LOCK_PATH.read_text(encoding="ascii")
                )
                oracle = value_dict["projection"]["component_quotient_ram"][
                    "decoder_oracle"
                ]
                if field == "receipt_sha256":
                    oracle[field] = value
                else:
                    oracle["counts"]["assignments_examined"] = value
                path = root / f"weak-{field.replace('.', '-')}.json"
                path.write_text(json.dumps(value_dict), encoding="ascii")
                with self.subTest(field=field), self.assertRaisesRegex(
                    CENSUS.CensusError, "oracle contract drift"
                ):
                    CENSUS.load_campaign_lock(path)


if __name__ == "__main__":
    unittest.main()
