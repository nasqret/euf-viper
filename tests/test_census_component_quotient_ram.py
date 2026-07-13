from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import sys
import tempfile
import unittest
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


def synthetic_record(
    *, eager: int, candidate: int, variables: tuple[int, int] = (100, 100)
) -> dict[str, object]:
    def total(value: int, variable_value: int) -> dict[str, int]:
        return {
            "variables": variable_value,
            "clauses": value,
            "literal_slots": value,
            "unit_clauses": 0,
            "watch_entries": value,
        }

    return {
        "counts": {
            "eager": {"total": total(eager, variables[0])},
            "component_quotient_ram": {"total": total(candidate, variables[1])},
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


class HashChainTests(unittest.TestCase):
    def records(self) -> list[dict[str, object]]:
        return CENSUS.chain_records(
            [
                {
                    "schema": CENSUS.RECORD_SCHEMA,
                    "lock_sha256": "a" * 64,
                    "source": {"relative_path": f"QF_UF/test/{name}.smt2"},
                    "payload": name,
                }
                for name in ("a", "b", "c")
            ]
        )

    @staticmethod
    def encode(records: list[dict[str, object]]) -> bytes:
        return b"".join(CENSUS.canonical_json_bytes(record) for record in records)

    def test_chain_accepts_intact_stream(self) -> None:
        records = self.records()
        self.assertEqual(
            CENSUS.verify_record_stream(self.encode(records), 3, "a" * 64), records
        )

    def test_deletion_reordering_and_tampering_fail(self) -> None:
        records = self.records()
        with self.assertRaisesRegex(CENSUS.CensusError, "cardinality"):
            CENSUS.verify_record_stream(self.encode(records[:-1]), 3, "a" * 64)
        reordered = [records[1], records[0], records[2]]
        with self.assertRaisesRegex(CENSUS.CensusError, "sequence|hash chain"):
            CENSUS.verify_record_stream(self.encode(reordered), 3, "a" * 64)
        tampered = [dict(record) for record in records]
        tampered[1]["payload"] = "changed"
        with self.assertRaisesRegex(CENSUS.CensusError, "hash drift"):
            CENSUS.verify_record_stream(self.encode(tampered), 3, "a" * 64)


class CensusFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.rows: list[dict[str, object]] = []

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


if __name__ == "__main__":
    unittest.main()
