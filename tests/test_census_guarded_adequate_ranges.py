from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "census_guarded_adequate_ranges.py"
SPEC = importlib.util.spec_from_file_location(
    "census_guarded_adequate_ranges", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
CENSUS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CENSUS
SPEC.loader.exec_module(CENSUS)


def query(body: str) -> str:
    return f"(set-logic QF_UF)\n{body.strip()}\n(check-sat)\n"


def declarations(sort: str = "U") -> str:
    return f"""
    (declare-sort {sort} 0)
    (declare-const a {sort})
    (declare-const b {sort})
    (declare-const c {sort})
    (declare-const x {sort})
    (declare-const y {sort})
    (declare-const z {sort})
    (declare-const w {sort})
    """


def guarded_pressure_body(duplicate: bool = False) -> str:
    ranges = """
    (assert (=> g (or (= x a) (= x b))))
    (assert (=> g (or (= y a) (= y b))))
    (assert (=> g (or (= z a) (= z b))))
    (assert (=> g (or (= w a) (= w b) (= w c))))
    """
    if duplicate:
        ranges += """
        (assert (=> g (or (= x a) (= x b))))
        (assert (distinct a b c))
        """
    return f"""
    {declarations()}
    (declare-const g Bool)
    (assert (distinct a b c))
    {ranges}
    (assert (=> g (distinct x y z)))
    """


class CensusFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.rows: list[dict[str, object]] = []

    def add(self, name: str, source: str | bytes, *, record_id: int | str | None = None) -> Path:
        relative_path = f"QF_UF/tests/{name}.smt2"
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = source.encode("utf-8") if isinstance(source, str) else source
        path.write_bytes(raw)
        self.rows.append(
            {
                "id": len(self.rows) if record_id is None else record_id,
                "path": relative_path,
                "relative_path": relative_path,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        return path

    def manifest(self, *, reverse: bool = False) -> Path:
        path = self.root / "manifest.jsonl"
        rows = reversed(self.rows) if reverse else self.rows
        path.write_text(
            "".join(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                for row in rows
            ),
            encoding="utf-8",
        )
        return path

    def run(
        self,
        *,
        caps: object | None = None,
        suffix: str = "",
    ) -> tuple[list[dict[str, object]], dict[str, object], bytes, bytes]:
        records_path = self.root / f"records{suffix}.jsonl"
        aggregate_path = self.root / f"aggregate{suffix}.json"
        records, aggregate = CENSUS.run_census(
            self.manifest(),
            records_path,
            aggregate_path,
            repository_root=self.root,
            caps=caps or CENSUS.Caps(),
        )
        return records, aggregate, records_path.read_bytes(), aggregate_path.read_bytes()


class StructuredOpportunityTests(unittest.TestCase):
    def test_guarded_ranges_report_nonuniform_savings_and_hall_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("guarded", query(guarded_pressure_body()))
            records, aggregate, _, _ = fixture.run()

        record = records[0]
        self.assertTrue(record["eligible"])
        self.assertEqual(record["ineligibility_reason"], None)
        self.assertEqual(record["totals"]["value_cell_savings"], 3)
        self.assertEqual(record["totals"]["hall_checked_conflicts"], 1)
        self.assertEqual(aggregate["totals"]["hall_checked_conflicts"], 1)
        domain = record["domains"][0]
        self.assertEqual(domain["guard_id"], record["guards"][0]["id"])
        conflicts = [
            witness
            for witness in domain["hall"]["witnesses"]
            if witness["kind"] == "checked_conflict"
        ]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["subset_size"], 3)
        self.assertEqual(conflicts[0]["candidate_union_size"], 2)
        self.assertEqual(record["interpretation"], CENSUS.INTERPRETATION)
        self.assertNotIn("result", record)

    def test_unguarded_disequality_is_available_inside_guarded_context(self) -> None:
        source = query(
            f"""
            {declarations()}
            (declare-const g Bool)
            (assert (distinct a b c))
            (assert (=> g (or (= x a) (= x b))))
            (assert (=> g (or (= y a) (= y b) (= y c))))
            (assert (distinct x y))
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("unguarded-edge", source)
            records, _, _, _ = fixture.run()

        guarded = records[0]["domains"][0]
        self.assertEqual(guarded["hall"]["summary"]["subsets_checked"], 1)
        self.assertEqual(guarded["hall"]["summary"]["tight_subsets"], 0)

    def test_guarded_disequality_is_not_promoted_to_unconditional(self) -> None:
        source = query(
            f"""
            {declarations()}
            (declare-const g Bool)
            (assert (distinct a b c))
            (assert (or (= x a) (= x b)))
            (assert (or (= y a) (= y b) (= y c)))
            (assert (=> g (distinct x y)))
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("guarded-edge", source)
            records, _, _, _ = fixture.run()

        domains = records[0]["domains"]
        unconditional = next(
            domain for domain in domains if domain["guard_id"] == "unconditional"
        )
        guarded = next(
            domain for domain in domains if domain["guard_id"] != "unconditional"
        )
        self.assertEqual(unconditional["hall"]["summary"]["subsets_checked"], 0)
        self.assertEqual(guarded["hall"]["summary"]["subsets_checked"], 1)

    def test_incomplete_guards_do_not_mix(self) -> None:
        source = query(
            f"""
            {declarations()}
            (declare-const g Bool)
            (declare-const h Bool)
            (assert (distinct a b c))
            (assert (=> g (or (= x a) (= x b))))
            (assert (=> g (or (= y a) (= y b) (= y c))))
            (assert (=> h (distinct x y)))
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("incomplete", source)
            records, _, _, _ = fixture.run()

        self.assertTrue(records[0]["eligible"])
        self.assertEqual(records[0]["totals"]["hall_subsets_checked"], 0)

    def test_mixed_sorts_are_partitioned_into_separate_domains(self) -> None:
        source = query(
            """
            (declare-sort U 0)
            (declare-sort V 0)
            (declare-const ua U) (declare-const ub U) (declare-const uc U)
            (declare-const ux U) (declare-const uy U)
            (declare-const va V) (declare-const vb V) (declare-const vc V)
            (declare-const vx V) (declare-const vy V)
            (assert (distinct ua ub uc))
            (assert (distinct va vb vc))
            (assert (or (= ux ua) (= ux ub)))
            (assert (or (= uy ua) (= uy ub) (= uy uc)))
            (assert (or (= vx va) (= vx vb)))
            (assert (or (= vy va) (= vy vb) (= vy vc)))
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("mixed", source)
            records, _, _, _ = fixture.run()

        record = records[0]
        self.assertTrue(record["eligible"])
        self.assertEqual(len(record["domains"]), 2)
        self.assertEqual(
            {domain["sort"]["name"] for domain in record["domains"]}, {"U", "V"}
        )
        self.assertEqual(record["totals"]["value_cell_savings"], 2)

    def test_bool_as_data_abstains_without_range_claims(self) -> None:
        source = query(
            """
            (declare-sort U 0)
            (declare-const a U)
            (declare-const b U)
            (declare-const p Bool)
            (declare-fun f (Bool) U)
            (assert (distinct a b))
            (assert (or (= (f p) a) (= (f p) b)))
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("bool-data", source)
            records, _, _, _ = fixture.run()

        record = records[0]
        self.assertFalse(record["eligible"])
        self.assertEqual(record["ineligibility_reason"], "bool_as_data_present")
        self.assertEqual(record["proven_range_facts"], [])
        self.assertEqual(record["domains"], [])


class FailClosedAndDeterminismTests(unittest.TestCase):
    def test_duplicate_clauses_do_not_duplicate_proved_facts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("plain", query(guarded_pressure_body()))
            fixture.add("duplicate", query(guarded_pressure_body(duplicate=True)))
            records, _, _, _ = fixture.run()

        by_name = {record["source"]["relative_path"]: record for record in records}
        plain = by_name["QF_UF/tests/plain.smt2"]
        duplicate = by_name["QF_UF/tests/duplicate.smt2"]
        self.assertEqual(
            plain["totals"]["proven_range_facts"],
            duplicate["totals"]["proven_range_facts"],
        )
        self.assertEqual(plain["totals"], duplicate["totals"])

    def test_malformed_source_is_an_ineligible_record_not_a_partial_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("malformed", "(set-logic QF_UF) (assert (or")
            records, aggregate, _, _ = fixture.run()

        record = records[0]
        self.assertEqual(record["ineligibility_reason"], "structured_parse_error")
        self.assertIn("parse_error", record)
        self.assertEqual(record["proven_range_facts"], [])
        self.assertEqual(record["domains"], [])
        self.assertEqual(aggregate["sources"]["eligible"], 0)

    def test_manifest_hash_mismatch_fails_before_writing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add("mismatch", query("(assert true)"))
            manifest = fixture.manifest()
            row = dict(fixture.rows[0])
            row["sha256"] = "0" * 64
            manifest.write_text(json.dumps(row) + "\n", encoding="utf-8")
            records_out = root / "records.jsonl"
            aggregate_out = root / "aggregate.json"
            with self.assertRaisesRegex(CENSUS.CensusError, "sha256 mismatch"):
                CENSUS.run_census(
                    manifest,
                    records_out,
                    aggregate_out,
                    repository_root=root,
                    caps=CENSUS.Caps(),
                )
            self.assertFalse(records_out.exists())
            self.assertFalse(aggregate_out.exists())

    def test_output_is_byte_deterministic_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("z", query(guarded_pressure_body()))
            fixture.add("a", query("(assert true)"))
            first = fixture.run(suffix="-one")
            second = fixture.run(suffix="-two")

        self.assertEqual(first[2], second[2])
        self.assertEqual(first[3], second[3])
        self.assertEqual(
            first[1]["hashes"]["records_jsonl_sha256"],
            hashlib.sha256(first[2]).hexdigest(),
        )
        paths = [record["source"]["relative_path"] for record in first[0]]
        self.assertEqual(paths, sorted(paths))

    def test_cli_emits_both_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add("cli", query(guarded_pressure_body()))
            manifest = fixture.manifest()
            records_path = root / "records.jsonl"
            aggregate_path = root / "aggregate.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(manifest),
                    "--repository-root",
                    str(root),
                    "--records-out",
                    str(records_path),
                    "--aggregate-out",
                    str(aggregate_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(records_path.is_file())
            self.assertTrue(aggregate_path.is_file())
            aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
            self.assertIn(aggregate["hashes"]["records_jsonl_sha256"], completed.stdout)

    def test_source_fact_and_hall_caps_abstain_explicitly(self) -> None:
        source = query(guarded_pressure_body())
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CensusFixture(Path(temporary))
            fixture.add("caps", source)

            byte_records, _, _, _ = fixture.run(
                caps=CENSUS.Caps(max_source_bytes=1), suffix="-bytes"
            )
            fact_records, _, _, _ = fixture.run(
                caps=CENSUS.Caps(max_proved_facts=1), suffix="-facts"
            )
            hall_records, _, _, _ = fixture.run(
                caps=CENSUS.Caps(max_hall_subset_enumerations=1), suffix="-hall"
            )

        self.assertEqual(byte_records[0]["ineligibility_reason"], "source_byte_cap")
        self.assertEqual(fact_records[0]["ineligibility_reason"], "proved_fact_cap")
        self.assertTrue(hall_records[0]["eligible"])
        domain = hall_records[0]["domains"][0]
        self.assertFalse(domain["hall"]["summary"]["complete"])
        self.assertIn("hall_subset_enumeration_cap", hall_records[0]["abstentions"])


if __name__ == "__main__":
    unittest.main()
