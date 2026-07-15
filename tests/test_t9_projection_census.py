from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.bench import audit_t9_projection_census as audit
from scripts.bench import run_t9_projection_census as census


FAKE_PROJECTOR = r'''#!/usr/bin/env python3
import os
import sys
from pathlib import Path

if any(key.startswith("EUF_VIPER_") for key in os.environ):
    print("ambient EUF_VIPER variable leaked", file=sys.stderr)
    raise SystemExit(9)

source = Path(sys.argv[2]).read_text(encoding="ascii")
selected = "SELECT" in source
sat_calls = 1 if "SAT_CALL" in source else 0
values = {
    "selected": int(selected),
    "reason": "selected" if selected else "selector_equality_graph_vertices",
    "finite_added": 0,
    "covered_finite_terms": 0,
    "closed_table_functions": 0,
    "all_different_clique_lb": 48,
    "disequality_graph_edges": 1128,
    "disequality_clique_excess_edges": 0,
    "equality_graph_vertices": 2500,
    "equality_graph_edges": 10000,
    "applications": 1,
    "backend": "kissat",
    "baseline_vars": 10,
    "baseline_clauses": 20,
    "baseline_literal_slots": 30,
    "ackermann_clauses": 1 if selected else 0,
    "ackermann_literal_slots": 2 if selected else 0,
    "fill_edges": 1 if selected else 0,
    "fill_pair_examinations": 1 if selected else 0,
    "transitivity_clauses": 3 if selected else 0,
    "triangle_visits": 1 if selected else 0,
    "candidate_vars": 12 if selected else 10,
    "candidate_clauses": 24 if selected else 20,
    "candidate_literal_slots": 42 if selected else 30,
    "added_literal_slots": 12 if selected else 0,
    "materialization_match": int(selected),
    "off_path_unchanged": 1,
    "sat_calls": sat_calls,
}
print("t9_projection_version 1")
for key, value in values.items():
    print(f"{key} {value}")
raise SystemExit(0 if selected else 3)
'''


class CensusFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.rows: list[dict[str, object]] = []

    def add(self, relative_path: str, marker: str) -> str:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = (marker + "\n").encode("ascii")
        path.write_bytes(payload)
        source_hash = hashlib.sha256(payload).hexdigest()
        self.rows.append(
            {
                "id": len(self.rows),
                "path": str(path),
                "relative_path": relative_path,
                "bytes": len(payload),
                "sha256": source_hash,
            }
        )
        return source_hash

    def manifest(self, name: str = "manifest.jsonl", *, reverse: bool = False) -> Path:
        path = self.root / name
        rows = reversed(self.rows) if reverse else self.rows
        path.write_text(
            "".join(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                for row in rows
            ),
            encoding="ascii",
        )
        return path

    def binary(self) -> Path:
        path = self.root / "fake-projector.py"
        path.write_text(FAKE_PROJECTOR, encoding="ascii")
        path.chmod(0o755)
        return path

    def run(
        self,
        manifest: Path,
        *,
        suffix: str = "",
    ) -> tuple[Path, Path, list[dict[str, object]], dict[str, object]]:
        records = self.root / f"records{suffix}.jsonl"
        summary = self.root / f"summary{suffix}.json"
        rows, aggregate = census.run_census(
            manifest,
            self.root,
            self.binary(),
            records,
            summary,
            expected_sources=len(self.rows),
            timeout_seconds=2.0,
        )
        return records, summary, rows, aggregate


def complete_fixture(root: Path, *, qg_selected: bool = False) -> tuple[CensusFixture, str]:
    fixture = CensusFixture(root)
    target_hash = fixture.add(audit.TARGET_PATH, "SELECT")
    fixture.add(
        "QF_UF/2018-Goel-hwbench/QF_UF_frogs.1.prop1_ab_br_max.smt2",
        "REJECT",
    )
    fixture.add(
        "QF_UF/2018-Goel-hwbench/QF_UF_frogs.4.prop1_ab_br_max.smt2",
        "REJECT",
    )
    fixture.add(
        "QF_UF/QG-classification/qg5/iso_icl001.smt2",
        "SELECT" if qg_selected else "REJECT",
    )
    fixture.add("QF_UF/tests/additional.smt2", "SELECT")
    return fixture, target_hash


class ProjectionParserTests(unittest.TestCase):
    def test_parser_rejects_duplicate_fields(self) -> None:
        fields = ["t9_projection_version 1"]
        fields.extend(f"{field} 0" for field in sorted(census.COUNT_FIELDS))
        fields.extend(f"{field} 0" for field in sorted(census.BOOLEAN_FIELDS))
        fields.extend(["reason rejected", "backend kissat", "reason duplicate"])
        with self.assertRaisesRegex(census.CensusError, "duplicate key"):
            census.parse_projection_report(("\n".join(fields) + "\n").encode("ascii"), 3)

    def test_parser_rejects_sat_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add("QF_UF/tests/sat-call.smt2", "SELECT SAT_CALL")
            records = root / "records.jsonl"
            summary = root / "summary.json"
            with self.assertRaisesRegex(census.CensusError, "attempted a SAT call"):
                census.run_census(
                    fixture.manifest(),
                    root,
                    fixture.binary(),
                    records,
                    summary,
                    expected_sources=1,
                    timeout_seconds=2.0,
                )
            self.assertFalse(records.exists())
            self.assertFalse(summary.exists())

    def test_manifest_duplicate_keys_fail_before_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "QF_UF/tests/a.smt2"
            source.parent.mkdir(parents=True)
            source.write_text("x\n", encoding="ascii")
            manifest = root / "manifest.jsonl"
            manifest.write_text(
                '{"id":0,"id":1,"path":"x","relative_path":"QF_UF/tests/a.smt2",'
                '"bytes":2,"sha256":"' + hashlib.sha256(b"x\n").hexdigest() + '"}\n',
                encoding="ascii",
            )
            with self.assertRaisesRegex(census.CensusError, "duplicate JSON key"):
                census.load_manifest(manifest, root)


class CensusAndAuditTests(unittest.TestCase):
    def test_complete_census_passes_frozen_audit_and_scrubs_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, target_hash = complete_fixture(root)
            manifest = fixture.manifest()
            previous = os.environ.get("EUF_VIPER_LEAK")
            os.environ["EUF_VIPER_LEAK"] = "must-not-reach-projector"
            try:
                records, summary, rows, aggregate = fixture.run(manifest)
            finally:
                if previous is None:
                    os.environ.pop("EUF_VIPER_LEAK", None)
                else:
                    os.environ["EUF_VIPER_LEAK"] = previous

            self.assertEqual(len(rows), 5)
            self.assertEqual(aggregate["sat_calls"], 0)
            self.assertEqual(aggregate["selected_count"], 2)
            old_target_hash = audit.TARGET_SHA256
            audit.TARGET_SHA256 = target_hash
            try:
                receipt = audit.audit_census(
                    manifest,
                    root,
                    fixture.binary(),
                    records,
                    summary,
                    root / "receipt.json",
                    expected_sources=5,
                )
            finally:
                audit.TARGET_SHA256 = old_target_hash
            self.assertEqual(receipt["status"], "pass")
            self.assertTrue(receipt["checks"]["terminal_timeout_selected"])
            self.assertTrue(receipt["checks"]["all_qg_rejected"])

    def test_record_bytes_are_deterministic_under_manifest_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, _ = complete_fixture(root)
            first_manifest = fixture.manifest("first.jsonl")
            reverse_manifest = fixture.manifest("reverse.jsonl", reverse=True)
            first_records, _, _, first_summary = fixture.run(first_manifest, suffix="-first")
            reverse_records, _, _, reverse_summary = fixture.run(
                reverse_manifest, suffix="-reverse"
            )
            self.assertEqual(first_records.read_bytes(), reverse_records.read_bytes())
            self.assertEqual(
                first_summary["selected_set_sha256"],
                reverse_summary["selected_set_sha256"],
            )
            self.assertNotEqual(
                first_summary["manifest_sha256"], reverse_summary["manifest_sha256"]
            )

    def test_audit_rejects_selected_qg_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, target_hash = complete_fixture(root, qg_selected=True)
            manifest = fixture.manifest()
            records, summary, _, _ = fixture.run(manifest)
            old_target_hash = audit.TARGET_SHA256
            audit.TARGET_SHA256 = target_hash
            try:
                with self.assertRaisesRegex(audit.AuditError, "QG sources were selected"):
                    audit.audit_census(
                        manifest,
                        root,
                        fixture.binary(),
                        records,
                        summary,
                        root / "receipt.json",
                        expected_sources=5,
                    )
            finally:
                audit.TARGET_SHA256 = old_target_hash
            self.assertFalse((root / "receipt.json").exists())

    def test_audit_rejects_tampered_record_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, target_hash = complete_fixture(root)
            manifest = fixture.manifest()
            records, summary, _, _ = fixture.run(manifest)
            lines = records.read_text(encoding="ascii").splitlines()
            row = json.loads(lines[0])
            row["projection"]["sat_calls"] = 1
            lines[0] = json.dumps(row, sort_keys=True, separators=(",", ":"))
            records.write_text("\n".join(lines) + "\n", encoding="ascii")
            old_target_hash = audit.TARGET_SHA256
            audit.TARGET_SHA256 = target_hash
            try:
                with self.assertRaises(audit.AuditError):
                    audit.audit_census(
                        manifest,
                        root,
                        fixture.binary(),
                        records,
                        summary,
                        root / "receipt.json",
                        expected_sources=5,
                    )
            finally:
                audit.TARGET_SHA256 = old_target_hash

    def test_census_refuses_to_replace_existing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add("QF_UF/tests/plain.smt2", "REJECT")
            manifest = fixture.manifest()
            records = root / "records.jsonl"
            summary = root / "summary.json"
            records.write_bytes(b"replacement\n")
            with self.assertRaisesRegex(census.CensusError, "overwrite"):
                census.run_census(
                    manifest,
                    root,
                    fixture.binary(),
                    records,
                    summary,
                    expected_sources=1,
                    timeout_seconds=2.0,
                )
            self.assertEqual(records.read_bytes(), b"replacement\n")
            self.assertFalse(summary.exists())


if __name__ == "__main__":
    unittest.main()
