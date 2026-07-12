from __future__ import annotations

import gzip
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "ingest_smtcomp_2025_qf_uf.py"
MODULE_SPEC = importlib.util.spec_from_file_location("ingest_smtcomp", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
INGEST = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(INGEST)


def result(family: list[str], name: str, solver: str = "solver") -> dict:
    return {
        "track": "SingleQuery",
        "solver": solver,
        "file": {
            "incremental": False,
            "logic": "QF_UF",
            "family": family,
            "name": name,
        },
        "result": "sat",
        "cpu_time": 0.1,
        "wallclock_time": 0.1,
        "memory_usage": 1,
    }


class SmtCompIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.results = self.root / "results.json.gz"
        self._write_results(
            [
                result(["family-a"], "a.smt2", "one"),
                result(["family-a"], "a.smt2", "two"),
                result(["family-b", "nested"], "b.smt2", "one"),
                {
                    **result(["other"], "ignored.smt2"),
                    "file": {
                        "incremental": False,
                        "logic": "QF_BV",
                        "family": ["other"],
                        "name": "ignored.smt2",
                    },
                },
            ]
        )
        self.manifest = self.root / "manifest.jsonl"
        rows = [
            {
                "id": 1,
                "relative_path": "QF_UF/family-a/a.smt2",
                "sha256": "a" * 64,
                "bytes": 10,
                "status": "sat",
            },
            {
                "id": 2,
                "relative_path": "QF_UF/family-b/nested/b.smt2",
                "sha256": "b" * 64,
                "bytes": 20,
                "status": "unsat",
            },
        ]
        self.manifest.write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_results(self, rows: list[dict]) -> None:
        with gzip.open(self.results, "wt", encoding="utf-8") as handle:
            json.dump({"results": rows}, handle)

    def test_reconstructs_unique_selection_and_joins_manifest(self) -> None:
        selected, counts = INGEST.official_selection(
            self.results, expected_sha256=None, expected_count=2
        )
        rows = INGEST.join_selection(self.manifest, selected, counts)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["relative_path"], "QF_UF/family-a/a.smt2")
        self.assertEqual(rows[0]["official_result_rows"], 2)
        self.assertEqual(rows[1]["official_family"], ["family-b", "nested"])
        self.assertEqual(
            rows[0]["path"],
            "benchmarks/smtlib-2025/QF_UF/QF_UF/family-a/a.smt2",
        )
        self.assertEqual(INGEST.canonical_jsonl(rows), INGEST.canonical_jsonl(rows))

    def test_wrong_selection_count_is_rejected(self) -> None:
        with self.assertRaisesRegex(INGEST.IngestError, "expected 3"):
            INGEST.official_selection(
                self.results, expected_sha256=None, expected_count=3
            )

    def test_wrong_source_hash_is_rejected(self) -> None:
        with self.assertRaisesRegex(INGEST.IngestError, "hash mismatch"):
            INGEST.official_selection(
                self.results, expected_sha256="0" * 64, expected_count=2
            )

    def test_missing_manifest_member_is_rejected(self) -> None:
        selected, counts = INGEST.official_selection(
            self.results, expected_sha256=None, expected_count=2
        )
        self.manifest.write_text(
            self.manifest.read_text(encoding="utf-8").splitlines()[0] + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(INGEST.IngestError, "missing 1"):
            INGEST.join_selection(self.manifest, selected, counts)

    def test_duplicate_official_key_in_manifest_is_rejected(self) -> None:
        original = self.manifest.read_text(encoding="utf-8")
        self.manifest.write_text(
            original + original.splitlines()[0] + "\n", encoding="utf-8"
        )
        selected, counts = INGEST.official_selection(
            self.results, expected_sha256=None, expected_count=2
        )
        with self.assertRaisesRegex(INGEST.IngestError, "duplicate official key"):
            INGEST.join_selection(self.manifest, selected, counts)


if __name__ == "__main__":
    unittest.main()
