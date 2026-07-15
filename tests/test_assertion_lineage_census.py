from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "assertion_lineage_census.py"
SBATCH = ROOT / "scripts" / "wmi" / "euf_viper_t8_lineage_census.sbatch"
SPEC = importlib.util.spec_from_file_location("assertion_lineage_census_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CENSUS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CENSUS
SPEC.loader.exec_module(CENSUS)


class AssertionLineageCensusTests(unittest.TestCase):
    def test_small_manifest_loader_is_strict_and_requires_unique_paths(self) -> None:
        rows = [
            {"bytes": 1, "relative_path": "QF_UF/a.smt2", "sha256": "1" * 64},
            {"bytes": 2, "relative_path": "QF_UF/b.smt2", "sha256": "2" * 64},
        ]
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "manifest.jsonl"
            content = b"".join(CENSUS.canonical_bytes(row) for row in rows)
            path.write_bytes(content)
            loaded = CENSUS.load_manifest(
                path, hashlib.sha256(content).hexdigest(), 2
            )
            self.assertEqual(loaded, rows)

            rows[1]["relative_path"] = rows[0]["relative_path"]
            duplicate = b"".join(CENSUS.canonical_bytes(row) for row in rows)
            path.write_bytes(duplicate)
            with self.assertRaises(CENSUS.CensusError) as caught:
                CENSUS.load_manifest(
                    path, hashlib.sha256(duplicate).hexdigest(), 2
                )
            self.assertIn("not unique", str(caught.exception))

    def test_error_classification_is_closed_and_records_have_no_result_field(self) -> None:
        cases = {
            "unsupported-accounting mismatch": "unsupported_accounting_error",
            "stale-source changed": "hash_error",
            "lineage loss": "lineage_error",
            "unknown sort": "parse_error",
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(CENSUS.classify_failure(message), expected)

        row = {
            "bytes": 10,
            "relative_path": "QF_UF/a.smt2",
            "sha256": "0" * 64,
        }
        record = CENSUS.record_error(
            0,
            row,
            "parse_error",
            "bad source",
            binary_sha256="1" * 64,
            physical_device=1,
            physical_inode=2,
            python_identity={
                "path": "/usr/bin/python3",
                "sha256": "2" * 64,
                "version": "Python 3.13.0",
            },
        )
        self.assertEqual(set(record), CENSUS.RECORD_KEYS)
        self.assertNotIn("result", record)
        self.assertNotIn("sat", record)
        self.assertNotIn("unsat", record)

    def test_parser_environment_is_exact(self) -> None:
        expected = {
            "EUF_VIPER_SCOPED_LET": "auto",
            "EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT": "1024",
            "EUF_VIPER_PROFILE": None,
        }
        saved = {name: os.environ.get(name) for name in expected}
        try:
            os.environ["EUF_VIPER_SCOPED_LET"] = "auto"
            os.environ["EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT"] = "1024"
            os.environ.pop("EUF_VIPER_PROFILE", None)
            CENSUS.validate_environment(expected)
            os.environ["EUF_VIPER_SCOPED_LET"] = "off"
            with self.assertRaises(CENSUS.CensusError):
                CENSUS.validate_environment(expected)
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_wmi_script_only_dispatches_the_lineage_census(self) -> None:
        text = SBATCH.read_text(encoding="ascii")
        executable_lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        joined = "\n".join(executable_lines)
        self.assertIn("assertion_lineage_census.py run-shard", joined)
        self.assertNotIn(" euf-viper solve", joined)
        self.assertNotIn("sbatch ", joined)
        self.assertNotIn("cargo ", joined)
        self.assertNotIn("frontier", joined)

    def test_audit_requires_exactly_7503_unique_physical_sources(self) -> None:
        revision = "a" * 40
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            records_path = directory / "records.jsonl"
            records = []
            for sequence in range(7503):
                records.append(
                    {
                        "assertions": 1,
                        "binary_sha256": "1" * 64,
                        "build_git_revision": revision,
                        "build_source_revision_sha256": "2" * 64,
                        "error_category": None,
                        "ledger_sha256": "3" * 64,
                        "lineage_sha256": "4" * 64,
                        "objects": 3,
                        "parser_source_revision_sha256": "5" * 64,
                        "physical_device": 7,
                        "physical_inode": sequence + 1,
                        "python_path": "/usr/bin/python3",
                        "python_sha256": "6" * 64,
                        "python_version": "Python 3.13.0",
                        "reason": None,
                        "relative_path": f"QF_UF/source-{sequence:04}.smt2",
                        "schema": CENSUS.RECORD_SCHEMA,
                        "sequence": sequence,
                        "source_bytes": 20,
                        "source_sha256": f"{sequence:064x}",
                        "status": "verified",
                        "unsupported_diagnostics": 0,
                    }
                )
            records_path.write_bytes(
                b"".join(CENSUS.canonical_bytes(record) for record in records)
            )
            output = directory / "audit.json"
            arguments = types.SimpleNamespace(
                contract=ROOT
                / "campaigns"
                / "t8-assertion-lineage-census-v1.json",
                out=output,
                records=[records_path],
                revision=revision,
                root=ROOT,
            )
            CENSUS.audit(arguments)
            audit = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(audit["status"], "pass")
            self.assertEqual(audit["counts"]["records"], 7503)
            self.assertEqual(audit["counts"]["unique_physical_sources"], 7503)
            self.assertEqual(audit["gate"]["solver_invocations"], 0)

            records[1]["physical_inode"] = records[0]["physical_inode"]
            records_path.write_bytes(
                b"".join(CENSUS.canonical_bytes(record) for record in records)
            )
            with self.assertRaises(CENSUS.CensusError):
                CENSUS.audit(arguments)
            failed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(failed["status"], "fail")
            self.assertFalse(failed["gate"]["unique_physical_sources"])


if __name__ == "__main__":
    unittest.main()
