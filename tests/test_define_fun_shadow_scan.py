from __future__ import annotations

import ast
import copy
import unittest
from pathlib import Path

from scripts.bench import scan_define_fun_shadowing as scan


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/define_fun_caller_shadow_unsat.smt2"


class DefineFunShadowScanTests(unittest.TestCase):
    def test_bounded_unsat_fixture_identifies_affected_definition(self) -> None:
        report = scan.scan_source(FIXTURE.read_text(encoding="ascii"))
        self.assertEqual(
            report["counts"],
            {
                "affected_definitions": 1,
                "colliding_call_sites": 1,
                "definitions": 1,
                "definitions_with_global_references": 1,
            },
        )
        affected = report["affected_definitions"][0]
        self.assertEqual(affected["name"], "read-global")
        self.assertEqual(affected["global_references"], ["global"])
        self.assertEqual(
            affected["colliding_calls"][0]["caller_bindings"], ["global"]
        )

    def test_noncolliding_call_remains_only_a_candidate(self) -> None:
        source = """
        (set-logic QF_UF)
        (declare-sort U 0)
        (declare-const global U)
        (declare-const other U)
        (define-fun read-global ((argument U)) U global)
        (assert (let ((local other)) (= (read-global local) global)))
        (check-sat)
        """
        report = scan.scan_source(source)
        self.assertEqual(report["counts"]["definitions_with_global_references"], 1)
        self.assertEqual(report["counts"]["affected_definitions"], 0)

    def test_scanner_has_no_dependency_on_either_semantic_parser(self) -> None:
        tree = ast.parse(
            (ROOT / "scripts/bench/scan_define_fun_shadowing.py").read_text(
                encoding="utf-8"
            )
        )
        imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        } | {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("scripts.cert.independent_qfuf", imports)
        self.assertNotIn("scripts.bench.t5_independent_smtlib", imports)
        self.assertNotIn("subprocess", imports)

    def test_corpus_report_validator_rejects_nested_call_drift(self) -> None:
        source = {
            "manifest_id": 0,
            "relative_path": "QF_UF/example.smt2",
            "sha256": "0" * 64,
        }
        definition = {
            "source": source,
            "command_index": 4,
            "global_references": ["global"],
            "name": "read-global",
            "parameters": ["argument"],
        }
        report = {
            "schema": scan.REPORT_SCHEMA,
            "status": "complete",
            "decisive": False,
            "authoritative": False,
            "analysis": {
                "kind": "standalone-s-expression-lexical-scope-scan",
                "solving_performed": False,
            },
            "corpus": {
                "expected_sources": scan.contract.EXPECTED_SOURCES,
                "manifest_relative_path": scan.contract.MANIFEST_RELATIVE_PATH,
                "manifest_sha256": scan.contract.MANIFEST_SHA256,
                "portable_source_set_sha256": scan.contract.PORTABLE_SOURCE_SET_SHA256,
            },
            "counts": {
                "affected_definitions": 1,
                "colliding_call_sites": 1,
                "definitions": 1,
                "definitions_with_global_references": 1,
                "scan_failures": 0,
                "sources": scan.contract.EXPECTED_SOURCES,
            },
            "candidate_definitions": [definition],
            "affected_definitions": [
                {
                    **definition,
                    "colliding_calls": [
                        {
                            "caller_bindings": ["global"],
                            "command_index": 5,
                            "context": "assert",
                            "expression_path": [1, 2],
                        }
                    ],
                }
            ],
            "failures": [],
        }
        self.assertIs(scan.validate_report(report), report)
        drifted = copy.deepcopy(report)
        drifted["affected_definitions"][0]["colliding_calls"][0][
            "caller_bindings"
        ] = ["caller-local"]
        with self.assertRaisesRegex(scan.ShadowScanError, "call identity"):
            scan.validate_report(drifted)


if __name__ == "__main__":
    unittest.main()
