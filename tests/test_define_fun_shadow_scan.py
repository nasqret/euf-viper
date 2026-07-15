from __future__ import annotations

import ast
import copy
import unittest
from pathlib import Path

from scripts.bench import scan_define_fun_shadowing as scan


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/define_fun_caller_shadow_unsat.smt2"
TRANSITIVE_FIXTURE = (
    ROOT / "tests/fixtures/define_fun_transitive_quoted_shadow_unsat.smt2"
)


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

    def test_transitive_quoted_inner_outer_let_collision_is_reported(self) -> None:
        report = scan.scan_source(TRANSITIVE_FIXTURE.read_text(encoding="ascii"))
        self.assertEqual(report["counts"]["definitions"], 2)
        self.assertEqual(report["counts"]["definitions_with_global_references"], 2)
        self.assertEqual(report["counts"]["affected_definitions"], 1)
        outer = report["affected_definitions"][0]
        self.assertEqual(outer["name"], "outer macro")
        self.assertEqual(outer["called_definitions"], ["inner macro"])
        self.assertEqual(outer["direct_global_references"], [])
        self.assertEqual(outer["global_references"], ["global value"])
        self.assertEqual(
            outer["colliding_calls"][0]["caller_bindings"], ["global value"]
        )

    def test_unsupported_recursive_definition_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            scan.ShadowScanError, "unsupported top-level command 'define-fun-rec'"
        ):
            scan.scan_source(
                "(set-logic QF_UF) (define-fun-rec f () Bool true) (check-sat)"
            )

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
        ledger = [
            {
                "manifest_id": 0,
                "manifest_path": "corpus/QF_UF/example.smt2",
                "relative_path": "QF_UF/example.smt2",
                "lexical_path": "/repo/corpus/QF_UF/example.smt2",
                "canonical_path": "/physical/QF_UF/example.smt2",
                "device": 1,
                "inode": 2,
                "bytes": 3,
                "sha256": "0" * 64,
            }
        ]
        portable = scan.hashlib.sha256(
            scan._portable_source_set_bytes(ledger)
        ).hexdigest()
        source = {
            "manifest_id": 0,
            "relative_path": "QF_UF/example.smt2",
            "sha256": "0" * 64,
        }
        definition = {
            "source": source,
            "called_definitions": [],
            "command_index": 4,
            "direct_global_references": ["global"],
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
                "expected_sources": 1,
                "manifest_relative_path": scan.contract.MANIFEST_RELATIVE_PATH,
                "manifest_sha256": scan.contract.MANIFEST_SHA256,
                "portable_source_set_sha256": portable,
                "source_ledger_sha256": scan.hashlib.sha256(
                    scan.contract.canonical_json_bytes(ledger)
                ).hexdigest(),
            },
            "counts": {
                "affected_definitions": 1,
                "colliding_call_sites": 1,
                "definitions": 1,
                "definitions_with_global_references": 1,
                "scan_failures": 0,
                "sources": 1,
            },
            "source_ledger": ledger,
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
        self.assertIs(
            scan._validate_report(
                report,
                expected_sources=1,
                expected_manifest_relative_path=scan.contract.MANIFEST_RELATIVE_PATH,
                expected_manifest_sha256=scan.contract.MANIFEST_SHA256,
                expected_portable_sha256=portable,
            ),
            report,
        )
        drifted = copy.deepcopy(report)
        drifted["affected_definitions"][0]["colliding_calls"][0][
            "caller_bindings"
        ] = ["caller-local"]
        with self.assertRaisesRegex(scan.ShadowScanError, "call identity"):
            scan._validate_report(
                drifted,
                expected_sources=1,
                expected_manifest_relative_path=scan.contract.MANIFEST_RELATIVE_PATH,
                expected_manifest_sha256=scan.contract.MANIFEST_SHA256,
                expected_portable_sha256=portable,
            )

    def test_source_ledger_rejects_resolved_and_inode_aliases(self) -> None:
        base = {
            "manifest_id": 0,
            "manifest_path": "corpus/a.smt2",
            "relative_path": "a.smt2",
            "lexical_path": "/repo/corpus/a.smt2",
            "canonical_path": "/physical/a.smt2",
            "device": 1,
            "inode": 2,
            "bytes": 1,
            "sha256": "a" * 64,
        }
        alias = {
            **base,
            "manifest_id": 1,
            "manifest_path": "corpus/b.smt2",
            "relative_path": "b.smt2",
            "lexical_path": "/repo/corpus/b.smt2",
            "sha256": "b" * 64,
        }
        mutations = {
            "resolved path": {**alias, "device": 2, "inode": 3},
            "physical inode": {
                **alias,
                "canonical_path": "/physical/b.smt2",
            },
            "lexical path": {
                **alias,
                "manifest_path": base["manifest_path"],
                "relative_path": base["relative_path"],
                "lexical_path": base["lexical_path"],
                "canonical_path": "/physical/b.smt2",
                "device": 2,
                "inode": 3,
            },
        }
        for label, changed_alias in mutations.items():
            with self.subTest(label=label):
                portable = scan.hashlib.sha256(
                    scan._portable_source_set_bytes([base, changed_alias])
                ).hexdigest()
                with self.assertRaisesRegex(
                    scan.ShadowScanError, "path or inode alias"
                ):
                    scan._validate_source_ledger(
                        [base, changed_alias],
                        expected_sources=2,
                        expected_portable_sha256=portable,
                    )


if __name__ == "__main__":
    unittest.main()
