#!/usr/bin/env python3
"""End-to-end tests for the certificate checker's manifest boundary."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "cert" / "check_certificate.py"
SAT_SOURCE = ROOT / "tests" / "fixtures" / "basic_sat.smt2"
UNSAT_SOURCE = ROOT / "tests" / "fixtures" / "basic_unsat.smt2"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CertificateCheckerManifestBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)
        self.manifest_path = self.directory / "certificate.json"
        self.dimacs_path = self.directory / "certificate.cnf"
        self.proof_path = self.directory / "certificate.drat"
        self.drat_trim = self.directory / "drat-trim"

        self.dimacs_path.write_text(
            "p cnf 2 3\n1 0\n-2 0\n-1 2 0\n", encoding="ascii"
        )
        self.proof_path.write_text("0\n", encoding="ascii")
        self.drat_trim.write_text(
            f"#!{sys.executable}\nprint('VERIFIED')\n", encoding="utf-8"
        )
        self.drat_trim.chmod(0o755)

    def sat_manifest(self) -> dict[str, object]:
        return {
            "format": "euf-viper-euf-cnf-v2",
            "encoding": "canonical-tseitin-v1",
            "result": "sat",
            "source": str(SAT_SOURCE),
            "source_sha256": sha256(SAT_SOURCE),
            "variables": 1,
            "assignment": [-1],
        }

    def unsat_manifest(self) -> dict[str, object]:
        return {
            "format": "euf-viper-euf-cnf-v2",
            "encoding": "canonical-tseitin-v1",
            "result": "unsat",
            "source": str(UNSAT_SOURCE),
            "source_sha256": sha256(UNSAT_SOURCE),
            "variables": 2,
            "finite_domain_axioms": 0,
            "clauses": {
                "base": 2,
                "transitivity": 0,
                "congruence": 1,
                "theory_conflicts": 0,
                "total": 3,
            },
            "dimacs": str(self.dimacs_path),
            "dimacs_sha256": sha256(self.dimacs_path),
            "proof": str(self.proof_path),
            "proof_sha256": sha256(self.proof_path),
        }

    def run_raw_manifest(self, raw_manifest: str) -> subprocess.CompletedProcess[str]:
        self.manifest_path.write_text(raw_manifest, encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                str(self.manifest_path),
                "--drat-trim",
                str(self.drat_trim),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def run_manifest(
        self, manifest: dict[str, object]
    ) -> subprocess.CompletedProcess[str]:
        return self.run_raw_manifest(json.dumps(manifest, sort_keys=True) + "\n")

    def assert_rejected(
        self, completed: subprocess.CompletedProcess[str], diagnostic: str
    ) -> None:
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertEqual(completed.stdout, "")
        self.assertIn(diagnostic, completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_valid_sat_manifest_is_accepted(self) -> None:
        completed = self.run_manifest(self.sat_manifest())

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["result"], "sat")
        self.assertEqual(report["variables"], 1)

    def test_valid_unsat_manifest_is_accepted(self) -> None:
        completed = self.run_manifest(self.unsat_manifest())

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["result"], "unsat")
        self.assertEqual(report["variables"], 2)
        self.assertEqual(report["replayed_theory_clauses"], 1)

    def test_duplicate_result_keys_are_rejected_before_validation(self) -> None:
        raw_manifest = json.dumps(self.sat_manifest(), sort_keys=True)
        raw_manifest = raw_manifest.replace(
            '"result": "sat"', '"result": "sat", "result": "unsat"', 1
        )

        completed = self.run_raw_manifest(raw_manifest)

        self.assert_rejected(completed, "duplicate JSON key 'result'")

    def test_non_finite_json_constants_are_rejected_before_validation(self) -> None:
        raw_manifest = json.dumps(self.sat_manifest(), sort_keys=True)
        self.assertIn('"variables": 1', raw_manifest)
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                malformed = raw_manifest.replace(
                    '"variables": 1', f'"variables": {constant}', 1
                )
                completed = self.run_raw_manifest(malformed)
                self.assert_rejected(completed, "non-finite JSON number")

    def test_sat_variables_reject_float_and_boolean_values(self) -> None:
        raw_manifest = json.dumps(self.sat_manifest(), sort_keys=True)
        for value in ("1.0", "true"):
            with self.subTest(value=value):
                malformed = raw_manifest.replace(
                    '"variables": 1', f'"variables": {value}', 1
                )
                completed = self.run_raw_manifest(malformed)
                self.assert_rejected(
                    completed, "SAT manifest variables must be an exact integer"
                )

    def test_missing_source_is_rejected_without_a_traceback(self) -> None:
        manifest = self.sat_manifest()
        del manifest["source"]

        completed = self.run_manifest(manifest)

        self.assert_rejected(
            completed,
            "certificate manifest field 'source' must be a nonempty string",
        )

    def test_wrong_typed_required_artifact_fields_fail_closed(self) -> None:
        cases = [
            (self.sat_manifest, "source"),
            (self.sat_manifest, "source_sha256"),
            (self.unsat_manifest, "dimacs"),
            (self.unsat_manifest, "dimacs_sha256"),
            (self.unsat_manifest, "proof"),
            (self.unsat_manifest, "proof_sha256"),
        ]
        for factory, field in cases:
            with self.subTest(field=field):
                manifest = factory()
                manifest[field] = False
                completed = self.run_manifest(manifest)
                self.assert_rejected(
                    completed,
                    f"certificate manifest field {field!r} must be a nonempty string",
                )


if __name__ == "__main__":
    unittest.main()
