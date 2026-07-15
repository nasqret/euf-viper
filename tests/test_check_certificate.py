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
CERT_SCRIPT_DIRECTORY = ROOT / "scripts" / "cert"
if str(CERT_SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(CERT_SCRIPT_DIRECTORY))
import independent_qfuf as QFUF


V3_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun c0 () U)
(declare-fun c1 () U)
(declare-fun f (U) U)
(declare-fun p (U) Bool)
(assert (distinct c0 c1))
(assert (or (= (f c0) c0) (= (f c0) c1)))
(assert (or (= (f c1) c0) (= (f c1) c1)))
(assert (= (f c0) (f c1)))
(assert (or (p c0) (not (p c0)) (p c1) (not (p c1))))
(assert
  (or
    (and (p (f c0)) (not (p (f c1))))
    (and (not (p (f c0))) (p (f c1)))))
(check-sat)
"""


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

    def v3_manifest(self) -> dict[str, object]:
        source_path = self.directory / "finite-orbit.smt2"
        source_path.write_text(V3_SOURCE, encoding="utf-8")
        problem = QFUF.parse_and_encode(V3_SOURCE)
        witness = {
            "domain_terms": [2, 3],
            "membership_terms": [2, 3, 4, 5],
            "lex_terms": [4, 5],
        }
        reconstruction = QFUF._reconstruct_v3_orbit_kernel(problem, witness)
        clauses = tuple(
            clause
            for category in QFUF._V3_CLAUSE_CATEGORIES
            for clause in reconstruction.categories[category]
        )
        self.dimacs_path.write_text(
            "p cnf "
            f"{reconstruction.variables} {len(clauses)}\n"
            + "".join(
                " ".join(str(literal) for literal in clause) + " 0\n"
                for clause in clauses
            ),
            encoding="ascii",
        )
        counts = {
            category: len(reconstruction.categories[category])
            for category in QFUF._V3_CLAUSE_CATEGORIES
        }
        counts["total"] = len(clauses)
        return {
            "format": QFUF.V3_FORMAT,
            "encoding": QFUF.V3_ENCODING,
            "result": "unsat",
            "source": str(source_path),
            "source_sha256": sha256(source_path),
            "variables": reconstruction.variables,
            "clauses": counts,
            "finite_orbit": witness,
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

    def test_valid_v3_unsat_manifest_is_accepted_and_invokes_drat(self) -> None:
        completed = self.run_manifest(self.v3_manifest())

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["result"], "unsat")
        self.assertEqual(report["variables"], 21)
        self.assertEqual(report["base_clauses"], 26)
        self.assertEqual(report["replayed_kernel_clauses"], 38)

    def test_v3_rejects_sat_unknown_keys_and_hash_tampering(self) -> None:
        cases = []

        sat = self.v3_manifest()
        sat["result"] = "sat"
        cases.append(("SAT result", sat, "must claim UNSAT"))

        unknown = self.v3_manifest()
        unknown["atoms"] = []
        cases.append(("unknown key", unknown, "unknown atoms"))

        bad_source_hash = self.v3_manifest()
        bad_source_hash["source_sha256"] = "0" * 64
        cases.append(("source hash", bad_source_hash, "source SHA-256 mismatch"))

        bad_dimacs_hash = self.v3_manifest()
        bad_dimacs_hash["dimacs_sha256"] = "0" * 64
        cases.append(("DIMACS hash", bad_dimacs_hash, "DIMACS SHA-256 mismatch"))

        bad_proof_hash = self.v3_manifest()
        bad_proof_hash["proof_sha256"] = "0" * 64
        cases.append(("proof hash", bad_proof_hash, "proof SHA-256 mismatch"))

        for label, manifest, diagnostic in cases:
            with self.subTest(label=label):
                self.assert_rejected(self.run_manifest(manifest), diagnostic)

    def test_v3_duplicate_keys_and_nonfinite_counts_fail_before_validation(self) -> None:
        raw_manifest = json.dumps(self.v3_manifest(), sort_keys=True)
        duplicate = raw_manifest.replace(
            '"result": "unsat"',
            '"result": "unsat", "result": "unsat"',
            1,
        )
        self.assert_rejected(
            self.run_raw_manifest(duplicate), "duplicate JSON key 'result'"
        )

        self.assertIn('"guarded_rows": 4', raw_manifest)
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                malformed = raw_manifest.replace(
                    '"guarded_rows": 4',
                    f'"guarded_rows": {constant}',
                    1,
                )
                self.assert_rejected(
                    self.run_raw_manifest(malformed), "non-finite JSON number"
                )

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
