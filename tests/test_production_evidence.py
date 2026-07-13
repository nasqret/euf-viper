from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts" / "cert" / "check_production_evidence.py"
SPEC = importlib.util.spec_from_file_location("check_production_evidence", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


SAT_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(declare-fun p () Bool)
(declare-fun h (Bool U) U)
(assert (and p (distinct a b)
  (= (h (ite p true false) a) (h true a))))
(check-sat)
"""

UNSAT_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(assert (distinct a a))
(check-sat)
"""

CLOSURE_SAT_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(check-sat)
"""

BACKEND_SAT_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(assert (distinct a b))
(check-sat)
"""


class ProductionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        completed = subprocess.run(
            ["cargo", "build", "--quiet"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr)
        cls.binary = ROOT / "target" / "debug" / "euf-viper"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def solve(
        self,
        source_text: str,
        name: str = "case",
        *,
        environment: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        source = self.root / f"{name}.smt2"
        evidence = self.root / f"{name}.evidence.json"
        source.write_text(source_text, encoding="utf-8")
        completed = subprocess.run(
            [
                str(self.binary),
                "solve",
                str(source),
                "--evidence-out",
                str(evidence),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, **(environment or {})},
        )
        return completed, source, evidence

    def test_sat_sidecar_validates_the_literal_assignment_and_model(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "sat")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "sat\n")
        result = CHECKER.validate_production_evidence(
            evidence,
            source,
            expected_status="sat",
        )
        self.assertEqual(result["status"], "sat")
        self.assertGreater(result["terms"], 0)
        self.assertGreater(result["assignment_variables"], 0)

        payload = json.loads(evidence.read_text(encoding="ascii"))
        self.assertEqual(payload["model"]["origin"], "cnf_assignment")
        self.assertIn(
            payload["solver"]["backend"],
            {"kissat", "cadical", "cadical-refine", "varisat", "dpll-t"},
        )
        self.assertTrue(payload["model"]["atoms"])

    def test_utf8_runtime_configuration_has_a_stable_hash(self) -> None:
        completed, source, evidence = self.solve(
            SAT_SOURCE,
            "utf8-config",
            environment={"EUF_VIPER_TEST_UNICODE": "alpha-\u03b1"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = CHECKER.validate_production_evidence(
            evidence,
            source,
            expected_status="sat",
        )
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["solver"]["config"]["EUF_VIPER_TEST_UNICODE"],
            "alpha-\u03b1",
        )
        self.assertEqual(
            result["solver_config_sha256"],
            payload["solver"]["config_sha256"],
        )

    def test_direct_closure_sidecar_validates_without_a_cnf_assignment(self) -> None:
        completed, source, evidence = self.solve(CLOSURE_SAT_SOURCE, "closure")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = CHECKER.validate_production_evidence(
            evidence,
            source,
            expected_status="sat",
        )
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(payload["solver"]["backend"], "congruence-closure")
        self.assertEqual(payload["model"]["origin"], "congruence_closure")
        self.assertIsNone(payload["model"]["assignment"])
        self.assertEqual(result["assignment_variables"], 0)

    def test_every_sat_backend_exports_its_same_run_model(self) -> None:
        backends = {
            "kissat": "kissat",
            "cadical": "cadical",
            "cadical-refine": "cadical-refine",
            "varisat": "varisat",
            "dpll": "dpll-t",
        }
        for selected, expected in backends.items():
            with self.subTest(backend=selected):
                completed, source, evidence = self.solve(
                    BACKEND_SAT_SOURCE,
                    f"backend-{selected}",
                    environment={"EUF_VIPER_BACKEND": selected},
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = CHECKER.validate_production_evidence(
                    evidence,
                    source,
                    expected_status="sat",
                )
                payload = json.loads(evidence.read_text(encoding="utf-8"))
                self.assertEqual(payload["solver"]["backend"], expected)
                self.assertGreater(result["assignment_variables"], 0)

    def test_tampered_atom_and_source_are_rejected(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "tamper")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="ascii"))
        payload["model"]["atoms"][0]["value"] = not payload["model"]["atoms"][0]["value"]
        evidence.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(CHECKER.ProductionEvidenceError, "atom .* disagrees"):
            CHECKER.validate_production_evidence(evidence, source, expected_status="sat")

        source.write_text(SAT_SOURCE + "; changed\n", encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ProductionEvidenceError, "source SHA-256 mismatch"):
            CHECKER.validate_production_evidence(evidence, source, expected_status="sat")

    def test_boolean_model_rejects_a_third_value(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "third-bool-value")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        true_term = payload["model"]["true_term"]
        false_term = payload["model"]["false_term"]
        candidate = next(
            term
            for term in payload["model"]["terms"]
            if term["sort"] == "Bool" and term["id"] not in {true_term, false_term}
        )
        candidate["class"] = max(
            term["class"] for term in payload["model"]["terms"]
        ) + 1
        evidence.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CHECKER.ProductionEvidenceError, "third value"):
            CHECKER.validate_production_evidence(evidence, source, expected_status="sat")

    def test_sidecar_is_immutable_and_never_replaced(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "immutable")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        original = evidence.read_bytes()
        rerun = subprocess.run(
            [
                str(self.binary),
                "solve",
                str(source),
                "--evidence-out",
                str(evidence),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rerun.returncode, 2)
        self.assertNotIn("sat", rerun.stdout.split())
        self.assertIn("refusing to replace immutable evidence", rerun.stderr)
        self.assertEqual(
            hashlib.sha256(evidence.read_bytes()).digest(),
            hashlib.sha256(original).digest(),
        )
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

    def test_unsat_without_same_run_proof_fails_closed(self) -> None:
        completed, source, evidence = self.solve(UNSAT_SOURCE, "unsat")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(completed.stdout, "unsupported\n")
        payload = json.loads(evidence.read_text(encoding="ascii"))
        self.assertEqual(payload["status"], "unsupported")
        self.assertEqual(payload["backend_status"], "unsat")
        self.assertIsNone(payload["model"])
        result = CHECKER.validate_production_evidence(
            evidence,
            source,
            expected_status="unsupported",
        )
        self.assertEqual(result["backend_status"], "unsat")


if __name__ == "__main__":
    unittest.main()
