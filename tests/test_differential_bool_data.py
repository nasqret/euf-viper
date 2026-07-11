from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "differential_bool_data.py"
SPEC = importlib.util.spec_from_file_location("differential_bool_data", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)


FAKE_SOLVER = r'''from __future__ import annotations

import sys
import time
from pathlib import Path

mode = sys.argv[1]
case_path = Path(sys.argv[-1])
if not case_path.is_file():
    print("missing case", file=sys.stderr)
    raise SystemExit(66)

if mode == "sat":
    print("diagnostic")
    print("sat")
elif mode == "unsat":
    print("unsat")
elif mode == "unknown":
    print("unknown")
elif mode == "malformed":
    print("success")
elif mode == "ambiguous":
    print("sat")
    print("unsat")
elif mode == "failure":
    print("sat")
    print("synthetic failure", file=sys.stderr)
    raise SystemExit(7)
elif mode == "timeout":
    time.sleep(2.0)
else:
    raise SystemExit(64)
'''


def write_fake_solver(root: Path) -> Path:
    path = root / "fake solver.py"
    path.write_text(FAKE_SOLVER, encoding="utf-8")
    return path


def result(classification: str, reason: str = "test"):
    return CAMPAIGN.SolverResult(classification, reason, 0, classification, "")


class GenerationTests(unittest.TestCase):
    def test_generation_is_seeded_and_deterministic(self) -> None:
        first = CAMPAIGN.generate_cases(seed=9817, random_count=12)
        second = CAMPAIGN.generate_cases(seed=9817, random_count=12)
        changed = CAMPAIGN.generate_cases(seed=9818, random_count=12)

        self.assertEqual(first, second)
        self.assertEqual(len(CAMPAIGN.generate_exhaustive_cases()), 41)
        self.assertEqual(len(first), 53)
        self.assertEqual(
            [case.source for case in first[:41]],
            [case.source for case in changed[:41]],
        )
        self.assertNotEqual(
            [case.source for case in first[41:]],
            [case.source for case in changed[41:]],
        )

    def test_generation_only_artifacts_are_byte_deterministic_without_solvers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bool data generation ") as temp_dir:
            root = Path(temp_dir)
            outputs = [root / "first output", root / "second output"]
            for output in outputs:
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        "--out",
                        str(output),
                        "--seed",
                        "19",
                        "--random-cases",
                        "7",
                        "--no-exhaustive",
                        "--generate-only",
                        "--viper-command",
                        "/definitely/missing/viper {file}",
                        "--z3-command",
                        "/definitely/missing/z3 {file}",
                        "--cvc5-command",
                        "/definitely/missing/cvc5 {file}",
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            def artifact_bytes(output: Path) -> dict[str, bytes]:
                return {
                    path.relative_to(output).as_posix(): path.read_bytes()
                    for path in sorted(output.rglob("*"))
                    if path.is_file()
                }

            self.assertEqual(artifact_bytes(outputs[0]), artifact_bytes(outputs[1]))
            summary = json.loads(
                (outputs[0] / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["mode"], "generation-only")
            self.assertEqual(summary["counts"]["generated_cases"], 7)
            self.assertEqual(summary["counts"]["executed_cases"], 0)
            self.assertNotIn("execution", summary)

    def test_every_formula_has_parser_supported_bool_data_shape(self) -> None:
        cases = CAMPAIGN.generate_cases(seed=44, random_count=80)

        for case in cases:
            with self.subTest(case=case.case_id):
                self.assertTrue(case.source.startswith("(set-logic QF_UF)\n"))
                self.assertIn("(declare-sort U 0)\n", case.source)
                self.assertRegex(
                    case.source,
                    r"\(declare-fun f \(Bool(?: Bool)?\) U\)",
                )
                self.assertIn("(f ", case.source)
                self.assertEqual(case.source.count("(check-sat)"), 1)
                self.assertEqual(case.source.count("("), case.source.count(")"))
                self.assertTrue(case.source.endswith("\n"))


class SolverExecutionTests(unittest.TestCase):
    def test_classifies_decisive_unknown_error_and_timeout_results(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bool data solver ") as temp_dir:
            root = Path(temp_dir)
            fake_solver = write_fake_solver(root)
            case_path = root / "case with spaces.smt2"
            case_path.write_text("(check-sat)\n", encoding="utf-8")

            expected = {
                "sat": ("sat", "solver_result"),
                "unsat": ("unsat", "solver_result"),
                "unknown": ("unknown", "solver_unknown"),
                "malformed": ("error", "malformed_output"),
                "ambiguous": ("error", "ambiguous_output"),
                "failure": ("error", "nonzero_exit"),
                "timeout": ("unknown", "timeout"),
            }
            for mode, classification in expected.items():
                with self.subTest(mode=mode):
                    observed = CAMPAIGN.run_solver(
                        [sys.executable, str(fake_solver), mode, "{file}"],
                        case_path,
                        0.05 if mode == "timeout" else 1.0,
                    )
                    self.assertEqual(
                        (observed.classification, observed.reason), classification
                    )

            missing = CAMPAIGN.run_solver(
                [str(root / "missing executable")], case_path, 1.0
            )
            self.assertEqual((missing.classification, missing.reason), ("error", "spawn_error"))

    def test_command_parser_preserves_argv_and_requires_standalone_placeholder(self) -> None:
        command = CAMPAIGN.parse_command(
            '"/path with spaces/viper" solve --flag "two words" {file}'
        )
        self.assertEqual(
            command,
            ("/path with spaces/viper", "solve", "--flag", "two words", "{file}"),
        )
        with self.assertRaises(ValueError):
            CAMPAIGN.parse_command("solver --input={file}")


class ComparisonTests(unittest.TestCase):
    def test_reference_disagreement_and_nondecisive_oracles_are_not_compared(self) -> None:
        reference, anomalies = CAMPAIGN.analyze_observations(
            {
                "euf-viper": result("sat"),
                "z3": result("sat"),
                "cvc5": result("unsat"),
            }
        )
        self.assertFalse(reference["agree"])
        self.assertFalse(reference["decisive"])
        self.assertIsNone(reference["classification"])
        self.assertEqual(anomalies, ["reference_disagreement"])

        reference, anomalies = CAMPAIGN.analyze_observations(
            {
                "euf-viper": result("unknown"),
                "z3": result("unknown"),
                "cvc5": result("unknown"),
            }
        )
        self.assertTrue(reference["agree"])
        self.assertFalse(reference["decisive"])
        self.assertEqual(anomalies, ["reference_nondecisive"])

    def test_candidate_is_checked_only_against_a_decisive_agreed_oracle(self) -> None:
        reference, anomalies = CAMPAIGN.analyze_observations(
            {
                "euf-viper": result("sat"),
                "z3": result("unsat"),
                "cvc5": result("unsat"),
            }
        )
        self.assertEqual(reference["classification"], "unsat")
        self.assertEqual(anomalies, ["viper_discrepancy"])

        _, no_anomalies = CAMPAIGN.analyze_observations(
            {
                "euf-viper": result("unsat"),
                "z3": result("unsat"),
                "cvc5": result("unsat"),
            }
        )
        self.assertEqual(no_anomalies, [])

    def test_campaign_copies_every_discrepancy_and_writes_json_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bool data artifacts ") as temp_dir:
            root = Path(temp_dir)
            fake_solver = write_fake_solver(root)
            output = root / "campaign output"
            case = CAMPAIGN.FormulaCase(
                "artifact-discrepancy",
                "test-family",
                """(set-logic QF_UF)
(declare-sort U 0)
(declare-fun p () Bool)
(declare-fun f (Bool) U)
(assert (= (f p) (f p)))
(check-sat)
""",
                {"generator": "random", "index": 0},
            )
            commands = {
                "euf-viper": (sys.executable, str(fake_solver), "sat", "{file}"),
                "z3": (sys.executable, str(fake_solver), "unsat", "{file}"),
                "cvc5": (sys.executable, str(fake_solver), "unsat", "{file}"),
            }

            summary = CAMPAIGN.execute_campaign(
                cases=[case],
                output_dir=output,
                seed=5,
                requested_random_cases=1,
                generation_only=False,
                commands=commands,
                timeout_s=1.0,
            )

            generated = output / "cases" / "artifact-discrepancy.smt2"
            discrepancy = output / "discrepancies" / "artifact-discrepancy.smt2"
            self.assertEqual(generated.read_text(encoding="utf-8"), case.source)
            self.assertEqual(discrepancy.read_text(encoding="utf-8"), case.source)
            self.assertEqual(summary["counts"]["viper_discrepancies"], 1)
            self.assertEqual(summary["counts"]["discrepancy_formulas"], 1)
            self.assertEqual(
                summary["cases"][0]["anomalies"], ["viper_discrepancy"]
            )
            self.assertEqual(
                summary["cases"][0]["discrepancy_path"],
                "discrepancies/artifact-discrepancy.smt2",
            )
            on_disk = json.loads(
                (output / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(on_disk, summary)


if __name__ == "__main__":
    unittest.main()
