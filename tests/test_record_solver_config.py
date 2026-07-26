from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "record_solver_config.py"
CAMPAIGN = ROOT / "campaigns" / "best-overall-qf-uf-2026-07.json"
MODULE_SPEC = importlib.util.spec_from_file_location("record_solver_config", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
RECORDER = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(RECORDER)


class RecordSolverConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.binary = self.root / "solver"
        self.binary.write_text(
            "#!/bin/sh\n"
            "case \"${1:-}\" in\n"
            "  --version|-version) echo 'euf-viper 4.16.0 1.3.4 2.7.0 2.9.2' ;;\n"
            "  *) echo sat ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_records_all_required_configurations_and_smokes(self) -> None:
        versions = RECORDER.load_versions(CAMPAIGN)
        records = RECORDER.make_records(
            versions=versions,
            viper=self.binary,
            z3=self.binary,
            cvc5=self.binary,
            yices2=self.binary,
            opensmt=self.binary,
            viper_version="test-build",
        )

        self.assertEqual(len(records), 6)
        self.assertEqual(
            {record["id"] for record in records},
            {
                "euf-viper",
                "z3-default",
                "z3-sat-euf",
                "cvc5",
                "yices2",
                "opensmt",
            },
        )
        self.assertTrue(all(len(record["sha256"]) == 64 for record in records))
        smoke = self.root / "smoke.smt2"
        smoke.write_text("(check-sat)\n", encoding="utf-8")
        for record in records:
            RECORDER.smoke_solver(record, smoke, "sat")

    def test_non_executable_binary_is_rejected(self) -> None:
        self.binary.chmod(0o644)
        with self.assertRaisesRegex(RECORDER.SolverConfigError, "not executable"):
            RECORDER.make_records(
                versions=RECORDER.load_versions(CAMPAIGN),
                viper=self.binary,
                z3=self.binary,
                cvc5=self.binary,
                yices2=self.binary,
                opensmt=self.binary,
                viper_version="test-build",
            )

    def test_records_explicit_structural_viper_command(self) -> None:
        records = RECORDER.make_records(
            versions=RECORDER.load_versions(CAMPAIGN),
            viper=self.binary,
            z3=self.binary,
            cvc5=self.binary,
            yices2=self.binary,
            opensmt=self.binary,
            viper_version="structural-build",
            viper_argv_template=[
                "{binary}",
                "fabric-solve",
                "--engine",
                "quotient-portfolio",
                "{instance}",
            ],
            viper_configuration="quotient-portfolio",
        )
        viper = next(record for record in records if record["id"] == "euf-viper")
        self.assertEqual(viper["configuration"], "quotient-portfolio")
        self.assertEqual(
            viper["argv_template"],
            [
                "{binary}",
                "fabric-solve",
                "--engine",
                "quotient-portfolio",
                "{instance}",
            ],
        )

    def test_rejects_ambiguous_viper_command(self) -> None:
        with self.assertRaisesRegex(RECORDER.SolverConfigError, "exactly one"):
            RECORDER.make_records(
                versions=RECORDER.load_versions(CAMPAIGN),
                viper=self.binary,
                z3=self.binary,
                cvc5=self.binary,
                yices2=self.binary,
                opensmt=self.binary,
                viper_version="test-build",
                viper_argv_template=["{binary}", "solve"],
            )

    def test_records_z3_runtime_environment_for_both_configurations(self) -> None:
        records = RECORDER.make_records(
            versions=RECORDER.load_versions(CAMPAIGN),
            viper=self.binary,
            z3=self.binary,
            cvc5=self.binary,
            yices2=self.binary,
            opensmt=self.binary,
            viper_version="test-build",
            z3_environment={"LD_LIBRARY_PATH": "/pinned/z3/lib"},
        )
        z3_records = [record for record in records if record["comparator_id"] == "z3"]
        self.assertEqual(len(z3_records), 2)
        self.assertTrue(
            all(
                record["environment"] == {"LD_LIBRARY_PATH": "/pinned/z3/lib"}
                for record in z3_records
            )
        )

    def test_environment_parser_is_strict(self) -> None:
        self.assertEqual(
            RECORDER.parse_environment(["B=two", "A=one"]),
            {"A": "one", "B": "two"},
        )
        with self.assertRaisesRegex(RECORDER.SolverConfigError, "NAME=VALUE"):
            RECORDER.parse_environment(["not-a-binding"])
        with self.assertRaisesRegex(RECORDER.SolverConfigError, "duplicate"):
            RECORDER.parse_environment(["A=one", "A=two"])

    def test_campaign_must_have_exact_comparator_set(self) -> None:
        spec = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        spec["comparators"] = spec["comparators"][:-1]
        path = self.root / "campaign.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        with self.assertRaisesRegex(RECORDER.SolverConfigError, "comparators must equal"):
            RECORDER.load_versions(path)

    def test_smoke_rejects_wrong_result(self) -> None:
        record = {
            "id": "fake",
            "binary": str(self.binary),
            "argv_template": ["{binary}", "{instance}"],
        }
        smoke = self.root / "smoke.smt2"
        smoke.write_text("(check-sat)\n", encoding="utf-8")
        with self.assertRaisesRegex(RECORDER.SolverConfigError, "result='sat'"):
            RECORDER.smoke_solver(record, smoke, "unsat")


if __name__ == "__main__":
    unittest.main()
