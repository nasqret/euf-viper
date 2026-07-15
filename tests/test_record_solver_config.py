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
            "  *)\n"
            "    previous=''\n"
            "    for argument in \"$@\"; do\n"
            "      if [ \"$previous\" = '--evidence-out' ]; then\n"
            "        printf '%s\\n' '{\"backend_cnf\":{},\"backend_status\":\"sat\",\"limitations\":[],\"model\":{},\"run_nonce\":\"test\",\"schema\":\"euf-viper.production-evidence.v4\",\"solver\":{},\"source\":{},\"status\":\"sat\"}' > \"$argument\"\n"
            "      fi\n"
            "      previous=$argument\n"
            "    done\n"
            "    echo sat\n"
            "    ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        self.feature_report = self.root / "euf-viper-build-features"
        self.feature_report.write_text(
            "#!/bin/sh\necho 'certificates,production-evidence'\n",
            encoding="ascii",
        )
        self.feature_report.chmod(0o755)

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
            viper_feature_report=self.feature_report,
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
                viper_feature_report=self.feature_report,
            )

    def test_campaign_must_have_exact_comparator_set(self) -> None:
        spec = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        spec["comparators"] = spec["comparators"][:-1]
        path = self.root / "campaign.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        with self.assertRaisesRegex(
            RECORDER.SolverConfigError, "missing required comparators|comparators must equal"
        ):
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

    def test_feature_probe_rejects_a_binary_without_evidence(self) -> None:
        self.feature_report.write_text(
            "#!/bin/sh\necho 'certificates,finite-symmetry'\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(
            RECORDER.SolverConfigError,
            "lacks required locked evidence features: production-evidence",
        ):
            RECORDER.require_viper_evidence_features(self.feature_report)

    def test_configuration_publication_is_immutable_and_no_follow(self) -> None:
        existing = self.root / "existing.json"
        existing.write_bytes(b"preserve\n")
        with self.assertRaisesRegex(
            RECORDER.SolverConfigError, "already exists|immutable artifact drift"
        ):
            RECORDER.atomic_write(existing, {"schema_version": 1})
        self.assertEqual(existing.read_bytes(), b"preserve\n")

        victim = self.root / "victim.json"
        victim.write_bytes(b"victim\n")
        link = self.root / "link.json"
        link.symlink_to(victim)
        with self.assertRaisesRegex(
            RECORDER.SolverConfigError,
            "already exists|symlink|immutable artifact drift|not a regular file",
        ):
            RECORDER.atomic_write(link, {"schema_version": 1})
        self.assertEqual(victim.read_bytes(), b"victim\n")


if __name__ == "__main__":
    unittest.main()
