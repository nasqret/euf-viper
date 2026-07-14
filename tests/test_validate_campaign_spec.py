from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "validate_campaign_spec.py"
CAMPAIGN = ROOT / "campaigns" / "best-overall-qf-uf-2026-07.json"
MODULE_SPEC = importlib.util.spec_from_file_location("validate_campaign_spec", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(VALIDATOR)


def load_spec() -> dict:
    return json.loads(CAMPAIGN.read_text(encoding="utf-8"))


class CampaignSpecTests(unittest.TestCase):
    def test_repository_campaign_is_valid(self) -> None:
        result = VALIDATOR.validate_spec(load_spec())

        self.assertTrue(result["valid"])
        self.assertEqual(result["budgets_s"], [2, 60, 1200])
        self.assertEqual(result["tracks"][0], "F0")
        self.assertIn("opensmt", result["comparators"])

    def test_missing_opensmt_is_rejected(self) -> None:
        spec = load_spec()
        spec["comparators"] = [
            item for item in spec["comparators"] if item["id"] != "opensmt"
        ]

        with self.assertRaises(VALIDATOR.CampaignSpecError) as caught:
            VALIDATOR.validate_spec(spec)

        self.assertTrue(any("opensmt" in error for error in caught.exception.errors))

    def test_unknown_track_dependency_is_rejected(self) -> None:
        spec = load_spec()
        spec["tracks"][1]["prerequisites"].append("MISSING")

        with self.assertRaises(VALIDATOR.CampaignSpecError) as caught:
            VALIDATOR.validate_spec(spec)

        self.assertTrue(
            any("unknown prerequisites" in error for error in caught.exception.errors)
        )

    def test_weakened_soundness_policy_is_rejected(self) -> None:
        spec = load_spec()
        spec["promotion_policy"]["wrong_answers_allowed"] = 1
        spec["promotion_policy"]["held_out_gate_before_superiority_claim"] = False

        with self.assertRaises(VALIDATOR.CampaignSpecError) as caught:
            VALIDATOR.validate_spec(spec)

        errors = caught.exception.errors
        self.assertTrue(any("wrong_answers_allowed" in error for error in errors))
        self.assertTrue(any("held_out_gate" in error for error in errors))

    def test_missing_release_lock_is_rejected(self) -> None:
        spec = load_spec()
        del spec["release_lock"]

        with self.assertRaises(VALIDATOR.CampaignSpecError) as caught:
            VALIDATOR.validate_spec(spec)

        self.assertTrue(any("release_lock" in error for error in caught.exception.errors))

    def test_boolean_schema_version_is_rejected(self) -> None:
        spec = load_spec()
        spec["schema_version"] = True

        with self.assertRaises(VALIDATOR.CampaignSpecError) as caught:
            VALIDATOR.validate_spec(spec)

        self.assertTrue(any("schema_version" in error for error in caught.exception.errors))

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "campaign.json"
            rendered = CAMPAIGN.read_text(encoding="utf-8").rstrip()
            path.write_text(
                rendered[:-1] + ',"schema_version":1}\n', encoding="utf-8"
            )

            with self.assertRaises(VALIDATOR.CampaignSpecError) as caught:
                VALIDATOR.load_and_validate(path)

            self.assertTrue(any("duplicate" in error for error in caught.exception.errors))

    def test_cli_writes_machine_readable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "validated.json"
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), str(CAMPAIGN), "--out", str(output)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(result["valid"])
            self.assertEqual(result["campaign_id"], "best-overall-qf-uf-2026-07")

    def test_bound_artifact_hash_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = Path(temp_dir)
            campaign_dir = repository / "campaigns"
            corpus_dir = repository / "benchmarks" / "smtcomp-2025"
            campaign_dir.mkdir(parents=True)
            corpus_dir.mkdir(parents=True)
            shutil.copy2(
                ROOT / "campaigns" / "solver-releases-2026-07.json",
                campaign_dir / "solver-releases-2026-07.json",
            )
            shutil.copy2(
                ROOT / "benchmarks" / "smtcomp-2025" / "qf_uf_manifest.jsonl",
                corpus_dir / "qf_uf_manifest.jsonl",
            )
            spec = load_spec()
            official = next(
                item for item in spec["corpora"] if item["id"] == "smtcomp-2025-qf-uf"
            )
            official["manifest_sha256"] = "0" * 64
            path = campaign_dir / "best-overall-qf-uf-2026-07.json"
            path.write_text(json.dumps(spec), encoding="utf-8")

            with self.assertRaises(VALIDATOR.CampaignSpecError) as caught:
                VALIDATOR.load_and_validate(path)

            self.assertTrue(any("mismatch" in error for error in caught.exception.errors))


if __name__ == "__main__":
    unittest.main()
