from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.test_analyze_campaign import write_raw_for_lock
from tests.test_shadow_campaign import CampaignFixture, canonical_bytes


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cert" / "audit_shadow_campaign.py"
SPEC = importlib.util.spec_from_file_location("audit_shadow_campaign", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ShadowShardAuditTests(unittest.TestCase):
    def test_reconstructs_complete_journal_and_rejects_summary_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("family/sat.smt2", expected="sat")
            fixture.finalize()
            completed = fixture.run(timeout=1.0)
            self.assertEqual(completed.returncode, 0, completed.stderr)

            summary = AUDIT.audit_shadow_shard(
                fixture.lock_path,
                fixture.raw_path,
                output_directory=fixture.output,
                binary=fixture.viper,
                checker=fixture.checker,
                timeout_s=1.0,
                timeout_grace_s=0.05,
            )
            self.assertEqual(summary["status"], "complete")
            self.assertEqual(summary["counts"]["verified_instances"], 1)

            summary_path = (
                fixture.output / "shard-0000-of-0001.summary.json"
            )
            drifted = json.loads(summary_path.read_text(encoding="utf-8"))
            drifted["counts"]["verified_instances"] = 0
            summary_path.write_bytes(canonical_bytes(drifted))
            with self.assertRaisesRegex(
                AUDIT.ShadowAuditError, "differs from reconstructed"
            ):
                AUDIT.audit_shadow_shard(
                    fixture.lock_path,
                    fixture.raw_path,
                    output_directory=fixture.output,
                    binary=fixture.viper,
                    checker=fixture.checker,
                    timeout_s=1.0,
                    timeout_grace_s=0.05,
                )

    def test_accepts_canonical_zero_work_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance(
                "family/unknown.smt2", expected="sat", campaign_result="unknown"
            )
            fixture.finalize()
            completed = fixture.run(timeout=1.0)
            self.assertEqual(completed.returncode, 0, completed.stderr)

            summary = AUDIT.audit_shadow_shard(
                fixture.lock_path,
                fixture.raw_path,
                output_directory=fixture.output,
                binary=fixture.viper,
                checker=fixture.checker,
                timeout_s=1.0,
                timeout_grace_s=0.05,
            )
            self.assertEqual(summary["selection"]["selected_instances"], 0)
            self.assertEqual(summary["counts"]["verified_instances"], 0)

    def test_global_audit_requires_the_exact_source_shard_union(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CampaignFixture(root / "fixture")
            for index in range(4):
                fixture.add_instance(f"family/case-{index}.smt2", expected="sat")
            parent_path, _ = fixture.finalize()
            parent = json.loads(parent_path.read_text(encoding="utf-8"))
            lock_directory = root / "bound-locks"
            results_root = root / "source-results"
            shadow_root = root / "shadow-results"
            for index in range(2):
                prepared = AUDIT.analyzer._expected_prepared_shard(parent, index, 2)
                bound = {
                    **prepared,
                    "lock_sha256": "",
                    "runtime_binding": {
                        "parent_lock_sha256": prepared["lock_sha256"],
                        "mechanism": "first_allowed_slurm_cpu",
                        "cpu_ids": [0],
                    },
                }
                bound["lock_sha256"] = AUDIT.analyzer._lock_sha256(bound)
                bound_path = lock_directory / f"bound-{index:04d}.json"
                bound_path.parent.mkdir(parents=True, exist_ok=True)
                bound_path.write_bytes(AUDIT.analyzer._canonical_json_bytes(bound))
                raw_path = results_root / f"shard-{index:04d}" / "raw.jsonl"
                write_raw_for_lock(bound, raw_path)
                AUDIT.shadow.run_shadow_campaign(
                    bound_path,
                    raw_path,
                    output_directory=shadow_root / f"source-shard-{index:04d}",
                    binary=fixture.viper,
                    checker=fixture.checker,
                    timeout_s=1.0,
                    timeout_grace_s=0.05,
                )

            report = AUDIT.audit_sharded_shadow_campaign(
                parent_path,
                lock_directory,
                results_root,
                shadow_output_root=shadow_root,
                binary=fixture.viper,
                checker=fixture.checker,
                timeout_s=1.0,
                timeout_grace_s=0.05,
            )

            self.assertEqual(report["status"], "complete")
            self.assertEqual(report["source_shards"], 2)
            self.assertEqual(report["selected_instances"], 4)
            self.assertEqual(report["verified_instances"], 4)
            self.assertEqual(report["verified_results"], {"sat": 4})

            missing_summary = (
                shadow_root
                / "source-shard-0001"
                / "shard-0000-of-0001.summary.json"
            )
            missing_summary.unlink()
            with self.assertRaisesRegex(AUDIT.ShadowAuditError, "shadow summary"):
                AUDIT.audit_sharded_shadow_campaign(
                    parent_path,
                    lock_directory,
                    results_root,
                    shadow_output_root=shadow_root,
                    binary=fixture.viper,
                    checker=fixture.checker,
                    timeout_s=1.0,
                    timeout_grace_s=0.05,
                )

    def test_global_audit_supports_sparse_continuation_physical_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CampaignFixture(root / "fixture")
            fixture.add_instance("family/case-0.smt2", expected="sat")
            fixture.add_instance("family/case-1.smt2", expected="sat")
            base_path, _ = fixture.finalize()
            base = json.loads(base_path.read_text(encoding="utf-8"))
            selection = [
                {"instance_id": "instance-0", "solver_id": "euf-viper"},
                {"instance_id": "instance-1", "solver_id": "z3"},
            ]
            for solver in base["solvers"]:
                solver["argv_template"] = ["{binary}", "{instance}"]
            base["schema_version"] = 2
            base["promotion_eligible"] = False
            base["budgets_s"] = [60]
            base["execution"]["order"] = "balanced_latin_square"
            base["run_selection"] = selection
            runner = ROOT / "scripts" / "bench" / "run_locked_campaign.py"
            base["continuation"] = {
                "mode": "timeout_only",
                "root_lock_sha256": "1" * 64,
                "parent_lock_path": str((root / "source-parent.json").resolve()),
                "parent_lock_file_sha256": "2" * 64,
                "parent_lock_sha256": "3" * 64,
                "shard_bundle_sha256": "4" * 64,
                "source_evidence_sha256": "4" * 64,
                "shard_lock_directory": str((root / "source-locks").resolve()),
                "shard_results_root": str((root / "source-results").resolve()),
                "source_budget_s": 2,
                "target_budget_s": 60,
                "selection_sha256": hashlib.sha256(
                    AUDIT.analyzer._canonical_json_bytes(selection)
                ).hexdigest(),
                "selected_instances": 2,
                "selected_runs": 2,
                "runner_path": str(runner.resolve()),
                "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
            }
            base["lock_sha256"] = AUDIT.analyzer._lock_sha256(base)
            parent_path = root / "continuation-parent.json"
            parent_path.write_bytes(AUDIT.analyzer._canonical_json_bytes(base))
            lock_directory = root / "bound-locks"
            results_root = root / "physical-results"
            shadow_root = root / "shadow-results"
            for index in range(2):
                prepared = AUDIT.analyzer._expected_prepared_shard(base, index, 2)
                bound = {
                    **prepared,
                    "lock_sha256": "",
                    "runtime_binding": {
                        "parent_lock_sha256": prepared["lock_sha256"],
                        "mechanism": "first_allowed_slurm_cpu",
                        "cpu_ids": [0],
                    },
                }
                bound["lock_sha256"] = AUDIT.analyzer._lock_sha256(bound)
                bound_path = lock_directory / f"bound-{index:04d}.json"
                bound_path.parent.mkdir(parents=True, exist_ok=True)
                bound_path.write_bytes(AUDIT.analyzer._canonical_json_bytes(bound))
                raw_path = results_root / f"shard-{index:04d}" / "raw.jsonl"
                write_raw_for_lock(bound, raw_path)
                AUDIT.shadow.run_shadow_campaign(
                    bound_path,
                    raw_path,
                    output_directory=shadow_root / f"source-shard-{index:04d}",
                    binary=fixture.viper,
                    checker=fixture.checker,
                    timeout_s=1.0,
                    timeout_grace_s=0.05,
                )

            report = AUDIT.audit_sharded_shadow_campaign(
                parent_path,
                lock_directory,
                results_root,
                shadow_output_root=shadow_root,
                binary=fixture.viper,
                checker=fixture.checker,
                timeout_s=1.0,
                timeout_grace_s=0.05,
            )

            self.assertEqual(report["selected_instances"], 1)
            self.assertEqual(report["verified_instances"], 1)
            self.assertEqual(
                [shard["verified_instances"] for shard in report["shards"]],
                [1, 0],
            )


if __name__ == "__main__":
    unittest.main()
