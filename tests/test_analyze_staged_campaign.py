from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from tests import test_derive_timeout_continuations as fixtures


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_staged_campaign.py"
MODULE_SPEC = importlib.util.spec_from_file_location("analyze_staged_campaign", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
STAGED = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(STAGED)

ANALYZER = STAGED.analyzer
DERIVER = STAGED.derivation


def execute_continuation(
    root: Path,
    index: Mapping[str, Any],
    classifications: Mapping[tuple[str, str], str] | None = None,
) -> tuple[Path, Path]:
    lock_record = index["continuation_lock"]
    assert isinstance(lock_record, dict)
    parent_path = Path(lock_record["path"])
    parent = json.loads(parent_path.read_text(encoding="utf-8"))
    instance_count = len(parent["corpus"]["instances"])
    shard_count = min(2, instance_count)
    lock_directory = root / "bound-locks"
    results_root = root / "shard-results"
    for shard_index in range(shard_count):
        prepared = ANALYZER._expected_prepared_shard(
            parent, shard_index, shard_count
        )
        cpu_id = 20 + shard_index
        bound = {
            **prepared,
            "lock_sha256": "",
            "execution": {**prepared["execution"], "cpu_ids": [cpu_id]},
            "runtime_binding": {
                "parent_lock_sha256": prepared["lock_sha256"],
                "mechanism": "first_allowed_slurm_cpu",
                "cpu_ids": [cpu_id],
            },
        }
        bound["lock_sha256"] = ANALYZER._lock_sha256(bound)
        bound_path = lock_directory / f"bound-{shard_index:04d}.json"
        bound_path.parent.mkdir(parents=True, exist_ok=True)
        bound_path.write_bytes(ANALYZER._canonical_json_bytes(bound))
        fixtures._write_raw(
            bound,
            results_root / f"shard-{shard_index:04d}" / "raw.jsonl",
            classifications or {},
        )
    return lock_directory, results_root


def raw_snapshot(*roots: Path) -> dict[Path, bytes]:
    return {
        path: path.read_bytes()
        for root in roots
        for path in sorted(root.glob("shard-*/raw.jsonl"))
    }


class StagedCampaignTests(unittest.TestCase):
    def test_full_2_60_1200_chain_preserves_raw_and_carries_solved_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_parent, base_locks, base_results = fixtures.write_sharded_campaign(
                root / "base",
                {
                    ("instance-0", "euf-viper"): "timeout",
                    ("instance-1", "z3"): "timeout",
                },
            )
            stage60_output = root / "stage-60"
            index60 = DERIVER.derive_continuation(
                base_parent,
                base_locks,
                base_results,
                60,
                stage60_output,
            )
            locks60, results60 = execute_continuation(
                root / "executed-60",
                index60,
                {("instance-1", "z3"): "timeout"},
            )

            stage1200_output = root / "stage-1200"
            index1200 = DERIVER.derive_continuation(
                Path(index60["continuation_lock"]["path"]),
                locks60,
                results60,
                1200,
                stage1200_output,
            )
            base_lock = json.loads(base_parent.read_text(encoding="utf-8"))
            lock60 = json.loads(
                Path(index60["continuation_lock"]["path"]).read_text(
                    encoding="utf-8"
                )
            )
            lock1200 = json.loads(
                Path(index1200["continuation_lock"]["path"]).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                lock60["continuation"]["root_lock_sha256"],
                base_lock["lock_sha256"],
            )
            self.assertEqual(
                lock1200["continuation"]["root_lock_sha256"],
                base_lock["lock_sha256"],
            )
            self.assertEqual(
                lock1200["continuation"]["parent_lock_sha256"],
                lock60["lock_sha256"],
            )
            self.assertEqual(
                lock1200["continuation"]["source_evidence_sha256"],
                index1200["source"]["shard_bundle_sha256"],
            )
            self.assertEqual(
                ANALYZER.sha256_file(
                    Path(lock1200["continuation"]["runner_path"])
                ),
                lock1200["continuation"]["runner_sha256"],
            )
            self.assertEqual(
                lock1200["run_selection"],
                [{"instance_id": "instance-1", "solver_id": "z3"}],
            )
            locks1200, results1200 = execute_continuation(
                root / "executed-1200", index1200
            )
            before = raw_snapshot(base_results, results60, results1200)

            report = STAGED.analyze_staged_campaign(
                base_parent,
                base_locks,
                base_results,
                [
                    (stage60_output / "index.json", locks60, results60),
                    (stage1200_output / "index.json", locks1200, results1200),
                ],
                candidate_id="euf-viper",
                baseline_ids=["z3"],
                seed=9,
                bootstrap_replicates=32,
                confidence_level=0.9,
            )

            self.assertEqual(before, raw_snapshot(base_results, results60, results1200))

        self.assertEqual(report["inputs"]["budgets_s"], [2.0, 60.0, 1200.0])
        self.assertTrue(report["assumptions"]["complete_declared_budget_ladder"])
        self.assertEqual(report["inputs"]["physical_raw_records"], 12)
        self.assertEqual(
            [stage["selected_runs"] for stage in report["inputs"]["stages"]],
            [2, 1],
        )
        self.assertEqual(
            len(report["inputs"]["stages"][0]["execution_shards"]), 2
        )
        self.assertEqual(
            report["inputs"]["stages"][1]["source_evidence"][
                "root_lock_sha256"
            ],
            report["inputs"]["stages"][0]["source_evidence"][
                "root_lock_sha256"
            ],
        )
        carried = [
            row
            for row in report["inputs"]["observation_provenance"]
            if row["relative_path"] == "QF_UF/alpha/case-0.smt2"
            and row["solver_id"] == "euf-viper"
            and row["budget_s"] == 1200.0
        ]
        self.assertEqual(len(carried), 1)
        self.assertTrue(carried[0]["carried_forward"])
        self.assertEqual(carried[0]["origin_budget_s"], 60.0)
        self.assertEqual(len(carried[0]["source_record_sha256s"]), 1)
        self.assertEqual(
            report["input_hashes"]["observation_provenance_sha256"],
            hashlib.sha256(
                STAGED.canonical_bytes(
                    report["inputs"]["observation_provenance"]
                )
            ).hexdigest(),
        )
        comparison = report["comparisons"]["z3"]["budgets"]
        self.assertEqual(comparison["2"]["aggregate"]["arms"]["candidate"]["solved"], 2)
        self.assertEqual(comparison["60"]["aggregate"]["arms"]["candidate"]["solved"], 3)
        self.assertEqual(comparison["60"]["aggregate"]["arms"]["baseline"]["solved"], 2)
        self.assertEqual(comparison["1200"]["aggregate"]["arms"]["baseline"]["solved"], 3)
        self.assertEqual(
            comparison["1200"]["aggregate"]["arms"]["candidate"]["wall_time"][
                "solved_total_s"
            ],
            6.0,
        )

    def test_zero_timeouts_terminate_execution_and_fill_declared_ladder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = fixtures.write_sharded_campaign(root / "base")
            output = root / "stage-60"
            index = DERIVER.derive_continuation(parent, locks, results, 60, output)
            self.assertEqual(index["status"], "no_timeouts")

            report = STAGED.analyze_staged_campaign(
                parent,
                locks,
                results,
                [(output / "index.json", None, None)],
                candidate_id="euf-viper",
                baseline_ids=["z3"],
                bootstrap_replicates=16,
                confidence_level=0.9,
            )

        self.assertEqual(report["inputs"]["budgets_s"], [2.0, 60.0, 1200.0])
        self.assertEqual(
            [stage["status"] for stage in report["inputs"]["stages"]],
            ["no_timeouts", "implicit_no_timeouts"],
        )
        self.assertEqual(report["inputs"]["physical_raw_records"], 9)

    def test_source_index_tampering_and_budget_skipping_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = fixtures.write_sharded_campaign(
                root / "base", {("instance-0", "z3"): "timeout"}
            )
            output = root / "stage-60"
            DERIVER.derive_continuation(parent, locks, results, 60, output)
            index_path = output / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["source"]["shard_bundle_sha256"] = "f" * 64
            index_path.write_bytes(STAGED.canonical_bytes(index))

            with self.assertRaisesRegex(
                STAGED.StagedCampaignError, "shard_bundle_sha256 mismatch"
            ):
                STAGED.analyze_staged_campaign(
                    parent,
                    locks,
                    results,
                    [(index_path, root / "unused-locks", root / "unused-results")],
                    bootstrap_replicates=8,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = fixtures.write_sharded_campaign(
                root / "base", {("instance-0", "z3"): "timeout"}
            )
            with self.assertRaisesRegex(
                DERIVER.ContinuationError, "next declared budget"
            ):
                DERIVER.derive_continuation(
                    parent, locks, results, 1200, root / "stage-1200"
                )


if __name__ == "__main__":
    unittest.main()
