from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "shard_campaign_lock.py"
MODULE_SPEC = importlib.util.spec_from_file_location("shard_campaign_lock", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
SHARDER = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(SHARDER)


def parent_lock(instance_count: int = 10) -> dict:
    lock = {
        "schema_version": 1,
        "campaign_id": "test",
        "lock_sha256": "",
        "promotion_eligible": True,
        "corpus": {
            "id": "test-corpus",
            "instances": [
                {
                    "id": str(index),
                    "relative_path": f"family/case-{index}.smt2",
                }
                for index in range(instance_count)
            ],
        },
        "output": {
            "directory": "/campaign/results",
            "journal": "journal.jsonl",
            "raw": "raw.jsonl",
        },
    }
    lock["lock_sha256"] = SHARDER.lock_hash(lock)
    return lock


class ShardCampaignLockTests(unittest.TestCase):
    def test_shards_are_disjoint_complete_and_self_hashing(self) -> None:
        parent = parent_lock()
        shards = SHARDER.derive_shards(parent, 3)

        self.assertEqual([len(item["corpus"]["instances"]) for item in shards], [4, 3, 3])
        flattened = [
            instance["id"]
            for shard in shards
            for instance in shard["corpus"]["instances"]
        ]
        self.assertEqual(set(flattened), {str(index) for index in range(10)})
        self.assertEqual(len(flattened), len(set(flattened)))
        for index, shard in enumerate(shards):
            self.assertEqual(shard["shard"]["index"], index)
            self.assertEqual(shard["shard"]["parent_lock_sha256"], parent["lock_sha256"])
            self.assertEqual(shard["lock_sha256"], SHARDER.lock_hash(shard))
            self.assertTrue(shard["output"]["directory"].endswith(f"shard-{index:04d}"))

    def test_invalid_shard_counts_are_rejected(self) -> None:
        with self.assertRaisesRegex(SHARDER.ShardError, "positive"):
            SHARDER.derive_shards(parent_lock(), 0)
        with self.assertRaisesRegex(SHARDER.ShardError, "exceed"):
            SHARDER.derive_shards(parent_lock(2), 3)

    def test_load_rejects_tampered_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            lock = parent_lock()
            lock["campaign_id"] = "tampered"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(SHARDER.ShardError, "self-hash"):
                SHARDER.load_lock(path)

    def test_refuses_to_shard_a_shard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            shard = SHARDER.derive_shards(parent_lock(), 2)[0]
            path.write_bytes(SHARDER.canonical_bytes(shard))
            with self.assertRaisesRegex(SHARDER.ShardError, "already sharded"):
                SHARDER.load_lock(path)


if __name__ == "__main__":
    unittest.main()
