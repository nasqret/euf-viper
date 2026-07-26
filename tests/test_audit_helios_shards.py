from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "helios" / "audit_sharded_campaign.py"
SPEC = importlib.util.spec_from_file_location("audit_sharded_campaign", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDITOR)

TASK_FIELDS = [
    "schema_version",
    "status",
    "job_id",
    "array_job_id",
    "array_task_id",
    "shard_index",
    "shard_count",
    "started_at",
    "finished_at",
    "exit_code",
    "orchestration_revision",
    "solver_revision",
    "preparation_receipt_sha256",
    "toolchain_sha256",
    "candidate_binary_sha256",
    "shard_lock_sha256",
    "bound_lock_sha256",
    "raw_sha256",
    "summary_sha256",
    "resource_capture_sha256",
]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(AUDITOR.canonical_bytes(value))


def write_tsv(path: Path, fieldnames: list[str], row: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="ascii") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader()
        writer.writerow(row)


def build_fixture(root: Path) -> tuple[Path, Path, Path]:
    preparation_root = root / "preparation"
    campaign_root = root / "campaign"
    analysis_path = campaign_root / "analysis.json"
    orchestration_revision = "1" * 40
    solver_revision = "2" * 40
    toolchain_hash = "3" * 64

    candidate = preparation_root / "target" / "release" / "euf-viper"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"candidate binary\n")
    candidate_hash = AUDITOR.sha256_file(candidate)

    parent = {
        "schema_version": 1,
        "lock_sha256": "",
        "corpus": {
            "instances": [
                {"id": "case-0", "relative_path": "case-0.smt2"},
                {"id": "case-1", "relative_path": "case-1.smt2"},
            ]
        },
        "output": {"directory": str(campaign_root / "results")},
    }
    parent["lock_sha256"] = AUDITOR.lock_self_hash(parent)
    parent_path = preparation_root / "campaign-lock.json"
    write_json(parent_path, parent)

    preparation_fields = [
        "schema_version",
        "status",
        "execution_mode",
        "shard_count",
        "orchestration_revision",
        "solver_revision",
        "toolchain_sha256",
        "candidate_binary_sha256",
    ]
    preparation_row = {
        "schema_version": "1",
        "status": "complete",
        "execution_mode": "prepare-sharded",
        "shard_count": "2",
        "orchestration_revision": orchestration_revision,
        "solver_revision": solver_revision,
        "toolchain_sha256": toolchain_hash,
        "candidate_binary_sha256": candidate_hash,
    }
    preparation_receipt = preparation_root / "receipt.tsv"
    write_tsv(preparation_receipt, preparation_fields, preparation_row)
    preparation_hash = AUDITOR.sha256_file(preparation_receipt)
    (preparation_root / "preparation.tsv").write_text(
        "\n".join(
            [
                "execution_mode\tprepare-sharded",
                "shard_count\t2",
                f"orchestration_revision\t{orchestration_revision}",
                f"solver_revision\t{solver_revision}",
                f"candidate_binary_sha256\t{candidate_hash}",
            ]
        )
        + "\n",
        encoding="ascii",
    )

    analysis_shards = []
    lock_hashes: dict[str, str] = {}
    raw_hashes: dict[str, str] = {}
    for index in range(2):
        padded = f"{index:04d}"
        shard_lock = preparation_root / "shard-locks" / f"lock-{padded}.json"
        bound_lock = campaign_root / "bound-locks" / f"bound-{padded}.json"
        result_root = campaign_root / "results" / f"shard-{padded}"
        task_root = campaign_root / "tasks" / f"shard-{padded}"
        raw = result_root / "raw.jsonl"
        summary = result_root / "summary.json"
        resource = task_root / "resource-usage.json"
        write_json(shard_lock, {"index": index, "kind": "prepared"})
        write_json(bound_lock, {"index": index, "kind": "bound"})
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(json.dumps({"index": index}) + "\n", encoding="ascii")
        write_json(
            summary,
            {"status": "complete", "expected_runs": 1, "completed_runs": 1},
        )
        write_json(resource, {"return_code": 0})

        bound_hash = AUDITOR.sha256_file(bound_lock)
        raw_hash = AUDITOR.sha256_file(raw)
        receipt = {
            "schema_version": "1",
            "status": "complete",
            "job_id": str(100 + index),
            "array_job_id": "100",
            "array_task_id": str(index),
            "shard_index": str(index),
            "shard_count": "2",
            "started_at": "2026-07-26T00:00:00Z",
            "finished_at": "2026-07-26T00:00:01Z",
            "exit_code": "0",
            "orchestration_revision": orchestration_revision,
            "solver_revision": solver_revision,
            "preparation_receipt_sha256": preparation_hash,
            "toolchain_sha256": toolchain_hash,
            "candidate_binary_sha256": candidate_hash,
            "shard_lock_sha256": AUDITOR.sha256_file(shard_lock),
            "bound_lock_sha256": bound_hash,
            "raw_sha256": raw_hash,
            "summary_sha256": AUDITOR.sha256_file(summary),
            "resource_capture_sha256": AUDITOR.sha256_file(resource),
        }
        write_tsv(task_root / "receipt.tsv", TASK_FIELDS, receipt)
        analysis_shards.append(
            {
                "index": index,
                "lock_file_sha256": bound_hash,
                "raw_sha256": raw_hash,
                "raw_records": 1,
            }
        )
        lock_hashes[str(index)] = bound_hash
        raw_hashes[str(index)] = raw_hash

    analysis = {
        "status": "rejected",
        "inputs": {
            "candidate_id": "euf-viper",
            "instances": 2,
            "raw_records": 2,
            "shards": analysis_shards,
        },
        "input_hashes": {
            "lock_file_sha256": AUDITOR.sha256_file(parent_path),
            "lock_sha256": parent["lock_sha256"],
            "shard_lock_file_sha256": lock_hashes,
            "shard_raw_sha256": raw_hashes,
            "solver_binary_sha256": {"euf-viper": candidate_hash},
        },
    }
    write_json(analysis_path, analysis)
    return preparation_root, campaign_root, analysis_path


class HeliosShardAuditTests(unittest.TestCase):
    def test_complete_hash_bound_shard_set_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            preparation, campaign, analysis = build_fixture(Path(directory))
            report = AUDITOR.audit(preparation, campaign, 2, analysis)
            self.assertEqual(report["shard_count"], 2)
            self.assertEqual(report["completed_runs"], 2)
            self.assertEqual(len(report["tasks"]), 2)
            self.assertEqual(report["analysis"]["status"], "rejected")
            self.assertEqual(report["analysis"]["path"], "analysis.json")
            self.assertEqual(
                report["tasks"][0]["receipt_path"],
                "tasks/shard-0000/receipt.tsv",
            )
            self.assertNotIn(directory, json.dumps(report))

    def test_tampered_raw_or_stale_analysis_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            preparation, campaign, analysis = build_fixture(Path(directory))
            raw = campaign / "results" / "shard-0001" / "raw.jsonl"
            raw.write_text('{"index": 999}\n', encoding="ascii")
            with self.assertRaisesRegex(AUDITOR.AuditError, "hash mismatch"):
                AUDITOR.audit(preparation, campaign, 2, analysis)

        with tempfile.TemporaryDirectory() as directory:
            preparation, campaign, analysis = build_fixture(Path(directory))
            payload = json.loads(analysis.read_text(encoding="ascii"))
            payload["inputs"]["shards"][1]["raw_sha256"] = "f" * 64
            write_json(analysis, payload)
            with self.assertRaisesRegex(AUDITOR.AuditError, "raw hash drifted"):
                AUDITOR.audit(preparation, campaign, 2, analysis)


if __name__ == "__main__":
    unittest.main()
