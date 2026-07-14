from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cert" / "recover_hash_journal.py"
SPEC = importlib.util.spec_from_file_location("recover_hash_journal", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)


class HashJournalRecoveryTests(unittest.TestCase):
    def test_recovery_is_hash_checked_separate_and_non_promotional(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "journal.jsonl"
            output = root / "recovered.jsonl"
            record = {
                "record_type": "plan",
                "schema_version": 1,
                "previous_record_sha256": None,
                "record_sha256": "",
            }
            record["record_sha256"] = RECOVERY._record_digest(record)
            original = RECOVERY.canonical_json_bytes(record) + b'{"incomplete":'
            source.write_bytes(original)

            marker = RECOVERY.recover(source, output)

            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(marker["promotion_eligible"])
            self.assertEqual(marker["record_type"], "non_promotional_recovery")
            self.assertEqual(marker["discarded_tail_bytes"], len(b'{"incomplete":'))
            recovered = output.read_bytes()
            self.assertTrue(recovered.endswith(RECOVERY.canonical_json_bytes(marker)))
            self.assertEqual(
                marker["source_journal_sha256"], hashlib.sha256(original).hexdigest()
            )

    def test_recovery_rejects_a_tampered_complete_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "journal.jsonl"
            source.write_bytes(
                b'{"previous_record_sha256":null,"record_sha256":"'
                + b"0" * 64
                + b'","record_type":"plan","schema_version":1}\npartial'
            )

            with self.assertRaisesRegex(RECOVERY.RecoveryError, "record hash drift"):
                RECOVERY.recover(source, root / "recovered.jsonl")


if __name__ == "__main__":
    unittest.main()
