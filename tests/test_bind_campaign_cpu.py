from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "bind_campaign_cpu.py"
MODULE_SPEC = importlib.util.spec_from_file_location("bind_campaign_cpu", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
BINDER = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(BINDER)


def prepared_lock() -> dict:
    lock = {
        "schema_version": 1,
        "campaign_id": "test",
        "lock_sha256": "",
        "execution": {"cpu_ids": [0]},
    }
    lock["lock_sha256"] = BINDER.lock_hash(lock)
    return lock


class BindCampaignCpuTests(unittest.TestCase):
    def test_binding_preserves_parent_and_self_hash(self) -> None:
        prepared = prepared_lock()
        bound = BINDER.bind_lock(prepared, 17)

        self.assertEqual(bound["execution"]["cpu_ids"], [17])
        self.assertEqual(
            bound["runtime_binding"]["parent_lock_sha256"],
            prepared["lock_sha256"],
        )
        self.assertEqual(bound["lock_sha256"], BINDER.lock_hash(bound))
        self.assertNotEqual(bound["lock_sha256"], prepared["lock_sha256"])
        self.assertNotIn("runtime_binding", prepared)

    def test_invalid_cpu_ids_are_rejected(self) -> None:
        for value in (-1, True, "0"):
            with self.subTest(value=value):
                with self.assertRaises(BINDER.BindingError):
                    BINDER.bind_lock(prepared_lock(), value)

    def test_reader_rejects_tampering_and_rebinding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            lock = prepared_lock()
            lock["campaign_id"] = "tampered"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(BINDER.BindingError, "self-hash"):
                BINDER.read_lock(path)

            bound = BINDER.bind_lock(prepared_lock(), 1)
            path.write_bytes(BINDER.canonical_bytes(bound))
            with self.assertRaisesRegex(BINDER.BindingError, "already"):
                BINDER.read_lock(path)

    def test_reader_requires_placeholder_cpu(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            lock = prepared_lock()
            lock["execution"]["cpu_ids"] = [2]
            lock["lock_sha256"] = BINDER.lock_hash(lock)
            path.write_bytes(BINDER.canonical_bytes(lock))
            with self.assertRaisesRegex(BINDER.BindingError, "placeholder"):
                BINDER.read_lock(path)


if __name__ == "__main__":
    unittest.main()
