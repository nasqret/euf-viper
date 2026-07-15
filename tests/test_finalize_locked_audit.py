from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wmi" / "finalize_locked_audit.py"
SPEC = importlib.util.spec_from_file_location("finalize_locked_audit_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
FINALIZER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FINALIZER
SPEC.loader.exec_module(FINALIZER)


def analysis_bytes(status: str = "complete") -> bytes:
    return (
        json.dumps(
            {
                "inputs": {"instances": 2, "raw_records": 4, "shards": [{}, {}]},
                "promoted": False,
                "status": status,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


class FinalizeLockedAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for kind in ("full", "official"):
            directory = self.root / "audit" / kind
            directory.mkdir(parents=True)
            path = directory / "global.json"
            path.write_bytes(analysis_bytes())
            path.chmod(0o400)
        self.output = self.root / "audit" / "index.json"
        self.provenance = {
            "attempt": "attempt-1",
            "environment": {"kind": "test"},
            "manifest_sha256": "1" * 64,
            "revision": "2" * 40,
            "source_blob_count": 3,
            "source_blobs_sha256": "4" * 64,
            "source_tree": "5" * 40,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def finalize(self, **kwargs: object) -> dict[str, object]:
        return FINALIZER.finalize(
            self.output,
            self.provenance,
            self.root,
            10,
            2,
            11,
            {"status": "accepted"},
            **kwargs,
        )

    def test_index_binds_the_exact_opened_global_inodes(self) -> None:
        payload = self.finalize()
        self.assertEqual(payload["schema"], FINALIZER.SCHEMA)
        stored = json.loads(self.output.read_text(encoding="ascii"))
        for kind in ("full", "official"):
            path = self.root / "audit" / kind / "global.json"
            binding = stored["analyses"][kind]
            metadata = path.stat()
            self.assertEqual(binding["inode"], metadata.st_ino)
            self.assertEqual(binding["device"], metadata.st_dev)
            self.assertEqual(binding["bytes"], metadata.st_size)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o400)
        self.assertEqual(self.finalize(), payload)

    def test_path_replacement_before_publish_is_rejected(self) -> None:
        target = self.root / "audit" / "full" / "global.json"

        def replace() -> None:
            target.unlink()
            target.write_bytes(analysis_bytes("attacker"))
            target.chmod(0o400)

        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "no longer names descriptor"
        ):
            self.finalize(pre_publish_hook=replace)
        self.assertFalse(self.output.exists())

    def test_in_place_mutation_before_publish_is_rejected(self) -> None:
        target = self.root / "audit" / "official" / "global.json"

        def mutate() -> None:
            target.chmod(0o600)
            target.write_bytes(analysis_bytes("attacker"))

        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "changed before index publication"
        ):
            self.finalize(pre_publish_hook=mutate)
        self.assertFalse(self.output.exists())

    def test_concurrent_no_replace_publication_never_mixes_indices(self) -> None:
        outcomes: list[str] = []

        def worker() -> None:
            try:
                self.finalize()
            except FINALIZER.AuditFinalizeError:
                outcomes.append("rejected")
            else:
                outcomes.append("published")

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("published", outcomes)
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o400)


if __name__ == "__main__":
    unittest.main()
