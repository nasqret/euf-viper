from __future__ import annotations

import hashlib
import importlib.util
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "bench" / "create_t11_stage0a_launch.py"
SPEC = importlib.util.spec_from_file_location("create_t11_stage0a_launch", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
LAUNCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LAUNCH
SPEC.loader.exec_module(LAUNCH)


class CreateT11Stage0ALaunchTests(unittest.TestCase):
    def test_artifact_map_exactly_covers_validator_contract(self) -> None:
        self.assertEqual(
            tuple(LAUNCH.PINNED_ARTIFACT_PATHS),
            tuple(LAUNCH.validator.PINNED_ARTIFACT_HASH_FIELDS),
        )
        self.assertEqual(len(set(LAUNCH.PINNED_ARTIFACT_PATHS.values())), 13)

    def test_canonical_json_is_ascii_sorted_and_rejects_nonfinite(self) -> None:
        self.assertEqual(LAUNCH._canonical_json({"z": 1, "a": 2}), b'{"a":2,"z":1}\n')
        with self.assertRaises(ValueError):
            LAUNCH._canonical_json({"value": float("nan")})

    def test_launch_json_preserves_rust_field_order(self) -> None:
        encoded = LAUNCH._ordered_json({"z": 1, "a": 2})
        self.assertEqual(encoded, b'{"z":1,"a":2}\n')
        with self.assertRaises(ValueError):
            LAUNCH._ordered_json({"value": float("nan")})

    def test_validated_publication_is_immutable_and_no_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "launch.json"
            encoded = LAUNCH._canonical_json({"status": "test"})
            observed: list[tuple[bytes, str]] = []

            def validate(path: Path, digest: str) -> None:
                observed.append((path.read_bytes(), digest))

            digest = LAUNCH._publish_validated(output, encoded, validate)
            self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())
            self.assertEqual(observed, [(encoded, digest)])
            self.assertEqual(output.read_bytes(), encoded)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
            with self.assertRaisesRegex(
                LAUNCH.LaunchConstructionError, "ceased to be fresh"
            ):
                LAUNCH._publish_validated(output, encoded, validate)
            self.assertEqual(output.read_bytes(), encoded)

    def test_failed_validation_publishes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "launch.json"

            def reject(_path: Path, _digest: str) -> None:
                raise LAUNCH.LaunchConstructionError("synthetic rejection")

            with self.assertRaisesRegex(
                LAUNCH.LaunchConstructionError, "synthetic rejection"
            ):
                LAUNCH._publish_validated(output, b"{}\n", reject)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
