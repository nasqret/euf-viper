from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wmi" / "sealed_linux_build.py"
SPEC = importlib.util.spec_from_file_location("sealed_linux_build_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SEALED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEALED)
LINUX = sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir()


class SealedLinuxBuildTests(unittest.TestCase):
    def test_extracted_snapshot_is_bound_by_bytes_mode_revision_and_tree(self) -> None:
        revision = "1" * 40
        tree = "2" * 40
        content = b"[package]\nname = \"bound\"\n"
        manifest = {
            "schema": SEALED.SOURCE_SCHEMA,
            "revision": revision,
            "tree": tree,
            "files": [
                SEALED.file_record("Cargo.toml", content, 0o444, "git")
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            path = source / "Cargo.toml"
            path.write_bytes(content)
            path.chmod(0o444)
            SEALED.verify_source_snapshot(
                source, manifest, revision=revision, tree=tree
            )
            path.chmod(0o644)
            path.write_bytes(b"replacement\n")
            with self.assertRaisesRegex(
                SEALED.SealedBuildError, "differs from its manifest"
            ):
                SEALED.verify_source_snapshot(
                    source, manifest, revision=revision, tree=tree
                )

    def test_toolchain_symlink_cannot_escape_copied_sysroot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toolchain"
            root.mkdir()
            (root / "escape").symlink_to("../../outside")
            with self.assertRaisesRegex(SEALED.SealedBuildError, "escapes"):
                SEALED.validate_internal_symlinks(root)

    def test_toolchain_pin_is_an_exact_release_from_the_git_snapshot(self) -> None:
        content = (
            b"[toolchain]\nchannel = \"1.96.0\"\n"
            b"components = [\"rustfmt\"]\nprofile = \"minimal\"\n"
        )
        records = [("rust-toolchain.toml", content, 0o444, "git")]
        self.assertEqual(SEALED.pinned_toolchain_channel(records), "1.96.0")
        moving = content.replace(b"1.96.0", b"stable")
        with self.assertRaisesRegex(SEALED.SealedBuildError, "exact numeric"):
            SEALED.pinned_toolchain_channel(
                [("rust-toolchain.toml", moving, 0o444, "git")]
            )

    @unittest.skipIf(LINUX, "non-Linux fail-closed test")
    def test_build_fails_closed_without_linux_namespace_primitives(self) -> None:
        with self.assertRaisesRegex(SEALED.SealedBuildError, "requires Linux"):
            SEALED.require_linux()


if __name__ == "__main__":
    unittest.main()
