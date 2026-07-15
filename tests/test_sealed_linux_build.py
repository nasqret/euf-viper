from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock
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

    def test_executed_descriptor_is_rehashed_after_path_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "tool"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            replacement = Path(temporary) / "replacement"
            replacement.write_bytes(b"#!/bin/sh\nexit 9\n")
            replacement.chmod(0o755)
            original = SEALED.stable_read
            replaced = False

            def substitute(path: Path, label: str):
                nonlocal replaced
                result = original(path, label)
                if path == executable and not replaced:
                    os.replace(replacement, executable)
                    replaced = True
                return result

            with mock.patch.object(SEALED, "stable_read", side_effect=substitute):
                with self.assertRaisesRegex(
                    SEALED.SealedBuildError, "descriptor differs"
                ):
                    SEALED.open_verified_descriptor(executable, "fixture executable")
            self.assertTrue(replaced)

    def test_second_binary_failure_rolls_back_the_entire_build_set(self) -> None:
        self._assert_publication_failure_rolls_back(failure_index=2)

    def test_manifest_failure_rolls_back_both_published_binaries(self) -> None:
        self._assert_publication_failure_rolls_back(failure_index=3)

    def test_receipt_rejects_attestor_outside_the_external_binding(self) -> None:
        binary = b"solver"
        features_binary = b"features"
        artifacts = {
            "euf-viper": {
                "bytes": len(binary),
                "name": "euf-viper",
                "sha256": hashlib.sha256(binary).hexdigest(),
            },
            "euf-viper-build-features": {
                "bytes": len(features_binary),
                "name": "euf-viper-build-features",
                "sha256": hashlib.sha256(features_binary).hexdigest(),
            },
        }
        manifest = {
            "artifacts": artifacts,
            "build_execution_closure_sha256": "1" * 64,
            "revision": "2" * 40,
            "source_snapshot_manifest_sha256": "3" * 64,
            "source_tree": "4" * 40,
            "toolchain": {
                "cargo": "cargo fixture",
                "rustc": "rustc fixture\nhost: x86_64-unknown-linux-gnu",
            },
        }
        manifest_raw = SEALED.canonical_bytes(manifest)
        attestation = {
            "artifacts": {
                name: {
                    "bytes": record["bytes"],
                    "mode": "0500",
                    "sha256": record["sha256"],
                }
                for name, record in artifacts.items()
            },
            "attestor_sha256": "5" * 64,
            "build_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "closure_sha256": manifest["build_execution_closure_sha256"],
            "features": ["production-evidence"],
            "schema": SEALED.ATTESTATION_SCHEMA,
            "status": "accepted",
            "toolchain": manifest["toolchain"],
        }
        files = {
            "sealed-build-manifest.json": (manifest_raw, 0o400),
            "sealed-build-attestation.json": (
                SEALED.canonical_bytes(attestation),
                0o400,
            ),
            "euf-viper": (binary, 0o500),
            "euf-viper-build-features": (features_binary, 0o500),
        }

        def fake_read(_parent_fd: int, name: str, _label: str):
            content, mode = files[name]
            metadata = os.stat_result((mode, 0, 0, 1, 0, 0, len(content), 0, 0, 0))
            return content, metadata

        with mock.patch.object(
            SEALED, "stable_read_at", side_effect=fake_read
        ), mock.patch.object(
            SEALED, "execute_published", return_value=b"production-evidence\n"
        ):
            with self.assertRaisesRegex(
                SEALED.SealedBuildError, "attestation differs"
            ):
                SEALED.create_external_receipt(
                    7, expected_attestor_sha256="6" * 64
                )

    def _assert_publication_failure_rolls_back(self, *, failure_index: int) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            original = SEALED.publish_bytes
            calls = 0

            def adversarial_publish(
                parent_fd: int, name: str, content: bytes, mode: int
            ) -> dict[str, object]:
                nonlocal calls
                calls += 1
                result = original(parent_fd, name, content, mode)
                if calls == failure_index:
                    raise SEALED.SealedBuildError("injected publication failure")
                return result

            try:
                with mock.patch.object(
                    SEALED, "publish_bytes", side_effect=adversarial_publish
                ):
                    with self.assertRaisesRegex(
                        SEALED.SealedBuildError, "injected publication failure"
                    ):
                        SEALED.publish_build_set(
                            descriptor,
                            [
                                ("euf-viper", b"binary-one", 0o500),
                                (
                                    "euf-viper-build-features",
                                    b"binary-two",
                                    0o500,
                                ),
                                ("sealed-build-manifest.json", b"{}\n", 0o400),
                            ],
                        )
            finally:
                os.close(descriptor)
            self.assertEqual(list(root.iterdir()), [])

    @unittest.skipIf(LINUX, "non-Linux fail-closed test")
    def test_build_fails_closed_without_linux_namespace_primitives(self) -> None:
        with self.assertRaisesRegex(SEALED.SealedBuildError, "requires Linux"):
            SEALED.require_linux()


if __name__ == "__main__":
    unittest.main()
