from __future__ import annotations

import errno
import importlib.util
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "cert" / "strict_artifacts.py"
SPEC = importlib.util.spec_from_file_location("strict_artifacts_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
STRICT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STRICT)


class StrictArtifactPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="strict-publication-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_final_path_replacement_is_detected_without_deleting_attacker(self) -> None:
        output = self.root / "evidence.json"
        real_fsync = os.fsync
        calls = 0

        def replace_on_directory_sync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                output.unlink()
                output.write_bytes(b"attacker\n")
            real_fsync(descriptor)

        with mock.patch.object(STRICT.os, "fsync", side_effect=replace_on_directory_sync):
            with self.assertRaisesRegex(
                STRICT.StrictArtifactError, "checked staging inode"
            ):
                STRICT.atomic_write_nofollow(
                    output, b"publisher\n", "replacement", immutable=True
                )
        self.assertEqual(output.read_bytes(), b"attacker\n")

    def test_parent_rename_cleans_only_the_publishers_inode(self) -> None:
        parent = self.root / "parent"
        parent.mkdir()
        moved = self.root / "moved"
        output = parent / "evidence.json"
        real_fsync = os.fsync
        calls = 0

        def rename_on_directory_sync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                parent.rename(moved)
                parent.mkdir()
            real_fsync(descriptor)

        with mock.patch.object(STRICT.os, "fsync", side_effect=rename_on_directory_sync):
            with self.assertRaisesRegex(STRICT.StrictArtifactError, "parent path changed"):
                STRICT.atomic_write_nofollow(
                    output, b"publisher\n", "parent rename", immutable=True
                )
        self.assertFalse(output.exists())
        self.assertFalse((moved / "evidence.json").exists())

    def test_directory_fsync_failure_leaves_no_final_path(self) -> None:
        output = self.root / "evidence.json"
        real_fsync = os.fsync
        calls = 0

        def fail_directory_sync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(errno.EIO, "injected directory sync failure")
            real_fsync(descriptor)

        with mock.patch.object(STRICT.os, "fsync", side_effect=fail_directory_sync):
            with self.assertRaisesRegex(STRICT.StrictArtifactError, "atomic publish failed"):
                STRICT.atomic_write_nofollow(
                    output, b"publisher\n", "fsync failure", immutable=True
                )
        self.assertFalse(output.exists())

    def test_post_link_verification_failure_cleans_all_publisher_links(self) -> None:
        output = self.root / "evidence.json"
        with mock.patch.object(
            STRICT,
            "_require_same_regular_identity",
            side_effect=STRICT.StrictArtifactError("injected post-link failure"),
        ):
            with self.assertRaisesRegex(
                STRICT.StrictArtifactError, "injected post-link failure"
            ):
                STRICT.atomic_write_nofollow(
                    output, b"publisher\n", "post-link failure", immutable=True
                )
        self.assertFalse(output.exists())
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

    def test_post_publish_callback_failure_rolls_back_new_inode(self) -> None:
        output = self.root / "evidence.json"
        callbacks: list[str] = []

        def before() -> None:
            callbacks.append("before")

        def after() -> None:
            callbacks.append("after")
            raise STRICT.StrictArtifactError("injected post-publication failure")

        with self.assertRaisesRegex(
            STRICT.StrictArtifactError, "injected post-publication failure"
        ):
            STRICT.atomic_write_nofollow(
                output,
                b"publisher\n",
                "post-publication callback",
                immutable=True,
                pre_publish=before,
                post_publish=after,
            )
        self.assertEqual(callbacks, ["before", "after"])
        self.assertFalse(output.exists())
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

    def test_idempotent_post_publish_replacement_is_rejected_without_cleanup(self) -> None:
        output = self.root / "evidence.json"
        output.write_bytes(b"publisher\n")
        output.chmod(0o600)

        def replace() -> None:
            output.unlink()
            output.write_bytes(b"replacement\n")
            output.chmod(0o600)

        with self.assertRaisesRegex(
            STRICT.StrictArtifactError, "checked staging inode"
        ):
            STRICT.atomic_write_nofollow(
                output,
                b"publisher\n",
                "idempotent replacement",
                immutable=True,
                post_publish=replace,
            )
        self.assertEqual(output.read_bytes(), b"replacement\n")
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

    def test_idempotent_callbacks_preserve_checked_inode(self) -> None:
        output = self.root / "evidence.json"
        output.write_bytes(b"publisher\n")
        output.chmod(0o600)
        callbacks: list[str] = []

        result = STRICT.atomic_write_nofollow(
            output,
            b"publisher\n",
            "idempotent callbacks",
            immutable=True,
            pre_publish=lambda: callbacks.append("before"),
            post_publish=lambda: callbacks.append("after"),
        )

        self.assertEqual(result, output.resolve())
        self.assertEqual(callbacks, ["before", "after"])
        self.assertEqual(output.read_bytes(), b"publisher\n")
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

    def test_concurrent_immutable_publish_has_one_inode_winner(self) -> None:
        output = self.root / "evidence.json"
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def publish(content: bytes) -> None:
            try:
                STRICT.atomic_write_nofollow(
                    output,
                    content,
                    "concurrent publication",
                    immutable=True,
                    pre_publish=lambda: barrier.wait(timeout=5),
                )
            except (STRICT.StrictArtifactError, threading.BrokenBarrierError):
                result = "rejected"
            else:
                result = "published"
            with lock:
                outcomes.append(result)

        threads = [
            threading.Thread(target=publish, args=(b"left\n",)),
            threading.Thread(target=publish, args=(b"right\n",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sorted(outcomes), ["published", "rejected"])
        self.assertIn(output.read_bytes(), {b"left\n", b"right\n"})
        self.assertFalse(list(self.root.glob(".*.tmp-*")))


if __name__ == "__main__":
    unittest.main()
