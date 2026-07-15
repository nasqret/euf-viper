from __future__ import annotations

import errno
import importlib.util
import os
import subprocess
import sys
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

    def test_parent_rename_preserves_failed_publisher_inode(self) -> None:
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
        self.assertEqual((moved / "evidence.json").read_bytes(), b"publisher\n")

    def test_directory_fsync_failure_preserves_publisher_output(self) -> None:
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
        self.assertEqual(output.read_bytes(), b"publisher\n")

    def test_post_link_verification_failure_preserves_publisher_output(self) -> None:
        output = self.root / "evidence.json"
        original = STRICT._require_same_regular_identity

        def reject_output(
            parent_fd: int,
            name: str,
            metadata: os.stat_result,
            context: str,
        ) -> None:
            if name == output.name:
                raise STRICT.StrictArtifactError("injected post-link failure")
            original(parent_fd, name, metadata, context)

        with mock.patch.object(
            STRICT,
            "_require_same_regular_identity",
            side_effect=reject_output,
        ):
            with self.assertRaisesRegex(
                STRICT.StrictArtifactError, "injected post-link failure"
            ):
                STRICT.atomic_write_nofollow(
                    output, b"publisher\n", "post-link failure", immutable=True
                )
        self.assertEqual(output.read_bytes(), b"publisher\n")
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

    def test_callback_failure_preserves_output_and_retry_revalidates(self) -> None:
        output = self.root / "evidence.json"
        callbacks: list[str] = []
        downstream: list[Path] = []

        def before() -> None:
            callbacks.append("before")

        def after() -> None:
            callbacks.append("after")
            raise STRICT.StrictArtifactError("injected post-publication failure")

        def publish_and_continue() -> None:
            result = STRICT.atomic_write_nofollow(
                output,
                b"publisher\n",
                "post-publication callback",
                immutable=True,
                pre_publish=before,
                post_publish=after,
            )
            downstream.append(result)

        with self.assertRaisesRegex(
            STRICT.StrictArtifactError, "injected post-publication failure"
        ):
            publish_and_continue()
        self.assertEqual(callbacks, ["before", "after"])
        self.assertEqual(downstream, [])
        self.assertEqual(output.read_bytes(), b"publisher\n")
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

        with self.assertRaisesRegex(STRICT.StrictArtifactError, "immutable artifact drift"):
            STRICT.atomic_write_nofollow(
                output,
                b"different\n",
                "different retry",
                immutable=True,
                post_publish=lambda: callbacks.append("wrong retry callback"),
            )

        result = STRICT.atomic_write_nofollow(
            output,
            b"publisher\n",
            "matching retry",
            immutable=True,
            pre_publish=lambda: callbacks.append("retry before"),
            post_publish=lambda: callbacks.append("retry after"),
        )
        self.assertEqual(result, output.resolve())
        self.assertEqual(
            callbacks, ["before", "after", "retry before", "retry after"]
        )
        self.assertEqual(output.read_bytes(), b"publisher\n")
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

    def test_callback_failure_has_no_stale_check_unlink_window(self) -> None:
        output = self.root / "evidence.json"
        original = STRICT._same_regular_identity
        armed = False
        interposed = False

        def fail_after_publish() -> None:
            nonlocal armed
            armed = True
            raise STRICT.StrictArtifactError("injected callback failure")

        def replace_after_check(
            parent_fd: int, name: str, metadata: os.stat_result
        ) -> bool:
            nonlocal interposed
            same = original(parent_fd, name, metadata)
            if armed and name == output.name and same:
                # The old rollback unlinked by name immediately after this
                # stale True result, deleting the replacement created here.
                interposed = True
                output.unlink()
                output.write_bytes(b"replacement\n")
                output.chmod(0o600)
            return same

        with mock.patch.object(
            STRICT, "_same_regular_identity", side_effect=replace_after_check
        ):
            with self.assertRaisesRegex(
                STRICT.StrictArtifactError, "injected callback failure"
            ):
                STRICT.atomic_write_nofollow(
                    output,
                    b"publisher\n",
                    "stale cleanup check",
                    immutable=True,
                    post_publish=fail_after_publish,
                )

        self.assertFalse(hasattr(STRICT, "_unlink_same_identity"))
        self.assertFalse(interposed)
        self.assertEqual(output.read_bytes(), b"publisher\n")

    def test_callback_failure_preserves_replacement_bytes(self) -> None:
        output = self.root / "evidence.json"

        def replace_and_fail() -> None:
            output.unlink()
            output.write_bytes(b"replacement\n")
            output.chmod(0o600)
            raise STRICT.StrictArtifactError("replacement callback failure")

        with self.assertRaisesRegex(
            STRICT.StrictArtifactError, "replacement callback failure"
        ):
            STRICT.atomic_write_nofollow(
                output,
                b"publisher\n",
                "callback replacement",
                immutable=True,
                post_publish=replace_and_fail,
            )
        self.assertEqual(output.read_bytes(), b"replacement\n")

    def test_fresh_post_publish_parent_replacement_preserves_replacement(self) -> None:
        parent = self.root / "parent"
        parent.mkdir()
        moved = self.root / "moved"
        output = parent / "evidence.json"

        def replace_parent() -> None:
            parent.rename(moved)
            parent.mkdir()
            output.write_bytes(b"replacement\n")
            output.chmod(0o600)

        with self.assertRaisesRegex(STRICT.StrictArtifactError, "parent path changed"):
            STRICT.atomic_write_nofollow(
                output,
                b"publisher\n",
                "fresh parent replacement",
                immutable=True,
                post_publish=replace_parent,
            )
        self.assertEqual(output.read_bytes(), b"replacement\n")
        self.assertEqual((moved / "evidence.json").read_bytes(), b"publisher\n")
        self.assertFalse(list(parent.glob(".*.tmp-*")))
        self.assertFalse(list(moved.glob(".*.tmp-*")))

    def test_existing_fifo_is_rejected_without_blocking(self) -> None:
        output = self.root / "evidence.json"
        os.mkfifo(output, mode=0o600)
        probe = """
import importlib.util
import pathlib
import sys

module_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("strict_fifo_probe", module_path)
assert spec is not None and spec.loader is not None
strict = importlib.util.module_from_spec(spec)
spec.loader.exec_module(strict)
try:
    strict.atomic_write_nofollow(
        pathlib.Path(sys.argv[2]),
        b"publisher\\n",
        "existing FIFO",
        immutable=True,
    )
except strict.StrictArtifactError as error:
    if "regular file" not in str(error):
        raise
else:
    raise AssertionError("existing FIFO was accepted")
"""
        try:
            completed = subprocess.run(
                [sys.executable, "-c", probe, str(MODULE_PATH), str(output)],
                check=False,
                capture_output=True,
                text=True,
                timeout=3,
            )
        except subprocess.TimeoutExpired as error:
            self.fail(f"existing FIFO acquisition blocked: {error}")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_idempotent_same_byte_replacement_is_rejected_without_cleanup(self) -> None:
        output = self.root / "evidence.json"
        output.write_bytes(b"publisher\n")
        output.chmod(0o600)

        def replace() -> None:
            output.unlink()
            output.write_bytes(b"publisher\n")
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
        self.assertEqual(output.read_bytes(), b"publisher\n")
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
        preserved = list(self.root.glob(".*.tmp-*"))
        self.assertEqual(len(preserved), 1)
        self.assertNotEqual(preserved[0].read_bytes(), output.read_bytes())


if __name__ == "__main__":
    unittest.main()
