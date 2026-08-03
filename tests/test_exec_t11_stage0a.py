from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "bench" / "exec_t11_stage0a.py"

LINUX_MEMFD = (
    sys.platform.startswith("linux")
    and Path("/proc/self/fd").is_dir()
    and callable(getattr(os, "memfd_create", None))
    and all(hasattr(os, name) for name in ("MFD_ALLOW_SEALING", "MFD_CLOEXEC"))
    and all(
        hasattr(fcntl, name)
        for name in (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_WRITE",
            "F_SEAL_GROW",
            "F_SEAL_SHRINK",
            "F_SEAL_SEAL",
        )
    )
)


def requires_linux_memfd(test):
    return unittest.skipUnless(
        LINUX_MEMFD, "sealed memfd execution requires Linux /proc and fcntl seals"
    )(test)


def load_helper():
    spec = importlib.util.spec_from_file_location("exec_t11_stage0a", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ExecIntercept(RuntimeError):
    pass


class T11Stage0AExecHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper = load_helper()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.executable = self.root / "probe.py"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        self.executable.chmod(0o700)
        self.source = self.root / "source.smt2"
        self.source.write_bytes(b"(set-logic QF_UF)\n(check-sat)\n")
        self.bundle = self.root / "bundle.json"
        self.bundle.write_bytes(b'{"bundle":true}\n')
        self.request_path = self.root / "request.json"
        self.original_proc_fd_root = self.helper.PROC_FD_ROOT

    def tearDown(self) -> None:
        self.helper.PROC_FD_ROOT = self.original_proc_fd_root
        self.temporary.cleanup()

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _record(self) -> dict[str, object]:
        return {
            "schema": self.helper.SCHEMA,
            "executable": {
                "path": str(self.executable),
                "sha256": self._sha256(self.executable),
            },
            "inputs": [
                {
                    "placeholder": "@SOURCE@",
                    "path": str(self.source),
                    "sha256": self._sha256(self.source),
                },
                {
                    "placeholder": "@BUNDLE@",
                    "path": str(self.bundle),
                    "sha256": self._sha256(self.bundle),
                },
            ],
            "argv": ["euf-viper", "audit-t11", "@SOURCE@", "@BUNDLE@"],
            "environment": {
                "HOME": "/nonexistent/euf-viper-stage0",
                "LANG": "C.UTF-8",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "RUST_BACKTRACE": "0",
                "TZ": "UTC",
            },
        }

    def _write_request(self, record: dict[str, object] | None = None) -> Path:
        if record is None:
            record = self._record()
        self.request_path.write_text(
            json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        return self.request_path

    @staticmethod
    def _sha256_bytes(encoded: bytes) -> str:
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _sealed_memfd(name: str, encoded: bytes, mode: int) -> int:
        fd = os.memfd_create(
            name, flags=os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC
        )
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise RuntimeError("memfd write made no progress")
                view = view[written:]
            os.fchmod(fd, mode)
            seals = (
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL
            )
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            os.lseek(fd, 0, os.SEEK_SET)
            os.set_inheritable(fd, True)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _descriptor_pair(
        self,
        request_bytes: bytes | None = None,
        helper_bytes: bytes | None = None,
    ) -> tuple[int, int, bytes, bytes]:
        if request_bytes is None:
            request_bytes = (
                json.dumps(self._record(), separators=(",", ":")) + "\n"
            ).encode("utf-8")
        if helper_bytes is None:
            helper_bytes = HELPER.read_bytes()
        self_fd = self._sealed_memfd(
            "euf-viper-test-self", helper_bytes, self.helper.EXECUTABLE_SNAPSHOT_MODE
        )
        try:
            request_fd = self._sealed_memfd(
                "euf-viper-test-request",
                request_bytes,
                self.helper.INPUT_SNAPSHOT_MODE,
            )
        except BaseException:
            os.close(self_fd)
            raise
        return request_fd, self_fd, request_bytes, helper_bytes

    def _load_descriptor_pair(
        self,
        request_fd: int,
        self_fd: int,
        request_bytes: bytes,
        helper_bytes: bytes,
    ):
        with mock.patch.object(
            self.helper, "__file__", f"/proc/self/fd/{self_fd}"
        ):
            return self.helper.load_request_from_descriptors(
                request_fd,
                self._sha256_bytes(request_bytes),
                self_fd,
                self._sha256_bytes(helper_bytes),
            )

    def _run_descriptor_helper(
        self,
        request_fd: int,
        self_fd: int,
        request_bytes: bytes,
        helper_bytes: bytes,
        *,
        extra_fds: tuple[int, ...] = (),
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                f"/proc/self/fd/{self_fd}",
                "--request-fd",
                str(request_fd),
                "--request-sha256",
                self._sha256_bytes(request_bytes),
                "--self-fd",
                str(self_fd),
                "--self-sha256",
                self._sha256_bytes(helper_bytes),
            ],
            check=False,
            capture_output=True,
            pass_fds=(request_fd, self_fd, *extra_fds),
        )

    def test_strict_request_parses(self) -> None:
        request = self.helper.load_request(str(self._write_request()))
        self.assertEqual(request.executable.path, str(self.executable))
        self.assertEqual(
            [item.placeholder for item in request.inputs], ["@SOURCE@", "@BUNDLE@"]
        )
        self.assertEqual(dict(request.environment), self._record()["environment"])
        self.assertEqual(request.runtime, ())

    def test_runtime_request_parses_sorted_hash_bound_files(self) -> None:
        record = self._record()
        record["schema"] = self.helper.RUNTIME_SCHEMA
        record["runtime"] = [
            {"path": "/runtime/a.so", "sha256": "1" * 64},
            {"path": "/runtime/b.so", "sha256": "2" * 64},
        ]
        request = self.helper.load_request(str(self._write_request(record)))
        self.assertEqual(
            [item.path for item in request.runtime],
            ["/runtime/a.so", "/runtime/b.so"],
        )

    def test_runtime_request_rejects_unsorted_or_duplicate_paths(self) -> None:
        for paths, pattern in (
            (["/runtime/b.so", "/runtime/a.so"], "not byte-sorted"),
            (["/runtime/a.so", "/runtime/a.so"], "duplicate paths"),
        ):
            with self.subTest(paths=paths):
                record = self._record()
                record["schema"] = self.helper.RUNTIME_SCHEMA
                record["runtime"] = [
                    {"path": path, "sha256": f"{index + 1}" * 64}
                    for index, path in enumerate(paths)
                ]
                with self.assertRaisesRegex(self.helper.Stage0ExecError, pattern):
                    self.helper.load_request(str(self._write_request(record)))

    def test_runtime_retention_rejects_user_writable_path(self) -> None:
        runtime = self.root / "runtime.so"
        runtime.write_bytes(b"runtime")
        spec = self.helper.FileSpec(
            path=str(runtime.resolve()), sha256=self._sha256(runtime)
        )
        with self.assertRaisesRegex(
            self.helper.Stage0ExecError, "writable by the executing identity"
        ):
            self.helper._open_retained_runtime(spec, 0)

    @requires_linux_memfd
    def test_descriptor_mode_parses_without_reopening_helper_or_request_path(self) -> None:
        request_fd, self_fd, request_bytes, helper_bytes = self._descriptor_pair()
        try:
            with mock.patch.object(
                self.helper,
                "_open_readonly_regular",
                side_effect=AssertionError("descriptor mode reopened a path"),
            ):
                request = self._load_descriptor_pair(
                    request_fd, self_fd, request_bytes, helper_bytes
                )
        finally:
            os.close(request_fd)
            os.close(self_fd)
        self.assertEqual(request.executable.path, str(self.executable))
        self.assertEqual(request.argv[2:], ("@SOURCE@", "@BUNDLE@"))

    @requires_linux_memfd
    def test_descriptor_mode_requires_exact_modes(self) -> None:
        request_bytes = (
            json.dumps(self._record(), separators=(",", ":")) + "\n"
        ).encode("utf-8")
        helper_bytes = HELPER.read_bytes()
        cases = (
            ("request", 0o500, self.helper.EXECUTABLE_SNAPSHOT_MODE),
            ("self", self.helper.INPUT_SNAPSHOT_MODE, 0o400),
        )
        for role, request_mode, self_mode in cases:
            with self.subTest(role=role):
                request_fd = self._sealed_memfd(
                    f"bad-{role}-request", request_bytes, request_mode
                )
                self_fd = self._sealed_memfd(
                    f"bad-{role}-self", helper_bytes, self_mode
                )
                try:
                    with self.assertRaisesRegex(
                        self.helper.Stage0ExecError, rf"{role} descriptor .* mode mismatch"
                    ):
                        self._load_descriptor_pair(
                            request_fd, self_fd, request_bytes, helper_bytes
                        )
                finally:
                    os.close(request_fd)
                    os.close(self_fd)

    @requires_linux_memfd
    def test_descriptor_mode_rejects_missing_memfd_seals(self) -> None:
        for name, seals in (
            ("unsealed", 0),
            (
                "missing-seal-seal",
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK,
            ),
        ):
            with self.subTest(name=name):
                old_request_fd, self_fd, request_bytes, helper_bytes = (
                    self._descriptor_pair()
                )
                os.close(old_request_fd)
                request_fd = os.memfd_create(
                    f"euf-viper-{name}-request",
                    flags=os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
                )
                try:
                    os.write(request_fd, request_bytes)
                    os.fchmod(request_fd, self.helper.INPUT_SNAPSHOT_MODE)
                    if seals:
                        fcntl.fcntl(request_fd, fcntl.F_ADD_SEALS, seals)
                    os.lseek(request_fd, 0, os.SEEK_SET)
                    os.set_inheritable(request_fd, True)
                    with self.assertRaisesRegex(
                        self.helper.Stage0ExecError, "not fully sealed"
                    ):
                        self._load_descriptor_pair(
                            request_fd, self_fd, request_bytes, helper_bytes
                        )
                finally:
                    os.close(request_fd)
                    os.close(self_fd)

    @requires_linux_memfd
    def test_descriptor_mode_rejects_nonregular_descriptor(self) -> None:
        _request_fd, self_fd, request_bytes, helper_bytes = self._descriptor_pair()
        os.close(_request_fd)
        request_fd = os.open(self.root, os.O_RDONLY)
        os.set_inheritable(request_fd, True)
        try:
            with self.assertRaisesRegex(
                self.helper.Stage0ExecError, "must be a regular file"
            ):
                self._load_descriptor_pair(
                    request_fd, self_fd, request_bytes, helper_bytes
                )
        finally:
            os.close(request_fd)
            os.close(self_fd)

    @requires_linux_memfd
    def test_descriptor_mode_rejects_digest_mismatch_before_json(self) -> None:
        request_bytes = b"not-json"
        request_fd, self_fd, _request_bytes, helper_bytes = self._descriptor_pair(
            request_bytes=request_bytes
        )
        try:
            with mock.patch.object(
                self.helper, "__file__", f"/proc/self/fd/{self_fd}"
            ):
                with self.assertRaisesRegex(
                    self.helper.Stage0ExecError, "bytes changed before execution"
                ):
                    self.helper.load_request_from_descriptors(
                        request_fd,
                        "0" * 64,
                        self_fd,
                        self._sha256_bytes(helper_bytes),
                    )
        finally:
            os.close(request_fd)
            os.close(self_fd)

    @requires_linux_memfd
    def test_descriptor_mode_rejects_wrong_running_helper_binding(self) -> None:
        request_fd, self_fd, request_bytes, helper_bytes = self._descriptor_pair()
        try:
            with self.assertRaisesRegex(
                self.helper.Stage0ExecError, "was not loaded from its declared descriptor"
            ):
                self.helper.load_request_from_descriptors(
                    request_fd,
                    self._sha256_bytes(request_bytes),
                    self_fd,
                    self._sha256_bytes(helper_bytes),
                )
        finally:
            os.close(request_fd)
            os.close(self_fd)

    @requires_linux_memfd
    def test_descriptor_mode_rejects_undeclared_inherited_fd_before_json(self) -> None:
        request_bytes = b"not-json"
        request_fd, self_fd, _request_bytes, helper_bytes = self._descriptor_pair(
            request_bytes=request_bytes
        )
        extra_fd = self._sealed_memfd("euf-viper-extra", b"extra", 0o400)
        try:
            with mock.patch.object(
                self.helper, "__file__", f"/proc/self/fd/{self_fd}"
            ):
                with self.assertRaisesRegex(
                    self.helper.Stage0ExecError, rf"undeclared=\[{extra_fd}\]"
                ):
                    self.helper.load_request_from_descriptors(
                        request_fd,
                        self._sha256_bytes(request_bytes),
                        self_fd,
                        self._sha256_bytes(helper_bytes),
                    )
        finally:
            os.close(extra_fd)
            os.close(request_fd)
            os.close(self_fd)

    @requires_linux_memfd
    def test_descriptor_mode_rejects_noninheritable_declared_fd(self) -> None:
        request_fd, self_fd, request_bytes, helper_bytes = self._descriptor_pair()
        os.set_inheritable(request_fd, False)
        try:
            with mock.patch.object(
                self.helper, "__file__", f"/proc/self/fd/{self_fd}"
            ):
                with self.assertRaisesRegex(
                    self.helper.Stage0ExecError, rf"missing=\[{request_fd}\]"
                ):
                    self.helper.load_request_from_descriptors(
                        request_fd,
                        self._sha256_bytes(request_bytes),
                        self_fd,
                        self._sha256_bytes(helper_bytes),
                    )
        finally:
            os.close(request_fd)
            os.close(self_fd)

    @requires_linux_memfd
    def test_descriptor_mode_rejects_proc_fd_identity_mismatch(self) -> None:
        request_fd, self_fd, request_bytes, helper_bytes = self._descriptor_pair()
        real_stat = self.helper.os.stat

        def mismatched_request_binding(path, *args, **kwargs):
            if path == f"/proc/self/fd/{request_fd}":
                return os.fstat(self_fd)
            return real_stat(path, *args, **kwargs)

        try:
            with mock.patch.object(
                self.helper, "__file__", f"/proc/self/fd/{self_fd}"
            ), mock.patch.object(
                self.helper.os, "stat", side_effect=mismatched_request_binding
            ):
                with self.assertRaisesRegex(
                    self.helper.Stage0ExecError, "proc-fd identity mismatch"
                ):
                    self.helper.load_request_from_descriptors(
                        request_fd,
                        self._sha256_bytes(request_bytes),
                        self_fd,
                        self._sha256_bytes(helper_bytes),
                    )
        finally:
            os.close(request_fd)
            os.close(self_fd)

    def test_unknown_top_level_and_nested_fields_are_rejected(self) -> None:
        top_level = self._record()
        top_level["unexpected"] = True
        with self.assertRaisesRegex(self.helper.Stage0ExecError, "keys differ"):
            self.helper.load_request(str(self._write_request(top_level)))

        nested = self._record()
        executable = nested["executable"]
        assert isinstance(executable, dict)
        executable["mode"] = "release"
        with self.assertRaisesRegex(self.helper.Stage0ExecError, "keys differ"):
            self.helper.load_request(str(self._write_request(nested)))

    def test_malformed_duplicate_and_nonfinite_json_are_rejected(self) -> None:
        cases = (
            b'{"schema":',
            b'{"schema":"a","schema":"b"}',
            b'{"schema":NaN}',
            b"\xff",
        )
        for index, encoded in enumerate(cases):
            with self.subTest(index=index):
                self.request_path.write_bytes(encoded)
                with self.assertRaises(self.helper.Stage0ExecError):
                    self.helper.load_request(str(self.request_path))

    def test_digest_must_be_canonical_lowercase_hex(self) -> None:
        for digest in ("A" * 64, "0" * 63, "g" * 64, 7):
            with self.subTest(digest=digest):
                record = self._record()
                executable = record["executable"]
                assert isinstance(executable, dict)
                executable["sha256"] = digest
                with self.assertRaisesRegex(
                    self.helper.Stage0ExecError,
                    "lowercase hexadecimal|must be a string",
                ):
                    self.helper.load_request(str(self._write_request(record)))

    def test_duplicate_missing_and_embedded_placeholders_are_rejected(self) -> None:
        duplicate_declaration = self._record()
        inputs = duplicate_declaration["inputs"]
        assert isinstance(inputs, list) and isinstance(inputs[1], dict)
        inputs[1]["placeholder"] = "@SOURCE@"

        missing = self._record()
        missing["argv"] = ["euf-viper", "audit-t11", "@SOURCE@", "literal"]

        embedded = self._record()
        embedded["argv"] = [
            "euf-viper",
            "audit-t11",
            "--source=@SOURCE@",
            "@BUNDLE@",
        ]

        for name, record in (
            ("duplicate declaration", duplicate_declaration),
            ("missing", missing),
            ("embedded", embedded),
        ):
            with self.subTest(name=name):
                with self.assertRaises(self.helper.Stage0ExecError):
                    self.helper.load_request(str(self._write_request(record)))

    def test_exact_placeholder_may_bind_multiple_arguments(self) -> None:
        record = self._record()
        record["argv"] = [
            "euf-viper",
            "audit-t11",
            "@SOURCE@",
            "@BUNDLE@",
            "--artifact",
            "source",
            str(self.source),
            "@SOURCE@",
        ]
        request = self.helper.load_request(str(self._write_request(record)))
        self.assertEqual(request.argv.count("@SOURCE@"), 2)

    def test_unsafe_environment_keys_and_values_are_rejected(self) -> None:
        cases = (
            ("LD_PRELOAD", "/tmp/inject.so"),
            ("PYTHONPATH", "/tmp/modules"),
            ("RUSTC_WRAPPER", "/tmp/wrapper"),
            ("HOME", "relative/home"),
            ("PATH", "/usr/bin::/bin"),
            ("RUST_BACKTRACE", "yes"),
        )
        for key, value in cases:
            with self.subTest(key=key, value=value):
                record = self._record()
                environment = record["environment"]
                assert isinstance(environment, dict)
                environment[key] = value
                with self.assertRaises(self.helper.Stage0ExecError):
                    self.helper.load_request(str(self._write_request(record)))

    def test_projection_selector_environment_is_exactly_allowlisted(self) -> None:
        record = self._record()
        environment = record["environment"]
        assert isinstance(environment, dict)
        environment["EUF_VIPER_T11_EQRES"] = "clique-er-auto"
        request = self.helper.load_request(str(self._write_request(record)))
        self.assertEqual(
            request.environment["EUF_VIPER_T11_EQRES"], "clique-er-auto"
        )

        environment["EUF_VIPER_T11_EQRES"] = "off"
        with self.assertRaisesRegex(self.helper.Stage0ExecError, "clique-er-auto"):
            self.helper.load_request(str(self._write_request(record)))

    def test_relative_paths_and_request_symlink_are_rejected(self) -> None:
        record = self._record()
        executable = record["executable"]
        assert isinstance(executable, dict)
        executable["path"] = "relative/executable"
        with self.assertRaisesRegex(self.helper.Stage0ExecError, "absolute path"):
            self.helper.load_request(str(self._write_request(record)))

        self._write_request()
        request_link = self.root / "request-link.json"
        request_link.symlink_to(self.request_path)
        with self.assertRaisesRegex(self.helper.Stage0ExecError, "symlink"):
            self.helper.load_request(str(request_link))

    @requires_linux_memfd
    def test_symlink_executable_and_input_are_rejected(self) -> None:
        executable_link = self.root / "executable-link"
        executable_link.symlink_to(self.executable)
        record = self._record()
        executable = record["executable"]
        assert isinstance(executable, dict)
        executable["path"] = str(executable_link)
        request = self.helper.load_request(str(self._write_request(record)))
        with self.assertRaisesRegex(self.helper.Stage0ExecError, "symlink"):
            self.helper.execute_request(request, execve=lambda *_: None)

        input_link = self.root / "source-link"
        input_link.symlink_to(self.source)
        record = self._record()
        inputs = record["inputs"]
        assert isinstance(inputs, list) and isinstance(inputs[0], dict)
        inputs[0]["path"] = str(input_link)
        request = self.helper.load_request(str(self._write_request(record)))
        with self.assertRaisesRegex(self.helper.Stage0ExecError, "symlink"):
            self.helper.execute_request(request, execve=lambda *_: None)

    @requires_linux_memfd
    def test_digest_mismatch_fails_before_exec(self) -> None:
        record = self._record()
        inputs = record["inputs"]
        assert isinstance(inputs, list) and isinstance(inputs[0], dict)
        inputs[0]["sha256"] = "0" * 64
        request = self.helper.load_request(str(self._write_request(record)))
        called = False

        def forbidden_exec(*_args):
            nonlocal called
            called = True

        with self.assertRaisesRegex(self.helper.Stage0ExecError, "SHA-256 mismatch"):
            self.helper.execute_request(request, execve=forbidden_exec)
        self.assertFalse(called)

    @requires_linux_memfd
    def test_nonregular_input_is_rejected(self) -> None:
        record = self._record()
        inputs = record["inputs"]
        assert isinstance(inputs, list) and isinstance(inputs[0], dict)
        inputs[0]["path"] = str(self.root)
        inputs[0]["sha256"] = "0" * 64
        request = self.helper.load_request(str(self._write_request(record)))
        with self.assertRaisesRegex(self.helper.Stage0ExecError, "regular file"):
            self.helper.execute_request(request, execve=lambda *_: None)

    @requires_linux_memfd
    def test_absent_proc_self_fd_fails_before_opening_artifacts(self) -> None:
        request = self.helper.load_request(str(self._write_request()))
        real_stat = self.helper.os.stat

        def absent_proc(path, *args, **kwargs):
            if path == "/proc/self/fd":
                raise FileNotFoundError(errno.ENOENT, "missing procfs", path)
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(self.helper.os, "stat", side_effect=absent_proc):
            with self.assertRaisesRegex(self.helper.Stage0ExecError, "unavailable"):
                self.helper.execute_request(request, execve=lambda *_: None)

    @requires_linux_memfd
    def test_substitution_inheritance_and_environment_are_exact(self) -> None:
        request = self.helper.load_request(str(self._write_request()))

        extra_path = self.root / "extra"
        extra_path.write_bytes(b"must not be inherited")
        extra_fd = os.open(extra_path, os.O_RDONLY)
        os.set_inheritable(extra_fd, True)
        observed: dict[str, object] = {}

        def intercept_exec(path, argv, environment):
            required_fds = {int(Path(path).name)}
            for argument in argv:
                if argument.startswith(f"{self.helper.PROC_FD_ROOT}/"):
                    required_fds.add(int(Path(argument).name))
            observed.update(path=path, argv=list(argv), environment=dict(environment))
            self.assertTrue(all(os.get_inheritable(fd) for fd in required_fds))
            self.assertFalse(os.get_inheritable(extra_fd))
            inherited = {
                int(entry)
                for entry in os.listdir("/proc/self/fd")
                if entry.isdecimal()
                and int(entry) > 2
                and self._is_inheritable(int(entry))
            }
            self.assertEqual(inherited, required_fds)
            raise ExecIntercept

        try:
            with self.assertRaises(ExecIntercept):
                self.helper.execute_request(request, execve=intercept_exec)
        finally:
            os.close(extra_fd)

        self.assertRegex(str(observed["path"]), rf"^{re.escape(self.helper.PROC_FD_ROOT)}/[0-9]+$")
        argv = observed["argv"]
        assert isinstance(argv, list)
        self.assertEqual(argv[:2], ["euf-viper", "audit-t11"])
        self.assertRegex(argv[2], rf"^{re.escape(self.helper.PROC_FD_ROOT)}/[0-9]+$")
        self.assertRegex(argv[3], rf"^{re.escape(self.helper.PROC_FD_ROOT)}/[0-9]+$")
        self.assertNotEqual(argv[2], argv[3])
        self.assertEqual(observed["environment"], self._record()["environment"])

    @staticmethod
    def _is_inheritable(fd: int) -> bool:
        try:
            return os.get_inheritable(fd)
        except OSError as error:
            if error.errno == errno.EBADF:
                return False
            raise

    @requires_linux_memfd
    def test_original_inode_mutation_cannot_change_sealed_execution_bytes(self) -> None:
        request = self.helper.load_request(str(self._write_request()))
        expected_executable = self.executable.read_bytes()
        expected_source = self.source.read_bytes()
        expected_bundle = self.bundle.read_bytes()
        base_seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )

        def intercept_exec(path, argv, _environment):
            self.executable.write_bytes(b"#!/bin/sh\nexit 91\n")
            self.executable.chmod(0o700)
            self.source.write_bytes(b"mutated source\n")
            self.bundle.write_bytes(b'{"mutated":true}\n')

            snapshot_paths = [path, argv[2], argv[3]]
            expected_bytes = [expected_executable, expected_source, expected_bundle]
            expected_modes = [
                self.helper.EXECUTABLE_SNAPSHOT_MODE,
                self.helper.INPUT_SNAPSHOT_MODE,
                self.helper.INPUT_SNAPSHOT_MODE,
            ]
            for snapshot_path, encoded, mode in zip(
                snapshot_paths, expected_bytes, expected_modes, strict=True
            ):
                fd = int(Path(snapshot_path).name)
                self.assertEqual(Path(snapshot_path).read_bytes(), encoded)
                self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), mode)
                seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
                self.assertEqual(seals & base_seals, base_seals)
                with self.assertRaises(OSError) as rejected_write:
                    os.write(fd, b"forbidden")
                self.assertEqual(rejected_write.exception.errno, errno.EPERM)
            raise ExecIntercept

        with self.assertRaises(ExecIntercept):
            self.helper.execute_request(request, execve=intercept_exec)

        self.assertNotEqual(self.executable.read_bytes(), expected_executable)
        self.assertNotEqual(self.source.read_bytes(), expected_source)
        self.assertNotEqual(self.bundle.read_bytes(), expected_bundle)

    @requires_linux_memfd
    def test_source_mutation_during_copy_is_rejected(self) -> None:
        request = self.helper.load_request(str(self._write_request()))
        source_identity = (self.source.stat().st_dev, self.source.stat().st_ino)
        real_read = self.helper.os.read
        mutated = False
        called = False

        def mutating_read(fd, count):
            nonlocal mutated
            chunk = real_read(fd, count)
            metadata = os.fstat(fd)
            if (
                chunk
                and not mutated
                and (metadata.st_dev, metadata.st_ino) == source_identity
            ):
                mutated = True
                self.source.write_bytes(b"changed while snapshotting\n")
            return chunk

        def forbidden_exec(*_args):
            nonlocal called
            called = True

        with mock.patch.object(self.helper.os, "read", side_effect=mutating_read):
            with self.assertRaisesRegex(self.helper.Stage0ExecError, "changed while"):
                self.helper.execute_request(request, execve=forbidden_exec)
        self.assertTrue(mutated)
        self.assertFalse(called)

    @requires_linux_memfd
    def test_sealing_failure_closes_snapshot_and_prevents_exec(self) -> None:
        request = self.helper.load_request(str(self._write_request()))
        real_memfd_create = self.helper.os.memfd_create
        real_fcntl = self.helper.fcntl.fcntl
        created_fds: list[int] = []
        called = False

        def tracking_memfd_create(name, flags):
            fd = real_memfd_create(name, flags=flags)
            created_fds.append(fd)
            return fd

        def rejecting_fcntl(fd, command, *args):
            if command == fcntl.F_ADD_SEALS:
                raise OSError(errno.EPERM, "sealing denied")
            return real_fcntl(fd, command, *args)

        def forbidden_exec(*_args):
            nonlocal called
            called = True

        with mock.patch.object(
            self.helper.os, "memfd_create", side_effect=tracking_memfd_create
        ), mock.patch.object(self.helper.fcntl, "fcntl", side_effect=rejecting_fcntl):
            with self.assertRaisesRegex(self.helper.Stage0ExecError, "cannot seal"):
                self.helper.execute_request(request, execve=forbidden_exec)

        self.assertFalse(called)
        self.assertTrue(created_fds)
        for fd in created_fds:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_missing_linux_or_memfd_primitives_fail_closed(self) -> None:
        request = self.helper.load_request(str(self._write_request()))
        called = False

        def forbidden_exec(*_args):
            nonlocal called
            called = True

        with mock.patch.object(self.helper.sys, "platform", "darwin"):
            with self.assertRaisesRegex(self.helper.Stage0ExecError, "requires Linux"):
                self.helper.execute_request(request, execve=forbidden_exec)

        with mock.patch.object(self.helper.sys, "platform", "linux"), mock.patch.object(
            self.helper.os, "memfd_create", None, create=True
        ):
            with self.assertRaisesRegex(self.helper.Stage0ExecError, "unavailable"):
                self.helper.execute_request(request, execve=forbidden_exec)
        self.assertFalse(called)

    @requires_linux_memfd
    def test_actual_script_exec_reads_sealed_input_and_isolates_environment(self) -> None:
        output = self.root / "observed.json"
        script = self.root / "actual-probe.py"
        script.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "source = pathlib.Path(sys.argv[1]).read_text(encoding='ascii')\n"
            "pathlib.Path(sys.argv[2]).write_text(json.dumps({\n"
            "    'source': source,\n"
            "    'home': os.environ.get('HOME'),\n"
            "    'leak': os.environ.get('STAGE0_MUST_NOT_LEAK'),\n"
            "}), encoding='ascii')\n",
            encoding="ascii",
        )
        script.chmod(0o700)
        record = {
            "schema": self.helper.SCHEMA,
            "executable": {
                "path": str(script),
                "sha256": self._sha256(script),
            },
            "inputs": [
                {
                    "placeholder": "@SOURCE@",
                    "path": str(self.source),
                    "sha256": self._sha256(self.source),
                }
            ],
            "argv": ["stage0-probe", "@SOURCE@", str(output)],
            "environment": {"HOME": "/stage0-isolated", "LANG": "C", "TZ": "UTC"},
        }
        self._write_request(record)
        parent_environment = os.environ.copy()
        parent_environment["STAGE0_MUST_NOT_LEAK"] = "inherited-secret"
        completed = subprocess.run(
            [sys.executable, str(HELPER), "--request", str(self.request_path)],
            check=False,
            capture_output=True,
            text=True,
            env=parent_environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        observed = json.loads(output.read_text(encoding="ascii"))
        self.assertEqual(observed["source"], self.source.read_text(encoding="ascii"))
        self.assertEqual(observed["home"], "/stage0-isolated")
        self.assertIsNone(observed["leak"])

    @requires_linux_memfd
    def test_actual_binary_exec_reads_sealed_input(self) -> None:
        executable = Path("/bin/cat").resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            self.skipTest("/bin/cat does not resolve to an executable regular file")
        record = {
            "schema": self.helper.SCHEMA,
            "executable": {
                "path": str(executable),
                "sha256": self._sha256(executable),
            },
            "inputs": [
                {
                    "placeholder": "@SOURCE@",
                    "path": str(self.source),
                    "sha256": self._sha256(self.source),
                }
            ],
            "argv": ["cat-snapshot", "@SOURCE@"],
            "environment": {"HOME": "/stage0-isolated", "LANG": "C", "TZ": "UTC"},
        }
        completed = subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "--request",
                str(self._write_request(record)),
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout, self.source.read_bytes())

    @requires_linux_memfd
    def test_runtime_supervisor_retains_and_revalidates_dependency(self) -> None:
        executable = Path("/bin/cat").resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            self.skipTest("/bin/cat does not resolve to an executable regular file")
        record = {
            "schema": self.helper.RUNTIME_SCHEMA,
            "executable": {
                "path": str(executable),
                "sha256": self._sha256(executable),
            },
            "inputs": [
                {
                    "placeholder": "@SOURCE@",
                    "path": str(self.source),
                    "sha256": self._sha256(self.source),
                }
            ],
            "runtime": [
                {"path": str(executable), "sha256": self._sha256(executable)}
            ],
            "argv": ["cat-supervised", "@SOURCE@"],
            "environment": {"HOME": "/stage0-isolated", "LANG": "C", "TZ": "UTC"},
        }
        completed = subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "--request",
                str(self._write_request(record)),
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout, self.source.read_bytes())

    @requires_linux_memfd
    def test_actual_descriptor_bootstrap_uses_sealed_original_bytes(self) -> None:
        executable = Path("/bin/cat").resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            self.skipTest("/bin/cat does not resolve to an executable regular file")
        record = {
            "schema": self.helper.SCHEMA,
            "executable": {
                "path": str(executable),
                "sha256": self._sha256(executable),
            },
            "inputs": [
                {
                    "placeholder": "@SOURCE@",
                    "path": str(self.source),
                    "sha256": self._sha256(self.source),
                }
            ],
            "argv": ["cat-sealed-bootstrap", "@SOURCE@"],
            "environment": {"HOME": "/stage0-isolated", "LANG": "C", "TZ": "UTC"},
        }
        request_copy = self.root / "descriptor-request.json"
        helper_copy = self.root / "descriptor-helper.py"
        request_bytes = (
            json.dumps(record, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        helper_bytes = HELPER.read_bytes()
        request_copy.write_bytes(request_bytes)
        helper_copy.write_bytes(helper_bytes)
        request_fd, self_fd, _, _ = self._descriptor_pair(
            request_bytes=request_copy.read_bytes(),
            helper_bytes=helper_copy.read_bytes(),
        )
        try:
            request_copy.write_bytes(b"not-json\n")
            helper_copy.write_bytes(b"raise SystemExit(91)\n")
            completed = self._run_descriptor_helper(
                request_fd, self_fd, request_bytes, helper_bytes
            )
        finally:
            os.close(request_fd)
            os.close(self_fd)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout, self.source.read_bytes())

    @requires_linux_memfd
    def test_actual_descriptor_bootstrap_rejects_extra_fd_before_json(self) -> None:
        request_bytes = b"not-json\n"
        request_fd, self_fd, _, helper_bytes = self._descriptor_pair(
            request_bytes=request_bytes
        )
        extra_fd = self._sealed_memfd("euf-viper-extra-child", b"extra", 0o400)
        try:
            completed = self._run_descriptor_helper(
                request_fd,
                self_fd,
                request_bytes,
                helper_bytes,
                extra_fds=(extra_fd,),
            )
        finally:
            os.close(extra_fd)
            os.close(request_fd)
            os.close(self_fd)
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"undeclared", completed.stderr)
        self.assertNotIn(b"strict JSON", completed.stderr)

    def test_cli_descriptor_modes_are_mutually_complete(self) -> None:
        cases = (
            (
                ["--request-fd", "3"],
                "requires descriptor verification options",
            ),
            (
                [
                    "--request",
                    str(self._write_request()),
                    "--self-sha256",
                    "0" * 64,
                ],
                "require --request-fd",
            ),
            (
                [
                    "--request",
                    str(self._write_request()),
                    "--request-fd",
                    "3",
                ],
                "not allowed with argument",
            ),
            (["--request-fd", "+3"], "canonical decimal integer"),
            (["--request-fd", "03"], "canonical decimal integer"),
            (["--request-fd", "2"], "canonical decimal integer"),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                completed = subprocess.run(
                    [sys.executable, str(HELPER), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn(expected, completed.stderr)

    def test_cli_rejects_unknown_arguments_without_execution(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "--request",
                str(self._write_request()),
                "--unknown",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unrecognized arguments", completed.stderr)


if __name__ == "__main__":
    unittest.main()
