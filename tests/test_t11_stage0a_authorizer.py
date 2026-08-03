from __future__ import annotations

import errno
import hashlib
import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/bench/authorize_t11_stage0a.py"
FINALIZER_PATH = ROOT / "scripts/bench/finalize_t11_stage0a.py"
FINALIZER_TEST_PATH = ROOT / "tests/test_t11_stage0a_finalizer.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


AUTHORIZER = load_module("authorize_t11_stage0a", MODULE_PATH)
FINALIZER_TESTS = load_module("t11_stage0a_finalizer_test_support", FINALIZER_TEST_PATH)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AuthorizerFixture:
    def __init__(self, case: unittest.TestCase, base: Path) -> None:
        self.case = case
        self.base = base.resolve()
        self.candidate = FINALIZER_TESTS.CandidateFixture(case, self.base)

        self.finalizer_module_path = self.base / "finalize_t11_stage0a.py"
        self.finalizer_module_path.write_bytes(FINALIZER_PATH.read_bytes())
        self.finalizer_module_path.chmod(0o400)
        self.finalizer_module_sha256 = digest(self.finalizer_module_path.read_bytes())

        self.authorizer_module_path = self.base / "authorize_t11_stage0a.py"
        self.authorizer_module_path.write_bytes(MODULE_PATH.read_bytes())
        self.authorizer_module_path.chmod(0o400)
        AUTHORIZER.__file__ = os.fspath(self.authorizer_module_path)

        self.sacct_path = self.base / "sacct"
        self.sacct_path.write_bytes(b"#!/bin/sh\nexit 97\n")
        self.sacct_path.chmod(0o500)

        control = self.candidate.submission["control"]
        control["finalizer_sha256"] = self.finalizer_module_sha256
        control["authorizer_sha256"] = digest(self.authorizer_module_path.read_bytes())
        control["sacct_sha256"] = digest(self.sacct_path.read_bytes())
        self._write_submission()

        fixture_runner = self.candidate.scheduler_runner()

        def compute_runner(argv):
            executable = {
                "/proc/self/fd/51": "/usr/bin/sacct",
                "/proc/self/fd/52": "/usr/bin/scontrol",
            }[argv[0]]
            result = fixture_runner((executable, *argv[1:]))
            return FINALIZER_TESTS.FINALIZER.CommandOutput(
                tuple(argv), result.returncode, result.stdout, result.stderr
            )

        scheduler_candidate = self.candidate.finalize(
            runner=compute_runner,
            sacct_bin="/proc/self/fd/51",
            scontrol_bin="/proc/self/fd/52",
        )
        self.scheduler_candidate_path = Path(
            self.candidate.submission["scheduler_candidate_path"]
        )
        self._write_json(self.scheduler_candidate_path, scheduler_candidate)
        self.output_path = Path(self.candidate.submission["final_decision_path"])

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(AUTHORIZER.canonical_json_bytes(payload))
        path.chmod(0o400)

    def _write_submission(self) -> None:
        self._write_json(self.candidate.submission_path, self.candidate.submission)

    def rewrite_candidate(self, update) -> None:
        payload = AUTHORIZER.decode_canonical_json(
            self.scheduler_candidate_path.read_bytes(), "test scheduler candidate"
        )
        update(payload)
        self._write_json(self.scheduler_candidate_path, payload)

    def rewrite_submission(self, update) -> None:
        update(self.candidate.submission)
        self._write_submission()

    def finalizer_runner(
        self,
        *,
        allocation_overrides: dict[str, str] | None = None,
        batch_overrides: dict[str, str] | None = None,
        on_allocation=None,
    ):
        fixture = self.candidate
        allocation = {
            "Cluster": fixture.cluster,
            "DBIndex": "9001",
            "JobIDRaw": str(fixture.finalizer_job_id),
            "JobName": fixture.finalizer_job_name,
            "User": "test",
            "UID": str(os.getuid()),
            "State": "COMPLETED",
            "ExitCode": "0:0",
            "DerivedExitCode": "0:0",
            "Submit": "2026-07-19T10:00:00",
            "Eligible": "2026-07-19T10:00:10",
            "Start": "2026-07-19T10:00:12",
            "End": "2026-07-19T10:00:20",
            "ElapsedRaw": "8",
            "Partition": fixture.partition,
            "NodeList": "wmi-node02",
            "NNodes": "1",
            "ReqCPUS": "1",
            "AllocCPUS": "1",
            "ReqMem": "1Gn",
            "ReqTRES": "cpu=1,mem=1G,node=1,billing=1",
            "AllocTRES": "cpu=1,mem=1G,node=1,billing=1",
            "TimelimitRaw": "10",
            "Comment": fixture.finalizer_comment,
            "SubmitLine": " ".join(
                fixture.submission["slurm"]["finalizer_sbatch_argv"]
            ),
            "WorkDir": fixture.work_dir,
            "StdOut": fixture.finalizer_stdout_path,
            "StdErr": fixture.finalizer_stderr_path,
        }
        batch = {
            "Cluster": fixture.cluster,
            "DBIndex": "9001",
            "JobIDRaw": f"{fixture.finalizer_job_id}.batch",
            "JobName": "batch",
            "State": "COMPLETED",
            "ExitCode": "0:0",
            "DerivedExitCode": "",
            "Submit": "2026-07-19T10:00:10",
            "Start": "2026-07-19T10:00:12",
            "End": "2026-07-19T10:00:20",
            "ElapsedRaw": "8",
            "NodeList": "wmi-node02",
            "NNodes": "1",
            "ReqCPUS": "1",
            "AllocCPUS": "1",
            "AllocTRES": "cpu=1,mem=1G,node=1,billing=1",
        }
        allocation.update(allocation_overrides or {})
        batch.update(batch_overrides or {})
        calls: list[tuple[str, ...]] = []
        allocation_hook_called = False

        def encode(record: dict[str, str], fields: tuple[str, ...]) -> bytes:
            return ("|".join(record[field] for field in fields) + "\n").encode("ascii")

        def runner(argv):
            nonlocal allocation_hook_called
            command = tuple(argv)
            calls.append(command)
            if "--allocations" in command:
                raw = encode(allocation, AUTHORIZER.FINALIZER_ALLOCATION_FIELDS)
                if on_allocation is not None and not allocation_hook_called:
                    allocation_hook_called = True
                    on_allocation()
            else:
                raw = encode(batch, AUTHORIZER.FINALIZER_BATCH_FIELDS)
            return AUTHORIZER.CommandOutput(command, 0, raw, b"")

        runner.calls = calls
        return runner

    def authorize(self, runner=None):
        return AUTHORIZER.build_authorization_payload(
            self.candidate.submission_path,
            self.scheduler_candidate_path,
            submission_sha256=digest(self.candidate.submission_path.read_bytes()),
            finalizer_module_path=self.finalizer_module_path,
            finalizer_module_sha256=self.finalizer_module_sha256,
            command_runner=runner or self.finalizer_runner(),
            sacct_bin=os.fspath(self.sacct_path),
            output_path=self.output_path,
        )


class T11Stage0AAuthorizerTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.fixture = AuthorizerFixture(self, self.base)

    def tearDown(self) -> None:
        for path in sorted(self.base.rglob("*"), reverse=True):
            try:
                if path.is_dir() and not path.is_symlink():
                    path.chmod(0o700)
                elif not path.is_symlink():
                    path.chmod(0o600)
            except FileNotFoundError:
                pass
        self.temporary.cleanup()

    def test_success_binds_inputs_and_finalizer_terminal_sacct_only(self) -> None:
        runner = self.fixture.finalizer_runner()
        payload = self.fixture.authorize(runner)
        self.assertEqual(payload["schema"], AUTHORIZER.AUTHORIZATION_SCHEMA)
        self.assertEqual(payload["status"], "stage0b_authorized")
        self.assertEqual(payload["decision"], AUTHORIZER.AUTHORIZATION_DECISION)
        self.assertTrue(payload["stage0b_authority"])
        self.assertEqual(
            payload["candidate_root_binding"]["path"],
            os.fspath(self.fixture.candidate.root),
        )
        self.assertEqual(
            payload["candidate_root_binding"]["inventory_sha256"],
            digest(
                AUTHORIZER.canonical_json_bytes(
                    AUTHORIZER.decode_canonical_json(
                        self.fixture.scheduler_candidate_path.read_bytes(),
                        "scheduler candidate",
                    )["artifacts"]
                )
            ),
        )
        self.assertEqual(
            payload["scheduler_candidate"]["sha256"],
            digest(self.fixture.scheduler_candidate_path.read_bytes()),
        )
        self.assertEqual(
            payload["finalizer_scheduler"]["allocation"]["JobIDRaw"],
            str(self.fixture.candidate.finalizer_job_id),
        )
        self.assertEqual(len(runner.calls), 2)
        self.assertTrue(all(command[0] == str(self.fixture.sacct_path) for command in runner.calls))
        self.assertTrue(all("--duplicates" in command for command in runner.calls))
        self.assertTrue(all("scontrol" not in command[0] for command in runner.calls))
        allocation_format = next(
            item for item in runner.calls[0] if item.startswith("--format=")
        )
        self.assertIn("DBIndex", allocation_format)
        self.assertIn("SubmitLine", allocation_format)
        self.assertNotIn("Restarts", allocation_format)
        self.assertNotIn("Requeue", allocation_format)
        encoded = AUTHORIZER.canonical_json_bytes(payload)
        self.assertEqual(AUTHORIZER.decode_canonical_json(encoded, "authorization"), payload)

    def test_nonterminal_and_failed_finalizer_records_reject(self) -> None:
        cases = (
            ({"State": "RUNNING"}, None, "must both be COMPLETED"),
            ({"ExitCode": "1:0"}, None, "exit and derived-exit"),
            (None, {"State": "FAILED"}, "must both be COMPLETED"),
            (None, {"ExitCode": "2:0"}, "batch exit evidence"),
        )
        for allocation, batch, pattern in cases:
            with self.subTest(allocation=allocation, batch=batch):
                runner = self.fixture.finalizer_runner(
                    allocation_overrides=allocation,
                    batch_overrides=batch,
                )
                with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, pattern):
                    self.fixture.authorize(runner)

    def test_finalizer_identity_resource_and_submitline_mismatches_reject(self) -> None:
        cases = (
            ({"UID": str(os.getuid() + 1)}, None, "UID differs"),
            ({"Comment": "changed"}, None, "comment differs"),
            ({"SubmitLine": "/usr/bin/sbatch changed"}, None, "SubmitLine differs"),
            ({"ReqMem": "2Gn"}, None, "requested memory differs"),
            ({"StdOut": "/changed/%j.out"}, None, "StdOut differs"),
            (None, {"DBIndex": "9002"}, "DBIndex differ"),
            (None, {"AllocCPUS": "2"}, "batch CPU or node resources differ"),
        )
        for allocation, batch, pattern in cases:
            with self.subTest(allocation=allocation, batch=batch):
                runner = self.fixture.finalizer_runner(
                    allocation_overrides=allocation,
                    batch_overrides=batch,
                )
                with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, pattern):
                    self.fixture.authorize(runner)

    def test_duplicate_accounting_rows_reject(self) -> None:
        underlying = self.fixture.finalizer_runner()

        def runner(argv):
            result = underlying(argv)
            stdout = result.stdout * 2 if "--allocations" in argv else result.stdout
            return AUTHORIZER.CommandOutput(tuple(argv), 0, stdout, b"")

        with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, "exactly one"):
            self.fixture.authorize(runner)

    def test_candidate_tampering_rejects(self) -> None:
        self.fixture.rewrite_candidate(
            lambda payload: payload.__setitem__(
                "decision", "requires_scheduler_finalization"
            )
        )
        with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, "decision differs"):
            self.fixture.authorize()

    def test_candidate_requires_sealed_compute_scheduler_commands(self) -> None:
        def use_mutable_path(payload) -> None:
            commands = payload["scheduler"]["commands"]
            commands["allocation"][0] = os.fspath(self.fixture.sacct_path)
            commands["batch"][0] = os.fspath(self.fixture.sacct_path)

        self.fixture.rewrite_candidate(use_mutable_path)
        with self.assertRaisesRegex(
            AUTHORIZER.AuthorizationError, "compute allocation command differs"
        ):
            self.fixture.authorize()

    def test_candidate_change_during_sacct_collection_rejects(self) -> None:
        def tamper() -> None:
            self.fixture.rewrite_candidate(
                lambda payload: payload.__setitem__("classification", "changed")
            )

        runner = self.fixture.finalizer_runner(on_allocation=tamper)
        with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, "changed during authorization"):
            self.fixture.authorize(runner)

    def test_submission_mismatch_rejects(self) -> None:
        self.fixture.rewrite_submission(
            lambda payload: payload.__setitem__("revision", "8" * 40)
        )
        with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, "revision differs"):
            self.fixture.authorize()

    def test_caller_submission_digest_mismatch_rejects(self) -> None:
        with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, "caller binding"):
            AUTHORIZER.build_authorization_payload(
                self.fixture.candidate.submission_path,
                self.fixture.scheduler_candidate_path,
                submission_sha256="0" * 64,
                finalizer_module_path=self.fixture.finalizer_module_path,
                finalizer_module_sha256=self.fixture.finalizer_module_sha256,
                command_runner=self.fixture.finalizer_runner(),
                sacct_bin=os.fspath(self.fixture.sacct_path),
                output_path=self.fixture.output_path,
            )

    def test_held_evidence_mismatch_rejects(self) -> None:
        path = self.fixture.candidate.finalizer_held_path
        original = path.read_bytes()
        path.chmod(0o600)
        path.write_bytes(original.replace(b":finalizer", b":tampered", 1))
        path.chmod(0o400)
        with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, "held scheduler record SHA-256"):
            self.fixture.authorize()

    def test_existing_output_is_never_replaced(self) -> None:
        payload = self.fixture.authorize()
        competitor = b"preexisting decision\n"
        self.fixture.output_path.write_bytes(competitor)
        self.fixture.output_path.chmod(0o400)
        with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, "must be fresh"):
            AUTHORIZER.publish_authorization(self.fixture.output_path, payload)
        self.assertEqual(self.fixture.output_path.read_bytes(), competitor)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "memfd_create"),
        "sealed scheduler execution requires Linux memfd support",
    )
    def test_default_runner_executes_anonymous_scheduler_snapshot(self) -> None:
        executable = self.base / "scheduler-probe"
        executable.write_bytes(b"#!/bin/sh\nprintf '%s\\n' \"$1\"\n")
        executable.chmod(0o500)
        argv = (os.fspath(executable), "bound-argument")
        result = AUTHORIZER._default_command_runner(argv)
        self.assertEqual(result.argv, argv)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"bound-argument\n")
        self.assertEqual(result.stderr, b"")

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "O_TMPFILE"),
        "anonymous authorization publication requires Linux O_TMPFILE",
    )
    def test_linux_success_publishes_canonical_authorization(self) -> None:
        runner = self.fixture.finalizer_runner()
        try:
            payload = AUTHORIZER.authorize_and_publish(
                self.fixture.candidate.submission_path,
                self.fixture.scheduler_candidate_path,
                self.fixture.output_path,
                submission_sha256=digest(
                    self.fixture.candidate.submission_path.read_bytes()
                ),
                finalizer_module_path=self.fixture.finalizer_module_path,
                finalizer_module_sha256=self.fixture.finalizer_module_sha256,
                command_runner=runner,
                sacct_bin=os.fspath(self.fixture.sacct_path),
            )
        except OSError as error:
            if error.errno in (errno.EOPNOTSUPP, errno.EINVAL):
                self.skipTest(f"test filesystem lacks O_TMPFILE: {error}")
            raise
        self.assertEqual(
            self.fixture.output_path.read_bytes(),
            AUTHORIZER.canonical_json_bytes(payload),
        )
        self.assertEqual(stat.S_IMODE(self.fixture.output_path.stat().st_mode), 0o400)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "O_TMPFILE"),
        "anonymous no-replace publication requires Linux O_TMPFILE",
    )
    def test_competitor_created_immediately_before_link_is_preserved(self) -> None:
        payload = self.fixture.authorize()
        competitor = b"racing decision\n"

        def create_competitor() -> None:
            self.fixture.output_path.write_bytes(competitor)
            self.fixture.output_path.chmod(0o400)

        try:
            with self.assertRaisesRegex(AUTHORIZER.AuthorizationError, "ceased to be fresh"):
                AUTHORIZER.publish_authorization(
                    self.fixture.output_path,
                    payload,
                    before_link=create_competitor,
                )
        except OSError as error:
            if error.errno in (errno.EOPNOTSUPP, errno.EINVAL):
                self.skipTest(f"test filesystem lacks O_TMPFILE: {error}")
            raise
        self.assertEqual(self.fixture.output_path.read_bytes(), competitor)
        self.assertEqual(stat.S_IMODE(self.fixture.output_path.stat().st_mode), 0o400)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "O_TMPFILE"),
        "candidate-root publication race requires Linux O_TMPFILE",
    )
    def test_candidate_root_replacement_immediately_before_link_rejects(self) -> None:
        displaced = self.fixture.candidate.root.with_name("candidate-displaced")

        def replace_root() -> None:
            self.fixture.candidate.root.rename(displaced)
            self.fixture.candidate.root.mkdir(mode=0o555)

        try:
            with self.assertRaisesRegex(
                AUTHORIZER.AuthorizationError, "candidate root changed"
            ):
                AUTHORIZER.authorize_and_publish(
                    self.fixture.candidate.submission_path,
                    self.fixture.scheduler_candidate_path,
                    self.fixture.output_path,
                    submission_sha256=digest(
                        self.fixture.candidate.submission_path.read_bytes()
                    ),
                    finalizer_module_path=self.fixture.finalizer_module_path,
                    finalizer_module_sha256=self.fixture.finalizer_module_sha256,
                    command_runner=self.fixture.finalizer_runner(),
                    sacct_bin=os.fspath(self.fixture.sacct_path),
                    before_publish=replace_root,
                )
        except OSError as error:
            if error.errno in (errno.EOPNOTSUPP, errno.EINVAL):
                self.skipTest(f"test filesystem lacks O_TMPFILE: {error}")
            raise
        self.assertFalse(self.fixture.output_path.exists())


if __name__ == "__main__":
    unittest.main()
