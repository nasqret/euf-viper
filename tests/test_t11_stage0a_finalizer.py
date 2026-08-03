from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts/bench/finalize_t11_stage0a.py"
SPEC = importlib.util.spec_from_file_location("finalize_t11_stage0a", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
FINALIZER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FINALIZER
SPEC.loader.exec_module(FINALIZER)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CandidateFixture:
    def __init__(
        self,
        case: unittest.TestCase,
        base: Path,
        *,
        semantic_overrides: dict[str, object] | None = None,
    ) -> None:
        self.case = case
        self.base = base.resolve()
        self.job_id = 42
        self.finalizer_job_id = 43
        self.cluster = "wmi"
        self.job_name = "euf-t11-stage0a"
        self.partition = "cpu_idle"
        self.nonce = "0123456789abcdef0123456789abcdef"
        self.revision = "7" * 40
        self.launch_sha256 = "1" * 64
        self.work_dir = "/work/euf-viper/t11"
        self.stdout_path = "/work/euf-viper/scheduler/compute-42.out"
        self.stderr_path = "/work/euf-viper/scheduler/compute-42.err"
        self.compute_script_path = "/work/euf-viper/euf_viper_t11_stage0a.sbatch"
        self.finalizer_job_name = "euf-t11-stage0a-finalize"
        self.finalizer_stdout_path = "/work/euf-viper/scheduler/finalizer-43.out"
        self.finalizer_stderr_path = "/work/euf-viper/scheduler/finalizer-43.err"
        self.finalizer_script_path = "/work/euf-viper/euf_viper_t11_stage0a_finalize.sbatch"
        self.compute_comment = f"euf-viper-t11:{self.nonce}:compute"
        self.finalizer_comment = f"euf-viper-t11:{self.nonce}:finalizer"
        self.root = self.base / "candidate-42"
        self.root.mkdir(mode=0o700)
        (self.root / "logs").mkdir(mode=0o700)

        semantic: dict[str, object] = {
            "schema": FINALIZER.SEMANTIC_SCHEMA,
            "status": "validated_candidate",
            "decision": FINALIZER.NONAUTHORIZING_DECISION,
            "stage0b_authority": False,
            "revision": self.revision,
            "launch_manifest_sha256": self.launch_sha256,
            "job_id": self.job_id,
            "resource_contract": {
                "cpus": 1,
                "memory_bytes": 8 * 1024**3,
                "sat_calls": 0,
            },
            "projection": {"outcome": "compiled", "proof_nodes": 17},
        }
        if semantic_overrides:
            semantic.update(semantic_overrides)
        self.semantic_path = self.root / "metadata.json"
        self._write_file(self.semantic_path, FINALIZER.canonical_json_bytes(semantic), 0o400)
        self._write_file(self.root / "logs/project.stdout", b"projected\n", 0o400)
        self._write_file(self.root / "logs/project.stderr", b"", 0o400)
        self._write_file(self.root / "candidate.bin", b"ELF test candidate\n", 0o500)
        os.chmod(self.root / "logs", 0o500)

        artifacts = self._artifact_records()
        index = {
            "schema": FINALIZER.CANDIDATE_SCHEMA,
            "status": "candidate_complete",
            "decision": FINALIZER.NONAUTHORIZING_DECISION,
            "stage0b_authority": False,
            "classification": "scientific_candidate",
            "candidate_outcome": "accept",
            "reason": None,
            "intended_exit_code": 0,
            "attempt": {
                "run_nonce": self.nonce,
                "cluster": self.cluster,
                "job_id": self.job_id,
                "array_job_id": None,
                "array_task_id": None,
                "step_id": "batch",
                "restart_count": 0,
                "hostname": "wmi-node01",
                "submit_dir": self.work_dir,
            },
            "revision": self.revision,
            "launch_manifest_sha256": self.launch_sha256,
            "validation_candidate_sha256": digest(
                self.semantic_path.read_bytes()
            ),
            "root_mode": "0500",
            "semantic_metadata_path": "metadata.json",
            "artifacts": artifacts,
            "missing_expected": [],
        }
        self.index_path = self.root / FINALIZER.COMPUTE_INDEX_NAME
        self._write_file(self.index_path, FINALIZER.canonical_json_bytes(index), 0o400)
        os.chmod(self.root, 0o500)

        self.compute_held_path = self.base / "compute-held.scontrol"
        self.finalizer_held_path = self.base / "finalizer-held.scontrol"
        compute_held = {
            "JobId": str(self.job_id),
            "JobName": self.job_name,
            "UserId": f"test({os.getuid()})",
            "JobState": "PENDING",
            "Reason": "JobHeldUser",
            "Dependency": "(null)",
            "Comment": self.compute_comment,
            "Command": self.compute_script_path,
            "WorkDir": self.work_dir,
            "StdOut": self.stdout_path,
            "StdErr": self.stderr_path,
            "Requeue": "0",
        }
        finalizer_held = {
            "JobId": str(self.finalizer_job_id),
            "JobName": self.finalizer_job_name,
            "UserId": f"test({os.getuid()})",
            "JobState": "PENDING",
            "Reason": "JobHeldUser",
            "Dependency": f"afterany:{self.job_id}",
            "Comment": self.finalizer_comment,
            "Command": self.finalizer_script_path,
            "WorkDir": self.work_dir,
            "StdOut": self.finalizer_stdout_path,
            "StdErr": self.finalizer_stderr_path,
            "Requeue": "0",
        }
        self._write_file(
            self.compute_held_path,
            (" ".join(f"{key}={value}" for key, value in compute_held.items()) + " \n").encode(
                "ascii"
            ),
            0o400,
        )
        self._write_file(
            self.finalizer_held_path,
            (" ".join(f"{key}={value}" for key, value in finalizer_held.items()) + " \n").encode(
                "ascii"
            ),
            0o400,
        )

        compute_argv = [
            "/usr/bin/sbatch",
            "--parsable",
            f"--clusters={self.cluster}",
            "--hold",
            "--no-requeue",
            f"--job-name={self.job_name}",
            f"--partition={self.partition}",
            "--nodes=1",
            "--ntasks=1",
            "--cpus-per-task=1",
            "--mem=8G",
            "--time=01:00:00",
            f"--chdir={self.work_dir}",
            "--open-mode=truncate",
            f"--output={self.stdout_path}",
            f"--error={self.stderr_path}",
            f"--comment={self.compute_comment}",
            "--export=TEST=compute",
            self.compute_script_path,
        ]
        finalizer_argv = [
            "/usr/bin/sbatch",
            "--parsable",
            f"--clusters={self.cluster}",
            "--hold",
            "--no-requeue",
            "--kill-on-invalid-dep=yes",
            f"--dependency=afterany:{self.job_id}",
            f"--job-name={self.finalizer_job_name}",
            f"--partition={self.partition}",
            "--nodes=1",
            "--ntasks=1",
            "--cpus-per-task=1",
            "--mem=1G",
            "--time=00:10:00",
            f"--chdir={self.work_dir}",
            "--open-mode=truncate",
            f"--output={self.finalizer_stdout_path}",
            f"--error={self.finalizer_stderr_path}",
            f"--comment={self.finalizer_comment}",
            "--export=TEST=finalizer",
            self.finalizer_script_path,
        ]

        self.submission = {
            "schema": FINALIZER.SUBMISSION_SCHEMA,
            "run_nonce": self.nonce,
            "revision": self.revision,
            "launch_manifest_sha256": self.launch_sha256,
            "candidate_root": os.fspath(self.root),
            "scheduler_candidate_path": os.fspath(self.base / "scheduler-candidate.json"),
            "final_decision_path": os.fspath(self.base / "stage0b-decision.json"),
            "control": {
                "submit_wrapper_sha256": "2" * 64,
                "compute_script_sha256": "3" * 64,
                "finalizer_script_sha256": "4" * 64,
                "finalizer_sha256": "5" * 64,
                "authorizer_sha256": "6" * 64,
                "validator_sha256": "7" * 64,
                "exec_helper_sha256": "8" * 64,
                "controller_python_sha256": "9" * 64,
                "git_sha256": "a" * 64,
                "sbatch_sha256": "b" * 64,
                "scontrol_sha256": "c" * 64,
                "scancel_sha256": "d" * 64,
                "sacct_sha256": "e" * 64,
            },
            "slurm": {
                "cluster": self.cluster,
                "owner_uid": os.getuid(),
                "compute_job_id": self.job_id,
                "finalizer_job_id": self.finalizer_job_id,
                "finalizer_dependency": f"afterany:{self.job_id}",
                "compute_job_name": self.job_name,
                "compute_comment": self.compute_comment,
                "finalizer_job_name": self.finalizer_job_name,
                "finalizer_comment": self.finalizer_comment,
                "partition": self.partition,
                "requested_nodes": 1,
                "requested_cpus": 1,
                "requested_memory_bytes": 8 * 1024**3,
                "timelimit_seconds": 3600,
                "work_dir": self.work_dir,
                "stdout_path": self.stdout_path,
                "stderr_path": self.stderr_path,
                "compute_script_path": self.compute_script_path,
                "finalizer_requested_nodes": 1,
                "finalizer_requested_cpus": 1,
                "finalizer_requested_memory_bytes": 1024**3,
                "finalizer_timelimit_seconds": 600,
                "finalizer_work_dir": self.work_dir,
                "finalizer_stdout_path": self.finalizer_stdout_path,
                "finalizer_stderr_path": self.finalizer_stderr_path,
                "finalizer_script_path": self.finalizer_script_path,
                "compute_sbatch_argv": compute_argv,
                "finalizer_sbatch_argv": finalizer_argv,
                "compute_held_record": {
                    "path": os.fspath(self.compute_held_path),
                    "sha256": digest(self.compute_held_path.read_bytes()),
                },
                "finalizer_held_record": {
                    "path": os.fspath(self.finalizer_held_path),
                    "sha256": digest(self.finalizer_held_path.read_bytes()),
                },
            },
        }
        self.submission_path = self.base / "submission.json"
        self._write_file(
            self.submission_path,
            FINALIZER.canonical_json_bytes(self.submission),
            0o400,
        )

    @staticmethod
    def _write_file(path: Path, data: bytes, mode: int) -> None:
        path.write_bytes(data)
        path.chmod(mode)

    def _artifact_records(self) -> list[dict[str, object]]:
        roles = {
            "metadata.json": "validation_candidate",
            "candidate.bin": "binary",
            "logs/project.stdout": "project_stdout",
            "logs/project.stderr": "project_stderr",
        }
        records: list[dict[str, object]] = []
        for path in sorted(self.root.rglob("*")):
            relative = path.relative_to(self.root).as_posix()
            metadata = path.lstat()
            if path.is_dir():
                continue
            data = path.read_bytes()
            records.append(
                {
                    "role": roles[relative],
                    "path_rel": relative,
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "size": len(data),
                    "sha256": digest(data),
                }
            )
        records.sort(key=lambda record: str(record["role"]))
        return records

    def scheduler_runner(
        self,
        *,
        allocation_overrides: dict[str, str] | None = None,
        batch_overrides: dict[str, str] | None = None,
        scontrol_overrides: dict[str, str] | None = None,
        allocation_outputs: list[bytes] | None = None,
    ):
        allocation = {
            "Cluster": self.cluster,
            "DBIndex": "8001",
            "JobIDRaw": str(self.job_id),
            "JobName": self.job_name,
            "User": "test",
            "UID": str(os.getuid()),
            "State": "COMPLETED",
            "ExitCode": "0:0",
            "DerivedExitCode": "0:0",
            "Submit": "2026-07-19T10:00:00",
            "Eligible": "2026-07-19T10:00:00",
            "Start": "2026-07-19T10:00:01",
            "End": "2026-07-19T10:00:11",
            "ElapsedRaw": "10",
            "Partition": self.partition,
            "NodeList": "wmi-node01",
            "NNodes": "1",
            "ReqCPUS": "1",
            "AllocCPUS": "1",
            "ReqMem": "8Gn",
            "ReqTRES": "cpu=1,mem=8G,node=1,billing=1",
            "AllocTRES": "cpu=1,mem=8G,node=1,billing=1",
            "TimelimitRaw": "60",
            "Comment": self.compute_comment,
            "SubmitLine": " ".join(
                self.submission["slurm"]["compute_sbatch_argv"]
            ),
            "WorkDir": self.work_dir,
            "StdOut": self.stdout_path,
            "StdErr": self.stderr_path,
        }
        batch = {
            "Cluster": self.cluster,
            "DBIndex": "8001",
            "JobIDRaw": f"{self.job_id}.batch",
            "JobName": "batch",
            "State": "COMPLETED",
            "ExitCode": "0:0",
            # WMI Slurm 24.05 leaves this allocation-level field empty on .batch.
            "DerivedExitCode": "",
            "Submit": "2026-07-19T10:00:01",
            "Start": "2026-07-19T10:00:01",
            "End": "2026-07-19T10:00:11",
            "ElapsedRaw": "10",
            "NodeList": "wmi-node01",
            "NNodes": "1",
            "ReqCPUS": "1",
            "AllocCPUS": "1",
            "AllocTRES": "cpu=1,mem=8G,node=1",
        }
        control = {
            "JobId": str(self.job_id),
            "JobName": self.job_name,
            "UserId": f"test({os.getuid()})",
            "JobState": "COMPLETED",
            "ExitCode": "0:0",
            "DerivedExitCode": "0:0",
            "Requeue": "0",
            "Restarts": "0",
            "Partition": self.partition,
            "NumNodes": "1",
            "NumCPUs": "1",
            "NumTasks": "1",
            "CPUs/Task": "1",
            "MinMemoryNode": "8G",
            "TimeLimit": "01:00:00",
            "WorkDir": self.work_dir,
            "StdOut": self.stdout_path,
            "StdErr": self.stderr_path,
            "Command": self.compute_script_path,
            "BatchHost": "wmi-node01",
            "Comment": self.compute_comment,
            "Dependency": "(null)",
        }
        allocation.update(allocation_overrides or {})
        batch.update(batch_overrides or {})
        control.update(scontrol_overrides or {})
        allocation_queue = list(allocation_outputs or [])
        calls: list[tuple[str, ...]] = []

        def encode_row(record: dict[str, str], fields: tuple[str, ...]) -> bytes:
            return ("|".join(record[field] for field in fields) + "\n").encode("ascii")

        def runner(argv):
            argv = tuple(argv)
            calls.append(argv)
            if argv[0].endswith("sacct") and "--allocations" in argv:
                raw = allocation_queue.pop(0) if allocation_queue else encode_row(
                    allocation, FINALIZER.ALLOCATION_FIELDS
                )
            elif argv[0].endswith("sacct"):
                raw = encode_row(batch, FINALIZER.BATCH_FIELDS)
            elif argv[0].endswith("scontrol"):
                raw = (
                    " ".join(f"{key}={value}" for key, value in control.items()) + "\n"
                ).encode("ascii")
            else:
                self.case.fail(f"unexpected command: {argv}")
            return FINALIZER.CommandOutput(argv, 0, raw, b"")

        runner.calls = calls
        return runner

    def finalize(self, runner=None, **kwargs):
        return FINALIZER.build_scheduler_candidate_payload(
            self.submission_path,
            self.root,
            command_runner=runner or self.scheduler_runner(),
            **kwargs,
        )

    def open_root_for_change(self) -> None:
        self.root.chmod(0o700)

    def reseal_root(self) -> None:
        self.root.chmod(0o500)


class T11Stage0AFinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.fixture = CandidateFixture(self, self.base)

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

    def assertRejected(self, pattern: str, runner=None) -> None:
        with self.assertRaisesRegex(FINALIZER.FinalizationError, pattern):
            self.fixture.finalize(runner=runner)

    @staticmethod
    def rewrite_index(fixture: CandidateFixture, update) -> None:
        payload = json.loads(fixture.index_path.read_text(encoding="ascii"))
        update(payload)
        fixture.index_path.chmod(0o600)
        fixture.index_path.write_bytes(FINALIZER.canonical_json_bytes(payload))
        fixture.index_path.chmod(0o400)

    def test_success_binds_candidate_scheduler_and_recursive_inventory(self) -> None:
        runner = self.fixture.scheduler_runner()
        payload = self.fixture.finalize(runner=runner)
        self.assertEqual(payload["schema"], FINALIZER.SCHEDULER_CANDIDATE_SCHEMA)
        self.assertEqual(
            payload["decision"], FINALIZER.TERMINAL_ATTESTATION_DECISION
        )
        self.assertEqual(payload["classification"], "scientific_candidate")
        self.assertFalse(payload["stage0b_authority"])
        self.assertEqual(payload["policy"], {"sat_calls": 0})
        self.assertEqual(payload["scheduler"]["allocation"]["State"], "COMPLETED")
        self.assertEqual(payload["scheduler"]["batch"]["State"], "COMPLETED")
        self.assertTrue(
            all("--duplicates" in command for command in runner.calls[:2])
        )
        self.assertEqual(
            [record["path"] for record in payload["artifacts"]],
            [
                "candidate.bin",
                FINALIZER.COMPUTE_INDEX_NAME,
                "logs",
                "logs/project.stderr",
                "logs/project.stdout",
                "metadata.json",
            ],
        )
        self.assertEqual(len(runner.calls), 3)
        self.assertIn("--allocations", runner.calls[0])
        allocation_format = next(
            item for item in runner.calls[0] if item.startswith("--format=")
        )
        self.assertNotIn("Restarts", allocation_format)
        self.assertNotIn("Requeue", allocation_format)
        self.assertEqual(runner.calls[2][-2], "-o")
        self.assertEqual(runner.calls[2][-1], str(self.fixture.job_id))
        encoded = FINALIZER.canonical_json_bytes(payload)
        self.assertEqual(FINALIZER.decode_canonical_json(encoded, "final payload"), payload)

    def test_scontrol_parser_accepts_real_slurm_key_and_nested_equals_shapes(self) -> None:
        record = FINALIZER._parse_scontrol(
            b"JobId=147317 AllocNode:Sid=access1:75571 "
            b"ReqB:S:C:T=0:0:*:* ReqTRES=cpu=1,mem=8G,node=1,billing=1 "
            b"TresPerTask=cpu=1 \n"
        )
        self.assertEqual(record["JobId"], "147317")
        self.assertEqual(record["AllocNode:Sid"], "access1:75571")
        self.assertEqual(record["ReqTRES"], "cpu=1,mem=8G,node=1,billing=1")
        self.assertEqual(record["TresPerTask"], "cpu=1")

    def test_module_contains_no_authorization_literal(self) -> None:
        source = MODULE_PATH.read_text(encoding="ascii")
        literal = "authorize_" + "stage0b"
        self.assertNotIn(literal, source)

    def test_canonical_json_rejects_duplicate_keys_and_noncanonical_encoding(self) -> None:
        with self.assertRaisesRegex(FINALIZER.FinalizationError, "duplicate JSON key"):
            FINALIZER.decode_canonical_json(b'{"a":1,"a":2}\n', "duplicate")
        with self.assertRaisesRegex(FINALIZER.FinalizationError, "not compact canonical"):
            FINALIZER.decode_canonical_json(b'{"b":2, "a":1}\n', "spaced")
        with self.assertRaisesRegex(FINALIZER.FinalizationError, "non-integral"):
            FINALIZER.decode_canonical_json(b'{"value":1.5}\n', "float")

    def test_direct_semantic_candidate_cannot_authorize(self) -> None:
        other = self.base / "direct-authority"
        other.mkdir()
        fixture = CandidateFixture(
            self,
            other,
            semantic_overrides={"decision": "authorize_" + "stage0b"},
        )
        with self.assertRaisesRegex(
            FINALIZER.FinalizationError, "forbidden authorization decision"
        ):
            fixture.finalize()

    def test_compute_index_matches_the_integration_v1_contract(self) -> None:
        index = json.loads(self.fixture.index_path.read_text(encoding="ascii"))
        self.assertEqual(index["schema"], "euf-viper.t11-stage0a-compute-index.v1")
        self.assertEqual(index["root_mode"], "0500")
        self.assertEqual(index["semantic_metadata_path"], "metadata.json")
        self.assertEqual(index["missing_expected"], [])
        self.assertEqual(
            [record["role"] for record in index["artifacts"]],
            sorted(record["role"] for record in index["artifacts"]),
        )
        semantic = json.loads(self.fixture.semantic_path.read_text(encoding="ascii"))
        self.assertEqual(
            semantic["schema"],
            "euf-viper.t11-stage0a-validation-candidate.v2",
        )

    def test_compute_index_root_semantic_and_attempt_drift_rejects(self) -> None:
        cases = (
            (
                "root mode differs",
                lambda value: value.update(root_mode="0400"),
            ),
            (
                "semantic path differs",
                lambda value: value.update(semantic_metadata_path="candidate.bin"),
            ),
            (
                "validation-candidate digest differs",
                lambda value: value.update(validation_candidate_sha256="9" * 64),
            ),
            (
                "attempt restart count is nonzero",
                lambda value: value["attempt"].update(restart_count=1),
            ),
            (
                "missing expected artifacts",
                lambda value: value.update(missing_expected=["build_stderr"]),
            ),
        )
        for position, (pattern, update) in enumerate(cases):
            with self.subTest(pattern=pattern):
                base = self.base / f"index-drift-{position}"
                base.mkdir()
                fixture = CandidateFixture(self, base)
                self.rewrite_index(fixture, update)
                with self.assertRaisesRegex(FINALIZER.FinalizationError, pattern):
                    fixture.finalize()

    def test_terminal_allocation_or_batch_failure_rejects(self) -> None:
        cases = (
            ({"State": "FAILED", "ExitCode": "2:0", "DerivedExitCode": "2:0"}, {}),
            ({}, {"State": "OUT_OF_MEMORY", "ExitCode": "0:9"}),
            ({"State": "CANCELLED"}, {}),
        )
        for allocation, batch in cases:
            with self.subTest(allocation=allocation, batch=batch):
                runner = self.fixture.scheduler_runner(
                    allocation_overrides=allocation, batch_overrides=batch
                )
                self.assertRejected("must both be COMPLETED", runner)

    def test_nonzero_exit_or_derived_exit_rejects(self) -> None:
        for field in ("ExitCode", "DerivedExitCode"):
            with self.subTest(field=field):
                self.assertRejected(
                    "allocation exit and derived-exit codes must both be 0:0",
                    self.fixture.scheduler_runner(allocation_overrides={field: "3:0"}),
                )
        self.assertRejected(
            "batch exit code must be 0:0",
            self.fixture.scheduler_runner(batch_overrides={"ExitCode": "3:0"}),
        )
        self.assertRejected(
            "batch derived-exit code must be absent or 0:0",
            self.fixture.scheduler_runner(batch_overrides={"DerivedExitCode": "3:0"}),
        )

    def test_restart_and_requeue_evidence_rejects(self) -> None:
        self.assertRejected(
            "scontrol Requeue differs",
            self.fixture.scheduler_runner(scontrol_overrides={"Requeue": "1"}),
        )
        self.assertRejected(
            "scontrol Restarts differs",
            self.fixture.scheduler_runner(scontrol_overrides={"Restarts": "1"}),
        )

    def test_duplicate_compute_accounting_rows_reject(self) -> None:
        underlying = self.fixture.scheduler_runner()

        def runner(argv):
            result = underlying(argv)
            stdout = result.stdout * 2 if "--allocations" in argv else result.stdout
            return FINALIZER.CommandOutput(tuple(argv), 0, stdout, b"")

        self.assertRejected("exactly one newline-terminated row", runner)

    def test_scheduler_identity_and_path_drift_rejects(self) -> None:
        cases = (
            ("accounting job identity", {"JobIDRaw": "99"}, {}),
            ("job name differs", {"JobName": "wrong"}, {}),
            ("WorkDir differs", {"WorkDir": "/wrong"}, {}),
            ("StdOut differs", {"StdOut": "/wrong"}, {}),
            ("StdErr differs", {"StdErr": "/wrong"}, {}),
            ("cluster differs", {"Cluster": "other"}, {}),
            ("scontrol Command differs", {}, {"Command": "/wrong"}),
            ("scontrol BatchHost differs", {}, {"BatchHost": "other-node"}),
        )
        for pattern, allocation, control in cases:
            with self.subTest(pattern=pattern):
                self.assertRejected(
                    pattern,
                    self.fixture.scheduler_runner(
                        allocation_overrides=allocation,
                        scontrol_overrides=control,
                    ),
                )

    def test_scheduler_resource_drift_rejects(self) -> None:
        cases = (
            ("CPU or node", {"NNodes": "2"}),
            ("CPU or node", {"ReqCPUS": "2"}),
            ("CPU or node", {"AllocCPUS": "2"}),
            ("memory differs", {"ReqMem": "4Gn"}),
            ("requested TRES CPU", {"ReqTRES": "cpu=2,mem=8G,node=1"}),
            ("allocated TRES memory", {"AllocTRES": "cpu=1,mem=4G,node=1"}),
            ("time limit differs", {"TimelimitRaw": "30"}),
        )
        for pattern, allocation in cases:
            with self.subTest(pattern=pattern):
                self.assertRejected(
                    pattern,
                    self.fixture.scheduler_runner(allocation_overrides=allocation),
                )
        self.assertRejected(
            "scontrol NumCPUs differs",
            self.fixture.scheduler_runner(scontrol_overrides={"NumCPUs": "2"}),
        )
        self.assertRejected(
            "scontrol memory differs",
            self.fixture.scheduler_runner(scontrol_overrides={"MinMemoryNode": "4G"}),
        )

    def test_mutated_bound_artifact_rejects(self) -> None:
        path = self.fixture.root / "logs/project.stdout"
        path.chmod(0o600)
        path.write_bytes(b"mutated\n")
        path.chmod(0o400)
        self.assertRejected("artifact closure differs")

    def test_extra_artifact_rejects(self) -> None:
        self.fixture.open_root_for_change()
        extra = self.fixture.root / "unexpected.txt"
        extra.write_text("unexpected\n", encoding="ascii")
        extra.chmod(0o400)
        self.fixture.reseal_root()
        self.assertRejected("extra=.*unexpected.txt")

    def test_unbound_empty_directory_rejects(self) -> None:
        self.fixture.open_root_for_change()
        empty = self.fixture.root / "unbound-empty"
        empty.mkdir(mode=0o500)
        self.fixture.reseal_root()
        self.assertRejected("directory closure differs.*unbound-empty")

    def test_missing_artifact_rejects(self) -> None:
        self.fixture.open_root_for_change()
        (self.fixture.root / "metadata.json").unlink()
        self.fixture.reseal_root()
        self.assertRejected("missing=.*metadata.json")

    def test_writable_file_or_directory_rejects(self) -> None:
        (self.fixture.root / "candidate.bin").chmod(0o700)
        self.assertRejected("entry is writable")
        (self.fixture.root / "candidate.bin").chmod(0o500)
        (self.fixture.root / "logs").chmod(0o700)
        self.assertRejected("entry is writable")

    def test_writable_root_rejects(self) -> None:
        self.fixture.root.chmod(0o700)
        self.assertRejected("candidate root is writable")

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "open-directory replacement semantics are Linux-specific",
    )
    def test_descriptor_inventory_rejects_replaced_root_path(self) -> None:
        descriptor = os.open(
            self.fixture.root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        displaced = self.fixture.root.with_name("descriptor-bound-root")
        try:
            self.fixture.root.rename(displaced)
            self.fixture.root.mkdir(mode=0o555)
            with self.assertRaisesRegex(
                FINALIZER.FinalizationError,
                "descriptor differs from its pathname",
            ):
                FINALIZER.inventory_run_root_descriptor(
                    self.fixture.root, descriptor
                )
        finally:
            os.close(descriptor)

    def test_symlink_artifact_rejects(self) -> None:
        self.fixture.open_root_for_change()
        os.symlink("candidate.bin", self.fixture.root / "alias")
        self.fixture.reseal_root()
        self.assertRejected("symbolic links are forbidden")

    def test_hardlink_alias_rejects_even_if_not_bound(self) -> None:
        self.fixture.open_root_for_change()
        os.link(self.fixture.root / "candidate.bin", self.fixture.root / "alias.bin")
        self.fixture.reseal_root()
        self.assertRejected("hardlink alias")

    def test_noncanonical_or_mutable_submission_rejects(self) -> None:
        self.fixture.submission_path.chmod(0o600)
        self.assertRejected("submission record is writable")
        self.fixture.submission_path.chmod(0o400)
        raw = self.fixture.submission_path.read_bytes()
        self.fixture.submission_path.chmod(0o600)
        self.fixture.submission_path.write_bytes(raw[:-1] + b" \n")
        self.fixture.submission_path.chmod(0o400)
        self.assertRejected("not compact canonical")

    def test_scheduler_accounting_can_be_polled_through_injected_runner(self) -> None:
        runner = self.fixture.scheduler_runner(allocation_outputs=[b""])
        sleeps: list[float] = []
        payload = self.fixture.finalize(
            runner=runner,
            poll_attempts=2,
            poll_interval_seconds=0.25,
            sleeper=sleeps.append,
        )
        self.assertEqual(payload["status"], "scheduler_validated_candidate")
        self.assertEqual(sleeps, [0.25])
        self.assertEqual(sum("--allocations" in call for call in runner.calls), 2)

    def test_existing_destination_is_never_replaced(self) -> None:
        destination = self.base / "final.json"
        original = b"preexisting\n"
        destination.write_bytes(original)
        destination.chmod(0o400)
        with self.assertRaisesRegex(FINALIZER.FinalizationError, "must be fresh"):
            FINALIZER.publish_scheduler_candidate(destination, {})
        self.assertEqual(destination.read_bytes(), original)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "O_TMPFILE"),
        "anonymous no-replace publication requires Linux O_TMPFILE support",
    )
    def test_linux_publication_is_exact_read_only_and_no_replace(self) -> None:
        payload = self.fixture.finalize()
        destination = self.base / "final.json"
        FINALIZER.publish_scheduler_candidate(destination, payload)
        self.assertEqual(destination.read_bytes(), FINALIZER.canonical_json_bytes(payload))
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
        with self.assertRaisesRegex(FINALIZER.FinalizationError, "must be fresh"):
            FINALIZER.publish_scheduler_candidate(destination, payload)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "O_TMPFILE"),
        "anonymous publication descriptor ordering requires Linux O_TMPFILE",
    )
    def test_linux_publication_closes_writer_before_readback(self) -> None:
        payload = self.fixture.finalize()
        destination = self.base / "descriptor-order.json"
        real_open = FINALIZER.os.open
        real_close = FINALIZER.os.close
        real_link = FINALIZER.os.link
        events: list[str] = []
        staging_descriptor = -1
        staging_closed = False

        def tracking_open(path, flags, *args, **kwargs):
            nonlocal staging_descriptor
            descriptor = real_open(path, flags, *args, **kwargs)
            if flags & os.O_TMPFILE == os.O_TMPFILE:
                staging_descriptor = descriptor
                events.append("writer-open")
            elif (
                path == destination.name
                and flags & os.O_ACCMODE == os.O_RDONLY
            ):
                self.assertTrue(staging_closed)
                events.append("reader-open")
            return descriptor

        def tracking_close(descriptor):
            nonlocal staging_closed
            if descriptor == staging_descriptor:
                staging_closed = True
                events.append("writer-close")
            return real_close(descriptor)

        def tracking_link(*args, **kwargs):
            events.append("link")
            return real_link(*args, **kwargs)

        FINALIZER.os.open = tracking_open
        FINALIZER.os.close = tracking_close
        FINALIZER.os.link = tracking_link
        try:
            FINALIZER.publish_scheduler_candidate(destination, payload)
        finally:
            FINALIZER.os.open = real_open
            FINALIZER.os.close = real_close
            FINALIZER.os.link = real_link
        self.assertEqual(
            events,
            ["writer-open", "link", "writer-close", "reader-open"],
        )

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "O_TMPFILE"),
        "anonymous no-replace publication requires Linux O_TMPFILE support",
    )
    def test_linux_publication_loses_a_no_replace_race_fail_closed(self) -> None:
        payload = self.fixture.finalize()
        destination = self.base / "raced-final.json"
        competitor = b"competitor\n"
        real_link = FINALIZER.os.link

        def racing_link(source, target, *args, **kwargs):
            directory_fd = kwargs["dst_dir_fd"]
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                self.assertEqual(os.write(descriptor, competitor), len(competitor))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return real_link(source, target, *args, **kwargs)

        FINALIZER.os.link = racing_link
        try:
            with self.assertRaisesRegex(
                FINALIZER.FinalizationError,
                "ceased to be fresh",
            ):
                FINALIZER.publish_scheduler_candidate(destination, payload)
        finally:
            FINALIZER.os.link = real_link
        self.assertEqual(destination.read_bytes(), competitor)


if __name__ == "__main__":
    unittest.main()
