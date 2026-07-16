from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cert" / "shadow_campaign.py"
SPEC = importlib.util.spec_from_file_location("shadow_campaign", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SHADOW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHADOW)


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_executable(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


FAKE_VIPER = textwrap.dedent(
    f"""\
    #!{sys.executable}
    import hashlib
    import json
    import os
    import signal
    import subprocess
    import sys
    import time
    from pathlib import Path

    if len(sys.argv) < 5 or sys.argv[1] != "certify" or sys.argv[3] != "--out-prefix":
        print("invalid fake certifier invocation", file=sys.stderr)
        raise SystemExit(64)

    source = Path(sys.argv[2])
    prefix = Path(sys.argv[4]).resolve()
    payload = json.loads(source.read_text(encoding="utf-8"))
    call_log = Path(os.environ["CALL_LOG"])
    with call_log.open("a", encoding="utf-8") as handle:
        handle.write(payload["_fixture_source_name"] + "\\n")
        handle.flush()
        os.fsync(handle.fileno())

    mode = payload.get("mode", "ok")
    if mode == "timeout":
        marker = payload["descendant_marker"]
        child = (
            "import signal,sys,time\\n"
            "from pathlib import Path\\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\\n"
            "time.sleep(0.6)\\n"
            "Path(sys.argv[1]).write_text('escaped', encoding='utf-8')\\n"
        )
        subprocess.Popen([sys.executable, "-c", child, marker])
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(10)
        raise SystemExit(0)
    if mode == "interrupt_once":
        marker = Path(payload["interrupt_marker"])
        if not marker.exists():
            marker.write_text("interrupted", encoding="utf-8")
            os.kill(os.getppid(), signal.SIGINT)
            time.sleep(10)

    result = payload.get("cert_result", payload["expected"])
    if result in {{"unknown", "unsupported"}}:
        print(result)
        raise SystemExit(0)

    prefix.parent.mkdir(parents=True, exist_ok=True)
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest = {{
        "format": "euf-viper-euf-cnf-v2",
        "encoding": "canonical-tseitin-v1",
        "result": result,
        "source": str(source),
        "source_sha256": source_hash,
    }}
    if result == "unsat":
        dimacs = Path(str(prefix) + ".cnf")
        proof = Path(str(prefix) + ".drat")
        dimacs.write_bytes(b"p cnf 0 0\\n")
        proof.write_bytes(b"fake proof\\n")
        manifest.update({{
            "dimacs": str(dimacs),
            "dimacs_sha256": hashlib.sha256(dimacs.read_bytes()).hexdigest(),
            "proof": str(proof),
            "proof_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
        }})
    Path(str(prefix) + ".euf.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\\n", encoding="utf-8"
    )
    print(result)
    """
)


FAKE_CHECKER = textwrap.dedent(
    f"""\
    #!{sys.executable}
    import json
    import os
    import sys
    from pathlib import Path

    manifest_path = Path(sys.argv[1])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = Path(sys.argv[sys.argv.index("--source") + 1])
    payload = json.loads(source.read_text(encoding="utf-8"))
    checker_log = Path(payload["checker_log"])
    with checker_log.open("a", encoding="utf-8") as handle:
        handle.write(source.name + "\\n")
        handle.flush()
        os.fsync(handle.fileno())

    if payload.get("checker_mode") == "fail":
        print("synthetic checker rejection", file=sys.stderr)
        raise SystemExit(7)
    if payload.get("checker_mode") == "abstain":
        print(json.dumps({{"status": "abstained", "result": manifest["result"]}}))
        raise SystemExit(0)
    if manifest["result"] == "unsat":
        if "--drat-trim" not in sys.argv:
            print("missing drat-trim", file=sys.stderr)
            raise SystemExit(8)
        drat = Path(sys.argv[sys.argv.index("--drat-trim") + 1])
        if not drat.is_file() or not os.access(drat, os.X_OK):
            print("invalid drat-trim", file=sys.stderr)
            raise SystemExit(9)
    print(json.dumps({{
        "status": "verified",
        "result": manifest["result"],
        "source_sha256": manifest["source_sha256"],
    }}, sort_keys=True))
    """
)


class CampaignFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.corpus = root / "corpus"
        self.output = root / "shadow"
        self.tools = root / "tools"
        self.call_log = root / "certifier-calls.log"
        self.checker_log = root / "checker-calls.log"
        self.lock_path = root / "campaign.lock.json"
        self.raw_path = root / "raw.jsonl"
        self.viper = self.tools / "euf-viper"
        self.z3 = self.tools / "z3"
        self.checker = self.tools / "check-certificate"
        self.drat = self.tools / "drat-trim"
        self.instances: list[dict[str, Any]] = []
        self.candidate_results: dict[str, str] = {}
        self.corpus.mkdir(parents=True)
        write_executable(self.viper, FAKE_VIPER)
        write_executable(
            self.z3,
            f"#!{sys.executable}\nimport sys\nprint('sat')\n",
        )
        write_executable(self.checker, FAKE_CHECKER)
        write_executable(self.drat, "#!/bin/sh\nexit 0\n")

    def add_instance(
        self,
        relative_path: str,
        *,
        expected: str = "sat",
        campaign_result: str | None = None,
        **payload: Any,
    ) -> Path:
        source = self.corpus / relative_path
        source.parent.mkdir(parents=True, exist_ok=True)
        content = {
            "_fixture_source_name": source.name,
            "expected": expected,
            "checker_log": str(self.checker_log),
            **payload,
        }
        source.write_text(json.dumps(content, sort_keys=True) + "\n", encoding="utf-8")
        self.instances.append(
            {
                "id": f"instance-{len(self.instances)}",
                "relative_path": relative_path,
                "path": str(source.resolve()),
                "sha256": sha256_file(source),
                "bytes": source.stat().st_size,
                "status": expected,
                "family": relative_path.split("/", 1)[0],
                "lineage": "synthetic/test",
                "normalized_sha256": sha256_bytes(
                    ("normalized:" + relative_path).encode("utf-8")
                ),
                "split": "development",
            }
        )
        self.candidate_results[relative_path] = campaign_result or expected
        return source

    def finalize(self) -> tuple[Path, Path]:
        self.instances.sort(key=lambda item: item["relative_path"])
        execution_environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
        solvers = [
            {
                "id": "euf-viper",
                "comparator_id": "euf-viper",
                "configuration": "cert-test",
                "version": "fake-1",
                "binary": str(self.viper.resolve()),
                "sha256": sha256_file(self.viper),
                "argv_template": ["{binary}", "{instance}", "{budget_s}"],
                "version_output": None,
                "version_output_sha256": None,
                "environment": {"CALL_LOG": str(self.call_log)},
            },
            {
                "id": "z3",
                "comparator_id": "z3",
                "configuration": "default",
                "version": "fake-1",
                "binary": str(self.z3.resolve()),
                "sha256": sha256_file(self.z3),
                "argv_template": ["{binary}", "{instance}", "{budget_s}"],
                "version_output": None,
                "version_output_sha256": None,
                "environment": {},
            },
        ]
        lock: dict[str, Any] = {
            "schema_version": 1,
            "campaign_id": "shadow-test",
            "lock_sha256": "",
            "created_from_commit_time": "2026-07-12T00:00:00+00:00",
            "promotion_eligible": True,
            "spec": {"path": str(self.root / "spec.json"), "sha256": "1" * 64},
            "repository": {},
            "host": {},
            "corpus": {
                "id": "shadow-corpus",
                "manifest_path": str(self.root / "manifest.jsonl"),
                "manifest_sha256": "2" * 64,
                "taxonomy_path": str(self.root / "taxonomy.jsonl"),
                "taxonomy_sha256": "3" * 64,
                "root": str(self.corpus.resolve()),
                "instances": self.instances,
            },
            "solver_config": {
                "path": str(self.root / "solvers.json"),
                "sha256": "4" * 64,
            },
            "solver_release_lock": {
                "path": str(self.root / "releases.json"),
                "sha256": "5" * 64,
            },
            "solvers": solvers,
            "budgets_s": [1],
            "execution": {
                "resource_model": "single_core_cold_process",
                "cpu_ids": [0],
                "memory_bytes": 1024**3,
                "order": "abba",
                "environment": execution_environment,
                "timeout_grace_s": 0.05,
            },
            "output": {
                "directory": str(self.root / "locked-output"),
                "journal": "journal.jsonl",
                "raw": "raw.jsonl",
                "summary": "summary.json",
            },
        }
        lock["lock_sha256"] = sha256_bytes(canonical_bytes(lock))
        self.lock_path.write_bytes(canonical_bytes(lock))

        records: list[dict[str, Any]] = []
        previous = "0" * 64
        sequence = 0
        for instance_index, instance in enumerate(self.instances):
            solver_order = [0, 1, 1, 0] if instance_index % 2 == 0 else [1, 0, 0, 1]
            repetitions = {0: 0, 1: 0}
            for solver_index in solver_order:
                solver = solvers[solver_index]
                repetition = repetitions[solver_index]
                repetitions[solver_index] += 1
                result = (
                    self.candidate_results[instance["relative_path"]]
                    if solver["id"] == "euf-viper"
                    else instance["status"]
                )
                environment = dict(execution_environment)
                environment.update(solver["environment"])
                key = {
                    "instance_id": instance["id"],
                    "solver_id": solver["id"],
                    "budget_s": 1,
                    "repetition": repetition,
                }
                record: dict[str, Any] = {
                    "record_type": "run",
                    "schema_version": 1,
                    "lock_sha256": lock["lock_sha256"],
                    "invocation": 0,
                    "sequence": sequence,
                    "key": key,
                    "instance_id": instance["id"],
                    "relative_path": instance["relative_path"],
                    "instance_sha256": instance["sha256"],
                    "expected_status": instance["status"],
                    "family": instance["family"],
                    "solver_id": solver["id"],
                    "solver_sha256": solver["sha256"],
                    "solver_version": solver["version"],
                    "budget_s": 1,
                    "repetition": repetition,
                    "cpu_id": 0,
                    "argv": [solver["binary"], instance["path"], "1"],
                    "descriptor_binding": {
                        "mechanism": "platform_pathname",
                        "solver_sha256": solver["sha256"],
                        "source_sha256": instance["sha256"],
                    },
                    "environment_sha256": sha256_bytes(canonical_bytes(environment)),
                    "pid": 1000 + sequence,
                    "started_at": "2026-07-12T00:00:00+00:00",
                    "finished_at": "2026-07-12T00:00:01+00:00",
                    "wall_time_s": 0.1,
                    "child_user_time_s": 0.05,
                    "child_system_time_s": 0.01,
                    "child_cpu_time_s": 0.06,
                    "max_rss_bytes": 1024,
                    "exit_code": 0,
                    "termination_cause": "exit",
                    "termination_signal": None,
                    "timed_out": False,
                    "spawn_error": None,
                    "stdout_sha256": sha256_bytes((result + "\n").encode("ascii")),
                    "stdout_bytes": len(result) + 1,
                    "stderr_sha256": sha256_bytes(b""),
                    "stderr_bytes": 0,
                    "result_token": result,
                    "result_token_status": "valid",
                    "previous_record_sha256": previous,
                    "record_sha256": "",
                }
                unhashed = dict(record)
                unhashed.pop("record_sha256")
                record["record_sha256"] = sha256_bytes(canonical_bytes(unhashed))
                previous = record["record_sha256"]
                records.append(record)
                sequence += 1
        self.raw_path.write_bytes(
            b"".join(canonical_bytes(record) for record in records)
        )
        return self.lock_path, self.raw_path

    def run(
        self,
        *,
        timeout: float = 1.0,
        checker_timeout: float | None = None,
        include_drat: bool = False,
        extra: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(SCRIPT),
            str(self.lock_path),
            str(self.raw_path),
            "--output-dir",
            str(self.output),
            "--binary",
            str(self.viper),
            "--checker",
            str(self.checker),
            "--timeout",
            str(timeout),
            "--timeout-grace",
            "0.05",
        ]
        if checker_timeout is not None:
            command.extend(["--checker-timeout", str(checker_timeout)])
        if include_drat:
            command.extend(["--drat-trim", str(self.drat)])
        if extra:
            command.extend(extra)
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def summary(self, shard_index: int = 0, shard_count: int = 1) -> dict[str, Any]:
        path = (
            self.output
            / f"shard-{shard_index:04d}-of-{shard_count:04d}.summary.json"
        )
        return json.loads(path.read_text(encoding="utf-8"))

    def journal_path(self, shard_index: int = 0, shard_count: int = 1) -> Path:
        return (
            self.output
            / f"shard-{shard_index:04d}-of-{shard_count:04d}.journal.jsonl"
        )


class SelectionAndPartitionTests(unittest.TestCase):
    def test_selects_decisive_correct_euf_viper_instances(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("alpha/a.smt2", expected="sat")
            fixture.add_instance("beta/b.smt2", expected="unsat")
            fixture.add_instance(
                "gamma/c.smt2", expected="sat", campaign_result="unknown"
            )
            lock_path, raw_path = fixture.finalize()

            campaign = SHADOW.load_validated_campaign(lock_path, raw_path)
            works = SHADOW.derive_work_records(campaign, lock_path)

            self.assertEqual(
                [work["relative_path"] for work in works],
                ["alpha/a.smt2", "beta/b.smt2"],
            )
            self.assertEqual([work["global_index"] for work in works], [0, 1])
            self.assertEqual(
                [work["expected_result"] for work in works], ["sat", "unsat"]
            )
            self.assertTrue(
                all(SHADOW._is_sha256(work["work_sha256"]) for work in works)
            )

    def test_wrong_decisive_candidate_result_rejects_the_workset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("family/wrong.smt2", expected="sat")
            lock_path, raw_path = fixture.finalize()

            campaign = SHADOW.load_validated_campaign(lock_path, raw_path)
            candidate_key = next(
                key for key in campaign["observations"] if key[2] == "euf-viper"
            )
            campaign["observations"][candidate_key]["result"] = "unsat"
            with self.assertRaisesRegex(
                SHADOW.ShadowError,
                "wrong decisive euf-viper observation.*claimed 'unsat'.*expected 'sat'",
            ):
                SHADOW.derive_work_records(campaign, lock_path)

    def test_independent_parser_canary_validates_and_hashes_the_complete_workset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = {
                "rodin/annotated.smt2": """
                    (set-logic QF_UF)
                    (declare-sort U 0)
                    (declare-const a U)
                    (declare-const b U)
                    (assert (! (= a b) :named rodin_goal))
                    (check-sat)
                """,
                "goel/multiline.smt2": """
                    (set-info :source |first line
                    second line|)
                    (set-logic QF_UF)
                    (assert true)
                    (check-sat)
                """,
            }
            works = []
            for relative_path, source_text in sources.items():
                source = root / relative_path
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(source_text, encoding="utf-8")
                works.append(
                    {
                        "relative_path": relative_path,
                        "source_path": str(source),
                        "source_sha256": sha256_file(source),
                    }
                )

            forward = SHADOW.validate_independent_parser_workset(works)
            reverse = SHADOW.validate_independent_parser_workset(
                list(reversed(works))
            )

        self.assertEqual(forward["status"], "validated")
        self.assertEqual(forward["selected_instances"], 2)
        self.assertEqual(forward["workset_sha256"], reverse["workset_sha256"])
        self.assertEqual(
            forward["parser"]["sha256"], sha256_file(SHADOW.INDEPENDENT_PARSER_PATH)
        )
        self.assertGreater(forward["totals"]["terms"], 0)
        self.assertGreater(forward["totals"]["base_clauses"], 0)

    def test_independent_parser_canary_rejects_before_certificate_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "malformed.smt2"
            source.write_text(
                "(set-logic QF_UF)\n(assert (! true))\n(check-sat)\n",
                encoding="utf-8",
            )
            work = {
                "relative_path": "family/malformed.smt2",
                "source_path": str(source),
                "source_sha256": sha256_file(source),
            }
            with self.assertRaisesRegex(
                SHADOW.ShadowError,
                "independent parser canary rejected 'family/malformed.smt2'",
            ):
                SHADOW.validate_independent_parser_workset([work])

    def test_modulo_partition_is_deterministic_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            for index in range(5):
                fixture.add_instance(f"family/case-{index}.smt2")
            lock_path, raw_path = fixture.finalize()
            campaign = SHADOW.load_validated_campaign(lock_path, raw_path)
            works = SHADOW.derive_work_records(campaign, lock_path)

            left = SHADOW.partition_work_records(works, 0, 2)
            right = SHADOW.partition_work_records(works, 1, 2)

            self.assertEqual([work["global_index"] for work in left], [0, 2, 4])
            self.assertEqual([work["global_index"] for work in right], [1, 3])
            self.assertEqual(
                {work["work_sha256"] for work in left + right},
                {work["work_sha256"] for work in works},
            )

    def test_no_decisive_candidate_rows_produce_explicit_empty_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance(
                "family/unknown.smt2", expected="sat", campaign_result="unknown"
            )
            lock_path, raw_path = fixture.finalize()

            campaign = SHADOW.load_validated_campaign(lock_path, raw_path)
            self.assertEqual(SHADOW.derive_work_records(campaign, lock_path), [])

            completed = fixture.run()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = fixture.summary()
            self.assertEqual(summary["status"], "complete")
            self.assertEqual(summary["selection"]["selected_instances"], 0)
            self.assertEqual(summary["counts"]["verified_instances"], 0)
            self.assertEqual(summary["verified"], [])


class DescriptorExecutionContractTests(unittest.TestCase):
    def test_procfd_manifest_source_requires_its_exact_execution_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix = root / "certificate"
            manifest_path = Path(f"{prefix}.euf.json")
            source = root / "input.smt2"
            source.write_text("fixture\n", encoding="ascii")
            source_path = str(source.resolve())
            source_sha256 = "1" * 64
            work = {
                "expected_result": "sat",
                "source_path": source_path,
                "source_sha256": source_sha256,
            }
            manifest = {
                "encoding": "canonical-tseitin-v1",
                "format": "euf-viper-euf-cnf-v2",
                "result": "sat",
                "source": "/proc/self/fd/17",
                "source_sha256": source_sha256,
            }

            def write_manifest_source(value: str) -> None:
                manifest["source"] = value
                manifest_path.write_bytes(canonical_bytes(manifest))

            source_record = {
                "execution_path": "/proc/self/fd/17",
                "path": source_path,
                "sha256": source_sha256,
            }
            descriptor_binding = {
                "files": [
                    {
                        "execution_path": "/proc/self/fd/16",
                        "path": "/tools/solver",
                        "sha256": "2" * 64,
                    },
                    source_record,
                ],
                "mechanism": "linux_procfd",
            }

            write_manifest_source(source_record["execution_path"])
            SHADOW.validate_manifest_binding(
                manifest_path, prefix, work, descriptor_binding
            )

            for invalid_source in (
                "/proc/self/fd/16",
                "/proc/self/fd/99999",
            ):
                with self.subTest(invalid_source=invalid_source):
                    write_manifest_source(invalid_source)
                    with self.assertRaisesRegex(
                        SHADOW.ShadowError,
                        "does not match its sealed source descriptor execution path",
                    ):
                        SHADOW.validate_manifest_binding(
                            manifest_path, prefix, work, descriptor_binding
                        )

            write_manifest_source("/proc/self/fd/1")
            with self.assertRaisesRegex(
                SHADOW.ShadowError, "not the sealed Linux descriptor path"
            ):
                SHADOW.validate_manifest_binding(
                    manifest_path, prefix, work, descriptor_binding
                )

            write_manifest_source(source_record["execution_path"])
            source_record["sha256"] = "3" * 64
            with self.assertRaisesRegex(
                SHADOW.ShadowError, "lacks its sealed descriptor binding"
            ):
                SHADOW.validate_manifest_binding(
                    manifest_path, prefix, work, descriptor_binding
                )
            source_record["sha256"] = source_sha256

            execution_path = source_record.pop("execution_path")
            with self.assertRaisesRegex(SHADOW.ShadowError, "incorrect fields"):
                SHADOW.validate_manifest_binding(
                    manifest_path, prefix, work, descriptor_binding
                )
            source_record["execution_path"] = execution_path

            platform_binding = {"files": [], "mechanism": "platform_pathname"}
            write_manifest_source(source_path)
            SHADOW.validate_manifest_binding(
                manifest_path, prefix, work, platform_binding
            )
            write_manifest_source(source_record["execution_path"])
            with self.assertRaisesRegex(SHADOW.ShadowError, "source path mismatch"):
                SHADOW.validate_manifest_binding(
                    manifest_path, prefix, work, platform_binding
                )

    def test_unsat_checker_command_binds_generated_proof_artifacts(self) -> None:
        prefix = Path("/attempt/certificate")
        command = SHADOW._checker_command(
            {
                "python": {"path": "/tools/python"},
                "checker": {"path": "/tools/checker.py"},
                "independent_parser": {"path": "/tools/independent.py"},
                "drat_trim": {"path": "/tools/drat-trim"},
            },
            {"expected_result": "unsat", "source_path": "/corpus/input.smt2"},
            Path("/attempt/certificate.euf.json"),
            prefix,
        )
        self.assertEqual(command[command.index("--dimacs") + 1], f"{prefix}.cnf")
        self.assertEqual(command[command.index("--proof") + 1], f"{prefix}.drat")
        self.assertIn("SourceFileLoader", SHADOW.CHECKER_BOOTSTRAP)

    @unittest.skipIf(
        sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir(),
        "non-Linux fail-closed test",
    )
    def test_checker_execution_fails_closed_without_procfd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                SHADOW.ShadowError, "requires Linux /proc/self/fd"
            ):
                SHADOW.run_cold_process(
                    [str(root / "checker")],
                    environment={},
                    timeout_s=1.0,
                    grace_s=0.1,
                    stdout_path=root / "stdout",
                    stderr_path=root / "stderr",
                    output_directory=root,
                    descriptor_hashes={str(root / "checker"): "1" * 64},
                )
            self.assertFalse((root / "stdout").exists())
            self.assertFalse((root / "stderr").exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir(),
        "Linux sealed-descriptor acquisition test",
    )
    def test_shadow_never_executes_a_second_read_from_the_mutable_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "checker"
            executable.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$0\"\n", encoding="ascii"
            )
            executable.chmod(0o755)
            expected = sha256_file(executable)
            real_lseek = os.lseek
            mutation_probe_reached = False

            def mutate_if_source_is_rewound(
                descriptor: int, offset: int, whence: int
            ) -> int:
                nonlocal mutation_probe_reached
                try:
                    target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                except OSError:
                    target = Path()
                if target == executable and offset == 0 and whence == os.SEEK_SET:
                    mutation_probe_reached = True
                    executable.write_text(
                        "#!/bin/sh\nprintf 'attacker\\n'\n", encoding="ascii"
                    )
                return real_lseek(descriptor, offset, whence)

            with mock.patch.object(os, "lseek", side_effect=mutate_if_source_is_rewound):
                process = SHADOW.run_cold_process(
                    [str(executable)],
                    environment={"PATH": "/usr/bin:/bin"},
                    timeout_s=1.0,
                    grace_s=0.1,
                    stdout_path=root / "stdout",
                    stderr_path=root / "stderr",
                    output_directory=root,
                    descriptor_hashes={str(executable): expected},
                )
            self.assertFalse(mutation_probe_reached)
            self.assertEqual(process["exit_code"], 0)
            binding = process["descriptor_binding"]
            self.assertEqual(binding["mechanism"], "linux_procfd")
            self.assertEqual(len(binding["files"]), 1)
            record = binding["files"][0]
            self.assertEqual(record["path"], str(executable))
            self.assertEqual(record["sha256"], expected)
            self.assertRegex(record["execution_path"], SHADOW.LINUX_PROC_FD)
            self.assertEqual(
                (root / "stdout").read_text(encoding="ascii"),
                record["execution_path"] + "\n",
            )


@unittest.skipUnless(
    sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir(),
    "certificate solver and checker execution requires Linux /proc/self/fd",
)
class ExecutionTests(unittest.TestCase):
    def test_parent_raw_tampering_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("family/case.smt2")
            fixture.finalize()
            records = [
                json.loads(line) for line in fixture.raw_path.read_text().splitlines()
            ]
            records[0]["wall_time_s"] = 99.0
            fixture.raw_path.write_bytes(
                b"".join(canonical_bytes(record) for record in records)
            )

            completed = fixture.run()

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("locked campaign validation failed", completed.stderr)
            self.assertIn("record SHA-256 mismatch", completed.stderr)
            self.assertFalse(fixture.call_log.exists())

    def test_journal_tampering_is_rejected_without_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("family/case.smt2")
            fixture.finalize()
            first = fixture.run()
            self.assertEqual(first.returncode, 0, first.stderr)
            calls_before = fixture.call_log.read_text(encoding="utf-8")

            journal_path = fixture.journal_path()
            records = [
                json.loads(line) for line in journal_path.read_text().splitlines()
            ]
            records[-1]["verified"] = False
            journal_path.write_bytes(
                b"".join(canonical_bytes(record) for record in records)
            )

            resumed = fixture.run()

            self.assertEqual(resumed.returncode, 2, resumed.stderr)
            self.assertIn("record hash drift", resumed.stderr)
            self.assertEqual(fixture.call_log.read_text(encoding="utf-8"), calls_before)

    def test_hash_framed_journal_rejects_an_incomplete_tail_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("family/case.smt2")
            fixture.finalize()
            first = fixture.run()
            self.assertEqual(first.returncode, 0, first.stderr)
            journal_path = fixture.journal_path()
            calls_before = fixture.call_log.read_text(encoding="utf-8")
            with journal_path.open("ab") as handle:
                handle.write(b'{"record_type":"attempt","record_sha256":"partial')
                handle.flush()
                os.fsync(handle.fileno())
            incomplete = journal_path.read_bytes()

            resumed = fixture.run()

            self.assertEqual(resumed.returncode, 2, resumed.stderr)
            self.assertIn("incomplete frame", resumed.stderr)
            self.assertEqual(journal_path.read_bytes(), incomplete)
            self.assertEqual(fixture.call_log.read_text(encoding="utf-8"), calls_before)

    def test_final_sidecar_mutation_cannot_publish_a_complete_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sidecar = root / "production-evidence" / "case.json"
            sidecar.parent.mkdir()
            sidecar.write_bytes(b"bound-sidecar\n")
            sidecar_hash = sha256_file(sidecar)
            work = {
                "global_index": 0,
                "relative_path": "family/case.smt2",
                "expected_result": "sat",
                "work_sha256": "1" * 64,
                "production_evidence": [
                    {
                        "artifact_path": str(sidecar),
                        "binding": {
                            "sha256": sidecar_hash,
                            "bytes": sidecar.stat().st_size,
                        },
                        "validation": {
                            "evidence_sha256": sidecar_hash,
                            "evidence_bytes": sidecar.stat().st_size,
                        },
                    }
                ],
            }
            journal_path = root / "journal.jsonl"
            journal_path.write_bytes(b"{}\n")
            journal = SimpleNamespace(
                path=journal_path,
                last_hash="2" * 64,
                sha256=lambda: sha256_file(journal_path),
                attempts=[
                    {
                        "work_sha256": work["work_sha256"],
                        "verified": True,
                        "attempt": 1,
                        "artifacts": {},
                        "failure_kind": None,
                    }
                ],
            )
            plan = {
                "campaign_id": "final-rehash-test",
                "parent_lock_sha256": "3" * 64,
                "parent_lock_file_sha256": "4" * 64,
                "parent_raw_sha256": "5" * 64,
                "record_sha256": "6" * 64,
                "solver": {},
                "checker": {},
                "drat_trim": None,
                "selection": {},
            }
            summary_path = root / "summary.json"
            summary_path.write_bytes(canonical_bytes({"status": "in_progress"}))

            def mutate_then_rehash() -> None:
                sidecar.write_bytes(b"mutated-after-summary-render\n")
                SHADOW.rehash_production_evidence([work])

            with self.assertRaisesRegex(
                SHADOW.ShadowError, "no longer matches its campaign journal binding"
            ):
                SHADOW._write_summary(
                    summary_path,
                    journal,
                    plan,
                    [work],
                    pre_publish=mutate_then_rehash,
                )

            self.assertEqual(
                json.loads(summary_path.read_text(encoding="utf-8"))["status"],
                "in_progress",
            )

    def test_timeout_kills_descendant_process_group_and_is_not_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "escaped"
            fixture = CampaignFixture(root)
            fixture.add_instance(
                "family/timeout.smt2",
                mode="timeout",
                descendant_marker=str(marker),
            )
            fixture.finalize()

            completed = fixture.run(timeout=0.1)

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("certify_timeout", completed.stderr)
            summary = fixture.summary()
            self.assertEqual(summary["status"], "failed")
            self.assertEqual(summary["counts"]["verified_instances"], 0)
            self.assertEqual(summary["failure_counts"], {"certify_timeout": 1})
            time.sleep(0.75)
            self.assertFalse(
                marker.exists(), "timed-out descendant survived group cleanup"
            )

    def test_resume_skips_verified_work_and_retries_interrupted_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interrupted = root / "interrupted-once"
            fixture = CampaignFixture(root)
            fixture.add_instance("family/a.smt2")
            fixture.add_instance(
                "family/b.smt2",
                mode="interrupt_once",
                interrupt_marker=str(interrupted),
            )
            fixture.finalize()

            first = fixture.run()
            self.assertEqual(first.returncode, 130, first.stderr)
            self.assertEqual(
                fixture.call_log.read_text(encoding="utf-8").splitlines(),
                ["a.smt2", "b.smt2"],
            )

            resumed = fixture.run()

            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertEqual(
                fixture.call_log.read_text(encoding="utf-8").splitlines(),
                ["a.smt2", "b.smt2", "b.smt2"],
            )
            summary = fixture.summary()
            self.assertEqual(summary["status"], "complete")
            self.assertEqual(summary["counts"]["verified_instances"], 2)
            self.assertEqual(summary["counts"]["attempts"], 3)
            self.assertEqual(summary["historical_failure_counts"], {"interrupted": 1})

    def test_result_mismatch_fails_before_checker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance(
                "family/mismatch.smt2", expected="sat", cert_result="unsat"
            )
            fixture.finalize()

            completed = fixture.run()

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("result_mismatch", completed.stderr)
            self.assertFalse(fixture.checker_log.exists())
            summary = fixture.summary()
            self.assertEqual(summary["counts"]["verified_instances"], 0)
            self.assertEqual(summary["failure_counts"], {"result_mismatch": 1})

    def test_checker_failure_and_abstention_are_never_verified(self) -> None:
        for payload, expected_kind in (
            ({"checker_mode": "fail"}, "checker_exit"),
            ({"cert_result": "unknown"}, "certify_abstention"),
        ):
            with self.subTest(
                expected_kind=expected_kind
            ), tempfile.TemporaryDirectory() as temporary:
                fixture = CampaignFixture(Path(temporary))
                fixture.add_instance("family/case.smt2", **payload)
                fixture.finalize()

                completed = fixture.run()

                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertIn(expected_kind, completed.stderr)
                summary = fixture.summary()
                self.assertEqual(summary["counts"]["verified_instances"], 0)
                self.assertEqual(summary["failure_counts"], {expected_kind: 1})

    def test_unsat_requires_drat_and_checker_receives_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("family/unsat.smt2", expected="unsat")
            fixture.finalize()

            missing = fixture.run()
            self.assertEqual(missing.returncode, 2, missing.stderr)
            self.assertIn("drat-trim is required", missing.stderr)
            self.assertFalse(fixture.call_log.exists())

            completed = fixture.run(include_drat=True)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = fixture.summary()
            self.assertEqual(summary["verified_results"], {"unsat": 1})
            self.assertTrue(summary["drat_trim"]["sha256"])


if __name__ == "__main__":
    unittest.main()
