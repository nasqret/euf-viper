from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "bench" / "run_locked_campaign.py"


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_executable(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Locked Campaign Test",
            "GIT_AUTHOR_EMAIL": "locked-campaign@example.invalid",
            "GIT_COMMITTER_NAME": "Locked Campaign Test",
            "GIT_COMMITTER_EMAIL": "locked-campaign@example.invalid",
        },
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return completed.stdout.strip()


GENERIC_SOLVER = textwrap.dedent(
    f"""\
    #!{sys.executable}
    import os
    import sys
    from pathlib import Path

    log = Path(os.environ["CALL_LOG"])
    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            os.environ["SOLVER_ID"]
            + ":"
            + Path(sys.argv[1]).name
            + ":"
            + sys.argv[2]
            + "\\n"
        )
        handle.flush()
        os.fsync(handle.fileno())
    sys.stderr.write(os.environ.get("STDERR_TEXT", ""))
    sys.stdout.write(os.environ.get("STDOUT_TEXT", "sat\\n"))
    """
)


class CampaignFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repository = root / "repository"
        self.artifacts = root / "artifacts"
        self.corpus_root = self.artifacts / "corpus"
        self.output = root / "output"
        self.lock_path = root / "campaign.lock.json"
        self.spec = self.repository / "campaign.json"
        self.release_lock = self.repository / "solver-releases.json"
        self.manifest = self.artifacts / "manifest.jsonl"
        self.solver_config = self.artifacts / "solvers.json"
        self.repository.mkdir(parents=True)
        self.corpus_root.mkdir(parents=True)
        self.spec.write_text('{"campaign_id":"test-campaign"}\n', encoding="utf-8")
        self.release_lock.write_text(
            '{"schema_version":1,"solvers":[]}\n', encoding="utf-8"
        )
        self.instances: list[dict[str, Any]] = []
        self.solvers: list[dict[str, Any]] = []
        self.payload: dict[str, Any] | None = None

    def add_instance(
        self, relative_path: str, *, status: str = "sat", content: bytes = b"test\n"
    ) -> Path:
        path = self.corpus_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        self.instances.append(
            {
                "id": str(len(self.instances)),
                "relative_path": relative_path,
                "path": str(path.resolve()),
                "sha256": sha256_file(path),
                "bytes": len(content),
                "status": status,
            }
        )
        return path

    def add_solver(
        self,
        identifier: str,
        source: str = GENERIC_SOLVER,
        *,
        environment: dict[str, str] | None = None,
        argv_template: list[str] | None = None,
    ) -> Path:
        path = self.artifacts / "solvers" / identifier
        write_executable(path, source)
        settings = {
            "CALL_LOG": str(self.root / "calls.log"),
            "SOLVER_ID": identifier,
        }
        if environment:
            settings.update(environment)
        self.solvers.append(
            {
                "id": identifier,
                "comparator_id": identifier,
                "configuration": "default",
                "version": "test-1",
                "binary": str(path.resolve()),
                "sha256": sha256_file(path),
                "argv_template": argv_template
                or ["{binary}", "{instance}", "{budget_s}"],
                "version_output": None,
                "version_output_sha256": None,
                "environment": dict(sorted(settings.items())),
            }
        )
        return path

    def finalize(
        self,
        *,
        budgets: list[int | float] | None = None,
        order: str = "balanced_latin_square",
        timeout_grace_s: float = 0.05,
        repository_clean: bool = True,
        shard: dict[str, Any] | None = None,
        continuation: dict[str, Any] | None = None,
        run_selection: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        self.instances.sort(key=lambda item: (item["relative_path"], item["id"]))
        self.solvers.sort(key=lambda item: item["id"])
        self.manifest.parent.mkdir(parents=True, exist_ok=True)
        self.manifest.write_text(
            "".join(canonical_bytes(instance).decode("ascii") for instance in self.instances),
            encoding="ascii",
        )
        self.solver_config.write_bytes(
            canonical_bytes({"schema_version": 1, "solvers": self.solvers})
        )

        git(self.repository, "init", "-q")
        git(self.repository, "add", "campaign.json", "solver-releases.json")
        git(
            self.repository,
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        )
        if not repository_clean:
            self.spec.write_text(
                '{"campaign_id":"dirty-test-campaign"}\n', encoding="utf-8"
            )

        commit = git(self.repository, "rev-parse", "HEAD")
        commit_time = git(self.repository, "show", "-s", "--format=%cI", "HEAD")
        if sys.platform.startswith("linux") and hasattr(os, "sched_getaffinity"):
            cpu_ids = [min(os.sched_getaffinity(0))]
        else:
            cpu_ids = [0]
        repository_record = {
            "root": str(self.repository.resolve()),
            "commit": commit,
            "commit_time": commit_time,
            "clean": repository_clean,
            "promotion_eligible": repository_clean,
        }
        payload: dict[str, Any] = {
            "schema_version": 1,
            "campaign_id": "locked-campaign-test",
            "lock_sha256": "",
            "created_from_commit_time": commit_time,
            "promotion_eligible": False,
            "spec": {
                "path": str(self.spec.resolve()),
                "sha256": sha256_file(self.spec),
            },
            "repository": repository_record,
            "host": {
                "system": "test",
                "release": "test",
                "machine": "test",
                "python": platform_python_version(),
            },
            "corpus": {
                "id": "test-corpus",
                "manifest_path": str(self.manifest.resolve()),
                "manifest_sha256": sha256_file(self.manifest),
                "taxonomy_path": None,
                "taxonomy_sha256": None,
                "root": str(self.corpus_root.resolve()),
                "instances": self.instances,
            },
            "solver_config": {
                "path": str(self.solver_config.resolve()),
                "sha256": sha256_file(self.solver_config),
            },
            "solver_release_lock": {
                "path": str(self.release_lock.resolve()),
                "sha256": sha256_file(self.release_lock),
            },
            "solvers": self.solvers,
            "budgets_s": budgets or [1],
            "execution": {
                "resource_model": "single_core_cold_process",
                "cpu_ids": cpu_ids,
                "memory_bytes": 8 * 1024**3,
                "order": order,
                "environment": {},
                "timeout_grace_s": timeout_grace_s,
            },
            "output": {
                "directory": str(self.output.resolve()),
                "journal": "journal.jsonl",
                "raw": "raw.jsonl",
                "summary": "summary.json",
            },
        }
        if shard is not None:
            payload["shard"] = shard
        if continuation is not None:
            payload["schema_version"] = 2
            payload["continuation"] = continuation
        if run_selection is not None:
            payload["run_selection"] = run_selection
        payload["lock_sha256"] = sha256_bytes(canonical_bytes(payload))
        self.lock_path.write_bytes(canonical_bytes(payload))
        self.payload = payload
        return payload

    def run(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(RUNNER), str(self.lock_path)],
            text=True,
            capture_output=True,
            check=False,
            cwd=self.root,
        )

    def raw_records(self) -> list[dict[str, Any]]:
        raw_path = self.output / "raw.jsonl"
        return [json.loads(line) for line in raw_path.read_text().splitlines()]


def platform_python_version() -> str:
    return ".".join(str(value) for value in sys.version_info[:3])


class LockedCampaignRunnerTests(unittest.TestCase):
    def test_optional_shard_metadata_is_validated_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("assigned-only.smt2")
            fixture.add_solver("solver-a")
            shard = {
                "index": 1,
                "count": 3,
                "parent_lock_sha256": "a" * 64,
            }
            fixture.finalize(shard=shard)

            completed = fixture.run()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(len(fixture.raw_records()), 1)
            summary = json.loads(
                (fixture.output / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["shard"], shard)

    def test_continuation_runs_only_hash_bound_selected_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CampaignFixture(root)
            fixture.add_instance("a.smt2")
            fixture.add_instance("b.smt2")
            fixed_argv = ["{binary}", "{instance}", "60"]
            fixture.add_solver("solver-a", argv_template=fixed_argv)
            fixture.add_solver("solver-b", argv_template=fixed_argv)
            selection = [
                {"instance_id": "0", "solver_id": "solver-a"},
                {"instance_id": "0", "solver_id": "solver-b"},
                {"instance_id": "1", "solver_id": "solver-b"},
            ]
            parent_lock = root / "source-parent.json"
            parent_payload = {"lock_sha256": ""}
            parent_payload["lock_sha256"] = sha256_bytes(
                canonical_bytes(parent_payload)
            )
            parent_lock.write_bytes(canonical_bytes(parent_payload))
            continuation = {
                "mode": "timeout_only",
                "root_lock_sha256": parent_payload["lock_sha256"],
                "parent_lock_path": str(parent_lock.resolve()),
                "parent_lock_file_sha256": sha256_file(parent_lock),
                "parent_lock_sha256": parent_payload["lock_sha256"],
                "shard_bundle_sha256": "2" * 64,
                "source_evidence_sha256": "2" * 64,
                "shard_lock_directory": str((root / "source-locks").resolve()),
                "shard_results_root": str((root / "source-results").resolve()),
                "source_budget_s": 2,
                "target_budget_s": 60,
                "selection_sha256": sha256_bytes(canonical_bytes(selection)),
                "selected_instances": 2,
                "selected_runs": 3,
                "runner_path": str(RUNNER.resolve()),
                "runner_sha256": sha256_file(RUNNER),
            }
            fixture.finalize(
                budgets=[60],
                continuation=continuation,
                run_selection=selection,
            )

            completed = fixture.run()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            records = fixture.raw_records()
            self.assertEqual(
                [(record["instance_id"], record["solver_id"]) for record in records],
                [("0", "solver-a"), ("0", "solver-b"), ("1", "solver-b")],
            )
            summary = json.loads(
                (fixture.output / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["selected_runs"], 3)
            self.assertEqual(summary["continuation"], continuation)

    def test_continuation_rejects_selection_drift_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CampaignFixture(root)
            fixture.add_instance("a.smt2")
            fixture.add_solver(
                "solver-a", argv_template=["{binary}", "{instance}", "60"]
            )
            selection = [{"instance_id": "0", "solver_id": "solver-a"}]
            parent_lock = root / "source-parent.json"
            parent_payload = {"lock_sha256": ""}
            parent_payload["lock_sha256"] = sha256_bytes(
                canonical_bytes(parent_payload)
            )
            parent_lock.write_bytes(canonical_bytes(parent_payload))
            fixture.finalize(
                budgets=[60],
                continuation={
                    "mode": "timeout_only",
                    "root_lock_sha256": parent_payload["lock_sha256"],
                    "parent_lock_path": str(parent_lock.resolve()),
                    "parent_lock_file_sha256": sha256_file(parent_lock),
                    "parent_lock_sha256": parent_payload["lock_sha256"],
                    "shard_bundle_sha256": "2" * 64,
                    "source_evidence_sha256": "2" * 64,
                    "shard_lock_directory": str((root / "locks").resolve()),
                    "shard_results_root": str((root / "results").resolve()),
                    "source_budget_s": 2,
                    "target_budget_s": 60,
                    "selection_sha256": "3" * 64,
                    "selected_instances": 1,
                    "selected_runs": 1,
                    "runner_path": str(RUNNER.resolve()),
                    "runner_sha256": sha256_file(RUNNER),
                },
                run_selection=selection,
            )

            completed = fixture.run()

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("selection SHA-256 mismatch", completed.stderr)
            self.assertFalse((root / "calls.log").exists())

    def test_continuation_rejects_budget_dependent_solver_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CampaignFixture(root)
            fixture.add_instance("a.smt2")
            fixture.add_solver("solver-a")
            selection = [{"instance_id": "0", "solver_id": "solver-a"}]
            parent_lock = root / "source-parent.json"
            parent_payload = {"lock_sha256": ""}
            parent_payload["lock_sha256"] = sha256_bytes(
                canonical_bytes(parent_payload)
            )
            parent_lock.write_bytes(canonical_bytes(parent_payload))
            fixture.finalize(
                budgets=[60],
                continuation={
                    "mode": "timeout_only",
                    "root_lock_sha256": parent_payload["lock_sha256"],
                    "parent_lock_path": str(parent_lock.resolve()),
                    "parent_lock_file_sha256": sha256_file(parent_lock),
                    "parent_lock_sha256": parent_payload["lock_sha256"],
                    "shard_bundle_sha256": "2" * 64,
                    "source_evidence_sha256": "2" * 64,
                    "shard_lock_directory": str((root / "locks").resolve()),
                    "shard_results_root": str((root / "results").resolve()),
                    "source_budget_s": 2,
                    "target_budget_s": 60,
                    "selection_sha256": sha256_bytes(canonical_bytes(selection)),
                    "selected_instances": 1,
                    "selected_runs": 1,
                    "runner_path": str(RUNNER.resolve()),
                    "runner_sha256": sha256_file(RUNNER),
                },
                run_selection=selection,
            )

            completed = fixture.run()

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("budget-dependent", completed.stderr)
            self.assertFalse((root / "calls.log").exists())

    def test_collects_hashes_resources_and_enforcement_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("case.smt2")
            fixture.add_solver("solver-a", environment={"STDERR_TEXT": "note\n"})
            fixture.finalize()

            completed = fixture.run()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            records = fixture.raw_records()
            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual(record["result_token"], "sat")
            self.assertEqual(record["result_token_status"], "valid")
            self.assertEqual(record["termination_cause"], "exit")
            self.assertEqual(record["exit_code"], 0)
            self.assertEqual(
                record["stdout_sha256"], sha256_bytes(b"sat\n")
            )
            self.assertEqual(
                record["stderr_sha256"], sha256_bytes(b"note\n")
            )
            self.assertGreaterEqual(record["wall_time_s"], 0.0)
            self.assertGreaterEqual(record["child_cpu_time_s"], 0.0)
            self.assertGreater(record["max_rss_bytes"], 0)
            summary = json.loads(
                (fixture.output / "summary.json").read_text(encoding="utf-8")
            )
            enforcement = summary["invocations"][0]["enforcement"]
            self.assertTrue(enforcement["cold_process"]["enforced"])
            self.assertTrue(enforcement["process_group"]["enforced"])
            self.assertFalse(enforcement["cgroup_or_benchexec_equivalent"])
            self.assertFalse(summary["cgroup_or_benchexec_equivalent"])
            if sys.platform.startswith("linux"):
                self.assertTrue(enforcement["cpu_affinity"]["enforced"])
                self.assertTrue(enforcement["cpu_affinity"]["one_cpu_per_solve"])

    def test_timeout_kills_the_full_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "descendant-finished"
            ready = root / "descendant-ready"
            source = textwrap.dedent(
                """\
                #!/bin/sh
                (
                  trap '' TERM
                  /bin/sleep 1.2
                  printf '%s' escaped > "$MARKER"
                ) &
                printf '%s' ready > "$READY"
                /bin/sleep 10
                """
            )
            fixture = CampaignFixture(root)
            fixture.add_instance("timeout.smt2")
            fixture.add_solver(
                "solver-a",
                source,
                environment={"MARKER": str(marker), "READY": str(ready)},
            )
            fixture.finalize(budgets=[1.0], timeout_grace_s=0.05)

            completed = fixture.run()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            record = fixture.raw_records()[0]
            self.assertTrue(record["timed_out"])
            self.assertEqual(record["termination_cause"], "timeout")
            self.assertIsNone(record["result_token"])
            self.assertTrue(ready.exists(), record)
            time.sleep(1.25)
            self.assertFalse(marker.exists(), "descendant survived process-group kill")

    def test_resume_appends_only_missing_schedule_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interrupted = root / "interrupted-once"
            source = textwrap.dedent(
                f"""\
                #!{sys.executable}
                import os
                import signal
                import sys
                import time
                from pathlib import Path

                log = Path(os.environ["CALL_LOG"])
                previous = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
                with log.open("a", encoding="utf-8") as handle:
                    handle.write(Path(sys.argv[1]).name + "\\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                marker = Path(os.environ["INTERRUPTED"])
                if len(previous) == 1 and not marker.exists():
                    marker.write_text("yes", encoding="utf-8")
                    os.kill(os.getppid(), signal.SIGINT)
                    time.sleep(10)
                print("sat")
                """
            )
            fixture = CampaignFixture(root)
            fixture.add_instance("a.smt2")
            fixture.add_instance("b.smt2")
            fixture.add_solver(
                "solver-a", source, environment={"INTERRUPTED": str(interrupted)}
            )
            fixture.finalize()

            first = fixture.run()
            self.assertEqual(first.returncode, 130, first.stderr)
            self.assertFalse((fixture.output / "raw.jsonl").exists())
            first_journal = (fixture.output / "journal.jsonl").read_text().splitlines()
            self.assertEqual(len(first_journal), 2)

            resumed = fixture.run()

            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertEqual(len(fixture.raw_records()), 2)
            self.assertEqual(
                (root / "calls.log").read_text().splitlines(),
                ["a.smt2", "b.smt2", "b.smt2"],
            )
            journal = [
                json.loads(line)
                for line in (fixture.output / "journal.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [record["record_type"] for record in journal],
                ["invocation", "run", "invocation", "run"],
            )
            self.assertEqual([record["sequence"] for record in fixture.raw_records()], [0, 1])

    def test_abba_and_balanced_latin_square_orders_use_only_ordinals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            abba = CampaignFixture(Path(temporary) / "abba")
            abba.add_instance("a.smt2")
            abba.add_instance("b.smt2")
            abba.add_solver("a")
            abba.add_solver("b")
            abba.finalize(order="abba")

            completed = abba.run()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                [record["solver_id"] for record in abba.raw_records()],
                ["a", "b", "b", "a", "b", "a", "a", "b"],
            )
            self.assertEqual(
                [record["repetition"] for record in abba.raw_records()],
                [0, 0, 1, 1, 0, 0, 1, 1],
            )

        with tempfile.TemporaryDirectory() as temporary:
            balanced = CampaignFixture(Path(temporary))
            for name in ("a.smt2", "b.smt2", "c.smt2"):
                balanced.add_instance(name)
            for identifier in ("a", "b", "c"):
                balanced.add_solver(identifier)
            balanced.finalize(order="balanced_latin_square")

            completed = balanced.run()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                [record["solver_id"] for record in balanced.raw_records()],
                ["a", "b", "c", "b", "c", "a", "c", "a", "b"],
            )

    def test_malformed_solver_output_is_recorded_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("case.smt2")
            fixture.add_solver(
                "solver-a", environment={"STDOUT_TEXT": "sat\nextra\n"}
            )
            fixture.finalize()

            completed = fixture.run()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            record = fixture.raw_records()[0]
            self.assertIsNone(record["result_token"])
            self.assertEqual(record["result_token_status"], "malformed")
            self.assertEqual(record["termination_cause"], "exit")

    def test_lock_and_artifact_drift_fail_before_solver_execution(self) -> None:
        mutations = {
            "lock": lambda fixture: self._mutate_lock(fixture.lock_path),
            "spec": lambda fixture: fixture.spec.write_text("changed\n"),
            "manifest": lambda fixture: fixture.manifest.write_text("changed\n"),
            "solver_config": lambda fixture: fixture.solver_config.write_text(
                "changed\n"
            ),
            "instance": lambda fixture: Path(
                fixture.instances[0]["path"]
            ).write_text("changed\n"),
            "solver": lambda fixture: Path(fixture.solvers[0]["binary"]).write_text(
                "changed\n"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = CampaignFixture(Path(temporary))
                fixture.add_instance("case.smt2")
                fixture.add_solver("solver-a")
                fixture.finalize()
                mutate(fixture)

                completed = fixture.run()

                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertIn("drift", completed.stderr)
                self.assertFalse((fixture.root / "calls.log").exists())
                self.assertFalse((fixture.output / "raw.jsonl").exists())

    def test_duplicate_resume_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CampaignFixture(Path(temporary))
            fixture.add_instance("case.smt2")
            fixture.add_solver("solver-a")
            fixture.finalize()
            first = fixture.run()
            self.assertEqual(first.returncode, 0, first.stderr)
            journal_path = fixture.output / "journal.jsonl"
            records = [json.loads(line) for line in journal_path.read_text().splitlines()]
            duplicate = dict(records[-1])
            duplicate["previous_record_sha256"] = records[-1]["record_sha256"]
            duplicate.pop("record_sha256")
            duplicate["record_sha256"] = sha256_bytes(canonical_bytes(duplicate))
            with journal_path.open("ab") as handle:
                handle.write(canonical_bytes(duplicate))

            resumed = fixture.run()

            self.assertEqual(resumed.returncode, 2, resumed.stderr)
            self.assertIn("duplicate run key", resumed.stderr)
            self.assertEqual((fixture.root / "calls.log").read_text().count("\n"), 1)

    @staticmethod
    def _mutate_lock(path: Path) -> None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["campaign_id"] = "drifted"
        path.write_bytes(canonical_bytes(payload))


if __name__ == "__main__":
    unittest.main()
