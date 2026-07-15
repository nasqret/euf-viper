from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
DISPATCH = WMI / "euf_viper_continuation_dispatch.sbatch"
SHARD = WMI / "euf_viper_continuation_shard.sbatch"
AUDIT = WMI / "euf_viper_continuation_audit.sbatch"
FINALIZE = WMI / "euf_viper_continuation_finalize.sbatch"
SUBMIT = WMI / "submit_locked_continuations.sh"
SCRIPTS = (DISPATCH, SHARD, AUDIT, FINALIZE, SUBMIT)
FINALIZER_TEST_PATH = ROOT / "tests" / "test_finalize_locked_audit.py"
FINALIZER_TEST_SPEC = importlib.util.spec_from_file_location(
    "continuation_finalizer_fixture", FINALIZER_TEST_PATH
)
assert FINALIZER_TEST_SPEC is not None and FINALIZER_TEST_SPEC.loader is not None
FINALIZER_TESTS = importlib.util.module_from_spec(FINALIZER_TEST_SPEC)
sys.modules[FINALIZER_TEST_SPEC.name] = FINALIZER_TESTS
FINALIZER_TEST_SPEC.loader.exec_module(FINALIZER_TESTS)


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
    path.chmod(0o755)


class ContinuationScriptContractTests(unittest.TestCase):
    def test_all_shell_scripts_parse(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", *(str(path) for path in SCRIPTS)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_revision_dependencies_and_raw_contracts_are_explicit(self) -> None:
        submit = SUBMIT.read_text(encoding="utf-8")
        dispatch = DISPATCH.read_text(encoding="utf-8")
        shard = SHARD.read_text(encoding="utf-8")
        audit = AUDIT.read_text(encoding="utf-8")
        finalizer = FINALIZE.read_text(encoding="utf-8")

        self.assertIn("git status --porcelain=v1", submit)
        self.assertIn("git ls-remote --exit-code origin refs/heads/main", submit)
        self.assertIn("EUF_VIPER_CONTINUATION_REVISION", submit)
        self.assertIn('=~ ^[0-9a-f]{40}$', submit)
        self.assertIn("git merge-base --is-ancestor", submit)
        self.assertIn('SHORT_REVISION="${REVISION:0:12}"', submit)
        self.assertIn('"submitter_revision": submitter_revision', submit)
        self.assertIn("--dependency=afterok:$BASE_AUDIT_JOB_ID", submit)
        self.assertIn('--dependency="afterok:$SLURM_JOB_ID"', dispatch)
        self.assertIn('JOIN_DEPENDENCY="afterok:', dispatch)
        self.assertIn('if [ "$INSTANCES" -lt "$SHARD_COUNT" ]', dispatch)
        self.assertIn('if [ "$STATUS" = ready ]', dispatch)
        self.assertIn("bind_campaign_cpu.py", shard)
        self.assertLess(
            shard.index("bind_campaign_cpu.py"),
            shard.index("run_locked_campaign.py"),
        )
        self.assertIn('if [ -e "$BOUND_LOCK" ] || [ -e "$RESULT_ROOT" ]', shard)
        self.assertIn("analyze_staged_campaign.py", audit)
        self.assertIn("complete_declared_budget_ladder", audit)
        self.assertIn("immutable per-shard raw.jsonl", finalizer)

    def test_dispatch_uses_minimum_shards_and_skips_zero_timeout_array(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            fake_bin = work / "bin"
            revision = "2" * 40
            prepare_job = 10
            audit_job = 11
            dispatcher_job = 500
            run_root = work / "results" / f"p0-{prepare_job}"

            project_dispatch = work / "scripts" / "wmi" / DISPATCH.name
            for source in (
                DISPATCH,
                WMI / "finalize_locked_audit.py",
                WMI / "hermetic_provenance.py",
                ROOT / "scripts" / "cert" / "strict_artifacts.py",
            ):
                destination = work / source.relative_to(ROOT)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)

            write_executable(
                fake_bin / "git",
                fr"""
                #!/usr/bin/env bash
                if [ "$1" = rev-parse ]; then
                  printf '%s\n' {revision}
                elif [ "$1" = status ]; then
                  :
                else
                  exit 2
                fi
                """,
            )
            sbatch_log = work / "sbatch.log"
            sbatch_counter = work / "sbatch.counter"
            sbatch_counter.write_text("700\n", encoding="ascii")
            write_executable(
                fake_bin / "sbatch",
                r"""
                #!/usr/bin/env bash
                printf '%s\n' "$*" >> "$TEST_SBATCH_LOG"
                value="$(cat "$TEST_SBATCH_COUNTER")"
                value=$((value + 1))
                printf '%s\n' "$value" > "$TEST_SBATCH_COUNTER"
                printf '%s\n' "$value"
                """,
            )

            write_executable(
                work / "scripts" / "bench" / "derive_timeout_continuations.py",
                r"""
                #!/usr/bin/env python3
                import json
                import sys
                from pathlib import Path

                arguments = sys.argv[1:]
                output = Path(arguments[arguments.index("--output-dir") + 1])
                target = int(arguments[arguments.index("--target-budget") + 1])
                kind = "official" if "official" in output.name else "full"
                if kind == "full":
                    status, instances, runs = "ready", 3, 4
                    lock = {
                        "path": str((output / "continuation-parent.json").resolve()),
                        "lock_sha256": "b" * 64,
                        "file_sha256": "c" * 64,
                    }
                    (output / "continuation-parent.json").write_text("{}\n")
                else:
                    status, instances, runs, lock = "no_timeouts", 0, 0, None
                payload = {
                    "schema_version": 1,
                    "status": status,
                    "target_budget_s": target,
                    "selected_instances": instances,
                    "selected_runs": runs,
                    "continuation_lock": lock,
                }
                (output / "index.json").write_text(json.dumps(payload) + "\n")
                print(json.dumps(payload))
                """,
            )
            write_executable(
                work / "scripts" / "bench" / "shard_campaign_lock.py",
                r"""
                #!/usr/bin/env python3
                import sys
                from pathlib import Path

                arguments = sys.argv[1:]
                count = int(arguments[arguments.index("--count") + 1])
                output = Path(arguments[arguments.index("--out-dir") + 1])
                for index in range(count):
                    (output / f"lock-{index:04d}.json").write_text("{}\n")
                print("{}")
                """,
            )

            class PinnedTemporaryDirectory:
                name = str(run_root)

                def cleanup(self) -> None:
                    pass

            finalized = FINALIZER_TESTS.FinalizeLockedAuditTests()
            with mock.patch.object(
                FINALIZER_TESTS.tempfile,
                "TemporaryDirectory",
                return_value=PinnedTemporaryDirectory(),
            ):
                finalized.setUp()
            self.addCleanup(finalized.tearDown)
            finalized_payload = finalized.finalize()
            self.assertEqual(finalized.root, run_root.resolve())
            self.assertEqual(
                finalized_payload["schema"], "euf-viper.locked-p0-audit.v4"
            )
            self.assertEqual(finalized_payload["status"], "complete")

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                    "SLURM_SUBMIT_DIR": str(work),
                    "SLURM_JOB_ID": str(dispatcher_job),
                    "EUF_VIPER_EXPECTED_REVISION": revision,
                    "EUF_VIPER_BASE_PREPARE_JOB_ID": str(prepare_job),
                    "EUF_VIPER_BASE_AUDIT_JOB_ID": str(audit_job),
                    "EUF_VIPER_CONTINUATION_TARGET_BUDGET": "60",
                    "EUF_VIPER_CONTINUATION_SHARDS": "64",
                    "EUF_VIPER_CONTINUATION_MAX_ACTIVE": "7",
                    "EUF_VIPER_CONTINUATION_BOOTSTRAP_REPLICATES": "8",
                    "TEST_SBATCH_LOG": str(sbatch_log),
                    "TEST_SBATCH_COUNTER": str(sbatch_counter),
                }
            )

            base_audit_path = finalized.output
            valid_index_bytes = base_audit_path.read_bytes()
            valid_index = json.loads(valid_index_bytes.decode("utf-8"))

            def run_dispatch(
                dispatch: Path = project_dispatch,
                run_env: dict[str, str] = env,
                *,
                timeout: float = 10.0,
            ) -> subprocess.CompletedProcess[str]:
                try:
                    return subprocess.run(
                        ["bash", str(dispatch)],
                        text=True,
                        capture_output=True,
                        env=run_env,
                        check=False,
                        timeout=timeout,
                    )
                except subprocess.TimeoutExpired as error:
                    self.fail(f"dispatcher blocked on adversarial evidence: {error}")

            def reject_current(name: str, expected_error: str | None = None) -> None:
                with self.subTest(evidence=name):
                    rejected = run_dispatch()
                    self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                    if expected_error is not None:
                        self.assertIn(expected_error, rejected.stderr)
                    self.assertFalse(sbatch_log.exists())

            def write_index(value: dict[str, object]) -> None:
                base_audit_path.chmod(0o600)
                base_audit_path.write_text(
                    json.dumps(
                        value,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                base_audit_path.chmod(0o400)

            def restore_index() -> None:
                base_audit_path.chmod(0o600)
                base_audit_path.write_bytes(valid_index_bytes)
                base_audit_path.chmod(0o400)

            invalid_indexes = {
                "legacy schema": {
                    **{key: value for key, value in valid_index.items() if key != "schema"},
                    "schema_version": 1,
                },
                "extra top-level field": {**valid_index, "unexpected": None},
                "incomplete analysis shape": {
                    **valid_index,
                    "analyses": {
                        **valid_index["analyses"],
                        "full": {
                            key: value
                            for key, value in valid_index["analyses"]["full"].items()
                            if key != "bytes"
                        },
                    },
                },
            }
            for name, invalid_index in invalid_indexes.items():
                try:
                    write_index(invalid_index)
                    reject_current(name, "incompatible")
                finally:
                    restore_index()

            copied_work = work / "copied-run"
            shutil.copytree(work / "scripts", copied_work / "scripts")
            copied_index = (
                copied_work
                / "results"
                / f"p0-{prepare_job}"
                / "audit"
                / "index.json"
            )
            copied_index.parent.mkdir(parents=True)
            shutil.copy2(base_audit_path, copied_index)
            copied_env = {**env, "SLURM_SUBMIT_DIR": str(copied_work)}
            copied_dispatch = (
                copied_work / "scripts" / "wmi" / project_dispatch.name
            )
            copied_rejection = run_dispatch(copied_dispatch, copied_env)
            self.assertNotEqual(copied_rejection.returncode, 0)
            self.assertIn("trusted run root", copied_rejection.stderr)
            self.assertEqual(copied_index.read_bytes(), valid_index_bytes)
            self.assertFalse(
                (
                    copied_work
                    / "results"
                    / f"p0-{prepare_job}"
                    / "continuations"
                ).exists()
            )
            self.assertFalse(sbatch_log.exists())

            analysis_path = run_root / "audit" / "full" / "global.json"
            analysis_bytes = analysis_path.read_bytes()
            analysis_inode = analysis_path.stat().st_ino
            analysis_backup = analysis_path.with_name(".global.json.dispatch-original")
            os.link(analysis_path, analysis_backup)
            analysis_path.unlink()
            analysis_path.write_bytes(analysis_bytes)
            analysis_path.chmod(0o400)
            replacement_inode = analysis_path.stat().st_ino
            self.assertNotEqual(replacement_inode, analysis_inode)
            try:
                reject_current(
                    "same-byte analysis replacement",
                    "analysis or input binding drifted",
                )
                self.assertEqual(analysis_path.stat().st_ino, replacement_inode)
                self.assertEqual(analysis_path.read_bytes(), analysis_bytes)
            finally:
                analysis_path.unlink()
                os.link(analysis_backup, analysis_path)
                analysis_backup.unlink()
            self.assertEqual(analysis_path.stat().st_ino, analysis_inode)

            raw_path = run_root / "official-2s" / "shard-0000" / "raw.jsonl"
            raw_bytes = raw_path.read_bytes()
            raw_mode = stat.S_IMODE(raw_path.stat().st_mode)
            modified_raw = raw_bytes + b'{"record_type":"drift"}\n'
            try:
                raw_path.write_bytes(modified_raw)
                raw_path.chmod(raw_mode)
                reject_current("modified shard raw", "raw hash is stale")
                self.assertEqual(raw_path.read_bytes(), modified_raw)
            finally:
                raw_path.write_bytes(raw_bytes)
                raw_path.chmod(raw_mode)

            scheduler_path = run_root / "audit" / "scheduler.json"
            scheduler_bytes = scheduler_path.read_bytes()
            scheduler_inode = scheduler_path.stat().st_ino
            scheduler_backup = scheduler_path.with_name(
                ".scheduler.json.dispatch-original"
            )
            os.link(scheduler_path, scheduler_backup)
            scheduler_path.unlink()
            scheduler_path.write_bytes(scheduler_bytes)
            scheduler_path.chmod(0o400)
            scheduler_replacement_inode = scheduler_path.stat().st_ino
            self.assertNotEqual(scheduler_replacement_inode, scheduler_inode)
            try:
                reject_current(
                    "same-byte scheduler receipt replacement",
                    "scheduler receipt binding drifted",
                )
                self.assertEqual(
                    scheduler_path.stat().st_ino, scheduler_replacement_inode
                )
                self.assertEqual(scheduler_path.read_bytes(), scheduler_bytes)
            finally:
                scheduler_path.unlink()
                os.link(scheduler_backup, scheduler_path)
                scheduler_backup.unlink()
            self.assertEqual(scheduler_path.stat().st_ino, scheduler_inode)

            os.link(scheduler_path, scheduler_backup)
            scheduler_path.unlink()
            unrelated_scheduler = b"{}\n"
            scheduler_path.write_bytes(unrelated_scheduler)
            scheduler_path.chmod(0o400)
            unrelated_inode = scheduler_path.stat().st_ino
            try:
                reject_current(
                    "unrelated scheduler receipt",
                    "SHA-256 differs from external binding",
                )
                self.assertEqual(scheduler_path.stat().st_ino, unrelated_inode)
                self.assertEqual(scheduler_path.read_bytes(), unrelated_scheduler)
            finally:
                scheduler_path.unlink()
                os.link(scheduler_backup, scheduler_path)
                scheduler_backup.unlink()

            os.link(scheduler_path, scheduler_backup)
            scheduler_path.unlink()
            os.mkfifo(scheduler_path, 0o400)
            try:
                reject_current("FIFO scheduler receipt", "not a regular file")
                self.assertTrue(stat.S_ISFIFO(scheduler_path.lstat().st_mode))
            finally:
                scheduler_path.unlink()
                os.link(scheduler_backup, scheduler_path)
                scheduler_backup.unlink()

            index_backup = base_audit_path.with_name(".index.json.dispatch-original")
            os.link(base_audit_path, index_backup)
            base_audit_path.unlink()
            base_audit_path.symlink_to(index_backup.name)
            try:
                reject_current("symlinked base index")
                self.assertTrue(base_audit_path.is_symlink())
            finally:
                base_audit_path.unlink()
                os.link(index_backup, base_audit_path)
                index_backup.unlink()

            os.link(base_audit_path, index_backup)
            base_audit_path.unlink()
            os.mkfifo(base_audit_path, 0o400)
            try:
                reject_current("FIFO base index")
                self.assertTrue(stat.S_ISFIFO(base_audit_path.lstat().st_mode))
            finally:
                base_audit_path.unlink()
                os.link(index_backup, base_audit_path)
                index_backup.unlink()

            chain_root = run_root / "continuations" / f"chain-{dispatcher_job}"
            self.assertFalse(chain_root.exists())
            completed = run_dispatch()
            self.assertEqual(completed.returncode, 0, completed.stderr)

            submissions = sbatch_log.read_text(encoding="utf-8").splitlines()
            arrays = [line for line in submissions if "continuation_shard" in line]
            audits = [line for line in submissions if "continuation_audit" in line]
            next_stages = [
                line for line in submissions if "continuation_dispatch" in line
            ]
            self.assertEqual(len(arrays), 1)
            self.assertIn("--array=0-2%7", arrays[0])
            self.assertNotIn("0--1", "\n".join(submissions))
            self.assertEqual(len(audits), 2)
            self.assertIn("--dependency=afterok:701", audits[0])
            self.assertIn("--dependency=afterok:500", audits[1])
            self.assertEqual(len(next_stages), 1)
            self.assertIn("--dependency=afterok:702:703", next_stages[0])

            metadata = json.loads(
                (chain_root / "submissions" / "60.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["corpora"]["full"]["shards"], 3)
            self.assertEqual(metadata["corpora"]["full"]["array_job_id"], 701)
            self.assertEqual(metadata["corpora"]["official"]["shards"], 0)
            self.assertIsNone(
                metadata["corpora"]["official"]["array_job_id"]
            )
            self.assertEqual(metadata["next"]["job_id"], 704)


if __name__ == "__main__":
    unittest.main()
