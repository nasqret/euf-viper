from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


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
            base_audit_dir = run_root / "audit"
            base_audit_dir.mkdir(parents=True)

            project_dispatch = work / "scripts" / "wmi" / DISPATCH.name
            project_dispatch.parent.mkdir(parents=True)
            shutil.copy2(DISPATCH, project_dispatch)

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

            finalized = FINALIZER_TESTS.FinalizeLockedAuditTests()
            finalized.setUp()
            self.addCleanup(finalized.tearDown)
            finalized_payload = finalized.finalize()
            self.assertEqual(
                finalized_payload["schema"], "euf-viper.locked-p0-audit.v4"
            )
            self.assertEqual(finalized_payload["status"], "complete")
            shutil.copy2(finalized.output, base_audit_dir / "index.json")

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

            valid_index = json.loads(finalized.output.read_text(encoding="utf-8"))
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
            base_audit_path = base_audit_dir / "index.json"
            for name, invalid_index in invalid_indexes.items():
                with self.subTest(base_audit=name):
                    base_audit_path.chmod(0o600)
                    base_audit_path.write_text(
                        json.dumps(
                            invalid_index,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    base_audit_path.chmod(0o400)
                    rejected = subprocess.run(
                        ["bash", str(project_dispatch)],
                        text=True,
                        capture_output=True,
                        env=env,
                        check=False,
                    )
                    self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                    self.assertIn("incompatible", rejected.stderr)
                    self.assertFalse(sbatch_log.exists())

            base_audit_path.chmod(0o600)
            shutil.copy2(finalized.output, base_audit_path)
            completed = subprocess.run(
                ["bash", str(project_dispatch)],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
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

            chain_root = run_root / "continuations" / f"chain-{dispatcher_job}"
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
