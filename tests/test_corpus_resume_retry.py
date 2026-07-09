from __future__ import annotations

import csv
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUBMIT_SCRIPT = ROOT / "scripts" / "wmi" / "sync_and_submit_sharded_corpus.sh"
SHARD_SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_corpus_shard.sbatch"
MERGE_JOB_SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_merge_shards.sbatch"
MERGE_SCRIPT = ROOT / "scripts" / "bench" / "merge_shards.py"
COMPARE_SCRIPT = ROOT / "scripts" / "bench" / "compare_solvers.py"
UNSET = object()

SPEC = importlib.util.spec_from_file_location("compare_solvers", COMPARE_SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def flag_values(arguments: list[str], flag: str) -> list[str]:
    return [
        arguments[index + 1]
        for index, argument in enumerate(arguments[:-1])
        if argument == flag
    ]


class RetrySelectionTests(unittest.TestCase):
    def test_empty_results_with_viper_solver_keeps_other_solver_timeouts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results = Path(temp_dir) / "resume.csv"
            with results.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=COMPARE.FIELDNAMES)
                writer.writeheader()
                for relative_path, solver, result in [
                    ("a.smt2", "euf-viper", "sat"),
                    ("a.smt2", "z3", "timeout"),
                    ("b.smt2", "euf-viper", "timeout"),
                    ("b.smt2", "z3", "unsat"),
                ]:
                    writer.writerow(
                        {
                            "id": relative_path,
                            "relative_path": relative_path,
                            "expected_status": "unknown",
                            "solver": solver,
                            "result": result,
                            "time_s": "1.0",
                            "exit_code": "124" if result == "timeout" else "0",
                            "stderr": "",
                        }
                    )

            observations = COMPARE.load_existing_results(
                results,
                {"a.smt2", "b.smt2"},
                {"euf-viper", "z3"},
                retry_results=set(),
                retry_solvers={"euf-viper"},
            )

            self.assertEqual(
                set(observations),
                {("a.smt2", "z3"), ("b.smt2", "z3")},
            )
            self.assertEqual(observations[("a.smt2", "z3")]["result"], "timeout")


class JobArgumentTests(unittest.TestCase):
    def run_job(
        self, script: Path, retry_results: object = UNSET
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            work = Path(temp_dir)
            capture = work / "arguments.json"
            recorder = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

Path(os.environ["ARGUMENT_CAPTURE"]).write_text(json.dumps(sys.argv[1:]))
"""
            if script == SHARD_SCRIPT:
                write_executable(
                    work / "scripts" / "bench" / "shard_manifest.py",
                    "#!/bin/sh\nexit 0\n",
                )
                write_executable(
                    work / "scripts" / "bench" / "compare_solvers.py", recorder
                )
            else:
                write_executable(
                    work / "scripts" / "bench" / "merge_shards.py", recorder
                )
                write_executable(
                    work / "scripts" / "bench" / "analyze_results.py",
                    "#!/bin/sh\nexit 0\n",
                )

            env = os.environ.copy()
            env.update(
                {
                    "ARGUMENT_CAPTURE": str(capture),
                    "SLURM_SUBMIT_DIR": str(work),
                    "SLURM_ARRAY_TASK_ID": "0",
                    "EUF_VIPER_RUN_ID": "200",
                    "EUF_VIPER_CORPUS_SHARDS": "1",
                    "EUF_VIPER_CORPUS_TIMEOUT": "10",
                    "EUF_VIPER_CORPUS_JOBS": "1",
                    "EUF_VIPER_CORPUS_RESUME_RUN_ID": "100",
                    "EUF_VIPER_CORPUS_RETRY_SOLVERS": "euf-viper,z3",
                }
            )
            env.pop("EUF_VIPER_CORPUS_RETRY_RESULTS", None)
            if retry_results is not UNSET:
                env["EUF_VIPER_CORPUS_RETRY_RESULTS"] = str(retry_results)

            completed = subprocess.run(
                ["bash", str(script)],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return json.loads(capture.read_text(encoding="utf-8"))

    def test_jobs_default_to_timeout_but_preserve_explicit_empty(self) -> None:
        for script in (SHARD_SCRIPT, MERGE_JOB_SCRIPT):
            with self.subTest(script=script.name):
                default_arguments = self.run_job(script)
                self.assertEqual(
                    flag_values(default_arguments, "--retry-result"), ["timeout"]
                )

                empty_arguments = self.run_job(script, "")
                self.assertEqual(flag_values(empty_arguments, "--retry-result"), [])
                self.assertEqual(
                    flag_values(empty_arguments, "--retry-solver"),
                    ["euf-viper", "z3"],
                )

    def test_shard_and_merge_expand_each_named_result(self) -> None:
        for script in (SHARD_SCRIPT, MERGE_JOB_SCRIPT):
            with self.subTest(script=script.name):
                arguments = self.run_job(script, "timeout,unsupported")
                self.assertEqual(
                    flag_values(arguments, "--retry-result"),
                    ["timeout", "unsupported"],
                )


class SubmitMetadataTests(unittest.TestCase):
    def run_submit(
        self, retry_results: object = UNSET
    ) -> tuple[subprocess.CompletedProcess[str], str, dict | None]:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            project = base / "project"
            remote = base / "remote"
            fake_bin = base / "bin"
            capture = base / "sbatch.log"
            remote.mkdir()
            script_copy = project / "scripts" / "wmi" / SUBMIT_SCRIPT.name
            script_copy.parent.mkdir(parents=True)
            shutil.copy2(SUBMIT_SCRIPT, script_copy)

            write_executable(
                fake_bin / "git",
                """#!/bin/sh
if [ "$1" = "rev-parse" ]; then
  printf '%s\n' 0123456789abcdef0123456789abcdef01234567
fi
exit 0
""",
            )
            write_executable(fake_bin / "rsync", "#!/bin/sh\nexit 0\n")
            write_executable(
                fake_bin / "ssh",
                """#!/bin/sh
shift
exec env -i PATH="$PATH" HOME="$HOME" TEST_SBATCH_CAPTURE="$TEST_SBATCH_CAPTURE" bash -c "$1"
""",
            )
            write_executable(
                fake_bin / "sbatch",
                """#!/usr/bin/env bash
{
  printf 'retry_results=%s\n' "${EUF_VIPER_CORPUS_RETRY_RESULTS-<unset>}"
  printf 'retry_solvers=%s\n' "${EUF_VIPER_CORPUS_RETRY_SOLVERS-<unset>}"
  for argument in "$@"; do
    printf 'arg=%s\n' "$argument"
  done
  printf '%s\n' '---'
} >> "$TEST_SBATCH_CAPTURE"
case "$*" in
  *euf_viper_prepare.sbatch*) printf '101\n' ;;
  *euf_viper_corpus_shard.sbatch*) printf '202\n' ;;
  *euf_viper_merge_shards.sbatch*) printf '303\n' ;;
  *) exit 2 ;;
esac
""",
            )

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                    "TEST_SBATCH_CAPTURE": str(capture),
                    "EUF_VIPER_REMOTE": f"testhost:{remote}",
                    "EUF_VIPER_CORPUS_SHARDS": "1",
                    "EUF_VIPER_CORPUS_MAX_ACTIVE": "1",
                    "EUF_VIPER_CORPUS_RESUME_RUN_ID": "77",
                    "EUF_VIPER_CORPUS_RETRY_SOLVERS": "euf-viper,z3",
                }
            )
            env.pop("EUF_VIPER_CORPUS_RETRY_RESULTS", None)
            if retry_results is not UNSET:
                env["EUF_VIPER_CORPUS_RETRY_RESULTS"] = str(retry_results)

            completed = subprocess.run(
                ["bash", str(script_copy)],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            log = capture.read_text(encoding="utf-8") if capture.exists() else ""
            metadata_path = remote / "results" / "qf-uf-campaign-101.json"
            metadata = (
                json.loads(metadata_path.read_text(encoding="utf-8"))
                if metadata_path.exists()
                else None
            )
            return completed, log, metadata

    def test_submit_forwards_legacy_default_and_explicit_empty(self) -> None:
        for configured, expected in ((UNSET, "timeout"), ("", "")):
            with self.subTest(configured=configured):
                completed, log, metadata = self.run_submit(configured)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(log.count(f"retry_results={expected}\n"), 3)
                self.assertIsNotNone(metadata)
                assert metadata is not None
                self.assertEqual(metadata["retry_results"], expected)

    def test_submit_keeps_comma_lists_intact_for_all_jobs(self) -> None:
        completed, log, metadata = self.run_submit("timeout,unsupported")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(log.count("retry_results=timeout,unsupported\n"), 3)
        self.assertEqual(log.count("retry_solvers=euf-viper,z3\n"), 2)
        self.assertIsNotNone(metadata)
        assert metadata is not None
        self.assertEqual(metadata["retry_results"], "timeout,unsupported")

    def test_submit_rejects_non_shell_safe_result_names(self) -> None:
        completed, log, metadata = self.run_submit("timeout;touch")

        self.assertEqual(completed.returncode, 1)
        self.assertIn("shell-safe result list", completed.stderr)
        self.assertEqual(log, "")
        self.assertIsNone(metadata)


class MergeMetadataTests(unittest.TestCase):
    def test_summary_reports_supplied_retry_results_instead_of_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            work = Path(temp_dir)
            manifest = work / "manifest.jsonl"
            shard = work / "shard.csv"
            manifest.write_text(
                json.dumps(
                    {
                        "id": "case-1",
                        "path": "/tmp/case.smt2",
                        "relative_path": "QF_UF/case.smt2",
                        "status": "sat",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with shard.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=COMPARE.FIELDNAMES)
                writer.writeheader()
                for solver in ("euf-viper", "z3"):
                    writer.writerow(
                        {
                            "id": "case-1",
                            "relative_path": "QF_UF/case.smt2",
                            "expected_status": "sat",
                            "solver": solver,
                            "result": "sat",
                            "time_s": "0.1",
                            "exit_code": "0",
                            "stderr": "",
                        }
                    )

            for retry_arguments, expected in (
                ([], []),
                (
                    ["--retry-result", "unsupported", "--retry-result", "timeout"],
                    ["timeout", "unsupported"],
                ),
            ):
                with self.subTest(retry_arguments=retry_arguments):
                    output = work / "merged.csv"
                    summary = work / "summary.json"
                    completed = subprocess.run(
                        [
                            sys.executable,
                            str(MERGE_SCRIPT),
                            str(manifest),
                            str(shard),
                            "--solver",
                            "euf-viper",
                            "--solver",
                            "z3",
                            "--timeout",
                            "10",
                            "--resume-run-id",
                            "99",
                            *retry_arguments,
                            "--out",
                            str(output),
                            "--summary",
                            str(summary),
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    payload = json.loads(summary.read_text(encoding="utf-8"))
                    self.assertEqual(payload["retry_results"], expected)


if __name__ == "__main__":
    unittest.main()
