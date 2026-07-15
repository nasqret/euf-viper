from __future__ import annotations

import importlib.util
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
COMMON = WMI / "t1_timing_common.sh"
PREPARE = WMI / "euf_viper_t1_timing_prepare.sbatch"
ARRAY = WMI / "euf_viper_t1_timing_array.sbatch"
AUDIT = WMI / "euf_viper_t1_timing_audit.sbatch"
SUBMIT = WMI / "submit_t1_timing.sh"
REMOTE_SUBMIT = WMI / "t1_timing_remote_submit.py"
BUILD_GUARD = WMI / "t1_timing_build_guard.py"
CI_INTEGRATION = ROOT / "scripts" / "ci" / "t1_timing_release_integration.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "campaign-contract.yml"
SCRIPTS = (COMMON, PREPARE, ARRAY, AUDIT, SUBMIT)
REMOTE_SPEC = importlib.util.spec_from_file_location("t1_timing_remote_submit", REMOTE_SUBMIT)
assert REMOTE_SPEC is not None and REMOTE_SPEC.loader is not None
REMOTE = importlib.util.module_from_spec(REMOTE_SPEC)
REMOTE_SPEC.loader.exec_module(REMOTE)


class WmiT1TimingTests(unittest.TestCase):
    def test_shell_scripts_are_executable_and_parse(self) -> None:
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                self.assertTrue(script.stat().st_mode & 0o111)
                subprocess.run(["bash", "-n", script], check=True)

    def test_every_job_validates_exact_root_before_source_and_rechecks_tools(self) -> None:
        for script in (PREPARE, ARRAY, AUDIT):
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                self.assertIn("t1_verify_checkout", text)
                self.assertIn("t1_verify_pinned_tool Python", text)
                self.assertIn("t1_verify_pinned_tool Cargo", text)
                self.assertIn("t1_verify_pinned_tool Rustc", text)
                self.assertIn("t1_verify_pinned_tool CC", text)
                self.assertIn("t1_verify_pinned_tool LD", text)
                self.assertIn("t1_verify_pinned_tool AR", text)
                self.assertIn('T1_JOB_ROOT="$1"', text)
                self.assertIn('EXPECTED_REVISION="$2"', text)
                self.assertIn('PUBLISHED_REF="$3"', text)
                self.assertIn('SUBMISSION_MODE="$4"', text)
                self.assertNotIn("${T1_", text)
                self.assertIn("T1 common helper blob mismatch", text)
                self.assertNotIn("SLURM_SUBMIT_DIR", text)
                self.assertLess(
                    text.index("T1 execution root published-ref mismatch"),
                    text.index("source /proc/self/fd/18"),
                )
                self.assertIn("hash-object --no-filters -- /proc/self/fd/18", text)
                self.assertIn("set -euo pipefail", text)
                self.assertIn('scripts/bench/typed_parser_timing.py"', text)
                self.assertNotIn(
                    'cd "$SOURCE_SNAPSHOT"\n"$EUF_VIPER_PYTHON"', text
                )

    def test_checkout_guard_rejects_hidden_state_and_binds_runtime_blobs(self) -> None:
        text = COMMON.read_text(encoding="utf-8")
        for required in (
            "git ls-files -v",
            "tracked index has nonnormal flags",
            "git diff --quiet",
            "git diff --cached --quiet",
            "git write-tree",
            "git hash-object --no-filters",
            "published ref",
            "src/main.rs",
            "src/smt2_stream.rs",
            "campaigns/t1-typed-parser-timing-v1.json",
            "scripts/bench/typed_parser_timing.py",
            "scripts/wmi/t1_timing_build_guard.py",
            "scripts/wmi/t1_timing_remote_submit.py",
        ):
            self.assertIn(required, text)

    def test_opened_shell_helper_survives_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            helper = root / "helper.sh"
            replacement = root / "replacement.sh"
            helper.write_text("BOUND_HELPER=original\n", encoding="ascii")
            replacement.write_text("BOUND_HELPER=replacement\n", encoding="ascii")
            descriptor_path = "/proc/self/fd/18" if Path("/proc/self/fd").is_dir() else "/dev/fd/18"
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    'set -euo pipefail; exec 18<"$1"; '
                    f'git hash-object --no-filters -- {descriptor_path} >/dev/null; '
                    'mv "$2" "$1"; '
                    "env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B -c "
                    "'import os; os.lseek(18, 0, os.SEEK_SET)'; "
                    f'source {descriptor_path}; test "$BOUND_HELPER" = original',
                    "t1-helper-test",
                    str(helper),
                    str(replacement),
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_prepare_builds_one_release_binary_and_uses_fixed_contract(self) -> None:
        text = PREPARE.read_text(encoding="utf-8")
        self.assertEqual(text.count("--release --locked"), 1)
        self.assertNotIn("--all-features", text)
        self.assertIn("campaigns/t1-typed-parser-timing-v1.json", text)
        self.assertIn('"$PYTHON_EXEC" -I -B "$HARNESS_EXEC" prepare', text)
        self.assertIn("git archive --format=tar", text)
        self.assertIn("t1_timing_build_guard.py", text)
        self.assertIn(" monitor ", text)
        self.assertIn("--control-fd 0", text)
        self.assertNotIn("--stop", text)
        self.assertIn("mutation monitor lost liveness during compilation", text)
        self.assertIn("3>&- 4>&- 5>&- 8>&- 13>&- 18>&- 19>&- 20>&-", text)
        self.assertIn("18>&- 19>&- 20>&- &", text)
        self.assertIn("--binary-fd 7", text)
        self.assertIn("--output-fd 17", text)
        self.assertIn(" inventory ", text)
        self.assertIn("$RUN_ROOT/source", text)
        self.assertIn("$RUN_ROOT/target", text)
        self.assertIn("$RUN_ROOT/build-cargo-home", text)
        self.assertIn("$RUN_ROOT/fetch-cargo-home", text)
        self.assertIn(
            'BUILD_GUARD="$SOURCE_SNAPSHOT/scripts/wmi/t1_timing_build_guard.py"',
            text,
        )
        self.assertIn("[ ! -e /.cargo/config ]", text)
        self.assertIn("cd /", text)
        self.assertIn('"$EUF_VIPER_CARGO" vendor', text)
        self.assertIn("--locked --versioned-dirs", text)
        self.assertIn("inventory-tree", text)
        self.assertIn("DEPENDENCY_MONITOR_RECEIPT", text)
        self.assertIn('--snapshot "$DEPENDENCY_ROOT"', text)
        self.assertIn("--dependency-monitor-receipt", text)
        self.assertIn("--dependency-monitor-ready", text)
        self.assertIn("verify-ready", text)
        self.assertIn("CARGO_NET_OFFLINE=true", text)
        self.assertIn("--release --locked --offline", text)
        self.assertIn("source.vendored-sources.directory", text)
        self.assertIn("target-feature=+crt-static", text)
        self.assertIn("BUILD_GUARD_EXEC=/proc/self/fd/18", text)
        self.assertIn("HARNESS_EXEC=/proc/self/fd/19", text)

    def test_submit_chain_is_prepare_then_array_then_audit(self) -> None:
        local = SUBMIT.read_text(encoding="utf-8")
        remote = REMOTE_SUBMIT.read_text(encoding="utf-8")
        self.assertIn('exec 30<"${BASH_SOURCE[0]}"', local)
        self.assertIn('exec 18<"$ROOT/$COMMON_RELATIVE"', local)
        self.assertIn("hash-object --no-filters -- \"$COMMON_DESCRIPTOR\"", local)
        self.assertIn("os.lseek(18, 0, os.SEEK_SET)", local)
        self.assertIn('source "$COMMON_DESCRIPTOR"', local)
        self.assertNotIn("source scripts/wmi/t1_timing_common.sh", local)
        self.assertIn('exec 17<"$ROOT/$HARNESS_RELATIVE"', local)
        self.assertIn("local_harness()", local)
        self.assertIn("os.lseek(17, 0, os.SEEK_SET)", local)
        self.assertIn('exec 19<"$ROOT/$REMOTE_HELPER_RELATIVE"', local)
        self.assertIn('ssh "$REMOTE_HOST" /usr/bin/python3 -I -B -', local)
        self.assertIn("remote_helper \"${STAGE_ARGUMENTS[@]}\"", local)
        self.assertIn("verify-submission-receipt-file", local)
        self.assertIn('exec 16<"$TEMPORARY"', local)
        self.assertIn("--submission-receipt-fd 16", local)
        self.assertIn("os.link(source, destination, follow_symlinks=False)", local)
        self.assertIn("published receipt is not the retained inode", local)
        self.assertNotIn('mv "$TEMPORARY" "$RECEIPT"', local)
        self.assertLess(
            local.index("os.link(source, destination"),
            local.index("remote_helper release"),
        )
        self.assertIn("remote_helper cancel", local)
        self.assertIn('STAGED=1', local)
        self.assertIn('STAGED=0', local)
        self.assertIn('REMOTE_HOST="wmicluster"', local)
        self.assertIn('PUBLISHED_REF="origin/research-typed-parser-timing"', local)
        self.assertIn('SHARDS=128', local)
        self.assertIn('MAX_PARALLEL=1', local)
        self.assertIn('WARMUP_ROUNDS=1', local)
        self.assertIn('MEASURED_ROUNDS=5', local)
        self.assertIn('TIMEOUT_SECONDS=2', local)
        self.assertNotIn("git push", local)

        self.assertIn('"/usr/bin/sbatch"', remote)
        self.assertIn('"--hold"', remote)
        self.assertIn('f"/proc/self/fd/{wrapper_fd}"', remote)
        self.assertIn('pass_fds=(wrapper_fd,)', remote)
        self.assertIn('f"--dependency=afterok:{prepare_id}"', remote)
        self.assertIn('f"--dependency=afterok:{array_id}"', remote)
        self.assertIn('publish(submission_receipt, content)', remote)
        self.assertLess(remote.index('publish(submission_receipt, content)'), remote.index("def release("))
        self.assertIn('f"JobName=euf-t1-{role}-{receipt_hash}"', remote)
        self.assertIn('["/usr/bin/scontrol", "release", job["id"]]', remote)
        self.assertIn('fields.get("WorkDir") == remote_work', remote)
        self.assertIn('fields.get("UserId", "").startswith', remote)
        self.assertIn('["/usr/bin/scancel", job_id]', remote)

    def test_full_placement_is_exactly_serial_and_exclusive(self) -> None:
        submit = REMOTE_SUBMIT.read_text(encoding="utf-8")
        self.assertIn('array_spec = "0-0%1" if args.mode == "canary" else "0-127%1"', submit)
        self.assertIn('array_options.extend(["--exclusive", f"--cpu-freq={FREQUENCY}"])', submit)
        self.assertIn('"schedule": "serial-exclusive-array.v2"', submit)
        self.assertIn('array_state["exclusive"] != "NODE"', submit)
        self.assertIn('fields.get("Exclusive") != held["exclusive"]', submit)
        self.assertNotIn("0-127%32", submit)
        array = ARRAY.read_text(encoding="utf-8")
        self.assertIn("srun --ntasks=1", array)
        self.assertIn("--require-placement-controls", array)
        self.assertIn("exec /proc/self/fd/19 -I -B /proc/self/fd/18", array)

    def test_canary_cannot_submit_a_complete_array_or_audit(self) -> None:
        text = REMOTE_SUBMIT.read_text(encoding="utf-8")
        self.assertIn('array_spec = "0-0%1" if args.mode == "canary" else "0-127%1"', text)
        self.assertIn('roles = ("prepare", "array") if args.mode == "canary"', text)
        self.assertIn('if args.mode == "full":', text)
        self.assertIn('"audit": None', text)
        self.assertIn('"scheduled_shards": array["count"]', text)
        array = ARRAY.read_text(encoding="utf-8")
        self.assertIn('bounded canary permits only shard 0', array)
        self.assertIn("--cpu-freq=high:UserSpace", array)
        self.assertIn("--require-placement-controls", array)

    def test_static_flags_are_target_scoped_for_host_proc_macros(self) -> None:
        for script in (PREPARE, CI_INTEGRATION):
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                self.assertIn('TARGET_TRIPLE="x86_64-unknown-linux-gnu"', text)
                self.assertIn("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=", text)
                self.assertIn('--target "$TARGET_TRIPLE"', text)
                self.assertIn('$CARGO_TARGET_DIR/$TARGET_TRIPLE/release/euf-viper', text)
                self.assertIsNone(
                    re.search(r"(?m)^\s*(?:export\s+)?RUSTFLAGS=", text),
                    "global RUSTFLAGS would infect host proc-macro compilation",
                )

    def test_hosted_paths_are_initialized_from_runner_environment_in_a_step(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("${{ runner.temp }}", text)
        self.assertIn('t1_root="$RUNNER_TEMP/euf-viper-t1-locked-release"', text)
        self.assertIn('>> "$GITHUB_ENV"', text)

    def test_build_guard_is_executable_and_compiles(self) -> None:
        self.assertTrue(BUILD_GUARD.stat().st_mode & 0o111)
        compile(BUILD_GUARD.read_text(encoding="utf-8"), str(BUILD_GUARD), "exec")
        text = BUILD_GUARD.read_text(encoding="utf-8")
        self.assertIn("parent-owned-pipe-eof.v1", text)
        self.assertIn("PT_INTERP", text)
        self.assertIn("DT_NEEDED", text)
        self.assertIn("must not contain PT_INTERP", text)
        self.assertIn("must not contain DT_NEEDED", text)
        self.assertNotIn("/usr/bin/ldd", text)

    def test_remote_transaction_helper_is_executable_and_compiles(self) -> None:
        self.assertTrue(REMOTE_SUBMIT.stat().st_mode & 0o111)
        compile(
            REMOTE_SUBMIT.read_text(encoding="utf-8"),
            str(REMOTE_SUBMIT),
            "exec",
        )

    def test_failed_publication_cleanup_cancels_only_exact_owned_staged_jobs(self) -> None:
        states = {
            "13": {
                "UserId": "other(999)",
                "WorkDir": "/tmp/t1/repo",
                "JobName": "euf-t1-audit-pending",
            },
            "12": {
                "UserId": "fixture-user(1000)",
                "WorkDir": "/tmp/t1/repo",
                "JobName": "euf-t1-array-pending",
            },
            "11": {
                "UserId": "fixture-user(1000)",
                "WorkDir": "/tmp/t1/repo",
                "JobName": "euf-t1-prepare-pending",
            },
        }
        with (
            patch.object(REMOTE, "job_state", side_effect=lambda job, **_: states[job]),
            patch.object(REMOTE.getpass, "getuser", return_value="fixture-user"),
            patch.object(REMOTE.subprocess, "run") as run,
        ):
            REMOTE.cancel_staged_jobs(
                [("prepare", "11"), ("array", "12"), ("audit", "13")],
                remote_work=Path("/tmp/t1/repo"),
                home=Path("/tmp"),
            )
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [["/usr/bin/scancel", "12"], ["/usr/bin/scancel", "11"]],
        )
        text = REMOTE_SUBMIT.read_text(encoding="utf-8")
        stage_failure = text.split("def stage(", 1)[1].split("def release(", 1)[0]
        self.assertIn(
            "cancel_staged_jobs(jobs, remote_work=remote_work, home=home)",
            stage_failure,
        )

    def test_release_failure_cancels_receipt_scoped_jobs(self) -> None:
        held = {
            "user": "fixture-user",
            "work_dir": "/tmp/t1/repo",
            "job_state": "PENDING",
            "reason": "JobHeldUser",
            "oversubscribe": "NO",
            "exclusive": "NO",
            "array_task_id": None,
            "array_task_throttle": None,
        }
        receipt = {
            "jobs": {
                "prepare": {"id": "11", "held_state": held},
                "array": None,
                "audit": None,
            }
        }
        state = {
            "UserId": "fixture-user(1000)",
            "WorkDir": "/tmp/t1/repo",
            "JobState": "PENDING",
            "Reason": "JobHeldUser",
            "JobName": "euf-t1-prepare-pending",
            "OverSubscribe": "NO",
            "Exclusive": "NO",
        }
        with (
            patch.object(REMOTE, "load_receipt", return_value=(receipt, b"receipt\n")),
            patch.object(REMOTE, "job_state", return_value=state),
            patch.object(REMOTE, "run", side_effect=REMOTE.TransactionError("update failed")),
            patch.object(REMOTE, "cancel_only_owned") as cancel,
        ):
            with self.assertRaisesRegex(REMOTE.TransactionError, "update failed"):
                REMOTE.release(
                    SimpleNamespace(receipt=Path("/tmp/receipt"), receipt_sha256="0" * 64)
                )
        cancel.assert_called_once_with(receipt, home=Path.home().resolve(strict=True))

    def test_monitor_setup_watches_parents_before_traversal_and_reconciles(self) -> None:
        text = BUILD_GUARD.read_text(encoding="utf-8")
        setup = text.split("def install_parent_first()", 1)[1].split(
            "ready = {", 1
        )[0]
        self.assertLess(setup.index("inotify_add_watch("), setup.index("os.scandir(directory)"))
        self.assertIn("first_watch_set = install_parent_first()", setup)
        self.assertIn("second_watch_set = install_parent_first()", setup)
        self.assertGreaterEqual(setup.count("drain_inotify(0)"), 2)
        self.assertIn("if first_watch_set != second_watch_set", setup)
        self.assertIn("validate_watch_set(watch_set, snapshot=snapshot, verify_current=True)", setup)
        self.assertIn('"setup_event_count": event_count', text)
        self.assertIn('ready["setup_event_count"] != 0', text)
        self.assertIn("while idle_polls < 4 and drain_polls < 100", text)
        self.assertIn('"events": ["DRAIN_LIMIT"]', text)


if __name__ == "__main__":
    unittest.main()
