from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
COMMON = WMI / "t1_timing_common.sh"
PREPARE = WMI / "euf_viper_t1_timing_prepare.sbatch"
ARRAY = WMI / "euf_viper_t1_timing_array.sbatch"
AUDIT = WMI / "euf_viper_t1_timing_audit.sbatch"
SUBMIT = WMI / "submit_t1_timing.sh"
BUILD_GUARD = WMI / "t1_timing_build_guard.py"
WORKFLOW = ROOT / ".github" / "workflows" / "campaign-contract.yml"
SCRIPTS = (COMMON, PREPARE, ARRAY, AUDIT, SUBMIT)


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
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn('exec 18<"$COMMON_PATH"', text)
        self.assertIn("hash-object --no-filters -- \"$COMMON_DESCRIPTOR\"", text)
        self.assertIn("os.lseek(18, 0, os.SEEK_SET)", text)
        self.assertIn('source "$COMMON_DESCRIPTOR"', text)
        self.assertNotIn("source scripts/wmi/t1_timing_common.sh", text)
        self.assertIn('REVISION" = "$BOOTSTRAP_REVISION', text)
        self.assertIn("--dependency=afterok:$PREPARE_JOB", text)
        self.assertIn("--dependency=afterok:$ARRAY_JOB", text)
        self.assertIn('ARRAY_SPEC="0-$LAST_SHARD%1"', text)
        self.assertIn('ARRAY_SPEC="0-$((CANARY_SHARDS - 1))%1"', text)
        self.assertIn('CANARY_SHARDS=1', text)
        self.assertIn('PARTITION="cpu_idle"', text)
        self.assertIn('NODELIST="c1n1"', text)
        self.assertIn('SHARDS=128', text)
        self.assertIn('MAX_PARALLEL=1', text)
        self.assertIn('WARMUP_ROUNDS=1', text)
        self.assertIn('MEASURED_ROUNDS=5', text)
        self.assertIn('TIMEOUT_SECONDS=2', text)
        self.assertNotIn('REPETITIONS=', text)
        self.assertIn("--nodelist='$NODELIST'", text)
        self.assertIn("--nodes=1", text)
        self.assertIn("--ntasks=1", text)
        self.assertIn("--cpus-per-task=1", text)
        self.assertIn("--hint=nomultithread", text)
        self.assertIn("--threads-per-core=1", text)
        self.assertIn("--cpu-bind=cores", text)
        self.assertIn("--mem-bind=local", text)
        self.assertIn('ARRAY_PLACEMENT="--exclusive --cpu-freq=high:UserSpace"', text)
        self.assertIn('"frequency_contract": "high:UserSpace"', text)
        self.assertIn('MODE="${1#--}"', text)
        self.assertIn('REMOTE_HOST="wmicluster"', text)
        self.assertIn('PUBLISHED_REF="origin/research-typed-parser-timing"', text)
        self.assertNotIn("T1_EXECUTION_ROOT=", text)
        self.assertIn("'$REMOTE_WORK' '$REVISION' '$PUBLISHED_REF' '$MODE'", text)
        self.assertNotIn('${EUF_VIPER_WMI_HOST', text)
        self.assertNotIn('${EUF_VIPER_T1_REMOTE_PARENT', text)
        self.assertNotIn('${EUF_VIPER_T1_CAMPAIGN_TAG', text)
        self.assertIn(
            'MANIFEST_SHA256="32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"',
            text,
        )
        self.assertNotIn('MANIFEST_SHA256="$(ssh', text)
        self.assertIn("verify-corpus", text)
        self.assertIn("t1_verify_checkout \"$REVISION\" \"$PUBLISHED_REF\"", text)
        self.assertIn("test ! -e '$REMOTE_RUN'", text)
        self.assertIn('ln "$TEMPORARY" "$RECEIPT"', text)
        self.assertNotIn('mv "$TEMPORARY" "$RECEIPT"', text)
        self.assertNotIn("git push", text)

    def test_full_placement_is_exactly_serial_and_exclusive(self) -> None:
        submit = SUBMIT.read_text(encoding="utf-8")
        self.assertIn('ARRAY_SPEC="0-$LAST_SHARD%1"', submit)
        self.assertIn('SCHEDULED_MAX_PARALLEL="$MAX_PARALLEL"', submit)
        self.assertIn('"schedule": "serial-exclusive-array.v1"', submit)
        self.assertNotIn('0-$LAST_SHARD%32', submit)
        array = ARRAY.read_text(encoding="utf-8")
        self.assertIn("srun --ntasks=1", array)
        self.assertIn("--require-placement-controls", array)
        self.assertIn("exec /proc/self/fd/19 -I -B /proc/self/fd/18", array)

    def test_canary_cannot_submit_a_complete_array_or_audit(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn('if [ "$MODE" = full ]; then', text)
        self.assertIn('SCHEDULED_SHARDS="$CANARY_SHARDS"', text)
        self.assertIn("AUDIT_JOB_PY=None", text)
        array = ARRAY.read_text(encoding="utf-8")
        self.assertIn('bounded canary permits only shard 0', array)
        self.assertIn("--cpu-freq=high:UserSpace", array)
        self.assertIn("--require-placement-controls", array)

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


if __name__ == "__main__":
    unittest.main()
