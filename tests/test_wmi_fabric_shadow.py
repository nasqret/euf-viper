from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SBATCH = ROOT / "scripts" / "wmi" / "euf_viper_fabric_shadow.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_fabric_shadow.sh"
SCRIPTS = (SBATCH, SUBMIT)


class WmiFabricShadowTests(unittest.TestCase):
    def text(self, path: Path) -> str:
        return path.read_text(encoding="ascii")

    def test_shell_syntax(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", *(str(path) for path in SCRIPTS)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_embedded_python_blocks_compile(self) -> None:
        pattern = re.compile(
            r"<<'(?P<marker>PY_[A-Z0-9_]+)'\n(?P<body>.*?)\n(?P=marker)$",
            re.MULTILINE | re.DOTALL,
        )
        blocks: list[tuple[Path, str]] = []
        for path in SCRIPTS:
            blocks.extend(
                (path, match.group("body"))
                for match in pattern.finditer(self.text(path))
            )
        self.assertEqual(len(blocks), 3)
        for path, body in blocks:
            compile(body, f"{path}:embedded-python", "exec")

    def test_default_smoke_wall_time_is_valid_and_zero_duration_is_not(self) -> None:
        text = self.text(SUBMIT)
        self.assertIn("EUF_VIPER_FABRIC_SMOKE_WALL_TIME:-00:15:00", text)
        match = re.search(
            r"^validate_wall_time\(\) \{\n.*?^\}",
            text,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        function = match.group(0) if match is not None else ""
        accepted = subprocess.run(
            ["bash", "-c", f"{function}\nvalidate_wall_time 00:15:00"],
            check=False,
        )
        rejected = subprocess.run(
            ["bash", "-c", f"{function}\nvalidate_wall_time 00:00:00"],
            check=False,
        )
        self.assertEqual(accepted.returncode, 0)
        self.assertNotEqual(rejected.returncode, 0)

    def test_direct_wmi_user_at_ip_host_is_accepted(self) -> None:
        text = self.text(SUBMIT)
        match = re.search(
            r"^safe_remote_value\(\) \{\n.*?^\}",
            text,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        function = match.group(0) if match is not None else ""
        accepted = subprocess.run(
            [
                "bash",
                "-c",
                f"{function}\nsafe_remote_value 'bnaskrecki@10.71.80.3'",
            ],
            check=False,
        )
        self.assertEqual(accepted.returncode, 0)

    def test_instance_timeout_is_finite_positive_and_explicit(self) -> None:
        submit = self.text(SUBMIT)
        job = self.text(SBATCH)
        self.assertIn("EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S:-60", submit)
        self.assertIn("EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S:-60", job)
        self.assertIn("positive_finite_decimal", submit)
        self.assertIn("math.isfinite(value) and value > 0", submit)
        self.assertIn("math.isfinite(value) and value > 0", job)
        self.assertIn('--timeout-s "$INSTANCE_TIMEOUT_S"', job)
        self.assertIn(
            "EUF_VIPER_FABRIC_INSTANCE_TIMEOUT_S=$INSTANCE_TIMEOUT_S", submit
        )
        self.assertEqual(submit.count('"instance_timeout_s": float('), 1)
        self.assertEqual(job.count('"instance_timeout_s": float('), 1)
        match = re.search(
            r"^positive_finite_decimal\(\) \{\n.*?^\}",
            submit,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        function = match.group(0) if match is not None else ""
        for value, expected in (
            ("60", 0),
            ("0.25", 0),
            ("0", 1),
            ("-1", 1),
            ("nan", 1),
            ("inf", 1),
        ):
            completed = subprocess.run(
                ["bash", "-c", f"{function}\npositive_finite_decimal '{value}'"],
                check=False,
            )
            with self.subTest(value=value):
                self.assertEqual(completed.returncode == 0, expected == 0)

    def test_job_is_explicitly_enabled_and_single_core(self) -> None:
        text = self.text(SBATCH)
        self.assertIn("EUF_VIPER_FABRIC_SHADOW_ENABLE", text)
        self.assertIn("Fabric shadow census is default-off", text)
        self.assertIn("#SBATCH --ntasks=1", text)
        self.assertIn("#SBATCH --cpus-per-task=1", text)
        self.assertIn('SLURM_CPUS_PER_TASK:-}" != 1', text)
        self.assertIn("export CARGO_BUILD_JOBS=1", text)
        self.assertIn("export OMP_NUM_THREADS=1", text)
        self.assertIn("export RAYON_NUM_THREADS=1", text)
        self.assertIn("export PYTHONDONTWRITEBYTECODE=1", text)
        self.assertIn("--jobs 1", text)

    def test_job_freezes_revision_manifest_runner_and_tools(self) -> None:
        text = self.text(SBATCH)
        self.assertIn("EUF_VIPER_FABRIC_EXPECTED_REVISION", text)
        self.assertIn("git rev-parse --verify 'HEAD^{commit}'", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=all", text)
        self.assertIn("EUF_VIPER_FABRIC_MANIFEST_SHA256", text)
        self.assertIn("RUNNER_SHA256", text)
        self.assertIn("EUF_VIPER_FABRIC_CARGO_SHA256", text)
        self.assertIn("EUF_VIPER_FABRIC_RUSTC_SHA256", text)
        self.assertIn("EUF_VIPER_FABRIC_PYTHON_SHA256", text)
        self.assertIn("manifest changed during Fabric census", text)
        self.assertIn("Fabric runner changed during census", text)
        self.assertIn("Fabric solver changed during census", text)

    def test_job_uses_rust_193_release_fabric_build(self) -> None:
        text = self.text(SBATCH)
        self.assertIn("cargo 1.93.0", text)
        self.assertIn("rustc 1.93.0", text)
        self.assertIn("rust-toolchain.toml", text)
        self.assertIn("channel = \"1.93.0\"", text)
        self.assertIn('"$CARGO" build --release --locked --features fabric', text)
        self.assertIn("CARGO_TARGET_DIR", text)
        self.assertIn('BUILD_ROOT="$WORK_ROOT/cargo-targets/slurm-$JOB_ID"', text)
        self.assertIn("Cargo build root must stay below absolute /work", text)
        self.assertNotIn("SLURM_TMPDIR", text)

    def test_job_requires_explicit_remote_corpus_root(self) -> None:
        text = self.text(SBATCH)
        self.assertIn("EUF_VIPER_FABRIC_CORPUS_ROOT", text)
        self.assertIn('canonical_directory "$CORPUS_ROOT"', text)
        self.assertIn('--corpus-root "$CORPUS_ROOT"', text)
        self.assertIn('"corpus_root": corpus_root_raw', text)
        self.assertIn('"corpus_access": "read_only"', text)
        self.assertIn("generated Fabric paths must stay outside", text)

    def test_corpus_root_is_forwarded_without_user_path_or_suffix_guessing(self) -> None:
        submit = self.text(SUBMIT)
        job = self.text(SBATCH)
        self.assertIn('REMOTE_CORPUS_ROOT="$(ssh', submit)
        self.assertIn(
            "EUF_VIPER_FABRIC_CORPUS_ROOT=$REMOTE_CORPUS_ROOT", submit
        )
        self.assertIn('--corpus-root "$CORPUS_ROOT"', job)
        for text in (submit, job):
            self.assertNotIn("/home/bnaskrecki", text)
            self.assertNotIn("$CORPUS_ROOT/QF_UF", text)
            self.assertNotIn("$REMOTE_CORPUS_ROOT/QF_UF", text)

    def test_job_calls_only_the_declared_runner_contract(self) -> None:
        text = self.text(SBATCH)
        self.assertIn('"$PYTHON" scripts/bench/run_fabric_shadow.py', text)
        self.assertIn('--solver "$PERSISTED_SOLVER"', text)
        self.assertIn('--out-jsonl "$RECORDS"', text)
        self.assertIn('--summary "$SUMMARY_CANDIDATE"', text)
        self.assertIn("RUN_ARGS+=(--resume)", text)
        self.assertNotIn('"$PERSISTED_SOLVER" solve', text)
        self.assertNotIn(".artifacts.partial/records.jsonl", self.text(SUBMIT))
        self.assertIn(
            ".artifacts.partial/fabric-shadow.jsonl", self.text(SUBMIT)
        )

    def test_job_publishes_one_atomic_artifact_directory_with_slurm_metadata(
        self,
    ) -> None:
        text = self.text(SBATCH)
        self.assertIn('STAGING_ROOT="$RUN_ROOT/.artifacts.partial"', text)
        self.assertIn('FINAL_ROOT="$RUN_ROOT/artifacts"', text)
        self.assertIn('mv "$STAGING_ROOT" "$FINAL_ROOT"', text)
        for artifact in (
            "fabric-shadow.jsonl",
            "summary.json",
            "slurm.json",
            "stdout.log",
            "stderr.log",
        ):
            self.assertIn(artifact, text)
        self.assertIn('"solver_result_claim": False', text)
        self.assertIn('"solver_result_claims_allowed": 0', text)
        self.assertIn('record.get("solver_result_emitted") is not False', text)
        self.assertIn('"performance_claim": False', text)
        self.assertIn('"promotion_claim": False', text)
        for token in (
            "SLURM_JOB_ID",
            "SLURM_JOB_NAME",
            "SLURM_CLUSTER_NAME",
            "SLURM_JOB_PARTITION",
            "SLURM_JOB_ACCOUNT",
            "SLURM_JOB_NODELIST",
            "SLURM_CPUS_PER_TASK",
            "SLURM_SUBMIT_DIR",
        ):
            self.assertIn(token, text)

    def test_submitter_has_full_and_smoke_modes_without_path_guessing(self) -> None:
        text = self.text(SUBMIT)
        self.assertIn("--full MANIFEST | --smoke MANIFEST", text)
        self.assertIn("EUF_VIPER_FABRIC_FULL_MANIFEST", text)
        self.assertIn("EUF_VIPER_FABRIC_SMOKE_MANIFEST", text)
        self.assertIn("full Fabric manifest must contain exactly 7503 rows", text)
        self.assertIn(
            "9c509b0ffd35a371738dbb31865f975b43350fca5f54393f7bb5014d450a08db",
            text,
        )
        self.assertIn("full Fabric manifest does not match the frozen F0 SHA-256", text)
        self.assertIn("smoke manifest cannot exceed", text)
        self.assertIn('REQUESTED_CORPUS_ROOT="${EUF_VIPER_FABRIC_CORPUS_ROOT:-}"', text)
        self.assertIn("remote corpus locations are never guessed", text)
        self.assertNotIn("benchmarks/smtlib-2025/QF_UF", text)

    def test_submitter_preflights_work_and_read_only_corpus_roots(self) -> None:
        text = self.text(SUBMIT)
        self.assertIn("Fabric work root must be outside remote HOME", text)
        self.assertIn("EUF_VIPER_FABRIC_WORK_ROOT must be below absolute /work", text)
        self.assertIn("canonical Fabric work root must stay below absolute /work", text)
        self.assertNotIn("Fabric corpus root must be outside remote HOME", text)
        self.assertIn("work root must stay outside the read-only corpus root", text)
        self.assertIn("test -d '$REQUESTED_CORPUS_ROOT'", text)
        self.assertIn("test ! -L '$REQUESTED_CORPUS_ROOT'", text)
        self.assertIn("test -r '$REQUESTED_CORPUS_ROOT'", text)
        self.assertIn("test -x '$REQUESTED_CORPUS_ROOT'", text)
        self.assertIn("test -f '$MANIFEST'", text)
        self.assertIn("test ! -L '$MANIFEST'", text)
        self.assertIn("test -w '$REQUESTED_WORK_ROOT'", text)

    def test_submitter_requires_published_clean_head_and_pinned_remote_tools(
        self,
    ) -> None:
        text = self.text(SUBMIT)
        self.assertIn("git status --porcelain=v1 --untracked-files=all", text)
        self.assertIn("git ls-remote --exit-code", text)
        self.assertIn("refs/heads/perf-viper-fabric", text)
        self.assertIn("HEAD $REVISION is not the published", text)
        self.assertIn("1.93.0-x86_64-unknown-linux-gnu/bin/cargo", text)
        self.assertIn("1.93.0-x86_64-unknown-linux-gnu/bin/rustc", text)
        self.assertIn("REMOTE_CARGO_SHA256", text)
        self.assertIn("REMOTE_RUSTC_SHA256", text)
        self.assertIn("REMOTE_PYTHON_SHA256", text)
        self.assertIn("RUNNER_SHA256", text)

    def test_submitter_uses_parsable_sbatch_and_prints_atomic_json_receipt(
        self,
    ) -> None:
        text = self.text(SUBMIT)
        self.assertEqual(text.count("sbatch --parsable"), 1)
        self.assertIn("--kill-on-invalid-dep=yes", text)
        self.assertIn("EUF_VIPER_FABRIC_CORPUS_ROOT=$REMOTE_CORPUS_ROOT", text)
        self.assertIn('"cpus_per_task": 1', text)
        self.assertIn('"runner_jobs": 1', text)
        self.assertIn('"solver_result_claim": False', text)
        self.assertIn("tempfile.mkstemp", text)
        self.assertIn("os.replace(temporary, output)", text)
        self.assertIn("write_receipt submission_intent", text)
        self.assertIn("write_receipt submitted", text)
        self.assertIn('cat "$SUBMISSION_PATH"', text)
        self.assertNotIn("scancel", text)
        self.assertNotIn("scontrol release", text)


if __name__ == "__main__":
    unittest.main()
